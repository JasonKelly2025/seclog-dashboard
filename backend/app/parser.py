"""Parse raw CSV / JSON / NDJSON security logs into normalized records.

Field names vary wildly between log sources, so we map common aliases onto a
normalized schema: timestamp, source_ip, username, event_type, status, message.
Unrecognized fields are preserved in the raw payload.
"""

import csv
import io
import json
import re
from datetime import datetime
from typing import Any

FIELD_ALIASES: dict[str, list[str]] = {
    "timestamp": ["timestamp", "time", "datetime", "date", "@timestamp", "event_time", "ts", "eventtime"],
    "source_ip": ["source_ip", "src_ip", "ip", "ip_address", "client_ip", "remote_addr", "srcaddr", "sourceip", "src"],
    "username": ["username", "user", "account", "user_name", "login", "uid", "accountname"],
    "event_type": ["event_type", "event", "action", "activity", "type", "event_name", "eventname", "category"],
    "status": ["status", "result", "outcome", "success", "disposition"],
    "message": ["message", "msg", "description", "details", "log", "text", "summary"],
}

TIMESTAMP_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%b %d %H:%M:%S",
    "%d %b %Y %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",
    "%d/%b/%Y:%H:%M:%S",
]

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Timestamp shapes commonly found at the start of plain-text log lines.
LINE_TIMESTAMP_RES = [
    re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"),
    re.compile(r"\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s[+-]\d{4})?"),  # Apache CLF
    re.compile(r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"),  # syslog
    re.compile(r"\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}"),
]

# Username shapes in free-form text, ordered by specificity.
LINE_USERNAME_RES = [
    re.compile(r"\buser(?:name)?[=:]\s*([\w.@-]+)", re.IGNORECASE),
    re.compile(r"\binvalid user ([\w.@-]+)", re.IGNORECASE),
    re.compile(r"\b(?:password|login|logon|session|authentication) for (?:user )?['\"]?([\w.@-]+)['\"]?", re.IGNORECASE),
    re.compile(r"\bfor user ['\"]?([\w.@-]+)['\"]?", re.IGNORECASE),
    re.compile(r"\buser ['\"]?([\w.@-]+)['\"]? (?:logged|login|logon|authenticated|failed)", re.IGNORECASE),
]


class ParseError(Exception):
    pass


def parse_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        # Unix epoch, seconds or milliseconds
        try:
            ts = float(value)
            if ts > 1e12:
                ts /= 1000.0
            return datetime.fromtimestamp(ts)
        except (ValueError, OSError, OverflowError):
            return None
    text = str(value).strip()
    if not text:
        return None
    cleaned = text.replace("Z", "+0000")
    for fmt in TIMESTAMP_FORMATS:
        try:
            dt = datetime.strptime(cleaned, fmt)
            # Syslog-style timestamps lack a year; assume the current one.
            if dt.year == 1900:
                dt = dt.replace(year=datetime.now().year)
            return dt.replace(tzinfo=None) if dt.tzinfo else dt
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return dt.replace(tzinfo=None) if dt.tzinfo else dt
    except ValueError:
        return None


def _normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    lowered = {str(k).strip().lower(): v for k, v in record.items()}
    normalized: dict[str, Any] = {}
    for field, aliases in FIELD_ALIASES.items():
        for alias in aliases:
            if alias in lowered and lowered[alias] not in (None, ""):
                normalized[field] = lowered[alias]
                break

    normalized["timestamp"] = parse_timestamp(normalized.get("timestamp"))

    # Fall back to scraping an IP out of the message text.
    if "source_ip" not in normalized:
        match = IPV4_RE.search(str(normalized.get("message", "")))
        if match:
            normalized["source_ip"] = match.group(0)

    for key in ("source_ip", "username", "event_type", "status", "message"):
        if key in normalized and normalized[key] is not None:
            normalized[key] = str(normalized[key]).strip()

    if not normalized.get("message"):
        # Without a message field, keep the full record as the message.
        normalized["message"] = json.dumps(record, default=str)

    normalized["raw"] = json.dumps(record, default=str)
    return normalized


def _parse_json(content: str) -> list[dict[str, Any]]:
    content = content.strip()
    if not content:
        return []
    # Try a single JSON document first (array or object wrapper).
    try:
        data = json.loads(content)
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        if isinstance(data, dict):
            # Common wrappers: {"logs": [...]}, {"events": [...]}, {"records": [...]}
            for key in ("logs", "events", "records", "entries", "data"):
                if isinstance(data.get(key), list):
                    return [r for r in data[key] if isinstance(r, dict)]
            return [data]
    except json.JSONDecodeError:
        pass
    # Fall back to NDJSON (one JSON object per line).
    records = []
    total_lines = 0
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        total_lines += 1
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                records.append(obj)
        except json.JSONDecodeError:
            continue
    # Require a majority of lines to be JSON; otherwise the file is likely
    # plain text with an incidental JSON-looking line, and the plaintext
    # parser will preserve every line instead of silently dropping most.
    if not records or len(records) / total_lines < 0.5:
        raise ParseError("File is not valid JSON, a JSON array, or NDJSON.")
    return records


def _parse_csv(content: str) -> list[dict[str, Any]]:
    sample = content[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(content), dialect=dialect)
    if not reader.fieldnames:
        raise ParseError("CSV file has no header row.")
    return [dict(row) for row in reader]


def _parse_line(line: str) -> dict[str, Any]:
    record: dict[str, Any] = {"message": line}

    for pattern in LINE_TIMESTAMP_RES:
        match = pattern.search(line)
        if match:
            record["timestamp"] = match.group(0)
            break

    for pattern in LINE_USERNAME_RES:
        match = pattern.search(line)
        if match:
            record["username"] = match.group(1)
            break

    # _normalize_record scrapes the IP out of the message if present.
    return record


def _parse_plaintext(content: str) -> list[dict[str, Any]]:
    records = [
        _parse_line(line.strip())
        for line in content.splitlines()
        if line.strip()
    ]
    if not records:
        raise ParseError("File contains no non-empty lines.")
    return records


def parse_file(filename: str, content: bytes) -> list[dict[str, Any]]:
    """Return a list of normalized log records from an uploaded file."""
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = content.decode("latin-1")

    name = filename.lower()
    if name.endswith((".json", ".ndjson", ".jsonl")):
        records = _parse_json(text)
    elif name.endswith((".csv", ".tsv")):
        records = _parse_csv(text)
    elif name.endswith((".txt", ".log")):
        # A .txt file may still hold JSON/NDJSON; sniff the content rather
        # than trusting the extension.
        if text.lstrip()[:1] in ("{", "["):
            try:
                records = _parse_json(text)
            except ParseError:
                records = _parse_plaintext(text)
        else:
            records = _parse_plaintext(text)
    else:
        # Unknown extension: try JSON, then CSV, then fall back to plain text.
        try:
            records = _parse_json(text)
        except ParseError:
            try:
                records = _parse_csv(text)
            except (ParseError, csv.Error):
                records = _parse_plaintext(text)

    if not records:
        raise ParseError("No records found in file.")
    return [_normalize_record(r) for r in records]

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
]

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


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
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                records.append(obj)
        except json.JSONDecodeError:
            continue
    if not records:
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
    else:
        # Unknown extension: try JSON first, then CSV.
        try:
            records = _parse_json(text)
        except ParseError:
            records = _parse_csv(text)

    if not records:
        raise ParseError("No records found in file.")
    return [_normalize_record(r) for r in records]

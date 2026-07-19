"""Severity scoring engine.

Each parsed record gets a 0-100 severity score built from two passes:

1. Per-entry indicators (failed login keywords, known bad IPs, privilege
   escalation, suspicious keywords, off-hours activity).
2. Batch aggregation across the whole upload (repeated failures from one IP
   suggest brute force; many usernames from one IP suggest password spraying).
"""

import ipaddress
import json
import re
from collections import defaultdict
from typing import Any

# Demo blocklist. In production this would come from a threat-intel feed.
KNOWN_BAD_IPS: set[str] = {
    "185.220.101.34",
    "45.155.205.233",
    "91.240.118.172",
    "103.94.108.114",
    "194.26.29.156",
    "23.129.64.130",
    "179.43.175.38",
    "5.188.206.18",
}

KNOWN_BAD_NETWORKS = [
    ipaddress.ip_network("185.220.100.0/22"),  # frequently-abused Tor exit range (demo)
    ipaddress.ip_network("45.155.204.0/23"),
]

FAILED_LOGIN_RE = re.compile(
    r"fail(ed|ure)?[\s_-]*(login|logon|password|auth)"
    r"|invalid\s+(user|password|credentials)"
    r"|authentication\s+fail"
    r"|access\s+denied"
    r"|login\s+fail",
    re.IGNORECASE,
)

PRIV_ESC_RE = re.compile(
    r"\bsudo\b|\broot\b|privilege\s+escalat|admin\s+(access|login|granted)"
    r"|added\s+to\s+(administrators|sudoers|admin)"
    r"|permission\s+elevat",
    re.IGNORECASE,
)

SUSPICIOUS_RE = re.compile(
    r"malware|ransomware|trojan|backdoor|rootkit"
    r"|brute[\s_-]?force|password\s+spray"
    r"|sql\s*injection|xss|cross[\s_-]site"
    r"|reverse\s+shell|c2\b|command\s+and\s+control"
    r"|exfiltrat|unauthorized|tamper|disabled\s+(firewall|antivirus|defender|logging)",
    re.IGNORECASE,
)

FAILURE_STATUS_RE = re.compile(r"^(fail(ed|ure)?|denied|blocked|reject(ed)?|error|4[0-9]{2})$", re.IGNORECASE)

SEVERITY_LEVELS = [
    (80, "Critical"),
    (60, "High"),
    (40, "Medium"),
    (20, "Low"),
    (0, "Info"),
]


def _is_known_bad_ip(ip: str | None) -> bool:
    if not ip:
        return False
    if ip in KNOWN_BAD_IPS:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in KNOWN_BAD_NETWORKS)


def _entry_indicators(record: dict[str, Any]) -> list[dict[str, Any]]:
    indicators = []
    text = " ".join(
        str(record.get(k) or "") for k in ("event_type", "status", "message")
    )

    status = str(record.get("status") or "")
    is_failure = bool(FAILED_LOGIN_RE.search(text)) or bool(FAILURE_STATUS_RE.match(status.strip()))
    if is_failure:
        indicators.append({"name": "failed_login", "label": "Failed login / access denied", "points": 25})

    if _is_known_bad_ip(record.get("source_ip")):
        indicators.append({"name": "known_bad_ip", "label": f"Known bad IP ({record.get('source_ip')})", "points": 45})

    if PRIV_ESC_RE.search(text):
        indicators.append({"name": "privilege_escalation", "label": "Privilege escalation activity", "points": 30})

    if SUSPICIOUS_RE.search(text):
        indicators.append({"name": "suspicious_keywords", "label": "Suspicious keywords (malware/injection/etc.)", "points": 35})

    ts = record.get("timestamp")
    if ts is not None and (ts.hour < 5 or ts.hour >= 23):
        indicators.append({"name": "off_hours", "label": "Off-hours activity (11pm-5am)", "points": 10})

    return indicators


def score_batch(records: list[dict[str, Any]]) -> None:
    """Mutates each record, adding severity_score, severity_label, indicators."""
    per_entry = [_entry_indicators(r) for r in records]

    # Aggregate failed logins per source IP and per username across the batch.
    fails_by_ip: dict[str, int] = defaultdict(int)
    users_by_ip: dict[str, set] = defaultdict(set)
    for record, indicators in zip(records, per_entry):
        ip = record.get("source_ip")
        if any(i["name"] == "failed_login" for i in indicators) and ip:
            fails_by_ip[ip] += 1
            if record.get("username"):
                users_by_ip[ip].add(record["username"])

    for record, indicators in zip(records, per_entry):
        ip = record.get("source_ip")
        if ip and fails_by_ip.get(ip, 0) >= 5 and any(i["name"] == "failed_login" for i in indicators):
            count = fails_by_ip[ip]
            points = 25 if count >= 10 else 15
            indicators.append({
                "name": "repeated_failures",
                "label": f"Repeated failures from IP ({count} in batch, possible brute force)",
                "points": points,
            })
            if len(users_by_ip.get(ip, set())) >= 3:
                indicators.append({
                    "name": "password_spray",
                    "label": f"Multiple usernames targeted from IP ({len(users_by_ip[ip])} accounts)",
                    "points": 20,
                })

        score = min(100, sum(i["points"] for i in indicators))
        record["severity_score"] = float(score)
        record["severity_label"] = severity_label(score)
        record["indicators"] = json.dumps(indicators)


def severity_label(score: float) -> str:
    for threshold, label in SEVERITY_LEVELS:
        if score >= threshold:
            return label
    return "Info"

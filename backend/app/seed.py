"""Seed the database with the bundled sample logs whenever it is empty.

This guarantees the demo data set is always visible: on startup after a fresh
deploy, and immediately after a "reset" that clears all entries.
"""

from pathlib import Path

from sqlalchemy.orm import Session

from . import models
from .parser import ParseError, parse_file
from .scoring import score_batch

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample_logs"
SEED_UPLOAD_ID = "sample-seed"


def seed_if_empty(db: Session) -> int:
    """Load sample logs if the table is empty. Returns rows inserted."""
    if db.query(models.LogEntry.id).first() is not None:
        return 0

    inserted = 0
    for path in sorted(SAMPLE_DIR.iterdir()):
        if not path.is_file():
            continue
        try:
            records = parse_file(path.name, path.read_bytes())
        except ParseError:
            continue
        score_batch(records)
        db.add_all(
            models.LogEntry(
                upload_id=SEED_UPLOAD_ID,
                source_file=path.name,
                timestamp=r.get("timestamp"),
                source_ip=r.get("source_ip"),
                username=r.get("username"),
                event_type=r.get("event_type"),
                status=r.get("status"),
                message=r.get("message", ""),
                raw=r.get("raw", ""),
                severity_score=r["severity_score"],
                severity_label=r["severity_label"],
                indicators=r["indicators"],
            )
            for r in records
        )
        inserted += len(records)
    db.commit()
    return inserted

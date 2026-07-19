import hmac
import os
import uuid
from collections import Counter

from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import desc, func, or_
from sqlalchemy.orm import Session

from . import models, schemas
from .database import Base, engine, get_db
from .parser import ParseError, parse_file
from .scoring import score_batch

Base.metadata.create_all(bind=engine)

app = FastAPI(title="SecLog Dashboard API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_UPLOAD_BYTES = 20 * 1024 * 1024  # 20 MB

# When ADMIN_KEY is set (e.g. on the hosted deployment), destructive endpoints
# require it. When unset (local development), they stay open for convenience.
ADMIN_KEY = os.environ.get("ADMIN_KEY")


@app.post("/api/upload", response_model=schemas.UploadResult)
async def upload_log_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File too large (max 20 MB).")
    if not content:
        raise HTTPException(status_code=400, detail="File is empty.")

    try:
        records = parse_file(file.filename or "upload", content)
    except ParseError as e:
        raise HTTPException(status_code=422, detail=str(e))

    score_batch(records)

    upload_id = str(uuid.uuid4())
    entries = [
        models.LogEntry(
            upload_id=upload_id,
            source_file=file.filename or "upload",
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
    ]
    db.add_all(entries)
    db.commit()

    breakdown = Counter(r["severity_label"] for r in records)
    return schemas.UploadResult(
        upload_id=upload_id,
        filename=file.filename or "upload",
        records_ingested=len(entries),
        severity_breakdown=dict(breakdown),
    )


@app.get("/api/logs", response_model=schemas.LogsPage)
def list_logs(
    q: str | None = Query(None, description="Free-text search"),
    severity: str | None = Query(None, description="Comma-separated severity labels"),
    source_ip: str | None = None,
    username: str | None = None,
    min_score: float | None = Query(None, ge=0, le=100),
    sort_by: str = Query("severity_score", pattern="^(severity_score|timestamp|id|source_ip|username)$"),
    sort_dir: str = Query("desc", pattern="^(asc|desc)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    db: Session = Depends(get_db),
):
    query = db.query(models.LogEntry)

    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(
                models.LogEntry.message.ilike(like),
                models.LogEntry.source_ip.ilike(like),
                models.LogEntry.username.ilike(like),
                models.LogEntry.event_type.ilike(like),
                models.LogEntry.status.ilike(like),
                models.LogEntry.raw.ilike(like),
            )
        )
    if severity:
        labels = [s.strip() for s in severity.split(",") if s.strip()]
        if labels:
            query = query.filter(models.LogEntry.severity_label.in_(labels))
    if source_ip:
        query = query.filter(models.LogEntry.source_ip == source_ip)
    if username:
        query = query.filter(models.LogEntry.username == username)
    if min_score is not None:
        query = query.filter(models.LogEntry.severity_score >= min_score)

    total = query.count()

    sort_col = getattr(models.LogEntry, sort_by)
    query = query.order_by(desc(sort_col) if sort_dir == "desc" else sort_col)
    items = query.offset((page - 1) * page_size).limit(page_size).all()

    return schemas.LogsPage(items=items, total=total, page=page, page_size=page_size)


@app.get("/api/stats", response_model=schemas.StatsOut)
def get_stats(db: Session = Depends(get_db)):
    total = db.query(func.count(models.LogEntry.id)).scalar() or 0

    breakdown_rows = (
        db.query(models.LogEntry.severity_label, func.count(models.LogEntry.id))
        .group_by(models.LogEntry.severity_label)
        .all()
    )
    breakdown = {label: count for label, count in breakdown_rows}

    top_ips = (
        db.query(
            models.LogEntry.source_ip,
            func.count(models.LogEntry.id).label("count"),
            func.avg(models.LogEntry.severity_score).label("avg_score"),
        )
        .filter(models.LogEntry.source_ip.isnot(None))
        .group_by(models.LogEntry.source_ip)
        .order_by(desc("avg_score"), desc("count"))
        .limit(5)
        .all()
    )
    top_users = (
        db.query(
            models.LogEntry.username,
            func.count(models.LogEntry.id).label("count"),
            func.avg(models.LogEntry.severity_score).label("avg_score"),
        )
        .filter(models.LogEntry.username.isnot(None))
        .group_by(models.LogEntry.username)
        .order_by(desc("avg_score"), desc("count"))
        .limit(5)
        .all()
    )

    avg_score = db.query(func.avg(models.LogEntry.severity_score)).scalar() or 0.0

    return schemas.StatsOut(
        total=total,
        severity_breakdown=breakdown,
        top_source_ips=[
            {"source_ip": ip, "count": c, "avg_score": round(s or 0, 1)} for ip, c, s in top_ips
        ],
        top_usernames=[
            {"username": u, "count": c, "avg_score": round(s or 0, 1)} for u, c, s in top_users
        ],
        avg_score=round(avg_score, 1),
    )


@app.delete("/api/logs")
def clear_logs(
    db: Session = Depends(get_db),
    x_admin_key: str | None = Header(default=None),
):
    if ADMIN_KEY and not hmac.compare_digest(x_admin_key or "", ADMIN_KEY):
        raise HTTPException(status_code=403, detail="Invalid admin key.")
    deleted = db.query(models.LogEntry).delete()
    db.commit()
    return {"deleted": deleted}


@app.get("/api/health")
def health():
    return {"status": "ok"}

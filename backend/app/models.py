from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


class LogEntry(Base):
    __tablename__ = "log_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    upload_id: Mapped[str] = mapped_column(String(36), index=True)
    source_file: Mapped[str] = mapped_column(String(255))

    timestamp: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    event_type: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    message: Mapped[str] = mapped_column(Text, default="")
    raw: Mapped[str] = mapped_column(Text, default="")

    severity_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    severity_label: Mapped[str] = mapped_column(String(16), default="Info", index=True)
    indicators: Mapped[str] = mapped_column(Text, default="[]")  # JSON list of triggered indicators

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

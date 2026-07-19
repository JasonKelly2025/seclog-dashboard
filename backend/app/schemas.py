from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator

import json


class LogEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    upload_id: str
    source_file: str
    timestamp: datetime | None
    source_ip: str | None
    username: str | None
    event_type: str | None
    status: str | None
    message: str
    severity_score: float
    severity_label: str
    indicators: list[dict[str, Any]]

    @field_validator("indicators", mode="before")
    @classmethod
    def parse_indicators(cls, v):
        if isinstance(v, str):
            return json.loads(v)
        return v


class LogsPage(BaseModel):
    items: list[LogEntryOut]
    total: int
    page: int
    page_size: int


class UploadResult(BaseModel):
    upload_id: str
    filename: str
    records_ingested: int
    severity_breakdown: dict[str, int]


class StatsOut(BaseModel):
    total: int
    severity_breakdown: dict[str, int]
    top_source_ips: list[dict[str, Any]]
    top_usernames: list[dict[str, Any]]
    avg_score: float

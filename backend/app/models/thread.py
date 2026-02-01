# Name: thread.py
# Description: Pydantic models for the thread API
# Date: 2026-01-31


from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class Email(BaseModel):
    sender: str
    recipient: str
    subject: str
    body: str
    timestamp: Optional[datetime] = None


class ThreadRequest(BaseModel):
    thread_id: str
    emails: list[Email]


class RiskIndicator(BaseModel):
    type: str
    description: str
    severity: str  # "low", "medium", "high"


class ThreadResponse(BaseModel):
    thread_id: str
    risk_score: float  # 0.0 - 1.0
    risk_level: str  # "safe", "suspicious", "dangerous"
    indicators: list[RiskIndicator]
    summary: str
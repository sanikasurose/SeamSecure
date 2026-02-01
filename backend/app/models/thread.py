# Name: thread.py
# Description: Pydantic models for the thread API
# Date: 2026-01-31

from pydantic import BaseModel, ConfigDict, Field
from typing import Optional


class Email(BaseModel):
    """
    Represents a single email in a thread.
    
    Attributes:
        from_address: Sender email address (aliased from 'from' in JSON)
        to: List of recipient email addresses
        subject: Email subject line
        timestamp: ISO-8601 formatted timestamp string
        body_text: Plain text body content
        body_html: Optional HTML body content
    """
    model_config = ConfigDict(populate_by_name=True)
    
    from_address: str = Field(..., alias="from")
    to: list[str]
    subject: str
    timestamp: str
    body_text: str
    body_html: Optional[str] = None


class ThreadRequest(BaseModel):
    """
    Request payload for thread analysis.
    
    Attributes:
        thread_id: Unique identifier for the email thread
        emails: List of emails in the thread, ordered chronologically
    """
    thread_id: str
    emails: list[Email]


class RiskIndicator(BaseModel):
    """
    Represents a detected risk indicator.
    
    Attributes:
        type: Indicator type identifier (e.g., 'urgency_language', 'external_links')
        description: Human-readable description of the detected risk
        severity: Risk severity level ('low', 'medium', 'high')
    """
    type: str
    description: str
    severity: str  # "low", "medium", "high"


class ExtractedFeatures(BaseModel):
    """
    Features extracted from an email thread for analysis.
    
    Attributes:
        full_text: Combined plain text from all emails
        subjects: List of all subject lines
        senders: List of unique sender addresses
        links: List of URLs extracted from email bodies
        timestamps: List of all email timestamps
    """
    full_text: str
    subjects: list[str]
    senders: list[str]
    links: list[str]
    timestamps: list[str]


class ThreadResponse(BaseModel):
    """
    Response payload from thread analysis.
    
    Attributes:
        thread_id: Identifier of the analyzed thread
        risk_score: Numeric risk score (0.0 - 1.0)
        risk_level: Categorical risk level ('safe', 'suspicious', 'dangerous')
        indicators: List of detected risk indicators
        summary: Human-readable summary of the analysis
    """
    thread_id: str
    risk_score: float  # 0.0 - 1.0
    risk_level: str  # "safe", "suspicious", "dangerous"
    indicators: list[RiskIndicator]
    summary: str

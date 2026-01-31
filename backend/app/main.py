from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

app = FastAPI(
    title="SeamSecure API",
    description="Email thread security analysis API",
    version="0.1.0",
)

# CORS configuration for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- Pydantic Models ----------

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


# ---------- Endpoints ----------

@app.get("/")
def root():
    return {"message": "SeamSecure backend is running"}


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/analyze-thread", response_model=ThreadResponse)
def analyze_thread(request: ThreadRequest) -> ThreadResponse:
    """
    Analyze an email thread for security risks.
    
    This is a stub endpoint that returns fake but realistic analysis results.
    Real ML/NLP analysis will be implemented later.
    """
    # Stub: return fake but realistic analysis
    return ThreadResponse(
        thread_id=request.thread_id,
        risk_score=0.72,
        risk_level="suspicious",
        indicators=[
            RiskIndicator(
                type="urgency_language",
                description="Email contains urgent language patterns commonly used in phishing attempts",
                severity="medium",
            ),
            RiskIndicator(
                type="link_mismatch",
                description="Display text does not match actual URL destination",
                severity="high",
            ),
            RiskIndicator(
                type="sender_impersonation",
                description="Sender domain closely resembles a known legitimate domain",
                severity="medium",
            ),
        ],
        summary="This email thread shows multiple indicators of a potential phishing attempt. "
        "Exercise caution before clicking any links or providing sensitive information.",
    )

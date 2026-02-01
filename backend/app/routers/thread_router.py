"""
Router for email thread analysis endpoints.

This module handles HTTP concerns and delegates business logic to the service layer.
"""

from fastapi import APIRouter

from app.models.thread import ThreadRequest, ThreadResponse
from app.services.analysis_service import analyze_thread

router = APIRouter(
    prefix="",
    tags=["analysis"],
)


@router.post("/analyze-thread", response_model=ThreadResponse)
def analyze_thread_endpoint(request: ThreadRequest) -> ThreadResponse:
    """
    Analyze an email thread for security risks.

    Accepts a JSON payload containing an email thread and returns
    a risk assessment with score, level, indicators, and summary.
    """
    return analyze_thread(request)

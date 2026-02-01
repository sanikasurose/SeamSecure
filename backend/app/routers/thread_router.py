# Name: thread_router.py
# Description: Router for email thread analysis endpoints
# Date: 2026-01-31

import logging
import time

from fastapi import APIRouter

from app.models.thread import ThreadRequest, ThreadResponse
from app.services.analysis_service import analyze_thread

logger = logging.getLogger(__name__)

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
    # Log request entry
    start_time = time.perf_counter()
    email_count = len(request.emails)
    logger.info(f"[REQUEST] thread={request.thread_id} emails={email_count}")
    
    # Process request
    response = analyze_thread(request)
    
    # Log response
    elapsed_ms = (time.perf_counter() - start_time) * 1000
    logger.info(
        f"[RESPONSE] thread={request.thread_id} "
        f"risk={response.risk_level} score={response.risk_score} "
        f"indicators={len(response.indicators)} elapsed={elapsed_ms:.0f}ms"
    )
    
    return response

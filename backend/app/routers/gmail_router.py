# Name: gmail_router.py
# Description: Gmail API endpoints for email thread access
# Date: 2026-02-01

import logging
import time
from datetime import datetime
from email.utils import parsedate_to_datetime

from fastapi import APIRouter, HTTPException, Query

from app.models.thread import Email, ThreadRequest
from app.services.gmail_service import list_thread_summaries, get_parsed_thread
from app.services.analysis_service import analyze_thread
from app.core.security import safe_log_email, safe_log_session

logger = logging.getLogger(__name__)


# =============================================================================
# GMAIL TO EMAIL MODEL CONVERTER
# =============================================================================

def parse_email_date(date_str: str) -> str:
    """
    Convert Gmail date string to ISO-8601 format.
    
    Args:
        date_str: Date string from Gmail (e.g., "Sat, 31 Jan 2026 21:25:54 -0800")
        
    Returns:
        ISO-8601 formatted timestamp
    """
    try:
        dt = parsedate_to_datetime(date_str)
        return dt.isoformat()
    except Exception:
        # Fallback to current time if parsing fails
        return datetime.utcnow().isoformat()


def gmail_message_to_email(msg: dict) -> Email:
    """
    Convert a parsed Gmail message to our Email model.
    
    Args:
        msg: Parsed Gmail message dict with from, to, subject, date, body_text
        
    Returns:
        Email model instance
    """
    # Parse 'to' field - can be comma-separated
    to_str = msg.get("to", "")
    to_list = [addr.strip() for addr in to_str.split(",") if addr.strip()]
    if not to_list:
        to_list = ["unknown@unknown.com"]
    
    return Email(
        **{
            "from": msg.get("from", "unknown@unknown.com"),
            "to": to_list,
            "subject": msg.get("subject", "(No Subject)"),
            "timestamp": parse_email_date(msg.get("date", "")),
            "body_text": msg.get("body_text", "") or msg.get("snippet", ""),
            "body_html": None,
        }
    )


def gmail_thread_to_request(thread_id: str, parsed_thread: dict) -> ThreadRequest:
    """
    Convert a parsed Gmail thread to a ThreadRequest for analysis.
    
    Args:
        thread_id: Gmail thread ID
        parsed_thread: Parsed thread from gmail_service
        
    Returns:
        ThreadRequest ready for analysis
    """
    messages = parsed_thread.get("messages", [])
    emails = [gmail_message_to_email(msg) for msg in messages]
    
    return ThreadRequest(
        thread_id=thread_id,
        emails=emails,
    )

router = APIRouter(
    prefix="/gmail",
    tags=["gmail"],
)


# =============================================================================
# SESSION VALIDATION HELPER
# =============================================================================

def validate_session(session_id: str) -> str:
    """
    Validate session and return user email.
    
    Args:
        session_id: Session ID from OAuth login
        
    Returns:
        User email if session is valid
        
    Raises:
        HTTPException: If session is invalid
    """
    from app.routers.auth_router import get_email_from_session, token_store
    
    email = get_email_from_session(session_id)
    if not email:
        logger.warning(f"[Gmail API] Invalid session: {session_id[:8] if session_id else 'None'}...")
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    
    if email not in token_store:
        raise HTTPException(status_code=401, detail="Session valid but tokens missing")
    
    return email


# =============================================================================
# GMAIL ENDPOINTS
# =============================================================================

@router.get("/threads")
async def get_gmail_threads(
    session_id: str = Query(..., description="Session ID from OAuth login"),
    max_results: int = Query(10, ge=1, le=50, description="Max threads to return (1-50)"),
):
    """
    List email threads from user's Gmail inbox.
    
    Returns enriched thread summaries with:
    - Thread ID
    - Snippet (preview text)
    - From (sender)
    - Subject
    - Date
    - Message count
    
    Args:
        session_id: Session ID from OAuth login
        max_results: Maximum threads to return (default 10, max 50)
    """
    start_time = time.perf_counter()
    
    # Validate session
    email = validate_session(session_id)
    logger.info(f"[Gmail API] GET /gmail/threads - user={safe_log_email(email)}, max={max_results}")
    
    # Fetch threads
    threads = await list_thread_summaries(email, max_results)
    
    if threads is None:
        raise HTTPException(status_code=500, detail="Failed to fetch threads from Gmail")
    
    elapsed = time.perf_counter() - start_time
    logger.info(f"[Gmail API] Returned {len(threads)} threads in {elapsed:.2f}s")
    
    return {
        "status": "success",
        "email": email,
        "thread_count": len(threads),
        "threads": threads,
        "response_time_ms": int(elapsed * 1000),
    }


@router.get("/threads/{thread_id}")
async def get_gmail_thread(
    thread_id: str,
    session_id: str = Query(..., description="Session ID from OAuth login"),
):
    """
    Get a specific email thread with full message content.
    
    Returns complete thread with all messages including:
    - Message ID
    - From, To, Subject, Date
    - Full body text
    - Snippet
    
    Args:
        thread_id: Gmail thread ID
        session_id: Session ID from OAuth login
    """
    start_time = time.perf_counter()
    
    # Validate session
    email = validate_session(session_id)
    logger.info(f"[Gmail API] GET /gmail/threads/{thread_id} - user={safe_log_email(email)}")
    
    # Fetch thread
    thread = await get_parsed_thread(email, thread_id)
    
    if thread is None:
        raise HTTPException(status_code=404, detail=f"Thread {thread_id} not found")
    
    elapsed = time.perf_counter() - start_time
    logger.info(f"[Gmail API] Returned thread {thread_id} in {elapsed:.2f}s")
    
    return {
        "status": "success",
        "email": email,
        "thread": thread,
        "response_time_ms": int(elapsed * 1000),
    }


@router.post("/analyze/{thread_id}")
async def analyze_gmail_thread(
    thread_id: str,
    session_id: str = Query(..., description="Session ID from OAuth login"),
):
    """
    Fetch and analyze a Gmail thread in one request.
    
    This endpoint:
    1. Fetches the Gmail thread
    2. Converts to internal Email models
    3. Runs rule-based + Gemini analysis
    4. Returns full analysis response
    
    Args:
        thread_id: Gmail thread ID to analyze
        session_id: Session ID from OAuth login
        
    Returns:
        Same schema as /analyze-thread endpoint
    """
    start_time = time.perf_counter()
    
    # Validate session
    email = validate_session(session_id)
    logger.info(f"[Gmail API] POST /gmail/analyze/{thread_id} - user={safe_log_email(email)}")
    
    # Step 1: Fetch Gmail thread
    logger.info(f"[Gmail API] Fetching thread {thread_id}...")
    parsed_thread = await get_parsed_thread(email, thread_id)
    
    if parsed_thread is None:
        raise HTTPException(status_code=404, detail=f"Thread {thread_id} not found")
    
    fetch_time = time.perf_counter() - start_time
    logger.info(f"[Gmail API] Thread fetched in {fetch_time:.2f}s ({len(parsed_thread.get('messages', []))} messages)")
    
    # Step 2: Convert to ThreadRequest
    try:
        thread_request = gmail_thread_to_request(thread_id, parsed_thread)
    except Exception as e:
        logger.error(f"[Gmail API] Failed to convert thread: {e}")
        raise HTTPException(status_code=500, detail="Failed to process thread format")
    
    # Step 3: Run analysis
    logger.info(f"[Gmail API] Running analysis on {len(thread_request.emails)} emails...")
    analysis_start = time.perf_counter()
    
    try:
        result = analyze_thread(thread_request)
    except Exception as e:
        logger.error(f"[Gmail API] Analysis failed: {e}")
        raise HTTPException(status_code=500, detail="Analysis failed")
    
    analysis_time = time.perf_counter() - analysis_start
    total_time = time.perf_counter() - start_time
    
    logger.info(
        f"[Gmail API] Analysis complete: "
        f"risk_level={result.risk_level}, "
        f"risk_score={result.risk_score:.2f}, "
        f"indicators={len(result.indicators)}, "
        f"fetch={fetch_time:.2f}s, "
        f"analysis={analysis_time:.2f}s, "
        f"total={total_time:.2f}s"
    )
    
    # Return the same schema as /analyze-thread
    return result

# Name: auth_router.py
# Description: Google OAuth authentication endpoints
# Date: 2026-02-01

import logging
import secrets
import time
from datetime import datetime
from typing import Optional
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import RedirectResponse

from app.core.config import settings
from app.core.security import safe_log_email, safe_log_session

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/auth",
    tags=["authentication"],
)

# =============================================================================
# IN-MEMORY STORES (MVP - replace with DB later)
# =============================================================================

# Token store: {user_email: {access_token, refresh_token, expires_at, ...}}
token_store: dict[str, dict] = {}

# Session store: {session_id: {email, created_at}}
session_store: dict[str, dict] = {}

# State tokens for CSRF protection (temporary, expire after use)
pending_states: dict[str, float] = {}  # {state: timestamp}


def create_session(email: str) -> str:
    """
    Create a new session for a user.
    
    Args:
        email: User's email address
        
    Returns:
        New session ID
    """
    # Generate secure random session ID
    session_id = secrets.token_urlsafe(32)
    
    # Store session
    session_store[session_id] = {
        "email": email,
        "created_at": datetime.utcnow().isoformat(),
    }
    
    logger.info(f"[Session] Created session for: {safe_log_email(email)} (id={safe_log_session(session_id)})")
    return session_id


def get_session(session_id: str) -> Optional[dict]:
    """Get session data by session ID."""
    return session_store.get(session_id)


def get_email_from_session(session_id: str) -> Optional[str]:
    """Get user email from session ID."""
    session = session_store.get(session_id)
    if session:
        return session.get("email")
    return None


def invalidate_session(session_id: str) -> bool:
    """Remove a session."""
    if session_id in session_store:
        email = session_store[session_id].get("email")
        del session_store[session_id]
        logger.info(f"[Session] Invalidated session for: {safe_log_email(email)}")
        return True
    return False


def store_tokens(email: str, tokens: dict) -> str:
    """
    Store user tokens and create a session.
    
    Args:
        email: User's email address
        tokens: OAuth tokens from Google
        
    Returns:
        Session ID for the user
    """
    token_store[email] = {
        "access_token": tokens.get("access_token"),
        "refresh_token": tokens.get("refresh_token"),
        "expires_at": time.time() + tokens.get("expires_in", 3600),
        "scope": tokens.get("scope"),
        "token_type": tokens.get("token_type"),
        "stored_at": datetime.utcnow().isoformat(),
    }
    logger.info(f"[OAuth] Stored tokens for user: {safe_log_email(email)}")
    
    # Create and return session
    return create_session(email)


def get_tokens(email: str) -> Optional[dict]:
    """Retrieve user tokens from memory."""
    return token_store.get(email)


def get_all_users() -> list[str]:
    """Get list of all authenticated users."""
    return list(token_store.keys())


def get_all_sessions() -> list[dict]:
    """Get all active sessions."""
    return [
        {"session_id": sid[:8] + "...", "email": data["email"], "created_at": data["created_at"]}
        for sid, data in session_store.items()
    ]


# =============================================================================
# GOOGLE OAUTH CONFIGURATION
# =============================================================================

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"

# Gmail read-only scope for reading email threads
SCOPES = [
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/gmail.readonly",
]


# =============================================================================
# OAUTH ENDPOINTS
# =============================================================================

@router.get("/google")
def login_with_google():
    """
    Redirect user to Google OAuth consent screen.
    
    This is the entry point for "Login with Google".
    """
    if not settings.is_oauth_configured:
        logger.error("[OAuth] OAuth not configured - missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET")
        raise HTTPException(
            status_code=500,
            detail="OAuth not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET."
        )
    
    # Generate state token for CSRF protection
    state = secrets.token_urlsafe(32)
    pending_states[state] = time.time()
    
    # Clean up old states (older than 10 minutes)
    current_time = time.time()
    expired = [s for s, t in pending_states.items() if current_time - t > 600]
    for s in expired:
        del pending_states[s]
    
    # Build authorization URL
    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": settings.oauth_redirect_uri,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "state": state,
        "access_type": "offline",  # Request refresh token
        "prompt": "consent",  # Force consent to get refresh token
    }
    
    auth_url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"
    
    logger.info(f"[OAuth] Redirecting to Google OAuth (state={state[:8]}...)")
    return RedirectResponse(url=auth_url)


@router.get("/google/callback")
async def google_callback(
    code: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
):
    """
    Handle Google OAuth callback.
    
    Exchanges authorization code for access/refresh tokens.
    """
    logger.info(f"[OAuth] Callback received (state={state[:8] if state else 'None'}...)")
    
    # Check for OAuth errors
    if error:
        logger.error(f"[OAuth] Google returned error: {error}")
        raise HTTPException(status_code=400, detail=f"OAuth error: {error}")
    
    # Validate required parameters
    if not code:
        logger.error("[OAuth] Missing authorization code")
        raise HTTPException(status_code=400, detail="Missing authorization code")
    
    if not state:
        logger.error("[OAuth] Missing state parameter")
        raise HTTPException(status_code=400, detail="Missing state parameter")
    
    # Validate state (CSRF protection)
    if state not in pending_states:
        logger.error("[OAuth] Invalid or expired state token")
        raise HTTPException(status_code=400, detail="Invalid or expired state token")
    
    # Remove used state
    del pending_states[state]
    
    # Exchange code for tokens
    logger.info("[OAuth] Exchanging code for tokens...")
    
    token_data = {
        "client_id": settings.google_client_id,
        "client_secret": settings.google_client_secret,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": settings.oauth_redirect_uri,
    }
    
    async with httpx.AsyncClient() as client:
        try:
            # Get tokens
            token_response = await client.post(GOOGLE_TOKEN_URL, data=token_data)
            
            if token_response.status_code != 200:
                logger.error(f"[OAuth] Token exchange failed: {token_response.text}")
                raise HTTPException(
                    status_code=400,
                    detail=f"Token exchange failed: {token_response.json().get('error_description', 'Unknown error')}"
                )
            
            tokens = token_response.json()
            logger.info("[OAuth] Tokens received successfully")
            logger.debug(f"[OAuth] Token response keys: {list(tokens.keys())}")
            
            # Get user info
            headers = {"Authorization": f"Bearer {tokens['access_token']}"}
            userinfo_response = await client.get(GOOGLE_USERINFO_URL, headers=headers)
            
            if userinfo_response.status_code != 200:
                logger.error(f"[OAuth] Failed to get user info: {userinfo_response.text}")
                raise HTTPException(status_code=400, detail="Failed to get user info")
            
            userinfo = userinfo_response.json()
            email = userinfo.get("email", "unknown")
            name = userinfo.get("name", "Unknown User")
            
            logger.info(f"[OAuth] User authenticated: {safe_log_email(email)} ({name})")
            
            # Store tokens and create session
            session_id = store_tokens(email, tokens)
            
            # Log token details (without exposing sensitive data)
            logger.info(
                f"[OAuth] SUCCESS: user={email}, "
                f"session={session_id[:8]}..., "
                f"has_refresh_token={'refresh_token' in tokens}, "
                f"expires_in={tokens.get('expires_in', 'N/A')}s"
            )
            
            # Redirect to frontend with session_id and user info
            # Frontend will read these from URL params and store them
            frontend_url = "http://localhost:5173"
            redirect_params = urlencode({
                "session_id": session_id,
                "email": email,
                "name": name,
            })
            redirect_url = f"{frontend_url}?{redirect_params}"
            
            logger.info(f"[OAuth] Redirecting to frontend: {frontend_url}")
            return RedirectResponse(url=redirect_url)
            
        except httpx.RequestError as e:
            logger.error(f"[OAuth] Network error during token exchange: {e}")
            raise HTTPException(status_code=500, detail=f"Network error: {str(e)}")


@router.get("/status")
def auth_status():
    """
    Check authentication status and list authenticated users/sessions.
    
    For debugging/development only.
    """
    users = get_all_users()
    sessions = get_all_sessions()
    return {
        "oauth_configured": settings.is_oauth_configured,
        "authenticated_users": len(users),
        "active_sessions": len(sessions),
        "users": [
            {
                "email": email,
                "has_refresh_token": bool(token_store[email].get("refresh_token")),
                "expires_at": token_store[email].get("expires_at"),
                "stored_at": token_store[email].get("stored_at"),
            }
            for email in users
        ],
        "sessions": sessions,
    }


@router.get("/me")
def get_current_user(session_id: str = Query(..., description="Session ID")):
    """
    Get current user info from session.
    
    Args:
        session_id: Session ID from OAuth login
    """
    email = get_email_from_session(session_id)
    if not email:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    
    tokens = token_store.get(email, {})
    return {
        "email": email,
        "session_valid": True,
        "has_refresh_token": bool(tokens.get("refresh_token")),
        "token_expires_at": tokens.get("expires_at"),
    }


@router.post("/logout")
def logout_session(session_id: str = Query(..., description="Session ID to invalidate")):
    """
    Logout by invalidating session.
    
    Args:
        session_id: Session ID to invalidate
    """
    email = get_email_from_session(session_id)
    if not email:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    
    # Invalidate session
    invalidate_session(session_id)
    
    # Optionally also remove tokens (full logout)
    if email in token_store:
        del token_store[email]
    
    logger.info(f"[OAuth] Logged out session: {safe_log_session(session_id)} (user={safe_log_email(email)})")
    return {"status": "success", "message": f"Logged out {email}"}


@router.delete("/logout/{email}")
def logout_user(email: str):
    """
    Remove user's stored tokens (legacy endpoint).
    """
    if email in token_store:
        del token_store[email]
        logger.info(f"[OAuth] Logged out user: {safe_log_email(email)}")
        return {"status": "success", "message": f"Logged out {email}"}
    else:
        raise HTTPException(status_code=404, detail="User not found")


# =============================================================================
# GMAIL API ENDPOINTS (Phase 2c)
# =============================================================================

@router.get("/gmail/threads")
async def list_gmail_threads(
    session_id: str = Query(..., description="Session ID from OAuth login"),
    max_results: int = Query(10, description="Maximum threads to return"),
):
    """
    List email threads from user's Gmail inbox.
    
    Args:
        session_id: Session ID returned from OAuth login
        max_results: Maximum number of threads to return (default 10)
    """
    from app.services.gmail_service import list_threads
    
    # Validate session
    email = get_email_from_session(session_id)
    if not email:
        logger.warning(f"[Gmail] Invalid session: {session_id[:8] if session_id else 'None'}...")
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    
    if email not in token_store:
        raise HTTPException(status_code=401, detail="Session valid but tokens missing")
    
    logger.info(f"[Gmail] Listing threads for session: {safe_log_session(session_id)} (user={safe_log_email(email)})")
    threads = await list_threads(email, max_results)
    
    if threads is None:
        raise HTTPException(status_code=500, detail="Failed to fetch threads from Gmail")
    
    return {
        "email": email,
        "thread_count": len(threads),
        "threads": threads,
    }


@router.get("/gmail/threads/{thread_id}")
async def get_gmail_thread(
    thread_id: str,
    session_id: str = Query(..., description="Session ID from OAuth login"),
):
    """
    Get a specific email thread with full message content.
    
    Args:
        thread_id: Gmail thread ID
        session_id: Session ID returned from OAuth login
    """
    from app.services.gmail_service import get_parsed_thread
    
    # Validate session
    email = get_email_from_session(session_id)
    if not email:
        logger.warning(f"[Gmail] Invalid session: {session_id[:8] if session_id else 'None'}...")
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    
    if email not in token_store:
        raise HTTPException(status_code=401, detail="Session valid but tokens missing")
    
    logger.info(f"[Gmail] Getting thread {thread_id} for session: {safe_log_session(session_id)} (user={safe_log_email(email)})")
    thread = await get_parsed_thread(email, thread_id)
    
    if thread is None:
        raise HTTPException(status_code=404, detail=f"Thread {thread_id} not found")
    
    return {
        "email": email,
        "thread": thread,
    }

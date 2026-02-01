# Name: gmail_service.py
# Description: Gmail API wrapper for fetching email threads
# Date: 2026-02-01

import base64
import logging
import time
from typing import Optional

import httpx

from app.core.config import settings
from app.core.security import safe_log_email

logger = logging.getLogger(__name__)

# =============================================================================
# GMAIL API CONFIGURATION
# =============================================================================

GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"


# =============================================================================
# TOKEN MANAGEMENT
# =============================================================================

# Import token store from auth_router (shared state)
def get_token_store():
    """Get the token store from auth_router."""
    from app.routers.auth_router import token_store
    return token_store


async def refresh_access_token(email: str) -> Optional[str]:
    """
    Refresh the access token using the refresh token.
    
    Args:
        email: User email to refresh token for
        
    Returns:
        New access token, or None if refresh failed
    """
    token_store = get_token_store()
    
    if email not in token_store:
        logger.error(f"[Gmail] No tokens found for user: {safe_log_email(email)}")
        return None
    
    user_tokens = token_store[email]
    refresh_token = user_tokens.get("refresh_token")
    
    if not refresh_token:
        logger.error(f"[Gmail] No refresh token for user: {safe_log_email(email)}")
        return None
    
    logger.info(f"[Gmail] Refreshing access token for: {safe_log_email(email)}")
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                GOOGLE_TOKEN_URL,
                data={
                    "client_id": settings.google_client_id,
                    "client_secret": settings.google_client_secret,
                    "refresh_token": refresh_token,
                    "grant_type": "refresh_token",
                },
            )
            
            if response.status_code != 200:
                logger.error(f"[Gmail] Token refresh failed: {response.text}")
                return None
            
            tokens = response.json()
            
            # Update stored tokens
            user_tokens["access_token"] = tokens["access_token"]
            user_tokens["expires_at"] = time.time() + tokens.get("expires_in", 3600)
            
            logger.info(f"[Gmail] Token refreshed successfully for: {safe_log_email(email)}")
            return tokens["access_token"]
            
        except Exception as e:
            logger.error(f"[Gmail] Token refresh error: {e}")
            return None


async def get_valid_access_token(email: str) -> Optional[str]:
    """
    Get a valid access token, refreshing if necessary.
    
    Args:
        email: User email
        
    Returns:
        Valid access token, or None if unavailable
    """
    token_store = get_token_store()
    
    if email not in token_store:
        logger.error(f"[Gmail] User not authenticated: {safe_log_email(email)}")
        return None
    
    user_tokens = token_store[email]
    expires_at = user_tokens.get("expires_at", 0)
    
    # Check if token is expired or will expire in next 60 seconds
    if time.time() >= expires_at - 60:
        logger.info(f"[Gmail] Token expired for {safe_log_email(email)}, refreshing...")
        return await refresh_access_token(email)
    
    return user_tokens.get("access_token")


# =============================================================================
# GMAIL API FUNCTIONS
# =============================================================================

async def list_threads(email: str, max_results: int = 10) -> Optional[list[dict]]:
    """
    List email threads from user's Gmail inbox.
    
    Args:
        email: Authenticated user's email
        max_results: Maximum number of threads to return (default 10)
        
    Returns:
        List of thread objects with id and snippet, or None if failed
    """
    logger.info(f"[Gmail] Listing threads for: {safe_log_email(email)} (max={max_results})")
    
    access_token = await get_valid_access_token(email)
    if not access_token:
        return None
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{GMAIL_API_BASE}/threads",
                headers={"Authorization": f"Bearer {access_token}"},
                params={"maxResults": max_results},
                timeout=30.0,
            )
            
            if response.status_code == 401:
                logger.warning("[Gmail] Token expired, attempting refresh...")
                access_token = await refresh_access_token(email)
                if not access_token:
                    return None
                
                response = await client.get(
                    f"{GMAIL_API_BASE}/threads",
                    headers={"Authorization": f"Bearer {access_token}"},
                    params={"maxResults": max_results},
                    timeout=30.0,
                )
            
            if response.status_code != 200:
                logger.error(f"[Gmail] List threads failed: {response.status_code} - {response.text}")
                return None
            
            data = response.json()
            threads = data.get("threads", [])
            
            logger.info(f"[Gmail] Retrieved {len(threads)} threads")
            return threads
            
        except httpx.TimeoutException:
            logger.error("[Gmail] List threads timed out")
            return None
        except Exception as e:
            logger.error(f"[Gmail] List threads error: {e}")
            return None


async def get_thread(email: str, thread_id: str) -> Optional[dict]:
    """
    Get a specific email thread with full message content.
    
    Args:
        email: Authenticated user's email
        thread_id: Gmail thread ID
        
    Returns:
        Thread object with messages, or None if failed
    """
    logger.info(f"[Gmail] Getting thread {thread_id} for: {safe_log_email(email)}")
    
    access_token = await get_valid_access_token(email)
    if not access_token:
        return None
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{GMAIL_API_BASE}/threads/{thread_id}",
                headers={"Authorization": f"Bearer {access_token}"},
                params={"format": "full"},
                timeout=30.0,
            )
            
            if response.status_code == 401:
                logger.warning("[Gmail] Token expired, attempting refresh...")
                access_token = await refresh_access_token(email)
                if not access_token:
                    return None
                
                response = await client.get(
                    f"{GMAIL_API_BASE}/threads/{thread_id}",
                    headers={"Authorization": f"Bearer {access_token}"},
                    params={"format": "full"},
                    timeout=30.0,
                )
            
            if response.status_code != 200:
                logger.error(f"[Gmail] Get thread failed: {response.status_code} - {response.text}")
                return None
            
            thread = response.json()
            logger.info(f"[Gmail] Retrieved thread with {len(thread.get('messages', []))} messages")
            
            return thread
            
        except httpx.TimeoutException:
            logger.error(f"[Gmail] Get thread {thread_id} timed out")
            return None
        except Exception as e:
            logger.error(f"[Gmail] Get thread error: {e}")
            return None


# =============================================================================
# MESSAGE PARSING HELPERS
# =============================================================================

def decode_base64(data: str) -> str:
    """Decode base64url encoded string."""
    try:
        # Gmail uses URL-safe base64
        padded = data + "=" * (4 - len(data) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        return decoded.decode("utf-8", errors="replace")
    except Exception as e:
        logger.warning(f"[Gmail] Base64 decode error: {e}")
        return ""


def get_header(headers: list[dict], name: str) -> str:
    """Extract a header value from Gmail headers list."""
    for header in headers:
        if header.get("name", "").lower() == name.lower():
            return header.get("value", "")
    return ""


def extract_body_text(payload: dict) -> str:
    """
    Extract plain text body from Gmail message payload.
    
    Handles both simple and multipart messages.
    """
    # Try direct body
    body_data = payload.get("body", {}).get("data")
    if body_data:
        return decode_base64(body_data)
    
    # Try multipart
    parts = payload.get("parts", [])
    for part in parts:
        mime_type = part.get("mimeType", "")
        
        # Look for plain text
        if mime_type == "text/plain":
            body_data = part.get("body", {}).get("data")
            if body_data:
                return decode_base64(body_data)
        
        # Recurse into nested parts
        if mime_type.startswith("multipart/"):
            nested = extract_body_text(part)
            if nested:
                return nested
    
    # Fallback to HTML if no plain text
    for part in parts:
        if part.get("mimeType") == "text/html":
            body_data = part.get("body", {}).get("data")
            if body_data:
                # Strip HTML tags (basic)
                html = decode_base64(body_data)
                # Very basic HTML stripping
                import re
                text = re.sub(r"<[^>]+>", " ", html)
                text = re.sub(r"\s+", " ", text)
                return text.strip()
    
    return ""


def parse_gmail_thread(thread: dict) -> dict:
    """
    Parse a Gmail thread into a simplified format.
    
    Args:
        thread: Raw Gmail thread object
        
    Returns:
        Simplified thread with extracted message content
    """
    messages = thread.get("messages", [])
    parsed_messages = []
    
    for msg in messages:
        payload = msg.get("payload", {})
        headers = payload.get("headers", [])
        
        parsed_msg = {
            "id": msg.get("id"),
            "thread_id": msg.get("threadId"),
            "from": get_header(headers, "From"),
            "to": get_header(headers, "To"),
            "subject": get_header(headers, "Subject"),
            "date": get_header(headers, "Date"),
            "snippet": msg.get("snippet", ""),
            "body_text": extract_body_text(payload),
        }
        parsed_messages.append(parsed_msg)
    
    return {
        "id": thread.get("id"),
        "history_id": thread.get("historyId"),
        "message_count": len(messages),
        "messages": parsed_messages,
    }


async def get_parsed_thread(email: str, thread_id: str) -> Optional[dict]:
    """
    Get a thread and parse it into a simplified format.
    
    Args:
        email: Authenticated user's email
        thread_id: Gmail thread ID
        
    Returns:
        Parsed thread object, or None if failed
    """
    thread = await get_thread(email, thread_id)
    if not thread:
        return None
    
    return parse_gmail_thread(thread)


# =============================================================================
# THREAD SUMMARIES (for listing with metadata)
# =============================================================================

async def get_thread_summary(
    client: httpx.AsyncClient,
    access_token: str,
    thread_id: str,
) -> Optional[dict]:
    """
    Get a thread's summary info (first message headers).
    
    Args:
        client: HTTP client
        access_token: Valid OAuth access token
        thread_id: Gmail thread ID
        
    Returns:
        Thread summary with id, snippet, from, subject, date
    """
    try:
        response = await client.get(
            f"{GMAIL_API_BASE}/threads/{thread_id}",
            headers={"Authorization": f"Bearer {access_token}"},
            params={"format": "metadata", "metadataHeaders": ["From", "Subject", "Date"]},
            timeout=10.0,
        )
        
        if response.status_code != 200:
            logger.warning(f"[Gmail] Failed to get thread {thread_id}: {response.status_code}")
            return None
        
        thread = response.json()
        messages = thread.get("messages", [])
        
        if not messages:
            return None
        
        # Get first message (thread starter)
        first_msg = messages[0]
        headers = first_msg.get("payload", {}).get("headers", [])
        
        return {
            "id": thread.get("id"),
            "snippet": thread.get("snippet", ""),
            "from": get_header(headers, "From"),
            "subject": get_header(headers, "Subject"),
            "date": get_header(headers, "Date"),
            "message_count": len(messages),
        }
        
    except Exception as e:
        logger.warning(f"[Gmail] Thread summary error for {thread_id}: {e}")
        return None


async def list_thread_summaries(email: str, max_results: int = 10) -> Optional[list[dict]]:
    """
    List email threads with full summary info (id, snippet, from, subject, date).
    
    This fetches thread list then gets metadata for each thread in parallel.
    
    Args:
        email: Authenticated user's email
        max_results: Maximum number of threads to return (default 10)
        
    Returns:
        List of thread summaries, or None if failed
    """
    import asyncio
    import time as time_module
    
    start_time = time_module.perf_counter()
    logger.info(f"[Gmail] Listing thread summaries for: {safe_log_email(email)} (max={max_results})")
    
    access_token = await get_valid_access_token(email)
    if not access_token:
        return None
    
    async with httpx.AsyncClient() as client:
        try:
            # Step 1: Get thread IDs
            response = await client.get(
                f"{GMAIL_API_BASE}/threads",
                headers={"Authorization": f"Bearer {access_token}"},
                params={"maxResults": max_results},
                timeout=15.0,
            )
            
            if response.status_code == 401:
                logger.warning("[Gmail] Token expired, attempting refresh...")
                access_token = await refresh_access_token(email)
                if not access_token:
                    return None
                
                response = await client.get(
                    f"{GMAIL_API_BASE}/threads",
                    headers={"Authorization": f"Bearer {access_token}"},
                    params={"maxResults": max_results},
                    timeout=15.0,
                )
            
            if response.status_code != 200:
                logger.error(f"[Gmail] List threads failed: {response.status_code} - {response.text}")
                return None
            
            threads = response.json().get("threads", [])
            
            if not threads:
                logger.info("[Gmail] No threads found")
                return []
            
            # Step 2: Fetch metadata for each thread in parallel
            tasks = [
                get_thread_summary(client, access_token, t["id"])
                for t in threads
            ]
            
            summaries = await asyncio.gather(*tasks)
            
            # Filter out failed fetches
            result = [s for s in summaries if s is not None]
            
            elapsed = time_module.perf_counter() - start_time
            logger.info(f"[Gmail] Retrieved {len(result)} thread summaries in {elapsed:.2f}s")
            
            return result
            
        except httpx.TimeoutException:
            logger.error("[Gmail] List thread summaries timed out")
            return None
        except Exception as e:
            logger.error(f"[Gmail] List thread summaries error: {e}")
            return None

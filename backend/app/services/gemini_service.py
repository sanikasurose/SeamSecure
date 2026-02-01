# Name: gemini_service.py
# Description: Gemini API integration for AI-powered email threat analysis
# Date: 2026-02-01
#
# Uses the new google-genai SDK (replaces deprecated google-generativeai)

import json
import logging
import time
from typing import Optional

from app.core.config import settings
from app.models.thread import Email, GeminiAnalysis, RiskIndicator

# Configure logging
logger = logging.getLogger(__name__)

# Gemini client (initialized at startup)
_client = None
_gemini_initialized = False
_gemini_available = False

# Timeout for Gemini API calls (seconds)
GEMINI_TIMEOUT = 15


def initialize_gemini() -> bool:
    """
    Initialize Gemini client at app startup.
    
    Returns:
        True if Gemini is ready to use, False otherwise.
    """
    global _client, _gemini_initialized, _gemini_available
    
    _gemini_initialized = True
    logger.info("[Gemini] Initializing...")
    
    if not settings.is_gemini_enabled:
        logger.info("[Gemini] DISABLED - set ENABLE_GEMINI=true and GEMINI_API_KEY to enable")
        _gemini_available = False
        return False
    
    try:
        from google import genai
        from google.genai import types
        
        logger.debug("[Gemini] Creating client with google-genai SDK...")
        
        # Create client with timeout configuration
        _client = genai.Client(
            api_key=settings.gemini_api_key,
            http_options=types.HttpOptions(
                timeout=GEMINI_TIMEOUT * 1000,  # milliseconds
            ),
        )
        
        _gemini_available = True
        logger.info(f"[Gemini] READY - timeout={GEMINI_TIMEOUT}s, model=gemini-2.0-flash")
        return True
        
    except Exception as e:
        logger.error(f"[Gemini] INIT FAILED: {e}")
        _gemini_available = False
        return False


def get_gemini_status() -> dict:
    """
    Get current Gemini status for health checks.
    
    Returns:
        Dict with initialization and availability status.
    """
    return {
        "configured": settings.is_gemini_enabled,
        "initialized": _gemini_initialized,
        "available": _gemini_available,
    }


# =============================================================================
# PROMPT TEMPLATES
# =============================================================================

SYSTEM_PROMPT = """You are an email security analyst. Analyze the provided email message in the context of its thread history. Return a JSON object with the following fields:
- intent: "informational" | "transactional" | "action_request" | "high_risk"
- sentiment: score from -1 (negative) to 1 (positive)
- urgency: score from 0 (none) to 1 (extreme)
- style_drift: score from 0 (consistent) to 1 (significant change)
- flagged_segments: array of {text, reason, severity} for any suspicious portions
- explanation: plain-English summary of findings

Return ONLY valid JSON. No preamble or markdown."""

USER_PROMPT_TEMPLATE = """Thread history summary: {thread_summary}

Current message:
From: {sender}
Subject: {subject}
Body: {body}

Analyze this message for phishing indicators, social engineering tactics, and suspicious patterns."""


def _build_thread_summary(emails: list[Email], current_index: int) -> str:
    """
    Build a summary of previous messages in the thread.
    
    Args:
        emails: All emails in the thread
        current_index: Index of the current message being analyzed
        
    Returns:
        Summary string of previous messages
    """
    if current_index == 0:
        return "This is the first message in the thread."
    
    previous = emails[:current_index]
    summaries = []
    
    for i, email in enumerate(previous):
        # Truncate body for summary
        body_preview = email.body_text[:200] + "..." if len(email.body_text) > 200 else email.body_text
        summaries.append(f"Message {i + 1}: From {email.from_address}, Subject: {email.subject}, Preview: {body_preview}")
    
    return "\n".join(summaries)


def _parse_gemini_response(response_text: str) -> Optional[dict]:
    """
    Parse Gemini's JSON response.
    
    Args:
        response_text: Raw response from Gemini
        
    Returns:
        Parsed dictionary, or None if parsing fails
    """
    try:
        # Clean up response - remove markdown code blocks if present
        text = response_text.strip()
        if text.startswith("```json"):
            text = text[7:]
        if text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        
        return json.loads(text.strip())
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse Gemini response: {e}")
        logger.debug(f"Raw response: {response_text}")
        return None


# =============================================================================
# MAIN ANALYSIS FUNCTION
# =============================================================================

def analyze_email_with_gemini(
    email: Email,
    emails: list[Email],
    email_index: int
) -> Optional[GeminiAnalysis]:
    """
    Analyze a single email using Gemini AI.
    
    Args:
        email: The email to analyze
        emails: All emails in the thread (for context)
        email_index: Index of current email in the thread
        
    Returns:
        GeminiAnalysis object with AI findings, or None if analysis fails
    """
    if not _gemini_available or _client is None:
        logger.debug(f"[Gemini] Email {email_index+1}: SKIPPED (client not available)")
        return None
    
    api_start = time.perf_counter()
    
    try:
        from google.genai import types
        
        # Build the prompt
        thread_summary = _build_thread_summary(emails, email_index)
        user_prompt = USER_PROMPT_TEMPLATE.format(
            thread_summary=thread_summary,
            sender=email.from_address,
            subject=email.subject,
            body=email.body_text[:2000]  # Truncate very long emails
        )
        
        logger.debug(f"[Gemini] Email {email_index+1}: Calling API...")
        
        # Call Gemini API using new SDK
        response = _client.models.generate_content(
            model="gemini-2.0-flash",
            contents=user_prompt,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.1,
                max_output_tokens=1024,
            ),
        )
        
        api_elapsed = (time.perf_counter() - api_start) * 1000
        
        if not response or not response.text:
            logger.warning(f"[Gemini] Email {email_index+1}: Empty response ({api_elapsed:.0f}ms)")
            return None
        
        # Parse response
        parsed = _parse_gemini_response(response.text)
        if parsed is None:
            logger.warning(f"[Gemini] Email {email_index+1}: Parse failed ({api_elapsed:.0f}ms)")
            return None
        
        logger.debug(
            f"[Gemini] Email {email_index+1}: SUCCESS intent={parsed.get('intent')} "
            f"urgency={parsed.get('urgency', 0):.1f} ({api_elapsed:.0f}ms)"
        )
        
        # Build GeminiAnalysis object
        return GeminiAnalysis(
            intent=parsed.get("intent", "informational"),
            sentiment=float(parsed.get("sentiment", 0.0)),
            urgency=float(parsed.get("urgency", 0.0)),
            style_drift=float(parsed.get("style_drift", 0.0)),
            flagged_segments=parsed.get("flagged_segments", []),
            explanation=parsed.get("explanation", ""),
        )
    
    except Exception as e:
        api_elapsed = (time.perf_counter() - api_start) * 1000
        logger.warning(f"[Gemini] Email {email_index+1}: API ERROR {e} ({api_elapsed:.0f}ms)")
        return None


def analyze_thread_with_gemini(emails: list[Email]) -> list[GeminiAnalysis]:
    """
    Analyze all emails in a thread using Gemini AI.
    
    Each email is analyzed individually. If any call fails,
    we continue with the remaining emails.
    
    Args:
        emails: List of emails in the thread (chronological order)
        
    Returns:
        List of GeminiAnalysis objects (may be empty if all calls fail)
    """
    if not _gemini_available:
        logger.debug("[Gemini] Thread analysis: SKIPPED (not available)")
        return []
    
    total_emails = len(emails)
    logger.debug(f"[Gemini] Thread analysis: Starting {total_emails} email(s)")
    
    thread_start = time.perf_counter()
    results = []
    success_count = 0
    fail_count = 0
    
    for i, email in enumerate(emails):
        analysis = analyze_email_with_gemini(email, emails, i)
        if analysis:
            results.append(analysis)
            success_count += 1
        else:
            fail_count += 1
    
    thread_elapsed = (time.perf_counter() - thread_start) * 1000
    logger.debug(
        f"[Gemini] Thread analysis: COMPLETE "
        f"success={success_count}/{total_emails} fail={fail_count} ({thread_elapsed:.0f}ms)"
    )
    
    return results


# =============================================================================
# INDICATOR CONVERSION
# =============================================================================

def gemini_to_indicators(analyses: list[GeminiAnalysis]) -> list[RiskIndicator]:
    """
    Convert Gemini analysis results to RiskIndicator objects.
    
    This function examines the Gemini analysis and generates appropriate
    risk indicators based on detected patterns.
    
    Args:
        analyses: List of GeminiAnalysis objects from the thread
        
    Returns:
        List of RiskIndicator objects derived from AI analysis
    """
    indicators = []
    
    if not analyses:
        return indicators
    
    # Check for intent drift across the thread
    if len(analyses) >= 2:
        intents = [a.intent for a in analyses]
        # If thread starts informational and ends with action_request or high_risk
        if intents[0] == "informational" and intents[-1] in ("action_request", "high_risk"):
            indicators.append(RiskIndicator(
                type="intent_drift",
                description="Thread shows intent drift from informational to action-requesting behavior",
                severity="medium" if intents[-1] == "action_request" else "high",
            ))
    
    # Check for high urgency in latest messages
    latest_analysis = analyses[-1]
    if latest_analysis.urgency >= 0.7:
        indicators.append(RiskIndicator(
            type="ai_urgency_detected",
            description="AI detected high urgency language patterns in the message",
            severity="medium",
        ))
    
    # Check for style drift
    if latest_analysis.style_drift >= 0.6:
        indicators.append(RiskIndicator(
            type="style_anomaly",
            description="AI detected significant writing style changes inconsistent with previous messages",
            severity="medium",
        ))
    
    # Check for negative sentiment shift
    if len(analyses) >= 2:
        initial_sentiment = analyses[0].sentiment
        final_sentiment = analyses[-1].sentiment
        if initial_sentiment >= 0 and final_sentiment <= -0.5:
            indicators.append(RiskIndicator(
                type="sentiment_shift",
                description="Thread shows suspicious shift from positive to negative/threatening tone",
                severity="medium",
            ))
    
    # Check for high-risk intent
    if latest_analysis.intent == "high_risk":
        indicators.append(RiskIndicator(
            type="ai_high_risk",
            description="AI classified this message as high-risk based on content analysis",
            severity="high",
        ))
    
    # Process flagged segments from Gemini
    for segment in latest_analysis.flagged_segments:
        if isinstance(segment, dict):
            severity = segment.get("severity", "medium")
            if severity not in ("low", "medium", "high"):
                severity = "medium"
            
            indicators.append(RiskIndicator(
                type="ai_flagged_content",
                description=f"AI flagged suspicious content: {segment.get('reason', 'unspecified')}",
                severity=severity,
            ))
    
    return indicators


def is_gemini_available() -> bool:
    """
    Check if Gemini API is initialized and available.
    
    Returns:
        True if Gemini can be used, False otherwise
    """
    return _gemini_available

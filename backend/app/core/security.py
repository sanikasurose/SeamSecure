# Name: security.py
# Description: Security utilities for logging and data protection
# Date: 2026-02-01

import re
import logging
from typing import Optional

from app.core.config import settings

logger = logging.getLogger(__name__)


# =============================================================================
# PII PATTERNS
# =============================================================================

# Email pattern
EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

# Phone patterns (various formats)
PHONE_PATTERN = re.compile(r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b')

# SSN pattern
SSN_PATTERN = re.compile(r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b')

# Credit card patterns (basic)
CC_PATTERN = re.compile(r'\b(?:\d{4}[-.\s]?){3}\d{4}\b')

# API keys and tokens (generic patterns)
TOKEN_PATTERN = re.compile(r'\b[A-Za-z0-9_-]{20,}\b')


# =============================================================================
# PII MASKING FUNCTIONS
# =============================================================================

def mask_email(email: str) -> str:
    """
    Mask an email address for safe logging.
    
    Example: "john.doe@example.com" -> "j***@e***.com"
    """
    if not email or '@' not in email:
        return email
    
    local, domain = email.rsplit('@', 1)
    domain_parts = domain.rsplit('.', 1)
    
    masked_local = local[0] + '***' if local else '***'
    masked_domain = domain_parts[0][0] + '***' if domain_parts[0] else '***'
    tld = domain_parts[1] if len(domain_parts) > 1 else 'com'
    
    return f"{masked_local}@{masked_domain}.{tld}"


def mask_token(token: str, visible_chars: int = 8) -> str:
    """
    Mask a token/session ID for safe logging.
    
    Example: "abc123xyz789..." -> "abc123xy..."
    """
    if not token:
        return token
    
    if len(token) <= visible_chars:
        return token[:2] + '***'
    
    return token[:visible_chars] + '...'


def mask_pii_in_text(text: str) -> str:
    """
    Mask common PII patterns in a text string.
    
    Args:
        text: Text that may contain PII
        
    Returns:
        Text with PII masked
    """
    if not text:
        return text
    
    # Mask emails
    text = EMAIL_PATTERN.sub('[EMAIL]', text)
    
    # Mask phone numbers
    text = PHONE_PATTERN.sub('[PHONE]', text)
    
    # Mask SSNs
    text = SSN_PATTERN.sub('[SSN]', text)
    
    # Mask credit cards
    text = CC_PATTERN.sub('[CARD]', text)
    
    return text


def sanitize_for_log(data: dict, max_body_length: int = 100) -> dict:
    """
    Sanitize a dictionary for safe logging.
    
    - Masks email addresses
    - Truncates body content
    - Removes sensitive fields
    
    Args:
        data: Dictionary to sanitize
        max_body_length: Max length for body fields before truncation
        
    Returns:
        Sanitized copy of the dictionary
    """
    if not data:
        return data
    
    sanitized = {}
    sensitive_keys = {'password', 'secret', 'token', 'access_token', 'refresh_token', 'api_key'}
    body_keys = {'body', 'body_text', 'body_html', 'content', 'message'}
    
    for key, value in data.items():
        key_lower = key.lower()
        
        # Skip sensitive fields entirely
        if key_lower in sensitive_keys:
            sanitized[key] = '[REDACTED]'
        
        # Truncate body fields
        elif key_lower in body_keys and isinstance(value, str):
            if settings.is_production:
                sanitized[key] = '[BODY_REDACTED]'
            elif len(value) > max_body_length:
                sanitized[key] = value[:max_body_length] + f'... ({len(value)} chars)'
            else:
                sanitized[key] = value
        
        # Mask email fields
        elif 'email' in key_lower and isinstance(value, str):
            sanitized[key] = mask_email(value)
        
        # Recurse into nested dicts
        elif isinstance(value, dict):
            sanitized[key] = sanitize_for_log(value, max_body_length)
        
        # Recurse into lists
        elif isinstance(value, list):
            sanitized[key] = [
                sanitize_for_log(item, max_body_length) if isinstance(item, dict) else item
                for item in value
            ]
        
        else:
            sanitized[key] = value
    
    return sanitized


# =============================================================================
# SAFE LOGGING HELPERS
# =============================================================================

def safe_log_email(email: str) -> str:
    """Get a safe-to-log version of an email address."""
    if settings.is_production:
        return mask_email(email)
    return email


def safe_log_session(session_id: str) -> str:
    """Get a safe-to-log version of a session ID."""
    return mask_token(session_id, 8)


def safe_log_thread(thread: dict) -> dict:
    """Get a safe-to-log version of a thread object."""
    return sanitize_for_log(thread)


# =============================================================================
# SECURITY CHECKS
# =============================================================================

def contains_sensitive_data(text: str) -> bool:
    """
    Check if text likely contains sensitive data.
    
    Args:
        text: Text to check
        
    Returns:
        True if sensitive patterns detected
    """
    if not text:
        return False
    
    # Check for PII patterns
    if EMAIL_PATTERN.search(text):
        return True
    if PHONE_PATTERN.search(text):
        return True
    if SSN_PATTERN.search(text):
        return True
    if CC_PATTERN.search(text):
        return True
    
    return False


def log_security_event(event_type: str, details: str, severity: str = "info"):
    """
    Log a security-related event.
    
    Args:
        event_type: Type of security event
        details: Event details (will be sanitized)
        severity: Log level (info, warning, error)
    """
    sanitized_details = mask_pii_in_text(details)
    message = f"[SECURITY] {event_type}: {sanitized_details}"
    
    if severity == "error":
        logger.error(message)
    elif severity == "warning":
        logger.warning(message)
    else:
        logger.info(message)

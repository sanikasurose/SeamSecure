# Name: analysis_service.py
# Description: Email thread analysis service combining rule-based and AI-powered detection
# Date: 2026-01-31

import re
import logging
import time
from typing import Optional

from app.models.thread import (
    ThreadRequest,
    ThreadResponse,
    RiskIndicator,
    ExtractedFeatures,
)
from app.core.config import API_VERSION
from app.services.scoring import score_indicators, determine_risk_level
from app.services.gemini_service import (
    analyze_thread_with_gemini,
    gemini_to_indicators,
    is_gemini_available,
)

# Configure logging
logger = logging.getLogger(__name__)


# =============================================================================
# FEATURE EXTRACTION
# =============================================================================

def extract_features(request: ThreadRequest) -> ExtractedFeatures:
    """
    Normalize raw thread data into a feature object.
    
    Extracts combined plain text, subjects, unique senders, URLs, and timestamps
    from all emails in the thread.
    
    Args:
        request: ThreadRequest containing the email thread data
        
    Returns:
        ExtractedFeatures object with normalized data ready for analysis
    """
    full_text_parts: list[str] = []
    subjects: list[str] = []
    senders_seen: set[str] = set()
    senders: list[str] = []
    all_links: list[str] = []
    timestamps: list[str] = []
    
    # URL regex pattern - matches http/https URLs
    url_pattern = re.compile(
        r'https?://[^\s<>"\')\]]+',
        re.IGNORECASE
    )
    
    for email in request.emails:
        # Collect body text
        full_text_parts.append(email.body_text)
        
        # Collect subjects
        subjects.append(email.subject)
        
        # Collect unique senders (preserve order of first appearance)
        sender = email.from_address.lower().strip()
        if sender not in senders_seen:
            senders_seen.add(sender)
            senders.append(sender)
        
        # Extract URLs from body text
        links_in_email = url_pattern.findall(email.body_text)
        all_links.extend(links_in_email)
        
        # Also extract from HTML if present
        if email.body_html:
            links_in_html = url_pattern.findall(email.body_html)
            all_links.extend(links_in_html)
        
        # Collect timestamps
        timestamps.append(email.timestamp)
    
    return ExtractedFeatures(
        full_text="\n".join(full_text_parts),
        subjects=subjects,
        senders=senders,
        links=list(dict.fromkeys(all_links)),  # Deduplicate while preserving order
        timestamps=timestamps,
    )


# =============================================================================
# INDICATOR DETECTION FUNCTIONS
# =============================================================================

def detect_urgency_language(text: str) -> Optional[RiskIndicator]:
    """
    Detect urgent language patterns commonly used in phishing attempts.
    
    Looks for phrases like "act now", "urgent", "immediately", "expire",
    "limited time", "within 24 hours", etc.
    
    Args:
        text: Combined text content from the email thread
        
    Returns:
        RiskIndicator if urgency patterns detected, None otherwise
    """
    if not text:
        return None
    
    text_lower = text.lower()
    
    # Urgency patterns commonly found in phishing emails
    urgency_patterns = [
        r'\bact\s+now\b',
        r'\burgent\b',
        r'\bimmediately\b',
        r'\bexpire[sd]?\b',
        r'\blimited\s+time\b',
        r'\bwithin\s+\d+\s+(hours?|days?|minutes?)\b',
        r'\baction\s+required\b',
        r'\basap\b',
        r'\bdon\'?t\s+delay\b',
        r'\bfinal\s+(notice|warning)\b',
        r'\bsuspend(ed)?\b',
        r'\bdeactivat(e|ed|ion)\b',
        r'\blocked\s+(out|account)\b',
        r'\bunauthorized\s+(access|activity)\b',
        r'\bverify\s+(now|immediately|your)\b',
        r'\bconfirm\s+(now|immediately|your)\b',
        r'\btime\s+sensitive\b',
        r'\brespond\s+(now|immediately|urgently)\b',
    ]
    
    for pattern in urgency_patterns:
        if re.search(pattern, text_lower):
            return RiskIndicator(
                type="urgency_language",
                description="Email contains urgent language patterns commonly used in phishing attempts",
                severity="medium",
            )
    
    return None


def detect_sensitive_requests(text: str) -> Optional[RiskIndicator]:
    """
    Detect requests for sensitive information.
    
    Looks for requests for passwords, SSN, credit card numbers,
    bank details, login credentials, etc.
    
    Args:
        text: Combined text content from the email thread
        
    Returns:
        RiskIndicator if sensitive info requests detected, None otherwise
    """
    if not text:
        return None
    
    text_lower = text.lower()
    
    # Patterns requesting sensitive information
    sensitive_patterns = [
        r'\b(enter|provide|confirm|verify|send|update)\s+(your\s+)?(password|pin)\b',
        r'\b(social\s+security|ssn)\b',
        r'\b(credit\s+card|card\s+number|cvv|expir(y|ation))\b',
        r'\b(bank\s+account|account\s+number|routing\s+number)\b',
        r'\blogin\s+(credentials?|details?|information)\b',
        r'\b(username|user\s+name)\s+and\s+password\b',
        r'\b(confirm|verify)\s+your\s+(identity|account)\b',
        r'\bpersonal\s+(information|details?|data)\b',
        r'\bdate\s+of\s+birth\b',
        r'\b(mother\'?s?\s+)?maiden\s+name\b',
        r'\bsecurity\s+(question|answer)\b',
        r'\btax\s+(id|identification)\b',
    ]
    
    for pattern in sensitive_patterns:
        if re.search(pattern, text_lower):
            return RiskIndicator(
                type="sensitive_request",
                description="Email requests sensitive personal or financial information",
                severity="high",
            )
    
    return None


def detect_external_links(links: list[str]) -> Optional[RiskIndicator]:
    """
    Detect suspicious external links in the email.
    
    Flags emails containing links to:
    - URL shorteners (bit.ly, tinyurl, etc.)
    - IP addresses instead of domains
    - Suspicious TLDs (.xyz, .top, .click, etc.)
    - Domains with unusual patterns (many hyphens, misspellings)
    
    Args:
        links: List of URLs extracted from the email thread
        
    Returns:
        RiskIndicator if suspicious links detected, None otherwise
    """
    if not links:
        return None
    
    # URL shortener domains - must match as complete domain or subdomain
    shorteners = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
        'is.gd', 'buff.ly', 'adf.ly', 'cutt.ly', 'rb.gy',
    ]
    
    # Suspicious TLDs often used in phishing
    suspicious_tlds = [
        '.xyz', '.top', '.click', '.link', '.work',
        '.gq', '.ml', '.cf', '.ga', '.tk',
    ]
    
    # IP address pattern
    ip_pattern = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    
    # Pattern to extract domain from URL
    domain_pattern = re.compile(r'https?://([^/]+)')
    
    for link in links:
        link_lower = link.lower()
        
        # Extract domain from URL
        domain_match = domain_pattern.match(link_lower)
        if domain_match:
            domain = domain_match.group(1)
            
            # Check for URL shorteners (must match as domain or end with .shortener)
            for shortener in shorteners:
                # Match exact domain or subdomain (e.g., "bit.ly" or "xyz.bit.ly")
                if domain == shortener or domain.endswith('.' + shortener):
                    return RiskIndicator(
                        type="external_links",
                        description="Email contains shortened URLs that obscure the true destination",
                        severity="medium",
                    )
        
        # Check for IP addresses
        if ip_pattern.match(link):
            return RiskIndicator(
                type="external_links",
                description="Email contains links using IP addresses instead of domain names",
                severity="high",
            )
        
        # Check for suspicious TLDs
        for tld in suspicious_tlds:
            if link_lower.endswith(tld) or f"{tld}/" in link_lower:
                return RiskIndicator(
                    type="external_links",
                    description="Email contains links to domains with suspicious top-level domains",
                    severity="medium",
                )
    
    return None


def detect_sender_anomalies(senders: list[str]) -> Optional[RiskIndicator]:
    """
    Detect anomalies in sender addresses.
    
    Flags:
    - Multiple different senders in a thread (potential spoofing)
    - Free email providers impersonating businesses
    - Domains resembling legitimate companies (typosquatting)
    - Unusual domain patterns
    
    Args:
        senders: List of unique sender email addresses
        
    Returns:
        RiskIndicator if sender anomalies detected, None otherwise
    """
    if not senders:
        return None
    
    # Multiple senders in a single thread is suspicious
    if len(senders) > 2:
        return RiskIndicator(
            type="sender_anomaly",
            description="Thread contains emails from multiple different senders",
            severity="medium",
        )
    
    # Free email domains that might impersonate businesses
    free_email_domains = [
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
        'aol.com', 'mail.com', 'protonmail.com', 'icloud.com',
    ]
    
    # Patterns that might indicate typosquatting/impersonation
    suspicious_domain_patterns = [
        r'paypa[l1]', r'app[l1]e', r'amaz[o0]n', r'micros[o0]ft',
        r'g[o0][o0]g[l1]e', r'faceb[o0][o0]k', r'netf[l1]ix',
        r'bank.?of.?america', r'we[l1][l1]s.?farg[o0]',
    ]
    
    for sender in senders:
        sender_lower = sender.lower()
        
        # Extract domain from email
        if '@' in sender_lower:
            domain = sender_lower.split('@')[1]
            
            # Check for suspicious domain patterns (typosquatting)
            for pattern in suspicious_domain_patterns:
                # Don't flag the actual legitimate domains
                legitimate_domains = [
                    'paypal.com', 'apple.com', 'amazon.com', 'microsoft.com',
                    'google.com', 'facebook.com', 'netflix.com',
                    'bankofamerica.com', 'wellsfargo.com',
                ]
                if domain in legitimate_domains:
                    continue
                    
                if re.search(pattern, domain):
                    return RiskIndicator(
                        type="sender_anomaly",
                        description="Sender domain resembles a known legitimate domain (potential impersonation)",
                        severity="high",
                    )
            
            # Check for domains with many hyphens (often suspicious)
            if domain.count('-') >= 3:
                return RiskIndicator(
                    type="sender_anomaly",
                    description="Sender uses a domain with an unusual pattern",
                    severity="low",
                )
    
    return None


# =============================================================================
# RULE ORCHESTRATION
# =============================================================================

def run_rule_checks(features: ExtractedFeatures) -> list[RiskIndicator]:
    """
    Run all detection functions and collect triggered indicators.
    
    Executes each detection function independently and filters out
    non-triggered (None) results.
    
    Args:
        features: Extracted features from the email thread
        
    Returns:
        List of triggered RiskIndicator objects (may be empty)
    """
    # Run each detection function
    results = [
        detect_urgency_language(features.full_text),
        detect_sensitive_requests(features.full_text),
        detect_external_links(features.links),
        detect_sender_anomalies(features.senders),
    ]
    
    # Filter out None values and return triggered indicators
    return [indicator for indicator in results if indicator is not None]


def run_rule_checks_per_email(emails: list) -> list[RiskIndicator]:
    """
    Run rule-based checks on each email individually.
    
    This ensures suspicious content in one email isn't diluted by
    safe content in other emails (like user's own replies).
    
    Args:
        emails: List of Email objects
        
    Returns:
        List of triggered RiskIndicator objects (deduplicated by type)
    """
    from app.models.thread import Email
    
    indicators = []
    found_types = set()
    
    # URL regex pattern
    url_pattern = re.compile(r'https?://[^\s<>"\')\]]+', re.IGNORECASE)
    
    for email in emails:
        # Extract links from this specific email
        links = url_pattern.findall(email.body_text)
        if email.body_html:
            links.extend(url_pattern.findall(email.body_html))
        links = list(dict.fromkeys(links))  # Deduplicate
        
        # Check this email's body for urgency language
        urgency = detect_urgency_language(email.body_text)
        if urgency and urgency.type not in found_types:
            indicators.append(urgency)
            found_types.add(urgency.type)
        
        # Check for sensitive requests
        sensitive = detect_sensitive_requests(email.body_text)
        if sensitive and sensitive.type not in found_types:
            indicators.append(sensitive)
            found_types.add(sensitive.type)
        
        # Check links in this email
        link_indicator = detect_external_links(links)
        if link_indicator and link_indicator.type not in found_types:
            indicators.append(link_indicator)
            found_types.add(link_indicator.type)
    
    return indicators


# =============================================================================
# EXPLANATION GENERATION
# =============================================================================

# Severity ordering for prioritization (higher index = more severe)
_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

# Human-readable labels for indicator types
_INDICATOR_TYPE_LABELS = {
    # Rule-based indicators
    "urgency_language": "urgent or pressuring language",
    "sensitive_request": "requests for sensitive information",
    "external_links": "suspicious links",
    "sender_anomaly": "sender address anomalies",
    # AI-powered indicators (Gemini)
    "intent_drift": "suspicious intent change in conversation",
    "sentiment_shift": "suspicious tone shift",
    "style_anomaly": "writing style inconsistencies",
    "ai_urgency_detected": "AI-detected urgency patterns",
    "ai_high_risk": "AI-classified high-risk content",
    "ai_flagged_content": "AI-flagged suspicious content",
}


def _get_indicator_label(indicator_type: str) -> str:
    """
    Get a human-readable label for an indicator type.
    
    Args:
        indicator_type: The technical indicator type string
        
    Returns:
        Human-readable label for the indicator type
    """
    return _INDICATOR_TYPE_LABELS.get(indicator_type, indicator_type.replace("_", " "))


def _sort_indicators_by_severity(indicators: list[RiskIndicator]) -> list[RiskIndicator]:
    """
    Sort indicators by severity (highest first).
    
    Args:
        indicators: List of RiskIndicator objects
        
    Returns:
        New list sorted by severity descending, then by type for stability
    """
    return sorted(
        indicators,
        key=lambda i: (-_SEVERITY_ORDER.get(i.severity, 0), i.type)
    )


def _get_most_severe_indicators(indicators: list[RiskIndicator]) -> list[RiskIndicator]:
    """
    Get indicators with the highest severity level present.
    
    Args:
        indicators: List of RiskIndicator objects
        
    Returns:
        List of indicators matching the highest severity found
    """
    if not indicators:
        return []
    
    sorted_indicators = _sort_indicators_by_severity(indicators)
    highest_severity = sorted_indicators[0].severity
    
    return [i for i in sorted_indicators if i.severity == highest_severity]


def generate_summary(indicators: list[RiskIndicator], risk_level: str) -> str:
    """
    Generate a deterministic, human-readable explanation of detected risks.
    
    The summary is template-based and varies based on:
    - The risk level (safe, suspicious, dangerous)
    - The number and severity of detected indicators
    - The specific types of risks detected
    
    Args:
        indicators: List of triggered RiskIndicator objects
        risk_level: Classified risk level ("safe", "suspicious", "dangerous")
        
    Returns:
        Human-readable summary string explaining the analysis results
    """
    # === SAFE LEVEL ===
    if risk_level == "safe":
        if not indicators:
            return (
                "This email thread appears to be safe. "
                "No significant risk indicators were detected during analysis."
            )
        # Safe but with minor indicators (low severity only)
        indicator_labels = [_get_indicator_label(i.type) for i in indicators]
        if len(indicators) == 1:
            return (
                f"This email thread appears to be safe. "
                f"A minor indicator was noted ({indicator_labels[0]}), "
                f"but it does not suggest significant risk."
            )
        return (
            f"This email thread appears to be safe. "
            f"Minor indicators were noted ({', '.join(indicator_labels)}), "
            f"but they do not suggest significant risk."
        )
    
    # === SUSPICIOUS LEVEL ===
    if risk_level == "suspicious":
        most_severe = _get_most_severe_indicators(indicators)
        severe_labels = [_get_indicator_label(i.type) for i in most_severe]
        
        if len(indicators) == 1:
            return (
                f"This email thread is suspicious. "
                f"Analysis detected {severe_labels[0]}. "
                f"Review the content carefully before taking any action."
            )
        
        # Multiple indicators
        all_labels = [_get_indicator_label(i.type) for i in _sort_indicators_by_severity(indicators)]
        return (
            f"This email thread is suspicious. "
            f"Analysis detected {len(indicators)} risk indicators, "
            f"including {severe_labels[0]}. "
            f"Concerns identified: {', '.join(all_labels)}. "
            f"Exercise caution before clicking links or responding."
        )
    
    # === DANGEROUS LEVEL ===
    if risk_level == "dangerous":
        most_severe = _get_most_severe_indicators(indicators)
        severe_labels = [_get_indicator_label(i.type) for i in most_severe]
        high_severity_descriptions = [i.description for i in most_severe]
        
        if len(indicators) == 1:
            return (
                f"Warning: This email thread is potentially dangerous. "
                f"{high_severity_descriptions[0]}. "
                f"Do not click any links or provide personal information."
            )
        
        # Multiple indicators with at least one high severity
        all_labels = [_get_indicator_label(i.type) for i in _sort_indicators_by_severity(indicators)]
        primary_concern = high_severity_descriptions[0]
        
        return (
            f"Warning: This email thread is potentially dangerous. "
            f"{len(indicators)} risk indicators were detected. "
            f"Primary concern: {primary_concern}. "
            f"Additional risks: {', '.join(all_labels[1:]) if len(all_labels) > 1 else 'none'}. "
            f"Do not click any links, download attachments, or provide personal information."
        )
    
    # Fallback for unknown risk levels (should not occur)
    return (
        f"Analysis complete. {len(indicators)} indicator(s) detected. "
        f"Risk level: {risk_level}."
    )


def build_response(
    thread_id: str,
    score: float,
    level: str,
    indicators: list[RiskIndicator],
    summary: str,
) -> ThreadResponse:
    """
    Assemble the final analysis response.
    
    Args:
        thread_id: Identifier of the analyzed thread
        score: Calculated risk score
        level: Classified risk level
        indicators: List of triggered indicators
        summary: Human-readable summary
        
    Returns:
        ThreadResponse object ready for API response
    """
    return ThreadResponse(
        thread_id=thread_id,
        risk_score=round(score, 2),  # Round to 2 decimal places
        risk_level=level,
        indicators=indicators,
        summary=summary,
        api_version=API_VERSION,
    )


# =============================================================================
# MAIN ORCHESTRATOR
# =============================================================================

def analyze_thread(request: ThreadRequest) -> ThreadResponse:
    """
    Analyze an email thread for security risks.
    
    This is the main orchestrator function that:
    1. Extracts features from the thread
    2. Runs all rule-based checks
    3. Runs AI-powered Gemini analysis (if available)
    4. Combines indicators from both sources
    5. Scores the risk
    6. Classifies the risk level
    7. Builds a human-readable summary
    8. Returns the complete response
    
    Args:
        request: ThreadRequest containing thread_id and list of emails
        
    Returns:
        ThreadResponse with risk assessment, indicators, and summary
    """
    thread_id = request.thread_id
    
    # -------------------------------------------------------------------------
    # STEP 1: Feature Extraction
    # -------------------------------------------------------------------------
    logger.info(f"[{thread_id}] STEP 1/4: Extracting features...")
    step_start = time.perf_counter()
    features = extract_features(request)
    logger.debug(
        f"[{thread_id}] Features: {len(features.senders)} senders, "
        f"{len(features.links)} links, {len(features.full_text)} chars"
    )
    
    # -------------------------------------------------------------------------
    # STEP 2: Rule-Based Analysis
    # -------------------------------------------------------------------------
    logger.info(f"[{thread_id}] STEP 2/4: Running rule-based checks...")
    rule_start = time.perf_counter()
    
    # Run checks on combined features (for sender anomalies, etc.)
    rule_indicators = run_rule_checks(features)
    found_types = {ind.type for ind in rule_indicators}
    
    # Also run per-email checks to catch suspicious content that might be
    # diluted when all emails are combined (e.g., user's safe reply)
    per_email_indicators = run_rule_checks_per_email(request.emails)
    for ind in per_email_indicators:
        if ind.type not in found_types:
            rule_indicators.append(ind)
            found_types.add(ind.type)
    
    rule_elapsed = (time.perf_counter() - rule_start) * 1000
    logger.info(
        f"[{thread_id}] Rule-based: {len(rule_indicators)} indicators ({rule_elapsed:.0f}ms)"
    )
    
    # -------------------------------------------------------------------------
    # STEP 3: Gemini AI Analysis
    # -------------------------------------------------------------------------
    ai_indicators = []
    gemini_available = is_gemini_available()
    
    if gemini_available and request.emails:
        logger.info(f"[{thread_id}] STEP 3/4: Starting Gemini AI analysis...")
        gemini_start = time.perf_counter()
        
        try:
            gemini_analyses = analyze_thread_with_gemini(request.emails)
            ai_indicators = gemini_to_indicators(gemini_analyses)
            gemini_elapsed = (time.perf_counter() - gemini_start) * 1000
            
            if gemini_analyses:
                logger.info(
                    f"[{thread_id}] Gemini SUCCESS: {len(gemini_analyses)} emails analyzed, "
                    f"{len(ai_indicators)} indicators ({gemini_elapsed:.0f}ms)"
                )
            else:
                logger.warning(
                    f"[{thread_id}] Gemini returned no results ({gemini_elapsed:.0f}ms)"
                )
        except Exception as e:
            gemini_elapsed = (time.perf_counter() - gemini_start) * 1000
            logger.warning(
                f"[{thread_id}] Gemini FAILED: {e} ({gemini_elapsed:.0f}ms) - "
                f"falling back to rule-based only"
            )
    elif not gemini_available:
        logger.info(f"[{thread_id}] STEP 3/4: Gemini DISABLED - skipping AI analysis")
    else:
        logger.info(f"[{thread_id}] STEP 3/4: No emails to analyze - skipping Gemini")
    
    # -------------------------------------------------------------------------
    # STEP 4: Combine, Score, and Build Response
    # -------------------------------------------------------------------------
    logger.info(f"[{thread_id}] STEP 4/4: Combining results and scoring...")
    
    # Combine indicators from both sources
    # Deduplicate by type to avoid double-counting similar detections
    all_indicators = rule_indicators.copy()
    existing_types = {ind.type for ind in rule_indicators}
    
    for ai_ind in ai_indicators:
        # Don't add AI urgency if rule-based already found urgency
        if ai_ind.type == "ai_urgency_detected" and "urgency_language" in existing_types:
            continue
        all_indicators.append(ai_ind)
    
    # Calculate numeric risk score
    score = score_indicators(all_indicators)
    
    # Classify into risk level
    level = determine_risk_level(score)
    
    # Generate human-readable summary
    summary = generate_summary(all_indicators, level)
    
    # Log completion
    total_elapsed = (time.perf_counter() - step_start) * 1000
    logger.info(
        f"[{thread_id}] COMPLETE: {len(all_indicators)} total indicators, "
        f"score={score:.2f}, level={level} ({total_elapsed:.0f}ms)"
    )
    
    # Assemble and return response
    return build_response(
        thread_id=thread_id,
        score=score,
        level=level,
        indicators=all_indicators,
        summary=summary,
    )

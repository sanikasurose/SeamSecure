# Name: __init__.py
# Description: Export all services for convenient importing
# Date: 2026-01-31

from app.services.analysis_service import analyze_thread
from app.services.scoring import (
    severity_to_weight,
    score_indicators,
    determine_risk_level,
)
from app.services.gemini_service import (
    initialize_gemini,
    get_gemini_status,
    analyze_thread_with_gemini,
    gemini_to_indicators,
    is_gemini_available,
)
from app.services.gmail_service import (
    list_threads,
    list_thread_summaries,
    get_thread,
    get_parsed_thread,
    parse_gmail_thread,
)

__all__ = [
    # Analysis
    "analyze_thread",
    # Scoring
    "severity_to_weight",
    "score_indicators",
    "determine_risk_level",
    # Gemini AI
    "initialize_gemini",
    "get_gemini_status",
    "analyze_thread_with_gemini",
    "gemini_to_indicators",
    "is_gemini_available",
    # Gmail
    "list_threads",
    "list_thread_summaries",
    "get_thread",
    "get_parsed_thread",
    "parse_gmail_thread",
]

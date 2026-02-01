# Name: analysis_service.py
# Description: Service for analyzing email threads
# Date: 2026-01-31

from app.models.thread import ThreadRequest, ThreadResponse, RiskIndicator


def analyze_thread(request: ThreadRequest) -> ThreadResponse:
    """
    Analyze an email thread for security risks.

    Args:
        request: ThreadRequest containing thread_id and list of emails.

    Returns:
        ThreadResponse with risk assessment, indicators, and summary.

    Note:
        This is a stub implementation returning fake but realistic data.
        Real ML/NLP analysis will be implemented in a future phase.
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

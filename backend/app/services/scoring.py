# Name: scoring.py
# Description: Risk scoring and aggregation system for email threat analysis
# Date: 2026-02-01
#
# This module provides deterministic, framework-agnostic scoring functions
# that convert detected risk indicators into normalized scores and risk levels.

from app.models.thread import RiskIndicator


# =============================================================================
# SEVERITY WEIGHT MAPPING
# =============================================================================

# Weight values for each severity level
# These weights are calibrated to produce meaningful risk scores:
# - low: Minor concern, contributes minimally to overall risk
# - medium: Moderate concern, noticeable contribution to risk
# - high: Serious concern, significant contribution to risk
SEVERITY_WEIGHTS = {
    "low": 0.2,
    "medium": 0.5,
    "high": 0.9,
}


def severity_to_weight(severity: str) -> float:
    """
    Convert a severity level string to its corresponding numeric weight.
    
    Mapping:
        - "low"    → 0.2
        - "medium" → 0.5
        - "high"   → 0.9
    
    Args:
        severity: Severity level string ("low", "medium", or "high")
        
    Returns:
        Numeric weight for the severity level.
        Returns 0.0 for unknown severity values.
    
    Examples:
        >>> severity_to_weight("low")
        0.2
        >>> severity_to_weight("high")
        0.9
        >>> severity_to_weight("unknown")
        0.0
    """
    return SEVERITY_WEIGHTS.get(severity.lower(), 0.0)


# =============================================================================
# INDICATOR SCORING
# =============================================================================

def score_indicators(indicators: list[RiskIndicator]) -> float:
    """
    Calculate a normalized risk score from a list of risk indicators.
    
    The score is computed by summing the weights of all indicator severities.
    The final score is capped at 1.0 to maintain normalization.
    
    This function is deterministic: the same input always produces the same output.
    
    Scoring behavior:
        - Empty list → 0.0
        - Single low indicator → 0.2
        - Single medium indicator → 0.5
        - Single high indicator → 0.9
        - Multiple indicators → sum of weights (capped at 1.0)
    
    Args:
        indicators: List of RiskIndicator objects to score
        
    Returns:
        Normalized risk score between 0.0 and 1.0 (inclusive)
    
    Examples:
        >>> score_indicators([])
        0.0
        >>> score_indicators([RiskIndicator(type="x", description="x", severity="high")])
        0.9
    """
    if not indicators:
        return 0.0
    
    # Sum all severity weights
    total_weight = sum(
        severity_to_weight(indicator.severity)
        for indicator in indicators
    )
    
    # Cap at 1.0 to maintain normalization
    return min(total_weight, 1.0)


# =============================================================================
# RISK LEVEL CLASSIFICATION
# =============================================================================

# Risk level thresholds
# These thresholds define the boundaries between risk categories
RISK_THRESHOLDS = {
    "safe_upper": 0.3,       # score < 0.3 → safe
    "suspicious_upper": 0.7,  # 0.3 ≤ score < 0.7 → suspicious
    # score ≥ 0.7 → dangerous
}


def determine_risk_level(score: float) -> str:
    """
    Classify a numeric risk score into a categorical risk level.
    
    Thresholds:
        - score < 0.3          → "safe"
        - 0.3 ≤ score < 0.7    → "suspicious"
        - score ≥ 0.7          → "dangerous"
    
    Args:
        score: Numeric risk score (expected range: 0.0 - 1.0)
        
    Returns:
        Risk level string: "safe", "suspicious", or "dangerous"
    
    Examples:
        >>> determine_risk_level(0.0)
        'safe'
        >>> determine_risk_level(0.5)
        'suspicious'
        >>> determine_risk_level(0.9)
        'dangerous'
    """
    if score < RISK_THRESHOLDS["safe_upper"]:
        return "safe"
    elif score < RISK_THRESHOLDS["suspicious_upper"]:
        return "suspicious"
    else:
        return "dangerous"

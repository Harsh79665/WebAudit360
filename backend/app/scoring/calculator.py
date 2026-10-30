"""WebAudit 360 — Transparent Versioned Scoring Algorithm (v1.0.0)
Author: Harsh Patel

Formula:
Overall Score = (0.25 × Perf) + (0.20 × SEO) + (0.20 × A11y) + (0.25 × Sec) + (0.10 × Tech)

Dynamic normalization is applied when specific categories are omitted or unavailable:
Normalized = sum(weight_i * score_i) / sum(weight_i)

Labels:
- 90–100: Excellent
- 75–89: Good
- 50–74: Needs Improvement
- 25–49: Poor
- 0–24: Critical
"""

from typing import Dict, Optional, Tuple

SCORING_ALGORITHM_VERSION = "1.0.0"

CATEGORY_WEIGHTS = {
    "PERFORMANCE": 0.25,
    "SEO": 0.20,
    "ACCESSIBILITY": 0.20,
    "SECURITY": 0.25,
    "TECHNICAL": 0.10,
}


def get_score_label(score: Optional[float]) -> str:
    """Returns the WebAudit 360 rating label for a numeric score."""
    if score is None:
        return "N/A"
    rounded = round(score)
    if rounded >= 90:
        return "Excellent"
    if rounded >= 75:
        return "Good"
    if rounded >= 50:
        return "Needs Improvement"
    if rounded >= 25:
        return "Poor"
    return "Critical"


def calculate_overall_score(
    score_perf: Optional[float] = None,
    score_seo: Optional[float] = None,
    score_a11y: Optional[float] = None,
    score_sec: Optional[float] = None,
    score_tech: Optional[float] = None,
) -> Tuple[Optional[float], Dict[str, Any]]:
    """
    Computes overall score using versioned category weights.
    Applies dynamic normalization if one or more categories are missing.
    Returns (overall_score, calculation_metadata).
    """
    category_inputs = {
        "PERFORMANCE": score_perf,
        "SEO": score_seo,
        "ACCESSIBILITY": score_a11y,
        "SECURITY": score_sec,
        "TECHNICAL": score_tech,
    }

    available_weights = {}
    weighted_sum = 0.0

    for cat, val in category_inputs.items():
        if val is not None and not isinstance(val, str):
            # Clamp value between 0.0 and 100.0
            clamped_val = max(0.0, min(100.0, float(val)))
            w = CATEGORY_WEIGHTS[cat]
            available_weights[cat] = w
            weighted_sum += clamped_val * w

    total_weight = sum(available_weights.values())

    if total_weight == 0.0:
        return None, {
            "version": SCORING_ALGORITHM_VERSION,
            "status": "INCOMPLETE_DATA",
            "evaluated_categories": 0,
            "overall_score": None,
            "label": "N/A",
            "message": "No scored categories were available to compute an overall rating."
        }

    overall_score = round(weighted_sum / total_weight, 1)

    metadata = {
        "version": SCORING_ALGORITHM_VERSION,
        "standard_weights": CATEGORY_WEIGHTS,
        "active_weights": available_weights,
        "is_normalized": total_weight < 1.0,
        "evaluated_categories_count": len(available_weights),
        "total_categories_count": len(CATEGORY_WEIGHTS),
        "overall_score": overall_score,
        "label": get_score_label(overall_score),
    }

    return overall_score, metadata


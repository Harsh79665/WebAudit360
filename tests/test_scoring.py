"""WebAudit 360 — Transparent Scoring Algorithm Unit Tests
Author: Harsh Patel
"""

from backend.app.scoring.calculator import (
    calculate_overall_score,
    get_score_label,
    CATEGORY_WEIGHTS,
)


def test_standard_all_categories_score():
    """Calculates overall score when all 5 categories are present."""
    # (0.25 * 100) + (0.20 * 90) + (0.20 * 85) + (0.25 * 95) + (0.10 * 80)
    # = 25 + 18 + 17 + 23.75 + 8 = 91.75 -> 91.8
    score, meta = calculate_overall_score(
        score_perf=100.0,
        score_seo=90.0,
        score_a11y=85.0,
        score_sec=95.0,
        score_tech=80.0
    )
    assert score == 91.8
    assert meta["label"] == "Excellent"
    assert meta["is_normalized"] is False
    assert meta["evaluated_categories_count"] == 5


def test_dynamic_normalization_missing_modules():
    """When some modules are omitted, available weights must be dynamically normalized."""
    # Performance (0.25) = 80, SEO (0.20) = 90. Missing: A11y, Sec, Tech.
    # Total available weight = 0.45
    # Weighted sum = (0.25 * 80) + (0.20 * 90) = 20 + 18 = 38
    # Normalized = 38 / 0.45 = 84.444... -> 84.4
    score, meta = calculate_overall_score(
        score_perf=80.0,
        score_seo=90.0,
        score_a11y=None,
        score_sec=None,
        score_tech=None
    )
    assert score == 84.4
    assert meta["label"] == "Good"
    assert meta["is_normalized"] is True
    assert meta["evaluated_categories_count"] == 2


def test_all_missing_returns_none():
    """If no scored categories are provided, score must be None (N/A) rather than 0 or fake pass."""
    score, meta = calculate_overall_score(
        score_perf=None,
        score_seo=None,
        score_a11y=None,
        score_sec=None,
        score_tech=None
    )
    assert score is None
    assert meta["label"] == "N/A"
    assert meta["status"] == "INCOMPLETE_DATA"


def test_score_rating_labels():
    """Verify WebAudit 360 label thresholds."""
    assert get_score_label(95.0) == "Excellent"
    assert get_score_label(80.0) == "Good"
    assert get_score_label(60.0) == "Needs Improvement"
    assert get_score_label(35.0) == "Poor"
    assert get_score_label(15.0) == "Critical"
    assert get_score_label(None) == "N/A"


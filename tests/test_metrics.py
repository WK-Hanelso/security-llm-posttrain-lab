import pytest

from security_llm.eval.metrics import compute


def test_metrics_include_invalid_as_wrong():
    rows = [
        {"gold": "CWE-79", "pred": "CWE-79", "valid_label": True, "exact_match": True, "error_flags": [], "is_kev": True},
        {"gold": "CWE-79", "pred": "CWE-79", "valid_label": True, "exact_match": True, "error_flags": [], "is_kev": False},
        {"gold": "CWE-79", "pred": None, "valid_label": False, "exact_match": False, "error_flags": ["not_json"], "is_kev": False},
        {"gold": "CWE-89", "pred": "CWE-89", "valid_label": True, "exact_match": True, "error_flags": [], "is_kev": True},
        {"gold": "CWE-89", "pred": "CWE-79", "valid_label": True, "exact_match": False, "error_flags": [], "is_kev": False},
        {"gold": "CWE-89", "pred": "CWE-89", "valid_label": True, "exact_match": True, "error_flags": [], "is_kev": False},
    ]
    result = compute(rows, ["CWE-79", "CWE-89"])
    assert result["accuracy"] == pytest.approx(4 / 6)
    assert result["invalid_rate"] == pytest.approx(1 / 6)
    assert result["macro_f1"] == pytest.approx((2 / 3 + 0.8) / 2)
    assert result["invalid_breakdown"]["not_json"] == 1


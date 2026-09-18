from security_llm.eval.failure_analysis import (
    _confusion_count,
    _gold_sinks,
    _prediction_concentration,
)


def _row(gold: str, pred: str | None, exact: bool = False):
    return {"gold": gold, "pred": pred, "exact_match": exact}


def test_tracked_confusion_and_gold_sinks_exclude_correct_predictions():
    rows = {
        "a": _row("CWE-416", "CWE-434"),
        "b": _row("CWE-416", "CWE-434"),
        "c": _row("CWE-416", "CWE-120"),
        "d": _row("CWE-416", None),
        "e": _row("CWE-416", "CWE-416", exact=True),
        "f": _row("CWE-862", "CWE-200"),
    }

    assert _confusion_count(rows, "CWE-416", "CWE-434") == 2
    assert _gold_sinks(rows, "CWE-416") == [
        {"pred": "CWE-434", "count": 2},
        {"pred": "CWE-120", "count": 1},
        {"pred": "INVALID", "count": 1},
    ]


def test_prediction_distribution_concentration_uses_all_rows_as_denominator():
    rows = {
        "a": _row("CWE-79", "CWE-200"),
        "b": _row("CWE-79", "CWE-200"),
        "c": _row("CWE-79", "CWE-120"),
        "d": _row("CWE-79", "CWE-79", exact=True),
        "e": _row("CWE-79", None),
    }

    result = _prediction_concentration(rows)

    assert result["top_3"] == [
        {"pred": "CWE-200", "count": 2},
        {"pred": "CWE-120", "count": 1},
        {"pred": "CWE-79", "count": 1},
    ]
    assert result["top_3_count"] == 4
    assert result["top_3_share"] == 0.8
    assert result["denominator"] == 5

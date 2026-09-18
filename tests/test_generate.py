import json

from security_llm.eval.generate import _select_rows
from security_llm.utils.io import read_jsonl


def test_select_rows_uses_reproducible_uniform_shuffle_before_limit():
    rows = [{"id": value} for value in range(10)]

    selected = _select_rows(rows, limit=4, subsample_seed=42)

    assert [row["id"] for row in selected] == [7, 3, 2, 8]
    assert [row["id"] for row in rows] == list(range(10))
    assert _select_rows(rows, limit=4, subsample_seed=42) == selected


def test_subset_manifest_pins_baseline_prediction_order_and_ignores_limit_seed():
    with open("reports/eval_subset_manifest.json", encoding="utf-8") as handle:
        manifest = json.load(handle)
    test_rows = read_jsonl("data/sft/test.jsonl")
    selected = _select_rows(test_rows, limit=1, subsample_seed=999, subset_manifest=manifest)
    prediction_ids = [
        row["cve_id"]
        for row in read_jsonl("experiments/exp_001_baseline/predictions.jsonl")
    ]
    assert [row["cve_id"] for row in selected] == prediction_ids
    assert manifest["row_ids"] == prediction_ids

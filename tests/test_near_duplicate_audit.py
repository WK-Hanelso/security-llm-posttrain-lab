import json
import random

import pytest

from security_llm.eval.near_duplicate_audit import (
    HIGH_THRESHOLD,
    VERY_HIGH_THRESHOLD,
    _nearest_train_rows,
    audit,
    proportional_allocation,
    stratified_sample,
)


def _write_jsonl(path, rows):
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_synthetic_audit_identical_text_and_same_label(tmp_path):
    train = [
        {"cve_id": "TR-1", "cwe_id": "CWE-79", "description": "alpha browser script injection repeated phrase"},
        {"cve_id": "TR-2", "cwe_id": "CWE-89", "description": "database query injection repeated phrase"},
        {"cve_id": "TR-3", "cwe_id": "CWE-22", "description": "path traversal archive repeated phrase"},
        {"cve_id": "TR-4", "cwe_id": "CWE-79", "description": "unrelated browser markup repeated phrase"},
        {"cve_id": "TR-5", "cwe_id": "CWE-89", "description": "unrelated database query repeated phrase"},
        {"cve_id": "TR-6", "cwe_id": "CWE-22", "description": "unrelated archive path repeated phrase"},
    ]
    test = [
        {"cve_id": "TE-1", "cwe_id": "CWE-79", "description": train[0]["description"]},
        {"cve_id": "TE-2", "cwe_id": "CWE-89", "description": train[1]["description"]},
        {"cve_id": "TE-3", "cwe_id": "CWE-22", "description": train[2]["description"]},
    ]
    base = [
        {"cve_id": "TE-1", "gold": "CWE-79", "pred": "CWE-20", "exact_match": False},
        {"cve_id": "TE-2", "gold": "CWE-89", "pred": "CWE-20", "exact_match": False},
        {"cve_id": "TE-3", "gold": "CWE-22", "pred": "CWE-20", "exact_match": False},
    ]
    sft = [
        {"cve_id": "TE-1", "gold": "CWE-79", "pred": "CWE-79", "exact_match": True},
        {"cve_id": "TE-2", "gold": "CWE-89", "pred": "CWE-89", "exact_match": True},
        {"cve_id": "TE-3", "gold": "CWE-22", "pred": "CWE-22", "exact_match": True},
    ]
    paths = {name: tmp_path / f"{name}.jsonl" for name in ("train", "test", "base", "sft")}
    for name, rows in (("train", train), ("test", test), ("base", base), ("sft", sft)):
        _write_jsonl(paths[name], rows)

    result = audit(
        paths["train"],
        paths["test"],
        paths["base"],
        paths["sft"],
        requested_sample={"fixed_by_sft": 3},
    )

    assert result["thresholds"] == {"high": HIGH_THRESHOLD, "very_high": VERY_HIGH_THRESHOLD}
    assert result["sample"]["allocation"]["fixed_by_sft"] == {
        "CWE-22": 1,
        "CWE-79": 1,
        "CWE-89": 1,
    }
    assert len(result["rows"]) == 3
    assert all(row["similarity"] == pytest.approx(1.0) for row in result["rows"])
    assert all(row["same_label"] for row in result["rows"])
    assert all("char5_jaccard" in row for row in result["rows"])


def test_nearest_train_same_label_logic_can_be_false():
    train = [
        {"cve_id": "TR-1", "cwe_id": "CWE-89", "description": "identical repeated query words"},
        {"cve_id": "TR-2", "cwe_id": "CWE-79", "description": "other repeated browser words"},
        {"cve_id": "TR-3", "cwe_id": "CWE-22", "description": "other repeated archive words"},
        {"cve_id": "TR-4", "cwe_id": "CWE-20", "description": "other repeated validation words"},
        {"cve_id": "TR-5", "cwe_id": "CWE-78", "description": "other repeated command words"},
        {"cve_id": "TR-6", "cwe_id": "CWE-125", "description": "other repeated memory words"},
    ]
    sample = [{
        "test_cve_id": "TE-1",
        "gold_cwe": "CWE-79",
        "transition": "fixed_by_sft",
        "base_prediction": "CWE-20",
        "sft_prediction": "CWE-79",
        "description": train[0]["description"],
    }]

    row = _nearest_train_rows(train, sample)[0]

    assert row["similarity"] == pytest.approx(1.0)
    assert row["nearest_train_cve_id"] == "TR-1"
    assert row["same_label"] is False


def test_stratification_returns_requested_count_and_minimum_one_per_class():
    rows = [
        {"gold_cwe": label, "id": f"{label}-{index}"}
        for label, count in (("A", 7), ("B", 2), ("C", 1))
        for index in range(count)
    ]

    sampled, allocation = stratified_sample(rows, 6, random.Random(42))

    assert len(sampled) == 6
    assert sum(allocation.values()) == 6
    assert allocation == proportional_allocation({"A": 7, "B": 2, "C": 1}, 6)
    assert all(count >= 1 for count in allocation.values())

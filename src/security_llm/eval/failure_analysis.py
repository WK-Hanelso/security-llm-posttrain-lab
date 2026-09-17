"""Compare baseline and SFT predictions and classify residual failures."""

from __future__ import annotations

import argparse
import json
import logging
from collections import Counter
from pathlib import Path
from typing import Any

from security_llm.utils.io import atomic_write_json, read_jsonl, write_jsonl

LOG = logging.getLogger(__name__)

CWE_FAMILIES = {
    "injection": {"CWE-79", "CWE-80", "CWE-89", "CWE-77", "CWE-78", "CWE-94", "CWE-91", "CWE-74", "CWE-116", "CWE-1336"},
    "memory": {"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-787", "CWE-416", "CWE-415", "CWE-476", "CWE-190", "CWE-191", "CWE-401", "CWE-786", "CWE-788"},
    "access_control": {"CWE-284", "CWE-285", "CWE-287", "CWE-306", "CWE-862", "CWE-863", "CWE-269", "CWE-266", "CWE-639", "CWE-732", "CWE-276"},
    "input_validation": {"CWE-20", "CWE-1284", "CWE-129"},
    "path": {"CWE-22", "CWE-23", "CWE-36", "CWE-73"},
    "info_exposure": {"CWE-200", "CWE-209", "CWE-532", "CWE-312", "CWE-319"},
    "request_forgery": {"CWE-352", "CWE-918"},
    "crypto": {"CWE-327", "CWE-326", "CWE-330", "CWE-338", "CWE-295", "CWE-347"},
    "file_upload": {"CWE-434", "CWE-494"}, "xml": {"CWE-611", "CWE-776"},
    "deserialization": {"CWE-502"}, "race": {"CWE-362", "CWE-367"},
    "resource": {"CWE-400", "CWE-770", "CWE-772", "CWE-835", "CWE-834"},
    "credentials": {"CWE-798", "CWE-522", "CWE-521", "CWE-256", "CWE-259"},
    "redirect": {"CWE-601"}, "ssti_expression": {"CWE-1321", "CWE-917"},
}


def family(cwe: str | None) -> str | None:
    return next((name for name, values in CWE_FAMILIES.items() if cwe in values), None) if cwe else None


def error_type(row: dict[str, Any], gold: str, allowed: set[str]) -> str | None:
    if not row.get("valid_json") or not row.get("has_key"):
        return "invalid_format"
    pred = row.get("pred")
    if pred is None or pred not in allowed:
        return "unknown_cwe"
    if row.get("exact_match"):
        return None
    return "nearby_cwe_confusion" if family(pred) is not None and family(pred) == family(gold) else "semantic_confusion"


def _transition(base_right: bool, sft_right: bool) -> str:
    return {(True, True): "both_right", (False, True): "fixed_by_sft", (True, False): "broken_by_sft", (False, False): "both_wrong"}[(base_right, sft_right)]


def analyze(base_path: str, sft_path: str, test_path: str, labels_path: str) -> dict[str, Any]:
    base = {row["cve_id"]: row for row in read_jsonl(base_path)}
    sft = {row["cve_id"]: row for row in read_jsonl(sft_path)}
    test = {row["cve_id"]: row for row in read_jsonl(test_path)}
    if set(base) != set(sft):
        raise AssertionError("Base and SFT prediction CVE sets differ")
    if set(base) != set(test):
        raise AssertionError("Predictions and test CVE sets differ")
    with Path(labels_path).open(encoding="utf-8") as handle:
        labels = json.load(handle)
    selected = labels["selected"]
    allowed = set(selected)
    ranked = sorted(selected, key=lambda cwe: (labels["train_counts"].get(cwe, 0), cwe))
    long_tail = set(ranked[: max(1, len(selected) // 3)])
    transitions: Counter[str] = Counter()
    error_counts = {"base": Counter(), "sft": Counter()}
    failures: list[dict[str, Any]] = []
    for cve_id in sorted(base):
        base_row, sft_row = base[cve_id], sft[cve_id]
        if base_row["gold"] != sft_row["gold"]:
            raise AssertionError(f"Gold mismatch for {cve_id}")
        gold = base_row["gold"]
        transition = _transition(bool(base_row["exact_match"]), bool(sft_row["exact_match"]))
        transitions[transition] += 1
        for name, row in (("base", base_row), ("sft", sft_row)):
            kind = error_type(row, gold, allowed)
            if kind:
                error_counts[name][kind] += 1
        if not sft_row["exact_match"]:
            source = test[cve_id]
            failures.append({"cve_id": cve_id, "description": source["description"], "gold": gold,
                "prediction": sft_row.get("pred"), "base_prediction": base_row.get("pred"),
                "sft_raw_output": sft_row["raw_output"], "base_raw_output": base_row["raw_output"],
                "transition": transition, "error_type": error_type(sft_row, gold, allowed),
                "gold_is_long_tail": gold in long_tail, "is_kev": source["is_kev"]})
    failures.sort(key=lambda row: (0 if row["transition"] == "broken_by_sft" else 1, row["cve_id"]))
    write_jsonl("reports/failures.jsonl", failures)
    if len(failures) < 30:
        LOG.warning("Only %d SFT failures are available", len(failures))
    with (Path(base_path).parent / "metrics.json").open(encoding="utf-8") as handle:
        base_metrics = json.load(handle)
    with (Path(sft_path).parent / "metrics.json").open(encoding="utf-8") as handle:
        sft_metrics = json.load(handle)
    per_class_delta = {cwe: {"base_f1": base_metrics["per_class"][cwe]["f1"],
        "sft_f1": sft_metrics["per_class"][cwe]["f1"],
        "delta": sft_metrics["per_class"][cwe]["f1"] - base_metrics["per_class"][cwe]["f1"]} for cwe in selected}

    def confusions(rows: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        counts = Counter((row["gold"], row.get("pred") or "INVALID") for row in rows.values() if not row["exact_match"])
        return [{"gold": gold, "pred": pred, "count": count} for (gold, pred), count in counts.most_common(15)]

    tail_ids = [cve_id for cve_id, row in base.items() if row["gold"] in long_tail]
    summary = {"n_test": len(base),
        "transitions": {name: transitions[name] for name in ("both_right", "fixed_by_sft", "broken_by_sft", "both_wrong")},
        "error_type_counts": {name: {kind: values[kind] for kind in ("invalid_format", "unknown_cwe", "nearby_cwe_confusion", "semantic_confusion")} for name, values in error_counts.items()},
        "per_class_delta": per_class_delta, "top_confusions_sft": confusions(sft), "top_confusions_base": confusions(base),
        "long_tail": {"base_accuracy": sum(base[cve_id]["exact_match"] for cve_id in tail_ids) / len(tail_ids) if tail_ids else 0.0,
            "sft_accuracy": sum(sft[cve_id]["exact_match"] for cve_id in tail_ids) / len(tail_ids) if tail_ids else 0.0, "n": len(tail_ids)}}
    atomic_write_json("reports/failure_summary.json", summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--sft", required=True)
    parser.add_argument("--test", required=True)
    parser.add_argument("--labels", required=True)
    args = parser.parse_args()
    analyze(args.base, args.sft, args.test, args.labels)


if __name__ == "__main__":
    main()

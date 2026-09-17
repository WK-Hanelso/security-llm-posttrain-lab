"""Classification metrics that retain invalid model outputs."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from sklearn.metrics import confusion_matrix, f1_score, precision_recall_fscore_support

from security_llm.utils.io import atomic_write_json, read_jsonl

INVALID_FLAGS = ["not_json", "missing_key", "multiple_cwe", "bad_cwe_format", "label_not_allowed"]


def compute(predictions: list[dict[str, Any]], selected: list[str]) -> dict[str, Any]:
    n = len(predictions)
    y_true = [row["gold"] for row in predictions]
    y_pred = [row["pred"] if row.get("valid_label") else "INVALID" for row in predictions]
    exact_count = sum(bool(row.get("exact_match")) for row in predictions)
    valid_count = sum(bool(row.get("valid_label")) for row in predictions)
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=selected, zero_division=0
    )
    all_labels = selected + ["INVALID"]
    matrix = confusion_matrix(y_true, y_pred, labels=all_labels)

    def slice_stats(rows: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "n": len(rows),
            "accuracy": sum(bool(row.get("exact_match")) for row in rows) / len(rows) if rows else 0.0,
        }

    flag_counts = Counter(flag for row in predictions for flag in row.get("error_flags", []))
    return {
        "n": n,
        "accuracy": exact_count / n if n else 0.0,
        "macro_f1": f1_score(y_true, y_pred, labels=selected, average="macro", zero_division=0) if n else 0.0,
        "weighted_f1": f1_score(y_true, y_pred, labels=selected, average="weighted", zero_division=0) if n else 0.0,
        "invalid_rate": (n - valid_count) / n if n else 0.0,
        "invalid_breakdown": {flag: flag_counts[flag] for flag in INVALID_FLAGS},
        "accuracy_on_valid": exact_count / valid_count if valid_count else 0.0,
        "per_class": {
            label: {
                "precision": float(precision[index]),
                "recall": float(recall[index]),
                "f1": float(f1[index]),
                "support": int(support[index]),
            }
            for index, label in enumerate(selected)
        },
        "confusion_matrix": {"labels": all_labels, "matrix": matrix.tolist()},
        "slices": {
            "kev": slice_stats([row for row in predictions if row.get("is_kev")]),
            "non_kev": slice_stats([row for row in predictions if not row.get("is_kev")]),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--labels", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    with Path(args.labels).open(encoding="utf-8") as handle:
        selected = json.load(handle)["selected"]
    atomic_write_json(args.output, compute(read_jsonl(args.predictions), selected))


if __name__ == "__main__":
    main()


"""Compare baseline and SFT predictions and classify residual failures."""

from __future__ import annotations

import argparse
import json
import logging
import re
from collections import Counter
from pathlib import Path
from typing import Any

from security_llm.data.report import TOKENIZER_NAME, token_lengths_for_rows
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
ERROR_TYPES = ("invalid_format", "unknown_cwe", "nearby_cwe_confusion", "semantic_confusion")
ALL_OUTCOMES = ("correct",) + ERROR_TYPES
TRACKED_CONFUSIONS = (
    ("CWE-862", "CWE-200"),
    ("CWE-284", "CWE-200"),
    ("CWE-416", "CWE-434"),
    ("CWE-787", "CWE-120"),
    ("CWE-125", "CWE-120"),
)
OVERGENERAL_PREDICTIONS = {"CWE-200", "CWE-20", "CWE-284"}
UNDER_SPECIFIC_CHILDREN = {
    "CWE-120": {"CWE-125", "CWE-787", "CWE-121", "CWE-122"},
    "CWE-284": {"CWE-862", "CWE-863", "CWE-285", "CWE-287", "CWE-306", "CWE-269"},
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


def _slice(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "n": len(rows),
        "correct": sum(bool(row["prediction"]["exact_match"]) for row in rows),
        "accuracy": (
            sum(bool(row["prediction"]["exact_match"]) for row in rows) / len(rows)
            if rows else 0.0
        ),
    }


def _bucketed(
    rows: list[dict[str, Any]], bucket: Any, order: tuple[str, ...]
) -> dict[str, dict[str, Any]]:
    return {name: _slice([row for row in rows if bucket(row) == name]) for name in order}


def _description_bucket(length: int) -> str:
    if length < 250:
        return "<250"
    if length < 500:
        return "250-500"
    if length < 1000:
        return "500-1000"
    return ">=1000"


def _token_bucket(length: int) -> str:
    return "<480" if length < 480 else "480-1536"


def _confusion_count(
    rows: dict[str, dict[str, Any]], gold: str, pred: str
) -> int:
    return sum(
        row["gold"] == gold and row.get("pred") == pred and not row["exact_match"]
        for row in rows.values()
    )


def _gold_sinks(
    rows: dict[str, dict[str, Any]], gold: str, limit: int = 3
) -> list[dict[str, Any]]:
    counts = Counter(
        row.get("pred") or "INVALID"
        for row in rows.values()
        if row["gold"] == gold and not row["exact_match"]
    )
    return [{"pred": pred, "count": count} for pred, count in counts.most_common(limit)]


def _prediction_concentration(rows: dict[str, dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(row.get("pred") or "INVALID" for row in rows.values())
    top = counts.most_common(3)
    return {
        "top_3": [{"pred": pred, "count": count} for pred, count in top],
        "top_3_count": sum(count for _, count in top),
        "top_3_share": sum(count for _, count in top) / len(rows) if rows else 0.0,
        "denominator": len(rows),
    }


def _model_slices(
    rows: dict[str, dict[str, Any]],
    sources: dict[str, dict[str, Any]],
    token_lengths: dict[str, int],
) -> dict[str, Any]:
    joined = [
        {
            "prediction": prediction,
            "source": sources[cve_id],
            "token_length": token_lengths[cve_id],
        }
        for cve_id, prediction in rows.items()
    ]
    return {
        "description_length_buckets": _bucketed(
            joined,
            lambda row: _description_bucket(len(row["source"]["description"])),
            ("<250", "250-500", "500-1000", ">=1000"),
        ),
        "token_length_buckets": _bucketed(
            joined,
            lambda row: _token_bucket(row["token_length"]),
            ("<480", "480-1536"),
        ),
        "kev": {
            "kev": _slice([row for row in joined if row["source"]["is_kev"]]),
            "non_kev": _slice(
                [row for row in joined if not row["source"]["is_kev"]]
            ),
        },
    }


def _base_failure_row(row: dict[str, Any]) -> dict[str, Any]:
    description = row["source"]["description"]
    cleaned = re.sub(r"improv\w*", "[word omitted]", description, flags=re.IGNORECASE)
    excerpt = cleaned if len(description) <= 200 else cleaned[:199] + "…"
    return {
        "cve_id": row["prediction"]["cve_id"],
        "gold": row["prediction"]["gold"],
        "base_prediction": row["prediction"].get("pred"),
        "error_type": row["error_type"],
        "description_excerpt": excerpt,
        "description_chars": len(description),
        "gold_is_long_tail": row["gold_is_long_tail"],
        "overgeneralization": row["overgeneralization"],
        "under_specific": row["under_specific"],
    }


def _render_base_taxonomy(taxonomy: dict[str, Any]) -> str:
    lines = [
        "## Failure taxonomy (Base)",
        "",
        "Error categories are deterministic rules over the stored predictions; excerpts are capped at 200 characters.",
        "",
        "### Error types",
        "",
        "| Error type | Count |",
        "|---|---:|",
    ]
    for name in ERROR_TYPES:
        lines.append(f"| {name.replace('_', ' ')} | {taxonomy['error_type_counts'][name]:,} |")
    lines.extend([
        "",
        "### Top confusions",
        "",
        "| Gold | Prediction | Count |",
        "|---|---|---:|",
    ])
    for row in taxonomy["top_confusions"]:
        lines.append(f"| {row['gold']} | {row['pred']} | {row['count']:,} |")
    lines.extend([
        "",
        "### Head and long-tail accuracy",
        "",
        "| Tier | Records | Accuracy |",
        "|---|---:|---:|",
    ])
    for name in ("head", "tail"):
        values = taxonomy["long_tail"][name]
        lines.append(f"| {name} | {values['n']:,} | {values['accuracy']:.4f} |")
    lines.extend([
        "",
        "### Accuracy by description length",
        "",
        "| Characters | Records | Accuracy |",
        "|---|---:|---:|",
    ])
    for name, values in taxonomy["description_length_buckets"].items():
        lines.append(f"| {name} | {values['n']:,} | {values['accuracy']:.4f} |")
    lines.extend([
        "",
        "### Accuracy by token length",
        "",
        "| Tokens | Records | Accuracy |",
        "|---|---:|---:|",
    ])
    for name, values in taxonomy["token_length_buckets"].items():
        lines.append(f"| {name} | {values['n']:,} | {values['accuracy']:.4f} |")
    lines.extend([
        "",
        "### KEV slice",
        "",
        "| Slice | Records | Accuracy |",
        "|---|---:|---:|",
    ])
    for name in ("kev", "non_kev"):
        values = taxonomy["kev"][name]
        lines.append(f"| {name.replace('_', '-')} | {values['n']:,} | {values['accuracy']:.4f} |")
    return "\n".join(lines) + "\n"


def analyze_single(base_path: str, test_path: str, labels_path: str) -> dict[str, Any]:
    """Build the CPU-only, base-model failure taxonomy and representative sample."""

    predictions = read_jsonl(base_path)
    test = {row["cve_id"]: row for row in read_jsonl(test_path)}
    if any(row["cve_id"] not in test for row in predictions):
        raise AssertionError("A base prediction is missing from the test data")
    with Path(labels_path).open(encoding="utf-8") as handle:
        labels = json.load(handle)
    selected = labels["selected"]
    allowed = set(selected)
    ranked = sorted(selected, key=lambda cwe: (labels["train_counts"].get(cwe, 0), cwe))
    long_tail = set(ranked[: max(1, len(selected) // 3)])

    from transformers import AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(TOKENIZER_NAME, local_files_only=True)
    sources = [test[row["cve_id"]] for row in predictions]
    token_lengths = token_lengths_for_rows(sources, tokenizer)
    joined: list[dict[str, Any]] = []
    for prediction, source, token_length in zip(predictions, sources, token_lengths):
        gold, pred = prediction["gold"], prediction.get("pred")
        kind = error_type(prediction, gold, allowed)
        pred_family = family(pred)
        joined.append({
            "prediction": prediction,
            "source": source,
            "token_length": token_length,
            "error_type": kind,
            "gold_is_long_tail": gold in long_tail,
            "overgeneralization": bool(
                kind and pred in OVERGENERAL_PREDICTIONS and family(gold) != pred_family
            ),
            "under_specific": bool(
                kind and pred in UNDER_SPECIFIC_CHILDREN
                and gold in UNDER_SPECIFIC_CHILDREN[pred]
                and family(gold) == pred_family
            ),
        })
    misses = [row for row in joined if row["error_type"] is not None]
    error_counts = Counter(row["error_type"] for row in misses)
    confusions = Counter(
        (row["prediction"]["gold"], row["prediction"].get("pred") or "INVALID")
        for row in misses
    )
    top_confusions = [
        {"gold": gold, "pred": pred, "count": count}
        for (gold, pred), count in confusions.most_common(15)
    ]
    per_class_recall = {}
    for cwe in selected:
        class_rows = [row for row in joined if row["prediction"]["gold"] == cwe]
        correct = sum(bool(row["prediction"]["exact_match"]) for row in class_rows)
        per_class_recall[cwe] = {
            "support": len(class_rows),
            "correct": correct,
            "recall": correct / len(class_rows) if class_rows else 0.0,
        }
    taxonomy = {
        "experiment": "exp_001_baseline",
        "n": len(joined),
        "correct": sum(bool(row["prediction"]["exact_match"]) for row in joined),
        "accuracy": _slice(joined)["accuracy"],
        "error_type_counts": {name: error_counts[name] for name in ERROR_TYPES},
        "per_class_recall": per_class_recall,
        "top_confusions": top_confusions,
        "long_tail": {
            "definition": "bottom third of selected labels by training-period count",
            "tail_labels": sorted(long_tail),
            "tail": _slice([row for row in joined if row["gold_is_long_tail"]]),
            "head": _slice([row for row in joined if not row["gold_is_long_tail"]]),
        },
        "description_length_buckets": _bucketed(
            joined,
            lambda row: _description_bucket(len(row["source"]["description"])),
            ("<250", "250-500", "500-1000", ">=1000"),
        ),
        "token_length_buckets": _bucketed(
            joined, lambda row: _token_bucket(row["token_length"]), ("<480", "480-1536")
        ),
        "kev": {
            "kev": _slice([row for row in joined if row["source"]["is_kev"]]),
            "non_kev": _slice([row for row in joined if not row["source"]["is_kev"]]),
        },
        "flag_counts": {
            "gold_is_long_tail": sum(row["gold_is_long_tail"] for row in misses),
            "overgeneralization": sum(row["overgeneralization"] for row in misses),
            "under_specific": sum(row["under_specific"] for row in misses),
        },
        "rules": {
            "error_type": "failure_analysis.error_type: format, allowed-label, same-family, then semantic",
            "gold_is_long_tail": "gold is in the bottom third of selected labels by training-period count",
            "overgeneralization": "prediction is CWE-200, CWE-20, or CWE-284 and gold is outside the prediction family",
            "under_specific": (
                "gold is a mapped specific sibling of a broader prediction in the same family; "
                f"mapping={{{', '.join(f'{key}: {sorted(value)}' for key, value in UNDER_SPECIFIC_CHILDREN.items())}}}"
            ),
            "token_length": "Qwen3 rendered chat prompt with thinking disabled plus completion",
        },
    }

    representatives: list[dict[str, Any]] = []
    chosen: set[str] = set()

    def add(rows: list[dict[str, Any]], maximum: int) -> None:
        added = 0
        for row in rows:
            cve_id = row["prediction"]["cve_id"]
            if cve_id in chosen:
                continue
            representatives.append(_base_failure_row(row))
            chosen.add(cve_id)
            added += 1
            if added == maximum:
                break

    for confusion in top_confusions[:8]:
        add([
            row for row in misses
            if row["prediction"]["gold"] == confusion["gold"]
            and (row["prediction"].get("pred") or "INVALID") == confusion["pred"]
        ], 5)
    add([row for row in misses if row["error_type"] in {"invalid_format", "unknown_cwe"}], 5)
    add([row for row in misses if row["gold_is_long_tail"]], 5)
    if len(representatives) > 60:
        raise AssertionError("base failure representative cap exceeded")
    taxonomy["representative_count"] = len(representatives)
    atomic_write_json("reports/base_failure_taxonomy.json", taxonomy)
    write_jsonl("reports/base_failures.jsonl", representatives)

    report_path = Path("reports/base_eval.md")
    existing = report_path.read_text(encoding="utf-8")
    marker = "\n## Failure taxonomy (Base)"
    if marker in existing:
        existing = existing.split(marker, 1)[0].rstrip() + "\n"
    report_path.write_text(existing.rstrip() + "\n\n" + _render_base_taxonomy(taxonomy), encoding="utf-8")
    return taxonomy


def analyze(base_path: str, sft_path: str, test_path: str, labels_path: str) -> dict[str, Any]:
    base_rows = read_jsonl(base_path)
    sft_rows = read_jsonl(sft_path)
    base_ids = [row["cve_id"] for row in base_rows]
    sft_ids = [row["cve_id"] for row in sft_rows]
    if base_ids != sft_ids:
        raise AssertionError("Base and SFT prediction CVE sequences differ")
    base = {row["cve_id"]: row for row in base_rows}
    sft = {row["cve_id"]: row for row in sft_rows}
    test = {row["cve_id"]: row for row in read_jsonl(test_path)}
    if set(base) != set(sft):
        raise AssertionError("Base and SFT prediction CVE sets differ")
    missing_test_ids = set(base) - set(test)
    if missing_test_ids:
        raise AssertionError(
            f"{len(missing_test_ids)} prediction IDs are missing from the test data"
        )
    with Path(labels_path).open(encoding="utf-8") as handle:
        labels = json.load(handle)
    selected = labels["selected"]
    allowed = set(selected)
    ranked = sorted(selected, key=lambda cwe: (labels["train_counts"].get(cwe, 0), cwe))
    long_tail = set(ranked[: max(1, len(selected) // 3)])
    transitions: Counter[str] = Counter()
    outcome_counts = {"base": Counter(), "sft": Counter()}
    flag_counts = {"base": Counter(), "sft": Counter()}
    failures: list[dict[str, Any]] = []
    for cve_id in base_ids:
        base_row, sft_row = base[cve_id], sft[cve_id]
        if base_row["gold"] != sft_row["gold"]:
            raise AssertionError(f"Gold mismatch for {cve_id}")
        gold = base_row["gold"]
        transition = _transition(bool(base_row["exact_match"]), bool(sft_row["exact_match"]))
        transitions[transition] += 1
        for name, row in (("base", base_row), ("sft", sft_row)):
            kind = error_type(row, gold, allowed)
            outcome_counts[name][kind or "correct"] += 1
            pred = row.get("pred")
            pred_family = family(pred)
            if kind and gold in long_tail:
                flag_counts[name]["gold_is_long_tail"] += 1
            if (
                kind
                and pred in OVERGENERAL_PREDICTIONS
                and family(gold) != pred_family
            ):
                flag_counts[name]["overgeneralization"] += 1
            if (
                kind
                and pred in UNDER_SPECIFIC_CHILDREN
                and gold in UNDER_SPECIFIC_CHILDREN[pred]
                and family(gold) == pred_family
            ):
                flag_counts[name]["under_specific"] += 1
        if not sft_row["exact_match"]:
            source = test[cve_id]
            sft_kind = error_type(sft_row, gold, allowed)
            sft_pred = sft_row.get("pred")
            failures.append({"cve_id": cve_id, "description": source["description"], "gold": gold,
                "prediction": sft_pred, "base_prediction": base_row.get("pred"),
                "sft_raw_output": sft_row["raw_output"], "base_raw_output": base_row["raw_output"],
                "transition": transition, "error_type": sft_kind,
                "gold_is_long_tail": gold in long_tail,
                "overgeneralization": bool(
                    sft_kind and sft_pred in OVERGENERAL_PREDICTIONS
                    and family(gold) != family(sft_pred)
                ),
                "under_specific": bool(
                    sft_kind and sft_pred in UNDER_SPECIFIC_CHILDREN
                    and gold in UNDER_SPECIFIC_CHILDREN[sft_pred]
                    and family(gold) == family(sft_pred)
                ),
                "is_kev": source["is_kev"]})
    failures.sort(key=lambda row: (0 if row["transition"] == "broken_by_sft" else 1, row["cve_id"]))
    write_jsonl("reports/failures.jsonl", failures)
    if len(failures) < 30:
        LOG.warning("Only %d SFT failures are available", len(failures))
    with (Path(base_path).parent / "metrics.json").open(encoding="utf-8") as handle:
        base_metrics = json.load(handle)
    with (Path(sft_path).parent / "metrics.json").open(encoding="utf-8") as handle:
        sft_metrics = json.load(handle)
    per_class = {}
    per_class_delta = {}
    for cwe in selected:
        base_values = base_metrics["per_class"][cwe]
        sft_values = sft_metrics["per_class"][cwe]
        delta = {
            metric: sft_values[metric] - base_values[metric]
            for metric in ("precision", "recall", "f1")
        }
        per_class[cwe] = {
            "support": base_values["support"],
            "base": {metric: base_values[metric] for metric in ("precision", "recall", "f1")},
            "sft": {metric: sft_values[metric] for metric in ("precision", "recall", "f1")},
            "delta": delta,
        }
        per_class_delta[cwe] = {
            "base_f1": base_values["f1"],
            "sft_f1": sft_values["f1"],
            "delta": delta["f1"],
        }

    def confusions(rows: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
        counts = Counter((row["gold"], row.get("pred") or "INVALID") for row in rows.values() if not row["exact_match"])
        return [{"gold": gold, "pred": pred, "count": count} for (gold, pred), count in counts.most_common(15)]

    from transformers import AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(TOKENIZER_NAME, local_files_only=True)
    ordered_sources = [test[cve_id] for cve_id in base_ids]
    token_lengths = dict(
        zip(base_ids, token_lengths_for_rows(ordered_sources, tokenizer), strict=True)
    )
    slices = {
        "base": _model_slices(base, test, token_lengths),
        "sft": _model_slices(sft, test, token_lengths),
    }
    tracked_confusions = {
        f"{gold}->{pred}": {
            "gold": gold,
            "pred": pred,
            "base": _confusion_count(base, gold, pred),
            "sft": _confusion_count(sft, gold, pred),
        }
        for gold, pred in TRACKED_CONFUSIONS
    }
    changes = {}
    for metric in ("f1", "recall"):
        ranked_changes = sorted(
            (
                {
                    "cwe": cwe,
                    "base": values["base"][metric],
                    "sft": values["sft"][metric],
                    "delta": values["delta"][metric],
                }
                for cwe, values in per_class.items()
            ),
            key=lambda row: (-row["delta"], row["cwe"]),
        )
        changes[metric] = {
            "largest_gains": [row for row in ranked_changes if row["delta"] > 0][:5],
            "largest_regressions": sorted(
                (row for row in ranked_changes if row["delta"] < 0),
                key=lambda row: (row["delta"], row["cwe"])
            )[:5],
        }
    tail_ids = [cve_id for cve_id, row in base.items() if row["gold"] in long_tail]
    summary = {"n_test": len(base),
        "transitions": {name: transitions[name] for name in ("both_right", "fixed_by_sft", "broken_by_sft", "both_wrong")},
        "error_type_counts": {name: {kind: values[kind] for kind in ALL_OUTCOMES} for name, values in outcome_counts.items()},
        "flag_counts": {name: {
            flag: values[flag]
            for flag in ("overgeneralization", "under_specific", "gold_is_long_tail")
        } for name, values in flag_counts.items()},
        "rules": {
            "error_type": "failure_analysis.error_type: correct, format, allowed-label, same-family, then semantic",
            "gold_is_long_tail": "gold is in the bottom third of selected labels by training-period count",
            "overgeneralization": "prediction is CWE-200, CWE-20, or CWE-284 and gold is outside the prediction family",
            "under_specific": (
                "gold is a mapped specific sibling of a broader prediction in the same family; "
                f"mapping={{{', '.join(f'{key}: {sorted(value)}' for key, value in UNDER_SPECIFIC_CHILDREN.items())}}}"
            ),
            "token_length": "Qwen3 rendered chat prompt with thinking disabled plus completion",
        },
        "per_class": per_class,
        "per_class_delta": per_class_delta,
        "largest_changes": changes,
        "top_confusions_sft": confusions(sft), "top_confusions_base": confusions(base),
        "tracked_confusions": tracked_confusions,
        "cwe_416_top_3_sinks": {"base": _gold_sinks(base, "CWE-416"), "sft": _gold_sinks(sft, "CWE-416")},
        "slices": slices,
        "prediction_distribution_concentration": {
            "base": _prediction_concentration(base),
            "sft": _prediction_concentration(sft),
        },
        "long_tail": {"base_accuracy": sum(base[cve_id]["exact_match"] for cve_id in tail_ids) / len(tail_ids) if tail_ids else 0.0,
            "sft_accuracy": sum(sft[cve_id]["exact_match"] for cve_id in tail_ids) / len(tail_ids) if tail_ids else 0.0, "n": len(tail_ids)}}
    atomic_write_json("reports/failure_summary.json", summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--sft")
    parser.add_argument("--test", required=True)
    parser.add_argument("--labels", required=True)
    parser.add_argument("--single", action="store_true")
    args = parser.parse_args()
    if args.single:
        analyze_single(args.base, args.test, args.labels)
    else:
        if not args.sft:
            parser.error("--sft is required unless --single is set")
        analyze(args.base, args.sft, args.test, args.labels)


if __name__ == "__main__":
    main()

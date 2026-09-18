"""Build machine-readable and Markdown dataset reports from JSON artifacts."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np

from security_llm.config import load_config
from security_llm.prompt import render_chat_prompt
from security_llm.utils.io import atomic_write_json, read_jsonl

SPLITS = ("train", "val", "test")
TOKENIZER_NAME = "Qwen/Qwen3-0.6B"


def _load(path: str | Path) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as handle:
        return json.load(handle)


def token_lengths_for_rows(rows: list[dict[str, Any]], tokenizer: Any) -> list[int]:
    """Tokenize rendered prompt+completion sequences in bounded CPU batches."""

    lengths: list[int] = []
    for offset in range(0, len(rows), 256):
        batch = rows[offset : offset + 256]
        texts = [
            render_chat_prompt(tokenizer, row["prompt"]) + row["completion"]
            for row in batch
        ]
        encoded = tokenizer(
            texts, add_special_tokens=False, return_length=True, truncation=False
        )
        lengths.extend(int(value) for value in encoded["length"])
    return lengths


def _token_summary(lengths: list[int]) -> dict[str, int]:
    if not lengths:
        return {"p50": 0, "p95": 0, "p99": 0, "max": 0, "n_over_480": 0, "n_over_1536": 0}
    return {
        "p50": int(np.percentile(lengths, 50)),
        "p95": int(np.percentile(lengths, 95)),
        "p99": int(np.percentile(lengths, 99)),
        "max": max(lengths),
        "n_over_480": sum(value > 480 for value in lengths),
        "n_over_1536": sum(value > 1536 for value in lengths),
    }


def compute_token_statistics(cfg: dict[str, Any]) -> dict[str, dict[str, int]]:
    from transformers import AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(TOKENIZER_NAME, local_files_only=True)
    sft_dir = Path(cfg["paths"]["sft_dir"])
    return {
        split: _token_summary(
            token_lengths_for_rows(read_jsonl(sft_dir / f"{split}.jsonl"), tokenizer)
        )
        for split in SPLITS
    }


def build_report(cfg: dict[str, Any]) -> dict[str, Any]:
    stats = _load(cfg["paths"]["stats"])
    manifest = _load(cfg["paths"]["manifest"])
    contamination = _load(cfg["paths"]["contamination"])
    labels = _load(cfg["paths"]["labels_file"])
    funnel = stats["funnel"]
    excluded_by_split = {
        name: {
            "placeholder_only": stats["label_status_by_split"][name].get("placeholder_only", 0),
            "multi_label": stats["label_status_by_split"][name].get("multi", 0),
            "not_in_selected": stats["coverage"][name]["single_label_total"]
            - stats["coverage"][name]["in_selected"],
        }
        for name in SPLITS
    }
    population_distribution = {
        name: dict(stats["split_class_distribution"][name]) for name in SPLITS
    }
    if cfg["dedup"].get("drop_val_overlap_with_test"):
        processed_dir = Path(cfg["paths"]["processed_dir"])
        train = read_jsonl(processed_dir / "train.jsonl")
        val = read_jsonl(processed_dir / "val.jsonl")
        test = read_jsonl(processed_dir / "test.jsonl")
        excluded_hashes = {
            row["description_norm_hash"] for row in train + test
        }
        kept_val = [
            row for row in val if row["description_norm_hash"] not in excluded_hashes
        ]
        population_distribution["val"] = dict(
            Counter(row["cwe_id"] for row in kept_val)
        )
    result = {
        "raw_records": funnel["raw_cves"],
        "unique_records": funnel["unique_cves"],
        "rejected": funnel["rejected"],
        "no_weakness": funnel["no_weakness"],
        "placeholder_only": funnel["placeholder_only"],
        "multi_label": funnel["multi_label"],
        "single_label": funnel["single_label"],
        "selected_class_records": manifest["population_counts"],
        "sampled_counts": manifest["counts"],
        "class_distribution": {
            "population": population_distribution,
            "sampled": manifest["class_distribution"],
        },
        "description_length_chars": stats["description_length_chars"],
        "token_length": stats.get("token_length", {}),
        "duplicate_cve_count": 0,
        "duplicate_cve_count_reason": (
            "The canonical record is keyed by CVE ID and normalization keeps the last occurrence."
        ),
        "duplicate_description_count": {
            "train_internal": contamination["train_internal_exact_duplicates"],
            "train_val": contamination["train_val_exact_text_overlap"],
            "train_test": contamination["train_test_exact_text_overlap"],
            "val_test": contamination["val_test_exact_text_overlap"],
        },
        "excluded_label_counts": excluded_by_split,
        "missing_data_counts": {
            "no_english_description": funnel["no_english_description"],
            "no_weakness": funnel["no_weakness"],
        },
        "label_policy": manifest["label_policy"],
        "split_policy": manifest["split_policy"],
        "snapshot_date": manifest["dataset_snapshot"],
        "schema_version": manifest["schema_version"],
    }
    # Keep the ranking used to mark the bottom third visible in the JSON artifact.
    tail_count = len(labels["selected"]) // 3
    result["label_tiers"] = {
        label: "tail" if label in labels["selected"][-tail_count:] else "head"
        for label in labels["selected"]
    }
    return result


def _range_text(values: list[str | None], snapshot: str) -> str:
    return f"{values[0]} to {values[1] or snapshot}"


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Dataset Report",
        "",
        f"Snapshot: `{report['snapshot_date']}`  ",
        f"Canonical schema: `{report['schema_version']}`",
        "",
        "## Record funnel",
        "",
        "| Measure | Records |",
        "|---|---:|",
    ]
    funnel_rows = (
        ("Raw API records", "raw_records"),
        ("Unique canonical records", "unique_records"),
        ("Rejected", "rejected"),
        ("No English description", None),
        ("No weakness", "no_weakness"),
        ("Placeholder only", "placeholder_only"),
        ("Multi-label", "multi_label"),
        ("Single-label", "single_label"),
    )
    lines.extend(
        f"| {label} | "
        f"{(report['missing_data_counts']['no_english_description'] if key is None else report[key]):,} |"
        for label, key in funnel_rows
    )
    lines.extend(
        [
            "",
            "## Split counts",
            "",
            "| Split | Selected-class population | SFT rows | Placeholder only | Multi-label | Single-label outside selected set |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for split in SPLITS:
        lines.append(
            f"| {split} | {report['selected_class_records'][split]:,} | "
            f"{report['sampled_counts'][split]:,} | "
            f"{report['excluded_label_counts'][split]['placeholder_only']:,} | "
            f"{report['excluded_label_counts'][split]['multi_label']:,} | "
            f"{report['excluded_label_counts'][split]['not_in_selected']:,} |"
        )
    lines.extend(
        [
            "",
            "## Class distribution",
            "",
            "Tail is the bottom third of selected labels by training-period count.",
            "",
            "| CWE | Tier | Train population | Train sample | Val population | Val sample | Test population | Test sample |",
            "|---|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    selected = report["label_policy"]["selected_labels"]
    population = report["class_distribution"]["population"]
    sampled = report["class_distribution"]["sampled"]
    for label in selected:
        values = [population[s].get(label, 0) for s in SPLITS]
        samples = [sampled[s].get(label, 0) for s in SPLITS]
        lines.append(
            f"| {label} | {report['label_tiers'][label]} | {values[0]:,} | {samples[0]:,} | "
            f"{values[1]:,} | {samples[1]:,} | {values[2]:,} | {samples[2]:,} |"
        )
    lines.extend(
        [
            "",
            "## Description lengths",
            "",
            "Character counts are for selected-class population records before SFT truncation.",
            "",
            "| Split | p50 | p90 | p99 | Maximum |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for split in SPLITS:
        lengths = report["description_length_chars"][split]
        lines.append(
            f"| {split} | {lengths['p50']:,} | {lengths['p90']:,} | "
            f"{lengths['p99']:,} | {lengths['max']:,} |"
        )
    lines.extend(
        [
            "",
            "## Token lengths",
            "",
            "Counts cover the rendered Qwen3 chat prompt plus completion, with thinking disabled.",
            "",
            "| Split | p50 | p95 | p99 | Maximum | Over 480 | Over 1,536 |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for split in SPLITS:
        lengths = report["token_length"][split]
        lines.append(
            f"| {split} | {lengths['p50']:,} | {lengths['p95']:,} | "
            f"{lengths['p99']:,} | {lengths['max']:,} | "
            f"{lengths['n_over_480']:,} | {lengths['n_over_1536']:,} |"
        )
    duplicates = report["duplicate_description_count"]
    lines.extend(
        [
            "",
            "## Duplicate and overlap checks",
            "",
            "| Check before SFT sampling | Count |",
            "|---|---:|",
            f"| Duplicate CVE IDs in canonical records | {report['duplicate_cve_count']:,} |",
            f"| Training internal normalized-description duplicates | {duplicates['train_internal']:,} |",
            f"| Train–validation normalized-description overlap | {duplicates['train_val']:,} |",
            f"| Train–test normalized-description overlap | {duplicates['train_test']:,} |",
            f"| Validation–test normalized-description overlap | {duplicates['val_test']:,} |",
            "",
            report["duplicate_cve_count_reason"],
            "The overlap check between fine-tuning splits uses exact hashes of normalized descriptions only.",
            "",
            "## Policy summary",
            "",
            "| Policy | Value |",
            "|---|---|",
            f"| Source | NVD CVE API 2.0 |",
            f"| Label set | Top {report['label_policy']['top_k']} from the training period; single-label records only |",
            f"| Minimum training records per class | {report['label_policy']['min_train_samples_per_class']:,} |",
            f"| Train | {_range_text(report['split_policy']['train'], report['snapshot_date'])} |",
            f"| Validation | {_range_text(report['split_policy']['val'], report['snapshot_date'])} |",
            f"| Test | {_range_text(report['split_policy']['test'], report['snapshot_date'])} |",
            "| Training duplicate policy | Drop normalized-description duplicates, keeping the earliest record |",
            "| Training overlap policy | Drop training records matching validation or test normalized-description hashes |",
            "| Evaluation overlap policy | Report only |",
            "",
        ]
    )
    return "\n".join(lines)


def write_report(cfg: dict[str, Any]) -> dict[str, Any]:
    stats = _load(cfg["paths"]["stats"])
    stats["token_length"] = compute_token_statistics(cfg)
    atomic_write_json(cfg["paths"]["stats"], stats)
    report = build_report(cfg)
    atomic_write_json("reports/dataset_report.json", report)
    Path("reports/dataset_report.md").write_text(render_markdown(report), encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--override", action="append", default=[])
    args = parser.parse_args()
    report = write_report(load_config(args.config, args.override))
    print(
        json.dumps(
            {
                "raw_records": report["raw_records"],
                "unique_records": report["unique_records"],
                "sampled_counts": report["sampled_counts"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

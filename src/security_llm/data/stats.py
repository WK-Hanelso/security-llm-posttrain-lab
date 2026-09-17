"""Compute dataset funnel and split statistics."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import numpy as np

from security_llm.config import load_config
from security_llm.data.split import assign_split
from security_llm.utils.io import atomic_write_json, read_jsonl

LOG = logging.getLogger(__name__)


def _percentiles(lengths: list[int]) -> dict[str, int]:
    if not lengths:
        return {"p50": 0, "p90": 0, "p99": 0, "max": 0}
    return {
        "p50": int(np.percentile(lengths, 50)),
        "p90": int(np.percentile(lengths, 90)),
        "p99": int(np.percentile(lengths, 99)),
        "max": max(lengths),
    }


def compute_stats(cfg: dict[str, Any]) -> dict[str, Any]:
    processed_dir = Path(cfg["paths"]["processed_dir"])
    rows = read_jsonl(processed_dir / "normalized.jsonl")
    with (Path(cfg["nvd"]["raw_dir"]) / "ingest_manifest.json").open(encoding="utf-8") as handle:
        ingest_manifest = json.load(handle)
    snapshot = ingest_manifest["snapshot_date"]
    funnel = {
        "raw_cves": int(ingest_manifest["total_cves"]),
        "unique_cves": len(rows),
        "rejected": sum(row["is_rejected"] for row in rows),
        "no_english_description": sum(not row["description_en"] for row in rows),
        "no_weakness": sum(row["label_status"] == "none" for row in rows),
        "placeholder_only": sum(row["label_status"] == "placeholder_only" for row in rows),
        "multi_label": sum(row["label_status"] == "multi" for row in rows),
        "single_label": sum(row["label_status"] == "single" for row in rows),
    }
    per_year: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "single_label": 0})
    train_frequency: Counter[str] = Counter()
    eligible_by_split: dict[str, list[dict[str, Any]]] = {name: [] for name in ("train", "val", "test")}
    for row in rows:
        year = row["published"][:4]
        per_year[year]["total"] += 1
        if row["label_status"] == "single":
            per_year[year]["single_label"] += 1
        eligible = not row["is_rejected"] and bool(row["description_en"]) and row["label_status"] == "single"
        if not eligible:
            continue
        split_name = assign_split(row["published"], cfg["split"], snapshot)
        if split_name:
            eligible_by_split[split_name].append(row)
            if split_name == "train":
                train_frequency[row["cwe_id"]] += 1
    labels_file = Path(cfg["paths"]["labels_file"])
    selected: list[str] = []
    if labels_file.exists():
        with labels_file.open(encoding="utf-8") as handle:
            selected = json.load(handle)["selected"]
    coverage: dict[str, dict[str, Any]] = {}
    split_distribution: dict[str, dict[str, int]] = {}
    description_lengths: dict[str, dict[str, int]] = {}
    kev: dict[str, int] = {}
    for name, population in eligible_by_split.items():
        in_selected = [row for row in population if row["cwe_id"] in selected]
        coverage[name] = {
            "single_label_total": len(population),
            "in_selected": len(in_selected),
            "fraction": len(in_selected) / len(population) if population else 0.0,
        }
        split_file = processed_dir / f"{name}.jsonl"
        split_rows = read_jsonl(split_file) if split_file.exists() else in_selected
        split_distribution[name] = dict(Counter(row["cwe_id"] for row in split_rows))
        description_lengths[name] = _percentiles([len(row["description_en"]) for row in split_rows])
        kev[name] = sum(row["is_kev"] for row in split_rows)
    top50 = dict(sorted(train_frequency.items(), key=lambda item: (-item[1], item[0]))[:50])
    result = {
        "snapshot_date": snapshot,
        "funnel": funnel,
        "per_year": dict(sorted(per_year.items())),
        "train_period_cwe_frequency_top50": top50,
        "selected_labels": selected,
        "coverage": coverage,
        "split_class_distribution": split_distribution,
        "description_length_chars": description_lengths,
        "kev": kev,
    }
    atomic_write_json(cfg["paths"]["stats"], result)
    LOG.info("funnel %s", json.dumps(funnel, sort_keys=True))
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--override", action="append", default=[])
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)
    compute_stats(load_config(args.config, args.override))


if __name__ == "__main__":
    main()


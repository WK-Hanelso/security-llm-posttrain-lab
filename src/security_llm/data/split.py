"""Temporal split creation and train-only label selection."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from security_llm.config import load_config
from security_llm.cwe_names import CWE_NAMES
from security_llm.utils.io import atomic_write_json, read_jsonl, write_jsonl

LOG = logging.getLogger(__name__)


def assign_split(
    published: str, split_cfg: dict[str, list[str | None]], snapshot: str
) -> str | None:
    for name in ("train", "val", "test"):
        low, high = split_cfg[name]
        high = high or snapshot
        if low <= published <= high:
            return name
    return None


def select_labels(
    train_records: list[dict[str, Any]], top_k: int, min_count: int
) -> tuple[list[str], dict[str, int]]:
    counts = Counter(row["cwe_id"] for row in train_records)
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    selected = [cwe for cwe, count in ranked[:top_k] if count >= min_count]
    return selected, dict(counts)


def create_splits(cfg: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    processed_dir = Path(cfg["paths"]["processed_dir"])
    records = read_jsonl(processed_dir / "normalized.jsonl")
    with (Path(cfg["nvd"]["raw_dir"]) / "ingest_manifest.json").open(encoding="utf-8") as handle:
        snapshot = json.load(handle)["snapshot_date"]
    eligible: list[dict[str, Any]] = []
    for record in records:
        if record["is_rejected"] or not record["description_en"] or record["label_status"] != "single":
            continue
        split_name = assign_split(record["published"], cfg["split"], snapshot)
        if split_name is not None:
            eligible.append({**record, "split": split_name})
    train_population = [row for row in eligible if row["split"] == "train"]
    selected, counts = select_labels(
        train_population,
        int(cfg["labels"]["top_k"]),
        int(cfg["labels"]["min_train_samples_per_class"]),
    )
    if len(selected) < 2:
        raise AssertionError(f"At least two labels are required; selected {selected}")
    missing = [cwe for cwe in selected if cwe not in CWE_NAMES]
    if missing:
        raise KeyError(f"Missing CWE names: {missing}")
    output: dict[str, list[dict[str, Any]]] = {}
    for name in ("train", "val", "test"):
        output[name] = [
            row for row in eligible if row["split"] == name and row["cwe_id"] in selected
        ]
        write_jsonl(processed_dir / f"{name}.jsonl", output[name])
    labels = {
        "selected": selected,
        "train_counts": {cwe: counts.get(cwe, 0) for cwe in selected},
        "top_k_requested": int(cfg["labels"]["top_k"]),
        "top_k_effective": len(selected),
        "min_train_samples_per_class": int(cfg["labels"]["min_train_samples_per_class"]),
        "train_period": cfg["split"]["train"],
        "names": {cwe: CWE_NAMES[cwe] for cwe in selected},
    }
    atomic_write_json(cfg["paths"]["labels_file"], labels)
    LOG.info("selected labels: %s", selected)
    LOG.info("split counts: %s", {name: len(rows) for name, rows in output.items()})
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--override", action="append", default=[])
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)
    create_splits(load_config(args.config, args.override))


if __name__ == "__main__":
    main()


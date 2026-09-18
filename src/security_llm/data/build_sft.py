"""Build sampled prompt/completion JSONL datasets and their manifest."""

from __future__ import annotations

import argparse
import json
import logging
import random
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from security_llm.config import load_config
from security_llm.adapters.cwe_instruction import (
    build_user_prompt,
    prompt_template_sha256,
    serialize_label,
)
from security_llm.data.dedup import drop_internal_duplicates
from security_llm.data.manifest import v2_fields
from security_llm.utils.io import atomic_write_json, read_jsonl, sha256_file, write_jsonl

LOG = logging.getLogger(__name__)


def _git_commit() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def sample_records(
    rows: list[dict[str, Any]],
    maximum: int | None,
    sampling: str,
    rng: random.Random,
    balanced_max_per_class: int | None = None,
) -> list[dict[str, Any]]:
    if sampling == "balanced":
        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            groups[row["cwe_id"]].append(row)
        cap = balanced_max_per_class or max(len(group) for group in groups.values())
        result: list[dict[str, Any]] = []
        for cwe in sorted(groups):
            group = groups[cwe]
            result.extend(rng.sample(group, min(cap, len(group))))
        rng.shuffle(result)
        if maximum is not None and len(result) > maximum:
            result = rng.sample(result, maximum)
        return result
    if sampling != "natural":
        raise ValueError(f"Unknown sampling strategy: {sampling}")
    result = list(rows) if maximum is None or maximum >= len(rows) else rng.sample(rows, maximum)
    rng.shuffle(result)
    return result


def to_sft_row(
    record: dict[str, Any], selected: list[str], max_chars: int
) -> dict[str, Any]:
    description = record["description_en"][:max_chars]
    return {
        "cve_id": record["cve_id"],
        "cwe_id": record["cwe_id"],
        "published": record["published"],
        "description": description,
        "truncated": len(record["description_en"]) > max_chars,
        "prompt": build_user_prompt(description, selected),
        "completion": serialize_label(record["cwe_id"]),
        "is_kev": record["is_kev"],
        "split": record["split"],
    }


def build(cfg: dict[str, Any], config_path: str | Path) -> dict[str, Any]:
    processed_dir = Path(cfg["paths"]["processed_dir"])
    sft_dir = Path(cfg["paths"]["sft_dir"])
    with Path(cfg["paths"]["labels_file"]).open(encoding="utf-8") as handle:
        labels = json.load(handle)
    selected = labels["selected"]
    populations = {name: read_jsonl(processed_dir / f"{name}.jsonl") for name in ("train", "val", "test")}
    train = populations["train"]
    duplicate_count = 0
    overlap_count = 0
    if cfg["dedup"]["drop_train_exact_duplicates"]:
        train, duplicate_count = drop_internal_duplicates(train)
    if cfg["dedup"]["drop_train_overlap_with_eval"]:
        eval_hashes = {
            row["description_norm_hash"] for row in populations["val"] + populations["test"]
        }
        before = len(train)
        train = [row for row in train if row["description_norm_hash"] not in eval_hashes]
        overlap_count = before - len(train)
    deduped = {"train": train, "val": populations["val"], "test": populations["test"]}
    rng = random.Random(int(cfg["seed"]))
    sampled: dict[str, list[dict[str, Any]]] = {}
    sampled["train"] = sample_records(
        deduped["train"], cfg["sft"]["train_max_samples"], cfg["sft"]["sampling"], rng,
        cfg["sft"].get("balanced_max_per_class"),
    )
    sampled["val"] = sample_records(deduped["val"], cfg["sft"]["val_max_samples"], "natural", rng)
    sampled["test"] = sample_records(deduped["test"], cfg["sft"]["test_max_samples"], "natural", rng)
    files: dict[str, dict[str, Any]] = {}
    class_distribution: dict[str, dict[str, int]] = {}
    for name in ("train", "val", "test"):
        output_path = sft_dir / f"{name}.jsonl"
        output_rows = [
            to_sft_row(row, selected, int(cfg["sft"]["max_description_chars"]))
            for row in sampled[name]
        ]
        write_jsonl(output_path, output_rows)
        files[name] = {"path": str(output_path), "rows": len(output_rows), "sha256": sha256_file(output_path)}
        class_distribution[name] = dict(Counter(row["cwe_id"] for row in output_rows))
    with (Path(cfg["nvd"]["raw_dir"]) / "ingest_manifest.json").open(encoding="utf-8") as handle:
        snapshot = json.load(handle)["snapshot_date"]
    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "git_commit": _git_commit(),
        "dataset_snapshot": snapshot,
        "data_config_sha256": sha256_file(config_path),
        "prompt_template_sha256": prompt_template_sha256(selected),
        "labels": selected,
        "files": files,
        "counts": {name: len(sampled[name]) for name in sampled},
        "population_counts": {name: len(populations[name]) for name in populations},
        "class_distribution": class_distribution,
        "sampling": cfg["sft"],
        "dedup": {
            "train_exact_duplicates_dropped": duplicate_count,
            "train_overlap_with_eval_dropped": overlap_count,
        },
    }
    manifest.update(v2_fields(cfg, snapshot, selected, files, manifest["counts"]))
    atomic_write_json(cfg["paths"]["manifest"], manifest)
    LOG.info("SFT counts: %s", manifest["counts"])
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--override", action="append", default=[])
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)
    build(load_config(args.config, args.override), args.config)


if __name__ == "__main__":
    main()

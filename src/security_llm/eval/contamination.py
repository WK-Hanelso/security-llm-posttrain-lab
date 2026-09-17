"""Measure exact CVE-ID and normalized-description overlap."""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
from typing import Any

from security_llm.config import load_config
from security_llm.data.dedup import find_overlap, text_hash
from security_llm.utils.io import atomic_write_json, read_jsonl


def _sft_rows(path: Path) -> list[dict[str, Any]]:
    rows = read_jsonl(path)
    return [{**row, "description_norm_hash": text_hash(row["description"])} for row in rows]


def compute_contamination(cfg: dict[str, Any]) -> dict[str, Any]:
    processed = Path(cfg["paths"]["processed_dir"])
    sft = Path(cfg["paths"]["sft_dir"])
    train, val, test = (read_jsonl(processed / f"{name}.jsonl") for name in ("train", "val", "test"))
    train_val_id = find_overlap(train, val, "cve_id")
    train_test_id = find_overlap(train, test, "cve_id")
    train_val_text = find_overlap(train, val, "description_norm_hash")
    train_test_text = find_overlap(train, test, "description_norm_hash")
    val_test_text = find_overlap(val, test, "description_norm_hash")
    hash_counts = Counter(row["description_norm_hash"] for row in train)
    internal_duplicates = sum(count - 1 for count in hash_counts.values() if count > 1)
    sft_train, sft_val, sft_test = (_sft_rows(sft / f"{name}.jsonl") for name in ("train", "val", "test"))
    result = {
        "computed_on": "data/processed/{train,val,test}.jsonl (before sampling) and data/sft/*.jsonl (after)",
        "train_val_cve_id_overlap": len(train_val_id),
        "train_test_cve_id_overlap": len(train_test_id),
        "train_val_exact_text_overlap": len(train_val_text),
        "train_test_exact_text_overlap": len(train_test_text),
        "val_test_exact_text_overlap": len(val_test_text),
        "train_internal_exact_duplicates": internal_duplicates,
        "examples": {"train_test_exact_text_overlap": train_test_text[:20]},
        "policy": "train records overlapping val/test by normalized-text hash were dropped before SFT build",
        "post_build": {
            "train_test_exact_text_overlap": len(find_overlap(sft_train, sft_test, "description_norm_hash")),
            "train_val_exact_text_overlap": len(find_overlap(sft_train, sft_val, "description_norm_hash")),
        },
        "limitations": "Exact-hash only. Pretraining-corpus contamination of the base model cannot be verified.",
    }
    atomic_write_json(cfg["paths"]["contamination"], result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--override", action="append", default=[])
    args = parser.parse_args()
    compute_contamination(load_config(args.config, args.override))


if __name__ == "__main__":
    main()

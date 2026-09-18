"""Fail-fast invariants for overlaps between SFT or processed splits."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from security_llm.config import load_config
from security_llm.data.dedup import text_hash
from security_llm.utils.io import read_jsonl

SPLIT_PAIRS = (("train", "val"), ("train", "test"), ("val", "test"))


def _row_hash(row: dict[str, Any]) -> str:
    stored = row.get("description_norm_hash")
    if stored is not None:
        return str(stored)
    if "description" not in row:
        raise ValueError("row has neither description_norm_hash nor description")
    return text_hash(str(row["description"]))


def _index(rows: list[dict[str, Any]], key: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for row in rows:
        value = str(row["cve_id"]) if key == "cve_id" else _row_hash(row)
        result.setdefault(value, []).append(str(row["cve_id"]))
    return result


def check_split_invariants(
    train: list[dict[str, Any]],
    val: list[dict[str, Any]],
    test: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return exact ID/text-hash overlap counts without exposing descriptions."""

    splits = {"train": train, "val": val, "test": test}
    pairs: dict[str, dict[str, Any]] = {}
    for left_name, right_name in SPLIT_PAIRS:
        left_ids = _index(splits[left_name], "cve_id")
        right_ids = _index(splits[right_name], "cve_id")
        left_hashes = _index(splits[left_name], "text_hash")
        right_hashes = _index(splits[right_name], "text_hash")
        common_ids = sorted(set(left_ids) & set(right_ids))
        common_hashes = sorted(set(left_hashes) & set(right_hashes))
        examples = [
            [left_hashes[value][0], right_hashes[value][0], value[:12]]
            for value in common_hashes[:5]
        ]
        pairs[f"{left_name}_{right_name}"] = {
            "cve_id": len(common_ids),
            "text_hash": len(common_hashes),
            "examples": examples,
        }
    return {
        "pairs": pairs,
        "ok": all(
            values[metric] == 0
            for values in pairs.values()
            for metric in ("cve_id", "text_hash")
        ),
    }


def load_stage_rows(cfg: dict[str, Any], stage: str) -> dict[str, list[dict[str, Any]]]:
    root = Path(cfg["paths"]["sft_dir" if stage == "sft" else "processed_dir"])
    return {name: read_jsonl(root / f"{name}.jsonl") for name in ("train", "val", "test")}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--stage", choices=("sft", "processed"), default="sft")
    parser.add_argument("--override", action="append", default=[])
    args = parser.parse_args()
    rows = load_stage_rows(load_config(args.config, args.override), args.stage)
    result = check_split_invariants(rows["train"], rows["val"], rows["test"])
    print(json.dumps(result, indent=2))
    if not result["ok"]:
        sys.exit(1)


if __name__ == "__main__":
    main()

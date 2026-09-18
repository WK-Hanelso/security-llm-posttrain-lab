"""Build sampled prompt/completion JSONL datasets and their manifest."""

from __future__ import annotations

import argparse
import json
import logging
import random
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from security_llm.config import load_config
from security_llm.adapters.cwe_instruction import (
    build_user_prompt,
    prompt_template_sha256,
    serialize_label,
)
from security_llm.data.dedup import drop_internal_duplicates
from security_llm.data.guard import check_split_invariants
from security_llm.data.manifest import dataset_hash, v2_fields
from security_llm.utils.io import atomic_write_json, read_jsonl, sha256_file, write_jsonl

LOG = logging.getLogger(__name__)
EXPECTED_FROZEN_HASHES = {
    "train": "1887fbb32b6af37f12e325656d799570c3474dc390dcca31477b7bf8a7d9f734",
    "test": "bb7c6952067ff5fc1cb8bcd210e673edae2b2bd8b136ccc356adeac7cb3b5801",
}
CHANGELOG_REASON = (
    "val rows overlapping test/train by normalized text dropped to satisfy the "
    "post-dedup invariant; train and test unchanged"
)


class SplitInvariantError(ValueError):
    def __init__(self, result: dict[str, Any]):
        super().__init__("post-dedup split invariant failed")
        self.result = result


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


def _drop_val_overlaps(
    populations: dict[str, list[dict[str, Any]]], enabled: bool
) -> tuple[list[dict[str, Any]], int]:
    if not enabled:
        return populations["val"], 0
    eval_hashes = {
        row["description_norm_hash"]
        for row in populations["train"] + populations["test"]
    }
    kept = [
        row for row in populations["val"]
        if row["description_norm_hash"] not in eval_hashes
    ]
    return kept, len(populations["val"]) - len(kept)


def _guard_or_raise(rows: dict[str, list[dict[str, Any]]]) -> None:
    result = check_split_invariants(rows["train"], rows["val"], rows["test"])
    if not result["ok"]:
        raise SplitInvariantError(result)


def _output_rows(
    sampled: dict[str, list[dict[str, Any]]], selected: list[str], max_chars: int
) -> dict[str, list[dict[str, Any]]]:
    return {
        name: [to_sft_row(row, selected, max_chars) for row in sampled[name]]
        for name in ("train", "val", "test")
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
    val, val_overlap_count = _drop_val_overlaps(
        populations, bool(cfg["dedup"].get("drop_val_overlap_with_test", False))
    )
    deduped = {"train": train, "val": val, "test": populations["test"]}
    seed = int(cfg["seed"])
    sampled: dict[str, list[dict[str, Any]]] = {}
    sampled["train"] = sample_records(
        deduped["train"], cfg["sft"]["train_max_samples"], cfg["sft"]["sampling"], random.Random(seed),
        cfg["sft"].get("balanced_max_per_class"),
    )
    sampled["val"] = sample_records(
        deduped["val"], cfg["sft"]["val_max_samples"], "natural", random.Random(seed)
    )
    sampled["test"] = sample_records(
        deduped["test"], cfg["sft"]["test_max_samples"], "natural", random.Random(seed)
    )
    output_rows = _output_rows(
        sampled, selected, int(cfg["sft"]["max_description_chars"])
    )
    _guard_or_raise(output_rows)
    files: dict[str, dict[str, Any]] = {}
    class_distribution: dict[str, dict[str, int]] = {}
    for name in ("train", "val", "test"):
        output_path = sft_dir / f"{name}.jsonl"
        write_jsonl(output_path, output_rows[name])
        files[name] = {"path": str(output_path), "rows": len(output_rows[name]), "sha256": sha256_file(output_path)}
        class_distribution[name] = dict(Counter(row["cwe_id"] for row in output_rows[name]))
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
        "population_counts": {
            "train": len(populations["train"]),
            "val": len(deduped["val"]),
            "test": len(populations["test"]),
        },
        "class_distribution": class_distribution,
        "sampling": cfg["sft"],
        "dedup": {
            "train_exact_duplicates_dropped": duplicate_count,
            "train_overlap_with_eval_dropped": overlap_count,
            "val_overlap_with_eval_dropped": val_overlap_count,
        },
        "dataset_version": "1.1",
        "changelog": [{"version": "1.1", "date": date.today().isoformat(), "reason": CHANGELOG_REASON}],
    }
    manifest.update(v2_fields(cfg, snapshot, selected, files, manifest["counts"]))
    atomic_write_json(cfg["paths"]["manifest"], manifest)
    LOG.info("SFT counts: %s", manifest["counts"])
    return manifest


def rebuild_val_only(cfg: dict[str, Any], config_path: str | Path) -> dict[str, Any]:
    """Rewrite only validation data and update the v1.1 manifest."""

    manifest_path = Path(cfg["paths"]["manifest"])
    with manifest_path.open(encoding="utf-8") as handle:
        manifest = json.load(handle)
    sft_dir = Path(cfg["paths"]["sft_dir"])
    before_hashes = {name: sha256_file(sft_dir / f"{name}.jsonl") for name in ("train", "val", "test")}
    for name, expected in EXPECTED_FROZEN_HASHES.items():
        if before_hashes[name] != expected or manifest["files"][name]["sha256"] != expected:
            raise AssertionError(
                f"{name} is not the frozen v1.0 artifact: disk={before_hashes[name]} "
                f"manifest={manifest['files'][name]['sha256']} expected={expected}"
            )

    processed_dir = Path(cfg["paths"]["processed_dir"])
    populations = {
        name: read_jsonl(processed_dir / f"{name}.jsonl")
        for name in ("train", "val", "test")
    }
    val, dropped = _drop_val_overlaps(populations, True)
    sampled_val = sample_records(
        val, cfg["sft"]["val_max_samples"], "natural", random.Random(int(cfg["seed"]))
    )
    with Path(cfg["paths"]["labels_file"]).open(encoding="utf-8") as handle:
        selected = json.load(handle)["selected"]
    val_rows = [
        to_sft_row(row, selected, int(cfg["sft"]["max_description_chars"]))
        for row in sampled_val
    ]
    guarded = {
        "train": read_jsonl(sft_dir / "train.jsonl"),
        "val": val_rows,
        "test": read_jsonl(sft_dir / "test.jsonl"),
    }
    _guard_or_raise(guarded)

    val_path = sft_dir / "val.jsonl"
    write_jsonl(val_path, val_rows)
    after_hashes = {name: sha256_file(sft_dir / f"{name}.jsonl") for name in ("train", "val", "test")}
    for name in ("train", "test"):
        if after_hashes[name] != before_hashes[name] or after_hashes[name] != EXPECTED_FROZEN_HASHES[name]:
            raise AssertionError(f"{name} changed during --rebuild-val-only")

    manifest["files"]["val"] = {
        "path": str(val_path), "rows": len(val_rows), "sha256": after_hashes["val"]
    }
    manifest["counts"]["val"] = len(val_rows)
    manifest["population_counts"]["val"] = len(val)
    manifest["class_distribution"]["val"] = dict(Counter(row["cwe_id"] for row in val_rows))
    manifest["dedup"]["val_overlap_with_eval_dropped"] = dropped
    manifest["data_config_sha256"] = sha256_file(config_path)
    manifest["dataset_version"] = "1.1"
    changelog = [entry for entry in manifest.get("changelog", []) if entry.get("version") != "1.1"]
    changelog.append({"version": "1.1", "date": date.today().isoformat(), "reason": CHANGELOG_REASON})
    manifest["changelog"] = changelog
    manifest["validation_count"] = len(val_rows)
    manifest["dataset_hash"] = dataset_hash(manifest["files"])
    atomic_write_json(manifest_path, manifest)
    return {"manifest": manifest, "before_hashes": before_hashes, "after_hashes": after_hashes}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--override", action="append", default=[])
    parser.add_argument("--rebuild-val-only", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)
    cfg = load_config(args.config, args.override)
    try:
        if args.rebuild_val_only:
            result = rebuild_val_only(cfg, args.config)
            print(json.dumps({
                "before_hashes": result["before_hashes"],
                "after_hashes": result["after_hashes"],
                "dataset_version": result["manifest"]["dataset_version"],
                "val_population": result["manifest"]["population_counts"]["val"],
                "val_rows": result["manifest"]["counts"]["val"],
            }, indent=2))
        else:
            build(cfg, args.config)
    except SplitInvariantError as exc:
        print(json.dumps(exc.result, indent=2), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

"""Dataset manifest v2 construction and one-off upgrade support."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from security_llm.config import load_config
from security_llm.data.schema import SCHEMA_VERSION
from security_llm.utils.io import atomic_write_json, sha256_file

SPLIT_ORDER = ("train", "val", "test")


def dataset_hash(files: dict[str, dict[str, Any]]) -> str:
    """Hash the concatenated train/val/test file digests in fixed order."""

    concatenated = "".join(files[name]["sha256"] for name in SPLIT_ORDER)
    return hashlib.sha256(concatenated.encode("ascii")).hexdigest()


def v2_fields(
    cfg: dict[str, Any], snapshot: str, selected_labels: list[str], files: dict[str, dict[str, Any]],
    counts: dict[str, int],
) -> dict[str, Any]:
    """Return the v2 additions shared by builds and upgrades."""

    return {
        "schema_version": SCHEMA_VERSION,
        "source": "NVD CVE API 2.0",
        "snapshot_time": snapshot,
        "label_policy": {
            "placeholder_cwes_excluded": cfg["filter"]["placeholder_cwes"],
            "single_label_only": cfg["filter"]["single_label_only"],
            "top_k": cfg["labels"]["top_k"],
            "min_train_samples_per_class": cfg["labels"]["min_train_samples_per_class"],
            "label_selection_period": cfg["split"]["train"],
            "selected_labels": selected_labels,
        },
        "split_policy": {
            "type": "temporal_by_published",
            "train": cfg["split"]["train"],
            "val": cfg["split"]["val"],
            "test": cfg["split"]["test"],
            "snapshot_date": snapshot,
        },
        "dedup_policy": {
            "train_exact_duplicates": "drop_keep_earliest",
            "train_overlap_with_eval": "drop",
            "eval_overlap": "report_only",
        },
        "dataset_hash": dataset_hash(files),
        "validation_count": counts["val"],
    }


def verify_files(manifest: dict[str, Any]) -> None:
    """Raise when a recorded SFT digest or row count differs from disk."""

    for name in SPLIT_ORDER:
        entry = manifest["files"][name]
        path = Path(entry["path"])
        actual_hash = sha256_file(path)
        if actual_hash != entry["sha256"]:
            raise ValueError(
                f"{name} sha256 mismatch: manifest={entry['sha256']} disk={actual_hash}"
            )
        with path.open(encoding="utf-8") as handle:
            actual_rows = sum(1 for line in handle if line.strip())
        if actual_rows != entry["rows"] or actual_rows != manifest["counts"][name]:
            raise ValueError(
                f"{name} row-count mismatch: file={actual_rows} "
                f"entry={entry['rows']} counts={manifest['counts'][name]}"
            )


def upgrade(cfg: dict[str, Any]) -> dict[str, Any]:
    """Verify and upgrade an existing v1 manifest without rebuilding data."""

    path = Path(cfg["paths"]["manifest"])
    with path.open(encoding="utf-8") as handle:
        manifest = json.load(handle)
    verify_files(manifest)
    manifest.update(
        v2_fields(
            cfg,
            manifest["dataset_snapshot"],
            manifest["labels"],
            manifest["files"],
            manifest["counts"],
        )
    )
    atomic_write_json(path, manifest)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--upgrade", action="store_true")
    parser.add_argument("--override", action="append", default=[])
    args = parser.parse_args()
    if not args.upgrade:
        parser.error("--upgrade is required")
    cfg = load_config(args.config, args.override)
    result = upgrade(cfg)
    print(
        json.dumps(
            {
                "manifest": str(cfg["paths"]["manifest"]),
                "verified_files": list(SPLIT_ORDER),
                "dataset_hash": result["dataset_hash"],
                "schema_version": result["schema_version"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

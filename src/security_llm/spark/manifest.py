"""Manifest generation for Spark Track A artifacts."""

from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pyspark.sql import DataFrame

from security_llm.utils.io import atomic_write_json, sha256_file


def _git_commit() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def write_manifest(
    final: DataFrame,
    output_root: str | Path,
    manifest_path: str | Path,
    config_path: str | Path,
    reference_manifest: str | Path,
    snapshot: str,
    labels: list[str],
    split_counts: dict[str, int],
    exact_duplicates: int,
    overlap: dict[str, Any],
    master: str,
    shuffle_partitions: int,
    spark_version: str,
) -> dict[str, Any]:
    """Write the §4 content manifest after all Parquet outputs are durable."""

    root = Path(output_root)
    partition_rows = final.groupBy("split", "published_year").count().collect()
    partitions = [
        {
            "split": str(row["split"]),
            "published_year": str(row["published_year"]),
            "rows": int(row["count"]),
        }
        for row in sorted(partition_rows, key=lambda item: (item["split"], item["published_year"]))
    ]
    files = [
        {
            "path": path.relative_to(Path.cwd()).as_posix()
            if path.is_relative_to(Path.cwd())
            else path.as_posix(),
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in sorted(root.rglob("*.parquet"))
    ]
    post_counts = {
        str(row["split"]): int(row["count"])
        for row in final.groupBy("split").count().collect()
    }
    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "git_commit": _git_commit(),
        "dataset_snapshot": snapshot,
        "data_config_sha256": sha256_file(config_path),
        "labels": labels,
        "partitions": partitions,
        "files": files,
        "counts": {
            "pre_dedup": split_counts,
            "post_exact_dedup": {
                **split_counts,
                "train": split_counts["train"] - exact_duplicates,
            },
            "post_overlap": post_counts,
        },
        "dedup": {
            "train_exact_duplicates_dropped": exact_duplicates,
            "train_overlap_with_eval_dropped": overlap["train_overlap_with_eval_dropped"],
            "val_overlap_with_eval_dropped": overlap["val_overlap_with_eval_dropped"],
        },
        "spark": {
            "master": master,
            "spark.sql.shuffle.partitions": shuffle_partitions,
            "version": spark_version,
        },
        "reference_manifest_sha256": sha256_file(reference_manifest),
    }
    atomic_write_json(manifest_path, manifest)
    return manifest

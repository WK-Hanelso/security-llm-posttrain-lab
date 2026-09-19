"""Temporal split assignment and train-only label selection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pyspark.sql import Column, DataFrame, functions as F
from pyspark.storagelevel import StorageLevel

from security_llm.cwe_names import CWE_NAMES
from security_llm.utils.io import atomic_write_json


def split_column(split_cfg: dict[str, list[str | None]], snapshot: str) -> Column:
    """Build the inclusive temporal assignment expression."""

    expression: Column | None = None
    for name in ("train", "val", "test"):
        low, high = split_cfg[name]
        condition = F.col("published").between(low, high or snapshot)
        expression = F.when(condition, F.lit(name)) if expression is None else expression.when(condition, name)
    assert expression is not None
    return expression


def select_labels_from_df(
    train: DataFrame, top_k: int, min_count: int
) -> tuple[list[str], dict[str, int]]:
    """Rank labels exactly as the reference: descending count, then CWE ID."""

    ranked = train.groupBy("cwe_id").count().orderBy(F.desc("count"), F.asc("cwe_id"))
    top = ranked.limit(top_k).collect()
    selected = [str(row["cwe_id"]) for row in top if int(row["count"]) >= min_count]
    counts = {str(row["cwe_id"]): int(row["count"]) for row in top}
    return selected, counts


def create_splits(
    normalized: DataFrame,
    cfg: dict[str, Any],
    snapshot: str,
    output_root: str | Path,
    reference_manifest: str | Path = "manifests/dataset_manifest.json",
) -> tuple[DataFrame, list[str], dict[str, int]]:
    """Run §3.2 and write selected populations and label metadata."""

    eligible = (
        normalized.where(~F.col("is_rejected"))
        .where(F.length("description_en") > 0)
        .where(F.col("label_status") == "single")
        .withColumn("split", split_column(cfg["split"], snapshot))
        .where(F.col("split").isNotNull())
    )
    train = eligible.where(F.col("split") == "train")
    selected, top_counts = select_labels_from_df(
        train,
        int(cfg["labels"]["top_k"]),
        int(cfg["labels"]["min_train_samples_per_class"]),
    )
    with Path(reference_manifest).open(encoding="utf-8") as handle:
        expected = json.load(handle)["labels"]
    if selected != expected:
        raise AssertionError(f"Selected labels differ from reference: actual={selected} expected={expected}")
    missing = [cwe for cwe in selected if cwe not in CWE_NAMES]
    if missing:
        raise KeyError(f"Missing CWE names: {missing}")

    splits = (
        eligible.where(F.col("cwe_id").isin(selected))
        .persist(StorageLevel.MEMORY_AND_DISK)
    )
    count_rows = splits.groupBy("split").count().collect()
    counts = {str(row["split"]): int(row["count"]) for row in count_rows}
    for name in ("train", "val", "test"):
        counts.setdefault(name, 0)

    root = Path(output_root)
    splits.write.mode("overwrite").partitionBy("split", "published_year").parquet(str(root / "splits"))
    labels = {
        "selected": selected,
        "train_counts": {cwe: top_counts[cwe] for cwe in selected},
        "top_k_requested": int(cfg["labels"]["top_k"]),
        "top_k_effective": len(selected),
        "min_train_samples_per_class": int(cfg["labels"]["min_train_samples_per_class"]),
        "train_period": cfg["split"]["train"],
        "names": {cwe: CWE_NAMES[cwe] for cwe in selected},
    }
    atomic_write_json(root / "labels.json", labels)
    return splits, selected, counts

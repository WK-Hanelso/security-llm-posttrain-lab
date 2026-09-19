"""Deterministic exact-text deduplication."""

from __future__ import annotations

from pyspark.sql import DataFrame, Window, functions as F
from pyspark.storagelevel import StorageLevel


def keep_first_train(train: DataFrame) -> DataFrame:
    """Keep the earliest `(published, cve_id)` for each normalized-text hash."""

    window = Window.partitionBy("description_norm_hash").orderBy("published", "cve_id")
    return (
        train.withColumn("_rn", F.row_number().over(window))
        .where(F.col("_rn") == 1)
        .drop("_rn")
    )


def deduplicate_train(splits: DataFrame) -> tuple[DataFrame, int]:
    """Apply keep-first only to train and retain val/test unchanged."""

    train = splits.where(F.col("split") == "train")
    before = train.count()
    kept_train = keep_first_train(train)
    combined = kept_train.unionByName(splits.where(F.col("split") != "train")).persist(
        StorageLevel.MEMORY_AND_DISK
    )
    after = combined.where(F.col("split") == "train").count()
    return combined, before - after

"""Cross-split exact overlap removal and fail-fast invariant."""

from __future__ import annotations

from itertools import combinations
from pathlib import Path
from typing import Any

from pyspark.sql import DataFrame, functions as F
from pyspark.storagelevel import StorageLevel

from security_llm.utils.io import atomic_write_json


def _hashes(*frames: DataFrame) -> DataFrame:
    result = frames[0].select("description_norm_hash")
    for frame in frames[1:]:
        result = result.unionByName(frame.select("description_norm_hash"))
    return result.distinct()


def _overlap_count(left: DataFrame, right: DataFrame, key: str) -> int:
    right_keys = right.select(key).distinct()
    return left.join(right_keys, key, "left_semi").count()


def enforce_overlap_invariant(
    exact: DataFrame,
    pre_dedup: DataFrame,
    output_root: str | Path,
    report_path: str | Path,
) -> tuple[DataFrame, dict[str, Any]]:
    """Run §3.4, preserving the reference's pre-dedup-train asymmetry."""

    exact_train = exact.where(F.col("split") == "train")
    pre_train = pre_dedup.where(F.col("split") == "train")
    val = pre_dedup.where(F.col("split") == "val")
    test = pre_dedup.where(F.col("split") == "test")

    train = exact_train.join(_hashes(val, test), "description_norm_hash", "left_anti")
    # Intentionally uses the pre-dedup train population, matching _drop_val_overlaps.
    kept_val = val.join(_hashes(pre_train, test), "description_norm_hash", "left_anti")
    train_drop = exact_train.count() - train.count()
    val_drop = val.count() - kept_val.count()

    final = train.unionByName(kept_val).unionByName(test).persist(StorageLevel.MEMORY_AND_DISK)
    final.count()
    frames = {name: final.where(F.col("split") == name) for name in ("train", "val", "test")}
    pairwise: dict[str, dict[str, int]] = {}
    failures: list[str] = []
    for left, right in combinations(("train", "val", "test"), 2):
        name = f"{left}_{right}"
        pairwise[name] = {
            "description_norm_hash": _overlap_count(frames[left], frames[right], "description_norm_hash"),
            "cve_id": _overlap_count(frames[left], frames[right], "cve_id"),
        }
        for key, count in pairwise[name].items():
            if count:
                failures.append(f"{name}:{key}={count}")

    report: dict[str, Any] = {
        "train_overlap_with_eval_dropped": train_drop,
        "val_overlap_with_eval_dropped": val_drop,
        "pairwise_post_drop": pairwise,
        "ok": not failures,
    }
    atomic_write_json(report_path, report)
    if failures:
        raise AssertionError("Post-drop overlap invariant failed: " + ", ".join(failures))
    final.write.mode("overwrite").partitionBy("split", "published_year").parquet(
        str(Path(output_root) / "deduped")
    )
    return final, report

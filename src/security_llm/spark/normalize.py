"""Normalize gated raw NVD pages into partitioned Parquet."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pyspark.sql import DataFrame, SparkSession, functions as F
from pyspark.storagelevel import StorageLevel

from security_llm.data.normalize import normalize_record
from security_llm.spark.schema import NORMALIZED_SCHEMA, RAW_PAGE_SCHEMA

EXPECTED_NORMALIZED_ROWS = 257_913


def _omit_schema_nulls(value: Any) -> Any:
    """Restore the missing-key shape seen by the reference JSON parser.

    Spark structs contain every declared field and represent a field absent from
    the source JSON as ``None``.  The reference normalizer instead receives a
    dict where that key is absent, so its ``dict.get(..., default)`` calls rely
    on the key not existing.  Explicit nulls would also have failed the
    completed reference run, so omitting these schema-generated nulls is the
    equivalent representation for this snapshot.
    """

    if isinstance(value, dict):
        return {
            key: _omit_schema_nulls(item)
            for key, item in value.items()
            if item is not None
        }
    if isinstance(value, list):
        return [_omit_schema_nulls(item) for item in value]
    return value


def complete_page_paths(raw_dir: str | Path) -> tuple[list[str], str]:
    """Return pages from complete manifest windows and the snapshot date."""

    raw_path = Path(raw_dir)
    with (raw_path / "ingest_manifest.json").open(encoding="utf-8") as handle:
        manifest = json.load(handle)
    pages: list[str] = []
    for window in manifest["windows"]:
        if window.get("complete"):
            directory = raw_path / f"{window['pub_start']}_{window['pub_end']}"
            pages.extend(str(path) for path in sorted(directory.glob("page_*.json")))
    if not pages:
        raise FileNotFoundError(f"No pages from complete windows under {raw_path}")
    return pages, str(manifest["snapshot_date"])


def _normalizer_udf(cfg: dict[str, Any]):
    # normalize_record ultimately calls data.dedup.normalize_text inside this UDF.
    @F.udf(returnType=NORMALIZED_SCHEMA)
    def normalize_cve(cve: Any) -> dict[str, Any] | None:
        if cve is None:
            return None
        value = cve.asDict(recursive=True) if hasattr(cve, "asDict") else cve
        return normalize_record(_omit_schema_nulls(value), cfg)

    return normalize_cve


def normalize_pages(
    spark: SparkSession, cfg: dict[str, Any], output_root: str | Path
) -> tuple[DataFrame, dict[str, int]]:
    """Run §3.1, assert snapshot identity, and write normalized Parquet."""

    pages, _ = complete_page_paths(cfg["nvd"]["raw_dir"])
    raw = (
        spark.read.option("multiLine", True)
        .schema(RAW_PAGE_SCHEMA)
        .json(pages)
        .select(F.explode("vulnerabilities").alias("vulnerability"))
        .select("vulnerability.cve")
    )
    rows = (
        raw.select(_normalizer_udf(cfg)("cve").alias("row"))
        .where(F.col("row").isNotNull())
        .select("row.*")
        .withColumn("published_year", F.substring("published", 1, 4))
        .persist(StorageLevel.MEMORY_AND_DISK)
    )
    counts = rows.agg(
        F.count("*").alias("rows"), F.countDistinct("cve_id").alias("unique_cve_ids")
    ).first()
    actual = {"rows": int(counts["rows"]), "unique_cve_ids": int(counts["unique_cve_ids"])}
    if actual != {"rows": EXPECTED_NORMALIZED_ROWS, "unique_cve_ids": EXPECTED_NORMALIZED_ROWS}:
        raise AssertionError(f"Normalized snapshot identity failed: {actual}")
    output = Path(output_root) / "normalized"
    rows.write.mode("overwrite").partitionBy("published_year").parquet(str(output))
    return rows, actual

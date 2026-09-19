"""E1-E12 row-level equivalence checks for Spark Track A."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pyspark.sql import DataFrame, functions as F

from security_llm.data.dedup import drop_internal_duplicates
from security_llm.spark.dedup import keep_first_train
from security_llm.spark.schema import NORMALIZED_FIELDS, NORMALIZED_SCHEMA, split_schema
from security_llm.spark.session import build_spark_session
from security_llm.utils.io import atomic_write_json, read_jsonl


def _check(number: str, name: str, expected: Any, actual: Any, passed: bool, cause: str = "") -> dict[str, Any]:
    return {
        "id": number,
        "check": name,
        "expected": expected,
        "actual": actual,
        "pass": passed,
        "delta": None if passed else _delta(expected, actual),
        "cause": "" if passed else cause,
    }


def _delta(expected: Any, actual: Any) -> Any:
    if isinstance(expected, (int, float)) and isinstance(actual, (int, float)):
        return actual - expected
    if isinstance(expected, list) and isinstance(actual, list):
        return {
            "missing": [item for item in expected if item not in actual],
            "unexpected": [item for item in actual if item not in expected],
        }
    if isinstance(expected, dict) and isinstance(actual, dict):
        return {
            key: actual.get(key, 0) - expected.get(key, 0)
            for key in sorted(set(expected) | set(actual))
            if actual.get(key, 0) != expected.get(key, 0)
        }
    return {"expected": expected, "actual": actual}


def _distribution(df: DataFrame) -> dict[str, dict[str, int]]:
    rows = df.groupBy("split", "cwe_id").count().collect()
    result = {name: {} for name in ("train", "val", "test")}
    for row in rows:
        result[str(row["split"])][str(row["cwe_id"])] = int(row["count"])
    return result


def _pairwise_zero(overlap: dict[str, Any]) -> list[int]:
    pairs = ("train_test", "train_val", "val_test")
    return [int(overlap["pairwise_post_drop"][pair]["description_norm_hash"]) for pair in pairs]


def _render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Spark Track A equivalence report",
        "",
        "Comparison is row-level by `cve_id`; Parquet byte identity and row order are not compared.",
        "",
        "| Check | Expected | Actual | Pass |",
        "|---|---|---|:---:|",
    ]
    for item in report["checks"]:
        expected = json.dumps(item["expected"], ensure_ascii=False, sort_keys=True).replace("|", "\\|")
        actual = json.dumps(item["actual"], ensure_ascii=False, sort_keys=True).replace("|", "\\|")
        lines.append(f"| {item['id']} — {item['check']} | `{expected}` | `{actual}` | {'yes' if item['pass'] else 'NO'} |")
    failures = [item for item in report["checks"] if not item["pass"]]
    lines.extend(["", f"Overall: **{'PASS' if report['all_passed'] else 'FAIL'}**."])
    if failures:
        lines.extend(["", "## Recorded failures", ""])
        for item in failures:
            lines.append(
                f"- **{item['id']}** delta: `{json.dumps(item['delta'], ensure_ascii=False, sort_keys=True)}`. "
                f"Cause: {item['cause']}"
            )
    if report.get("e3_field_mismatches"):
        lines.extend(["", "## E3 field mismatch counts", "", "```json"])
        lines.append(json.dumps(report["e3_field_mismatches"], indent=2, sort_keys=True))
        lines.append("```")
    lines.append("")
    return "\n".join(lines)


def run(args: argparse.Namespace) -> dict[str, Any]:
    spark = build_spark_session(args.master, args.shuffle_partitions, "security-llm-equivalence")
    try:
        root = Path(args.output_root)
        normalized = spark.read.parquet(str(root / "normalized"))
        splits = spark.read.parquet(str(root / "splits"))
        final = spark.read.parquet(str(root / "deduped"))
        reference_normalized = spark.read.schema(NORMALIZED_SCHEMA).json(args.reference_normalized)
        reference_splits = spark.read.schema(split_schema()).json(
            [str(Path(args.reference_processed) / f"{name}.jsonl") for name in ("train", "val", "test")]
        )
        with Path(args.reference_manifest).open(encoding="utf-8") as handle:
            reference_manifest = json.load(handle)
        with (root / "labels.json").open(encoding="utf-8") as handle:
            spark_labels = json.load(handle)["selected"]
        with Path(args.overlap_report).open(encoding="utf-8") as handle:
            overlap = json.load(handle)

        checks: list[dict[str, Any]] = []
        normalized_count = normalized.count()
        checks.append(_check("E1", "normalized row count", 257_913, normalized_count, normalized_count == 257_913,
                             "The gated raw population or CVE normalization changed."))

        spark_ids = normalized.select("cve_id")
        ref_ids = reference_normalized.select("cve_id")
        id_difference = spark_ids.join(ref_ids, "cve_id", "left_anti").count() + ref_ids.join(
            spark_ids, "cve_id", "left_anti"
        ).count()
        checks.append(_check("E2", "normalized cve_id symmetric difference", 0, id_difference, id_difference == 0,
                             "Spark and reference normalization retained different CVE IDs."))

        spark_rows = normalized.select(
            "cve_id", F.struct(*[F.col(field) for field in NORMALIZED_FIELDS]).alias("spark_row")
        )
        ref_rows = reference_normalized.select(
            "cve_id", F.struct(*[F.col(field) for field in NORMALIZED_FIELDS]).alias("reference_row")
        )
        row_join = spark_rows.join(ref_rows, "cve_id", "full")
        mismatches = row_join.where(~F.col("spark_row").eqNullSafe(F.col("reference_row")))
        mismatch_count = mismatches.count()
        field_mismatches: dict[str, int] = {}
        if mismatch_count:
            matched = normalized.alias("s").join(reference_normalized.alias("r"), "cve_id", "inner")
            aggregates = [
                F.sum((~F.col(f"s.{field}").eqNullSafe(F.col(f"r.{field}"))).cast("long")).alias(field)
                for field in NORMALIZED_FIELDS
                if field != "cve_id"
            ]
            summary = matched.agg(*aggregates).first().asDict()
            field_mismatches = {key: int(value) for key, value in summary.items() if value}
        checks.append(_check("E3", "normalized per-row field mismatches", 0, mismatch_count, mismatch_count == 0,
                             f"Field-level deltas: {field_mismatches}; inspect normalization semantics."))

        expected_labels = reference_manifest["labels"]
        checks.append(_check("E4", "selected labels (ordered)", expected_labels, spark_labels,
                             spark_labels == expected_labels, "Train-only label frequency ranking differs."))

        split_counts = {str(row["split"]): int(row["count"]) for row in splits.groupBy("split").count().collect()}
        expected_counts = {"train": 65_272, "val": 21_151, "test": 24_975}
        checks.append(_check("E5", "split populations", expected_counts, split_counts,
                             split_counts == expected_counts, "Eligibility, temporal assignment, or selected labels differ."))

        spark_assignments = {(row["cve_id"], row["split"]) for row in splits.select("cve_id", "split").collect()}
        ref_assignments = {(row["cve_id"], row["split"]) for row in reference_splits.select("cve_id", "split").collect()}
        assignment_delta = len(spark_assignments.symmetric_difference(ref_assignments))
        checks.append(_check("E6", "split assignment disagreements", 0, assignment_delta, assignment_delta == 0,
                             "Inclusive temporal boundaries or eligibility assignment differ."))

        spark_distribution = _distribution(splits)
        ref_distribution = _distribution(reference_splits)
        checks.append(_check("E7", "class distribution per split", ref_distribution, spark_distribution,
                             spark_distribution == ref_distribution, "One or more split/CWE populations differ."))

        exact_train = keep_first_train(splits.where(F.col("split") == "train")).cache()
        exact_count = exact_train.count()
        duplicate_drop = split_counts["train"] - exact_count
        checks.append(_check("E8", "train exact duplicates dropped", 3_427, duplicate_drop,
                             duplicate_drop == 3_427, "Normalized-text hash groups differ."))

        reference_train = read_jsonl(Path(args.reference_processed) / "train.jsonl")
        expected_survivors, _ = drop_internal_duplicates(reference_train)
        expected_survivor_ids = {row["cve_id"] for row in expected_survivors}
        spark_survivor_ids = {row["cve_id"] for row in exact_train.select("cve_id").collect()}
        survivor_delta = len(expected_survivor_ids.symmetric_difference(spark_survivor_ids))
        checks.append(_check("E9", "post-train-dedup cve_id symmetric difference", 0, survivor_delta,
                             survivor_delta == 0, "Keep-first survivor identity differs; inspect ordering by published and cve_id."))
        exact_train.unpersist()

        train_overlap = int(overlap["train_overlap_with_eval_dropped"])
        checks.append(_check("E10", "train↔eval overlap dropped", 36, train_overlap, train_overlap == 36,
                             "Train anti-join hashes or upstream populations differ."))
        val_overlap = int(overlap["val_overlap_with_eval_dropped"])
        checks.append(_check("E11", "val↔eval overlap dropped", 233, val_overlap, val_overlap == 233,
                             "Validation anti-join did not use the pre-dedup train population or upstream data differ."))

        pairwise = _pairwise_zero(overlap)
        cve_pairwise = [
            int(overlap["pairwise_post_drop"][pair]["cve_id"])
            for pair in ("train_test", "train_val", "val_test")
        ]
        pairwise_ok = pairwise == [0, 0, 0] and cve_pairwise == [0, 0, 0]
        checks.append(_check("E12", "post-drop pairwise overlaps", [0, 0, 0], pairwise, pairwise_ok,
                             f"Residual CVE-ID overlap counts: {cve_pairwise}."))

        report = {
            "comparison": "row-level by cve_id",
            "all_passed": all(item["pass"] for item in checks),
            "checks": checks,
            "e3_field_mismatches": field_mismatches,
        }
        atomic_write_json(args.json_report, report)
        md_path = Path(args.markdown_report)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(_render_markdown(report), encoding="utf-8")

        print("check\texpected\tactual\tpass")
        for item in checks:
            print(f"{item['id']}\t{json.dumps(item['expected'], sort_keys=True)}\t"
                  f"{json.dumps(item['actual'], sort_keys=True)}\t{item['pass']}")
        return report
    finally:
        spark.stop()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--master", default="local[8]")
    parser.add_argument("--shuffle-partitions", type=int, default=64)
    parser.add_argument("--output-root", default="data/spark")
    parser.add_argument("--reference-normalized", default="data/processed/normalized.jsonl")
    parser.add_argument("--reference-processed", default="data/processed")
    parser.add_argument("--reference-manifest", default="manifests/dataset_manifest.json")
    parser.add_argument("--overlap-report", default="reports/distributed/spark_overlap.json")
    parser.add_argument("--json-report", default="reports/distributed/equivalence_report.json")
    parser.add_argument("--markdown-report", default="reports/distributed/equivalence_report.md")
    return parser.parse_args()


def main() -> None:
    run(parse_args())


if __name__ == "__main__":
    main()

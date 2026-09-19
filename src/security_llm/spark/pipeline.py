"""CLI entry point for the Spark Track A pipeline."""

from __future__ import annotations

import argparse
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, TypeVar

from security_llm.config import load_config
from security_llm.spark.dedup import deduplicate_train
from security_llm.spark.manifest import write_manifest
from security_llm.spark.normalize import complete_page_paths, normalize_pages
from security_llm.spark.overlap import enforce_overlap_invariant
from security_llm.spark.session import build_spark_session
from security_llm.spark.split import create_splits
from security_llm.utils.io import atomic_write_json

T = TypeVar("T")
LOG_TIMESTAMP = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})")


def _timed(name: str, fn: Callable[[], T], timings: dict[str, float]) -> T:
    print(f"=== SPARK STEP {name} START ===", flush=True)
    start = time.perf_counter()
    result = fn()
    timings[name] = round(time.perf_counter() - start, 3)
    print(f"=== SPARK STEP {name} END ({timings[name]:.3f}s) ===", flush=True)
    return result


def _single_process_measurement(log_dir: str | Path = "logs") -> dict[str, Any]:
    """Read the completed reference run without executing it again."""

    candidates: list[tuple[Path, list[str]]] = []
    for path in sorted(Path(log_dir).glob("prepare_data_*.log")):
        lines = path.read_text(encoding="utf-8").splitlines()
        if "=== PREPARE_DATA DONE ===" in lines:
            candidates.append((path, lines))
    if not candidates:
        raise FileNotFoundError("No completed logs/prepare_data_*.log found")
    path, lines = candidates[-1]
    start_match = re.search(r"prepare_data_(\d{8}T\d{6}Z)\.log$", path.name)
    if not start_match:
        raise ValueError(f"Cannot parse run start from {path}")
    start_utc = datetime.strptime(start_match.group(1), "%Y%m%dT%H%M%SZ").replace(
        tzinfo=timezone.utc
    ).timestamp()
    end_epoch = path.stat().st_mtime
    timestamps = [
        datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S,%f").timestamp()
        for line in lines
        if (match := LOG_TIMESTAMP.match(line))
    ]
    # The last ingest log line immediately precedes the untimestamped normalize marker.
    ingest_end_line = max(
        index for index, line in enumerate(lines) if line == "=== STEP ingest END ==="
    )
    prior = next(
        LOG_TIMESTAMP.match(lines[index])
        for index in range(ingest_end_line - 1, -1, -1)
        if LOG_TIMESTAMP.match(lines[index])
    )
    track_a_start = datetime.strptime(prior.group(1), "%Y-%m-%d %H:%M:%S,%f").timestamp()
    return {
        "source": str(path),
        "full_prepare_data_seconds": round(end_epoch - start_utc, 3),
        "full_prepare_data_includes_ingestion": True,
        "post_ingest_pipeline_seconds": round(end_epoch - track_a_start, 3),
        "post_ingest_interval_includes": [
            "normalize",
            "dataset statistics",
            "split",
            "SFT construction",
            "contamination",
        ],
        "method": (
            "full: UTC timestamp in filename to log mtime; post-ingest: final ingest timestamp "
            "immediately before normalize marker to log mtime; untimestamped stage markers prevent "
            "a narrower reference measurement"
        ),
        "timestamped_log_events": len(timestamps),
    }


def _update_runtime(
    path: str | Path, master: str, shuffle_partitions: int, timings: dict[str, float]
) -> None:
    output = Path(path)
    if output.exists():
        with output.open(encoding="utf-8") as handle:
            runtime = json.load(handle)
    else:
        runtime = {
            "measurement_scope": "single node only; no cluster scaling is claimed or extrapolated",
            "single_process": _single_process_measurement(),
            "spark_runs": {},
        }
    runtime["spark_runs"][master] = {
        "master": master,
        "spark.sql.shuffle.partitions": shuffle_partitions,
        "stages_seconds": timings,
        "track_a_total_seconds": round(sum(timings.values()), 3),
        "single_node": True,
    }
    atomic_write_json(output, runtime)


def run(args: argparse.Namespace) -> dict[str, Any]:
    cfg = load_config(args.config)
    spark = build_spark_session(args.master, args.shuffle_partitions)
    timings: dict[str, float] = {}
    try:
        normalized, normalized_counts = _timed(
            "normalize", lambda: normalize_pages(spark, cfg, args.output_root), timings
        )
        _, snapshot = complete_page_paths(cfg["nvd"]["raw_dir"])
        splits, labels, split_counts = _timed(
            "split",
            lambda: create_splits(
                normalized, cfg, snapshot, args.output_root, args.reference_manifest
            ),
            timings,
        )
        normalized.unpersist()
        exact, exact_duplicates = _timed(
            "dedup", lambda: deduplicate_train(splits), timings
        )
        final, overlap = _timed(
            "overlap",
            lambda: enforce_overlap_invariant(
                exact, splits, args.output_root, args.overlap_report
            ),
            timings,
        )
        exact.unpersist()
        splits.unpersist()
        manifest = _timed(
            "manifest",
            lambda: write_manifest(
                final,
                args.output_root,
                args.manifest,
                args.config,
                args.reference_manifest,
                snapshot,
                labels,
                split_counts,
                exact_duplicates,
                overlap,
                args.master,
                args.shuffle_partitions,
                spark.version,
            ),
            timings,
        )
        final.unpersist()
        _update_runtime(args.runtime_report, args.master, args.shuffle_partitions, timings)
        return {
            "normalized": normalized_counts,
            "split_counts": split_counts,
            "dedup": manifest["dedup"],
            "timings": timings,
        }
    finally:
        spark.stop()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configs/data.yaml")
    parser.add_argument("--master", default="local[8]")
    parser.add_argument("--shuffle-partitions", type=int, default=64)
    parser.add_argument("--output-root", default="data/spark")
    parser.add_argument("--manifest", default="manifests/spark_dataset_manifest.json")
    parser.add_argument("--reference-manifest", default="manifests/dataset_manifest.json")
    parser.add_argument("--overlap-report", default="reports/distributed/spark_overlap.json")
    parser.add_argument("--runtime-report", default="reports/distributed/runtime.json")
    return parser.parse_args()


def main() -> None:
    print(json.dumps(run(parse_args()), indent=2))


if __name__ == "__main__":
    main()

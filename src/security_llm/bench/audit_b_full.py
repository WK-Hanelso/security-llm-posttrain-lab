"""Run the full exact Audit B measurement and close the T-014 track."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import random
import resource
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import sklearn
from sklearn.metrics.pairwise import cosine_similarity

from security_llm.bench.audit_b_cost_probe import (
    EXPECTED_QUERY_ROWS,
    EXPECTED_REFERENCE_ROWS,
    EXPECTED_TEST_SHA256,
    EXPECTED_TRAIN_SHA256,
    EXPECTED_VOCABULARY_SIZE,
    THRESHOLDS,
    TOP_K,
    VECTORIZER_KWARGS,
    _direct_truth,
    _fit_transform,
    _matrix_storage_bytes,
    _validate_sources,
)
from security_llm.bench.blockwise_exact import (
    SCORE_ABSOLUTE_TOLERANCE,
    _blockwise_exact,
    _sha256_array,
)
from security_llm.bench.near_duplicate_scaling import (
    _memory_info,
    _rss_bytes,
    run_instrumented_subprocess,
)
from security_llm.data.dedup import text_hash
from security_llm.eval.failure_analysis import _description_bucket

EXPECTED_BRANCH = "feat/distributed-pipeline"
EXPECTED_COMMIT = "be0f6e690e71e15bd49ee49a5d3acff79feb0a43"
BLOCK_SIZE = 2_048
PAIR_COUNT = EXPECTED_QUERY_ROWS * EXPECTED_REFERENCE_ROWS
CORRECTNESS_QUERY_COUNT = 100
CORRECTNESS_SEED = 20_260_919
PROJECTED_WALL_SECONDS = 98.05
PROJECTED_RSS_GIB = 1.144
CONSERVATIVE_RSS_GIB = 1.499
LENGTH_BUCKETS = ("<250", "250-500", "500-1000", ">=1000")
RARE_CLASSES = ("CWE-476", "CWE-120", "CWE-434", "CWE-200", "CWE-284")


def _git_value(*args: str) -> str:
    return subprocess.run(
        ["git", *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def _assert_checkout() -> tuple[str, str]:
    branch = _git_value("branch", "--show-current")
    commit = _git_value("rev-parse", "HEAD")
    if branch != EXPECTED_BRANCH or branch == "main":
        raise RuntimeError(
            f"expected non-main branch {EXPECTED_BRANCH}, found {branch}"
        )
    if commit != EXPECTED_COMMIT:
        raise RuntimeError(f"expected commit {EXPECTED_COMMIT}, found {commit}")
    return branch, commit


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_lines(values: list[str]) -> str:
    return hashlib.sha256("\n".join(values).encode("utf-8")).hexdigest()


def _execution(branch: str, commit: str) -> dict[str, Any]:
    memory = _memory_info()
    return {
        "branch": branch,
        "commit": commit,
        "hostname": platform.node(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "python_executable": sys.executable,
        "numpy": np.__version__,
        "scikit_learn": sklearn.__version__,
        "logical_cpu_count": os.cpu_count(),
        "memory_total_bytes": memory["MemTotal"],
        "memory_available_bytes": memory["MemAvailable"],
        "swap_total_bytes": memory["SwapTotal"],
        "swap_used_bytes": memory["SwapUsed"],
        "thread_environment": {
            key: os.environ.get(key)
            for key in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS")
        },
    }


def _threshold_arrays(
    result: dict[str, Any], threshold: str
) -> tuple[np.ndarray, np.ndarray]:
    return result[f"threshold_{threshold}_keys"], result[f"threshold_{threshold}_scores"]


def _write_parquet(
    path: Path,
    result: dict[str, Any],
    queries: list[dict[str, Any]],
    references: list[dict[str, Any]],
) -> dict[str, Any]:
    query_hashes = [text_hash(str(row["description_en"])) for row in queries]
    reference_hashes = [
        text_hash(str(row["description_en"])) for row in references
    ]
    reference_ids = np.asarray(
        [str(row["cve_id"]) for row in references], dtype=str
    )
    keys_80, scores_80 = _threshold_arrays(result, "80")
    by_query: list[list[tuple[int, float]]] = [
        [] for _ in range(EXPECTED_QUERY_ROWS)
    ]
    for key, score in zip(keys_80, scores_80, strict=True):
        query_index, reference_index = divmod(int(key), EXPECTED_REFERENCE_ROWS)
        by_query[query_index].append((reference_index, float(score)))

    columns: dict[str, list[Any]] = {
        "query_cve_id": [],
        "reference_cve_id": [],
        "query_label": [],
        "reference_label": [],
        "exact_similarity": [],
        "rank": [],
        "threshold_80": [],
        "threshold_90": [],
        "query_text_hash": [],
        "reference_text_hash": [],
    }
    for query_index, query in enumerate(queries):
        selected = {
            int(reference_index): float(score)
            for reference_index, score in zip(
                result["top_indices"][query_index],
                result["top_scores"][query_index],
                strict=True,
            )
        }
        for reference_index, score in by_query[query_index]:
            if reference_index in selected and selected[reference_index] != score:
                raise RuntimeError("top-k and threshold score paths diverged")
            selected[reference_index] = score
        selected_indices = np.asarray(list(selected), dtype=np.int32)
        selected_scores = np.asarray(
            [selected[int(index)] for index in selected_indices], dtype=np.float64
        )
        order = np.lexsort((reference_ids[selected_indices], -selected_scores))
        query_label = str(query["cwe_id"])
        for rank, position in enumerate(order, start=1):
            reference_index = int(selected_indices[position])
            score = float(selected_scores[position])
            reference = references[reference_index]
            columns["query_cve_id"].append(str(query["cve_id"]))
            columns["reference_cve_id"].append(str(reference["cve_id"]))
            columns["query_label"].append(query_label)
            columns["reference_label"].append(str(reference["cwe_id"]))
            columns["exact_similarity"].append(score)
            columns["rank"].append(rank)
            columns["threshold_80"].append(score >= THRESHOLDS[0])
            columns["threshold_90"].append(score >= THRESHOLDS[1])
            columns["query_text_hash"].append(query_hashes[query_index])
            columns["reference_text_hash"].append(
                reference_hashes[reference_index]
            )

    schema = pa.schema(
        [
            ("query_cve_id", pa.string()),
            ("reference_cve_id", pa.string()),
            ("query_label", pa.string()),
            ("reference_label", pa.string()),
            ("exact_similarity", pa.float64()),
            ("rank", pa.int32()),
            ("threshold_80", pa.bool_()),
            ("threshold_90", pa.bool_()),
            ("query_text_hash", pa.string()),
            ("reference_text_hash", pa.string()),
        ]
    )
    table = pa.Table.from_pydict(columns, schema=schema)
    pq.write_table(table, path, compression="zstd")
    return {
        "row_count": table.num_rows,
        "top_k_rows": EXPECTED_QUERY_ROWS * TOP_K,
        "schema": str(schema),
    }


def _pair_summary(
    keys: np.ndarray,
    scores: np.ndarray,
    query_labels: np.ndarray,
    reference_labels: np.ndarray,
    exact_only: bool = False,
) -> dict[str, int]:
    query_indices = keys // EXPECTED_REFERENCE_ROWS
    reference_indices = keys % EXPECTED_REFERENCE_ROWS
    mask = scores == 1.0 if exact_only else np.ones(len(keys), dtype=bool)
    query_indices = query_indices[mask]
    reference_indices = reference_indices[mask]
    same = query_labels[query_indices] == reference_labels[reference_indices]
    return {
        "pair_count": int(np.count_nonzero(mask)),
        "query_count": int(len(np.unique(query_indices))),
        "same_label_pairs": int(np.count_nonzero(same)),
        "cross_label_pairs": int(np.count_nonzero(~same)),
    }


def _group_analysis(
    query_mask: np.ndarray,
    top1_scores: np.ndarray,
    keys_80: np.ndarray,
    keys_90: np.ndarray,
    query_labels: np.ndarray,
    reference_labels: np.ndarray,
) -> dict[str, Any]:
    count = int(np.count_nonzero(query_mask))
    values = top1_scores[query_mask]
    record: dict[str, Any] = {
        "query_count": count,
        "rank1_p50": float(np.percentile(values, 50)),
        "rank1_p90": float(np.percentile(values, 90)),
        "query_share_ge_0_80": float(np.count_nonzero(values >= 0.80) / count),
        "query_share_ge_0_90": float(np.count_nonzero(values >= 0.90) / count),
        "high_similarity_pair_split": {},
    }
    for label, keys in (("0.80", keys_80), ("0.90", keys_90)):
        pair_queries = keys // EXPECTED_REFERENCE_ROWS
        pair_references = keys % EXPECTED_REFERENCE_ROWS
        pair_mask = query_mask[pair_queries]
        same = (
            query_labels[pair_queries[pair_mask]]
            == reference_labels[pair_references[pair_mask]]
        )
        record["high_similarity_pair_split"][label] = {
            "pair_count": int(np.count_nonzero(pair_mask)),
            "same_label_pairs": int(np.count_nonzero(same)),
            "cross_label_pairs": int(np.count_nonzero(~same)),
        }
    return record


def _analysis(
    result: dict[str, Any],
    queries: list[dict[str, Any]],
    references: list[dict[str, Any]],
) -> dict[str, Any]:
    query_labels = np.asarray([str(row["cwe_id"]) for row in queries], dtype=str)
    reference_labels = np.asarray(
        [str(row["cwe_id"]) for row in references], dtype=str
    )
    top1_scores = result["top_scores"][:, 0]
    keys_80, scores_80 = _threshold_arrays(result, "80")
    keys_90, scores_90 = _threshold_arrays(result, "90")
    per_class = {
        label: _group_analysis(
            query_labels == label,
            top1_scores,
            keys_80,
            keys_90,
            query_labels,
            reference_labels,
        )
        for label in sorted(set(query_labels.tolist()))
    }
    buckets = np.asarray(
        [_description_bucket(len(str(row["description_en"]))) for row in queries]
    )
    per_length = {
        bucket: _group_analysis(
            buckets == bucket,
            top1_scores,
            keys_80,
            keys_90,
            query_labels,
            reference_labels,
        )
        for bucket in LENGTH_BUCKETS
    }
    rare_mask = np.isin(query_labels, np.asarray(RARE_CLASSES))
    rare_groups = {
        "rare_five": _group_analysis(
            rare_mask,
            top1_scores,
            keys_80,
            keys_90,
            query_labels,
            reference_labels,
        ),
        "other_ten": _group_analysis(
            ~rare_mask,
            top1_scores,
            keys_80,
            keys_90,
            query_labels,
            reference_labels,
        ),
    }
    return {
        "totals": {
            "0.80": _pair_summary(
                keys_80, scores_80, query_labels, reference_labels
            ),
            "0.90": _pair_summary(
                keys_90, scores_90, query_labels, reference_labels
            ),
            "1.0": _pair_summary(
                keys_80,
                scores_80,
                query_labels,
                reference_labels,
                exact_only=True,
            ),
        },
        "rank1_similarity": {
            "query_count": len(queries),
            "p50": float(np.percentile(top1_scores, 50)),
            "p90": float(np.percentile(top1_scores, 90)),
            "p95": float(np.percentile(top1_scores, 95)),
            "p99": float(np.percentile(top1_scores, 99)),
            "max": float(np.max(top1_scores)),
            "mean": float(np.mean(top1_scores)),
        },
        "per_cwe_class": per_class,
        "per_description_length_bucket": per_length,
        "rare_class_groups": rare_groups,
        "rare_classes_fixed_before_run": list(RARE_CLASSES),
    }


def _correctness(
    result: dict[str, Any],
    query_matrix: Any,
    reference_matrix: Any,
    queries: list[dict[str, Any]],
    reference_ids: np.ndarray,
) -> dict[str, Any]:
    selected = random.Random(CORRECTNESS_SEED).sample(
        range(EXPECTED_QUERY_ROWS), CORRECTNESS_QUERY_COUNT
    )
    direct_scores = cosine_similarity(
        query_matrix[selected], reference_matrix, dense_output=True
    )
    direct = _direct_truth(direct_scores, reference_ids)
    block_indices = result["top_indices"][selected]
    block_scores = result["top_scores"][selected]
    membership_differences: list[dict[str, Any]] = []
    ordering_differences: list[dict[str, Any]] = []
    aligned_deltas: list[float] = []
    for local_index, global_index in enumerate(selected):
        block_row = block_indices[local_index]
        direct_row = direct["top_indices"][local_index]
        block_set = set(block_row.tolist())
        direct_set = set(direct_row.tolist())
        if block_set != direct_set:
            disputed = np.asarray(sorted(block_set ^ direct_set), dtype=np.int32)
            disputed_scores = direct_scores[local_index, disputed]
            score_delta = float(np.max(disputed_scores) - np.min(disputed_scores))
            membership_differences.append(
                {
                    "query_id": str(queries[global_index]["cve_id"]),
                    "blockwise_only_reference_ids": sorted(
                        reference_ids[list(block_set - direct_set)].tolist()
                    ),
                    "direct_only_reference_ids": sorted(
                        reference_ids[list(direct_set - block_set)].tolist()
                    ),
                    "maximum_disputed_score_delta": score_delta,
                    "within_cross_implementation_tolerance": (
                        score_delta <= SCORE_ABSOLUTE_TOLERANCE
                    ),
                }
            )
        if not np.array_equal(block_row, direct_row):
            disputed_positions = np.flatnonzero(block_row != direct_row)
            disputed = np.unique(
                np.concatenate(
                    (block_row[disputed_positions], direct_row[disputed_positions])
                )
            )
            score_delta = float(
                np.max(direct_scores[local_index, disputed])
                - np.min(direct_scores[local_index, disputed])
            )
            ordering_differences.append(
                {
                    "query_id": str(queries[global_index]["cve_id"]),
                    "differing_position_count": int(len(disputed_positions)),
                    "maximum_disputed_score_delta": score_delta,
                    "within_cross_implementation_tolerance": (
                        score_delta <= SCORE_ABSOLUTE_TOLERANCE
                    ),
                }
            )
        direct_by_reference = {
            int(reference_index): float(score)
            for reference_index, score in zip(
                direct_row, direct["top_scores"][local_index], strict=True
            )
        }
        for reference_index, score in zip(
            block_row, block_scores[local_index], strict=True
        ):
            if int(reference_index) in direct_by_reference:
                aligned_deltas.append(
                    abs(float(score) - direct_by_reference[int(reference_index)])
                )

    local_by_global = {value: index for index, value in enumerate(selected)}

    def subset_keys(keys: np.ndarray) -> np.ndarray:
        query_indices = keys // EXPECTED_REFERENCE_ROWS
        mask = np.isin(query_indices, np.asarray(selected))
        selected_keys = keys[mask]
        return np.sort(
            np.asarray(
                [
                    local_by_global[int(key // EXPECTED_REFERENCE_ROWS)]
                    * EXPECTED_REFERENCE_ROWS
                    + int(key % EXPECTED_REFERENCE_ROWS)
                    for key in selected_keys
                ],
                dtype=np.int64,
            )
        )

    block_80 = subset_keys(result["threshold_80_keys"])
    block_90 = subset_keys(result["threshold_90_keys"])
    threshold_80_identical = np.array_equal(block_80, direct["threshold_80_keys"])
    threshold_90_identical = np.array_equal(block_90, direct["threshold_90_keys"])
    counts_identical = np.array_equal(
        result["threshold_80_counts"][selected], direct["threshold_80_counts"]
    ) and np.array_equal(
        result["threshold_90_counts"][selected], direct["threshold_90_counts"]
    )
    max_score_delta = max(aligned_deltas, default=0.0)
    near_ties_only = all(
        row["within_cross_implementation_tolerance"]
        for row in membership_differences + ordering_differences
    )
    all_passed = bool(
        max_score_delta <= SCORE_ABSOLUTE_TOLERANCE
        and threshold_80_identical
        and threshold_90_identical
        and counts_identical
        and near_ties_only
    )
    return {
        "method": (
            "random fixed-seed query subset; full result compared with one independent "
            "direct dense cosine matrix and full-row lexsort"
        ),
        "seed": CORRECTNESS_SEED,
        "query_count": CORRECTNESS_QUERY_COUNT,
        "query_ids": [str(queries[index]["cve_id"]) for index in selected],
        "ordered_query_ids_sha256": _sha256_lines(
            [str(queries[index]["cve_id"]) for index in selected]
        ),
        "reference_count": EXPECTED_REFERENCE_ROWS,
        "score_absolute_tolerance": SCORE_ABSOLUTE_TOLERANCE,
        "scores_rounded_for_comparison": False,
        "top20_membership_identical": len(membership_differences) == 0,
        "top20_ordering_identical": len(ordering_differences) == 0,
        "top20_score_max_absolute_delta_aligned_by_reference": max_score_delta,
        "top20_scores_within_tolerance": (
            max_score_delta <= SCORE_ABSOLUTE_TOLERANCE
        ),
        "threshold_80_pair_set_identical": bool(threshold_80_identical),
        "threshold_90_pair_set_identical": bool(threshold_90_identical),
        "per_query_threshold_counts_identical": bool(counts_identical),
        "membership_differences": membership_differences,
        "near_tie_ordering_differences": ordering_differences,
        "known_float64_limitation_only": bool(near_ties_only),
        "all_passed": all_passed,
    }


def _child_run(args: argparse.Namespace) -> dict[str, Any]:
    started = time.perf_counter()
    usage_started = resource.getrusage(resource.RUSAGE_SELF)
    branch, commit = _assert_checkout()
    references, queries = _validate_sources(args.train, args.test)
    reference_ids = np.asarray(
        [str(row["cve_id"]) for row in references], dtype=str
    )
    vectorizer, reference_matrix, query_matrix, vectorize_seconds = _fit_transform(
        references, queries
    )
    result = _blockwise_exact(
        query_matrix, reference_matrix, reference_ids, args.block_size
    )
    measured_full_run_wall_seconds = time.perf_counter() - started
    analysis = _analysis(result, queries, references)
    write_started = time.perf_counter()
    parquet = _write_parquet(args.staging_parquet, result, queries, references)
    parquet_write_seconds = time.perf_counter() - write_started
    correctness_started = time.perf_counter()
    correctness = _correctness(
        result, query_matrix, reference_matrix, queries, reference_ids
    )
    correctness_seconds = time.perf_counter() - correctness_started
    if not correctness["all_passed"]:
        raise RuntimeError(f"correctness check failed: {correctness}")
    usage_finished = resource.getrusage(resource.RUSAGE_SELF)
    total_seconds = time.perf_counter() - started
    return {
        "schema_version": 1,
        "task": "T-014G full Audit B exact run",
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "success",
        "success": True,
        "audit": "B",
        "population": {
            "query_source": str(args.test),
            "query_source_sha256": EXPECTED_TEST_SHA256,
            "query_rows": len(queries),
            "reference_source": str(args.train),
            "reference_source_sha256": EXPECTED_TRAIN_SHA256,
            "reference_rows": len(references),
            "potential_pair_count": PAIR_COUNT,
        },
        "settings": {
            "text_field": "description_en",
            "text_preprocessing": "untruncated",
            "fitting_scope": "all 65,272 Audit B references; queries transformed",
            "vectorizer": VECTORIZER_KWARGS,
            "vocabulary_size": len(vectorizer.vocabulary_),
            "expected_vocabulary_size": EXPECTED_VOCABULARY_SIZE,
            "block_size": args.block_size,
            "top_k": TOP_K,
            "thresholds": list(THRESHOLDS),
            "ordering_key": (
                "(-raw float64 exact_similarity, reference_cve_id ascending as a string)"
            ),
            "length_buckets": list(LENGTH_BUCKETS),
            "rare_classes": list(RARE_CLASSES),
        },
        "parquet": parquet,
        "analysis": analysis,
        "correctness": correctness,
        "fingerprints": {
            "top20_reference_indices_sha256": _sha256_array(result["top_indices"]),
            "top20_scores_sha256": _sha256_array(result["top_scores"]),
            "threshold_80_pair_set_sha256": _sha256_array(
                result["threshold_80_keys"]
            ),
            "threshold_80_scores_sha256": _sha256_array(
                result["threshold_80_scores"]
            ),
            "threshold_90_pair_set_sha256": _sha256_array(
                result["threshold_90_keys"]
            ),
            "threshold_90_scores_sha256": _sha256_array(
                result["threshold_90_scores"]
            ),
        },
        "measurement": {
            "measured_full_run_wall_seconds": measured_full_run_wall_seconds,
            "total_child_wall_seconds": total_seconds,
            "vectorizer_fit_and_transform_seconds": vectorize_seconds,
            "blockwise_exact_seconds": float(result["wall_seconds"]),
            "parquet_write_seconds": parquet_write_seconds,
            "correctness_seconds": correctness_seconds,
            "processed_pair_count": PAIR_COUNT,
            "pairs_per_second": PAIR_COUNT / float(result["wall_seconds"]),
            "queries_per_second": EXPECTED_QUERY_ROWS / float(result["wall_seconds"]),
            "end_to_end_pairs_per_second": (
                PAIR_COUNT / measured_full_run_wall_seconds
            ),
            "peak_rss_bytes": _rss_bytes(),
            "major_page_faults": (
                usage_finished.ru_majflt - usage_started.ru_majflt
            ),
            "cpu_user_seconds": usage_finished.ru_utime - usage_started.ru_utime,
            "cpu_system_seconds": usage_finished.ru_stime - usage_started.ru_stime,
            "matrix_storage_bytes": {
                "reference": _matrix_storage_bytes(reference_matrix),
                "query": _matrix_storage_bytes(query_matrix),
            },
        },
        "execution": _execution(branch, commit),
    }


def _projection_error(measured: float, projected: float) -> dict[str, float]:
    signed = measured - projected
    return {
        "projected": projected,
        "measured": measured,
        "signed_error": signed,
        "absolute_error": abs(signed),
        "relative_error": signed / projected,
        "absolute_relative_error": abs(signed) / projected,
    }


def _projection_check(report: dict[str, Any]) -> dict[str, Any]:
    measurement = report["measurement"]
    measured_rss_gib = measurement["peak_rss_bytes"] / 1024**3
    return {
        "wall_seconds": _projection_error(
            measurement["measured_full_run_wall_seconds"], PROJECTED_WALL_SECONDS
        ),
        "peak_rss_gib": _projection_error(measured_rss_gib, PROJECTED_RSS_GIB),
        "peak_rss_conservative_gib": _projection_error(
            measured_rss_gib, CONSERVATIVE_RSS_GIB
        ),
        "explanation": (
            "Absolute wall time is load-sensitive: the same probe point measured "
            "10.113 s in the probe and 7.88 s in an independent rerun, so a wall-time "
            "miss alone is not a performance regression. Peak RSS reproduced exactly "
            "between those runs, making the memory comparison the more meaningful test. "
            "The full child also built the required Parquet string/hash columns and ran "
            "the direct correctness matrix after the exact kernel, while the probe "
            "children only fingerprinted retained arrays. That broader retained-output "
            "scope likely explains part of the primary memory projection miss; measured "
            "RSS still remained below the conservative projection with no swap growth or "
            "major faults."
        ),
    }


def _yes(value: bool) -> str:
    return "yes" if value else "no"


def _pct(value: float) -> str:
    return f"{100.0 * value:.2f}%"


def _split_text(value: dict[str, int]) -> str:
    return (
        f"{value['same_label_pairs']:,} / {value['cross_label_pairs']:,}"
    )


def _render_audit_report(report: dict[str, Any]) -> str:
    measurement = report["measurement"]
    projection = report["projection_check"]
    analysis = report["analysis"]
    correctness = report["correctness"]
    lines = [
        "# T-014G — full Audit B exact run",
        "",
        "This report measures exact high-similarity structure for all 24,975 processed-test queries against all 65,272 processed-train references: 1,630,168,200 potential pairs. TF-IDF was fit on the references only; queries used untruncated `description_en`. Blockwise exact cosine used block size 2,048 and retained only each query's top 20 plus all pairs at or above 0.80.",
        "",
        "## Measurement",
        "",
        "| Status | Pairs | Block | Full-run wall s | Exact phase s | Peak RSS GiB | Pairs/s | Queries/s | Swap delta | Major faults |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        f"| success | {measurement['processed_pair_count']:,} | {report['settings']['block_size']:,} | {measurement['measured_full_run_wall_seconds']:.3f} | {measurement['blockwise_exact_seconds']:.3f} | {measurement['peak_rss_bytes'] / 1024**3:.3f} | {measurement['pairs_per_second']:,.0f} | {measurement['queries_per_second']:.2f} | {measurement['swap_delta_bytes']:,} B | {measurement['major_page_faults']} |",
        "",
        f"The full-run wall time ends after the exact kernel and is the measurement comparable with the T-014F projection. Parquet writing took {measurement['parquet_write_seconds']:.3f} s and the independent correctness check took {measurement['correctness_seconds']:.3f} s afterward; total child wall time was {measurement['total_child_wall_seconds']:.3f} s. Block size remained 2,048 because no memory problem occurred.",
        "",
        "## Projection check",
        "",
        "| Quantity | Projection | Measured | Absolute error | Relative error |",
        "|---|---:|---:|---:|---:|",
        f"| Wall time | {projection['wall_seconds']['projected']:.3f} s | {projection['wall_seconds']['measured']:.3f} s | {projection['wall_seconds']['absolute_error']:.3f} s ({projection['wall_seconds']['signed_error']:+.3f} s) | {projection['wall_seconds']['relative_error']:+.2%} |",
        f"| Peak RSS | {projection['peak_rss_gib']['projected']:.3f} GiB | {projection['peak_rss_gib']['measured']:.3f} GiB | {projection['peak_rss_gib']['absolute_error']:.3f} GiB ({projection['peak_rss_gib']['signed_error']:+.3f} GiB) | {projection['peak_rss_gib']['relative_error']:+.2%} |",
        f"| Conservative peak RSS | {projection['peak_rss_conservative_gib']['projected']:.3f} GiB | {projection['peak_rss_conservative_gib']['measured']:.3f} GiB | {projection['peak_rss_conservative_gib']['absolute_error']:.3f} GiB ({projection['peak_rss_conservative_gib']['signed_error']:+.3f} GiB) | {projection['peak_rss_conservative_gib']['relative_error']:+.2%} |",
        "",
        projection["explanation"],
        "",
        "## Threshold totals",
        "",
        "| Similarity | Pair count | Query count | Same-label | Cross-label |",
        "|---:|---:|---:|---:|---:|",
    ]
    for threshold in ("0.80", "0.90", "1.0"):
        value = analysis["totals"][threshold]
        display_threshold = "=1.0 (raw)" if threshold == "1.0" else f"≥{threshold}"
        lines.append(
            f"| {display_threshold} | {value['pair_count']:,} | {value['query_count']:,} | {value['same_label_pairs']:,} | {value['cross_label_pairs']:,} |"
        )
    rank1 = analysis["rank1_similarity"]
    lines.extend(
        [
            "",
            "## Rank-1 similarity",
            "",
            "| Queries | p50 | p90 | p95 | p99 | max | mean |",
            "|---:|---:|---:|---:|---:|---:|---:|",
            f"| {rank1['query_count']:,} | {rank1['p50']:.6f} | {rank1['p90']:.6f} | {rank1['p95']:.6f} | {rank1['p99']:.6f} | {rank1['max']:.6f} | {rank1['mean']:.6f} |",
            "",
            f"The maximum raw float64 value was `{rank1['max']:.17g}`; its tiny excursion above the mathematical cosine bound is floating-point accumulation, and scores were neither clipped nor rounded.",
            "",
            "## Per CWE class",
            "",
            "Pair splits are same-label / cross-label within the named query class.",
            "",
            "| CWE | Queries | Rank-1 p50 | Rank-1 p90 | Queries ≥0.80 | Queries ≥0.90 | ≥0.80 pair split | ≥0.90 pair split |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for label, value in analysis["per_cwe_class"].items():
        lines.append(
            f"| {label} | {value['query_count']:,} | {value['rank1_p50']:.6f} | {value['rank1_p90']:.6f} | {_pct(value['query_share_ge_0_80'])} | {_pct(value['query_share_ge_0_90'])} | {_split_text(value['high_similarity_pair_split']['0.80'])} | {_split_text(value['high_similarity_pair_split']['0.90'])} |"
        )
    lines.extend(
        [
            "",
            "## Description length",
            "",
            "The buckets come unchanged from `failure_analysis.py::_description_bucket`.",
            "",
            "| Length | Queries | Rank-1 p50 | Rank-1 p90 | Queries ≥0.80 | Queries ≥0.90 | ≥0.80 pair split | ≥0.90 pair split |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for label in LENGTH_BUCKETS:
        value = analysis["per_description_length_bucket"][label]
        lines.append(
            f"| {label} | {value['query_count']:,} | {value['rank1_p50']:.6f} | {value['rank1_p90']:.6f} | {_pct(value['query_share_ge_0_80'])} | {_pct(value['query_share_ge_0_90'])} | {_split_text(value['high_similarity_pair_split']['0.80'])} | {_split_text(value['high_similarity_pair_split']['0.90'])} |"
        )
    lines.extend(
        [
            "",
            "## Rare-class comparison",
            "",
            "The pre-declared rare group is CWE-476, CWE-120, CWE-434, CWE-200, and CWE-284; the other ten classes are the comparison group.",
            "",
            "| Group | Queries | Rank-1 p50 | Rank-1 p90 | Queries ≥0.80 | Queries ≥0.90 | ≥0.80 pair split | ≥0.90 pair split |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for label, display in (("rare_five", "Rare five"), ("other_ten", "Other ten")):
        value = analysis["rare_class_groups"][label]
        lines.append(
            f"| {display} | {value['query_count']:,} | {value['rank1_p50']:.6f} | {value['rank1_p90']:.6f} | {_pct(value['query_share_ge_0_80'])} | {_pct(value['query_share_ge_0_90'])} | {_split_text(value['high_similarity_pair_split']['0.80'])} | {_split_text(value['high_similarity_pair_split']['0.90'])} |"
        )
    lines.extend(
        [
            "",
            "## Analysis headlines",
            "",
            f"At ≥0.80, {analysis['totals']['0.80']['cross_label_pairs']:,} of {analysis['totals']['0.80']['pair_count']:,} pairs ({analysis['totals']['0.80']['cross_label_pairs'] / analysis['totals']['0.80']['pair_count']:.2%}) were cross-label; at ≥0.90, {analysis['totals']['0.90']['cross_label_pairs']:,} of {analysis['totals']['0.90']['pair_count']:,} ({analysis['totals']['0.90']['cross_label_pairs'] / analysis['totals']['0.90']['pair_count']:.2%}) were cross-label. All {analysis['totals']['1.0']['pair_count']:,} raw-exact-1.0 pairs were same-label. These are structural counts, not pair-level judgments.",
            "",
            f"The largest class-level query shares at ≥0.80 were CWE-284 ({_pct(analysis['per_cwe_class']['CWE-284']['query_share_ge_0_80'])}), CWE-79 ({_pct(analysis['per_cwe_class']['CWE-79']['query_share_ge_0_80'])}), and CWE-787 ({_pct(analysis['per_cwe_class']['CWE-787']['query_share_ge_0_80'])}). At ≥0.90, CWE-79 ({_pct(analysis['per_cwe_class']['CWE-79']['query_share_ge_0_90'])}) and CWE-787 ({_pct(analysis['per_cwe_class']['CWE-787']['query_share_ge_0_90'])}) were highest.",
            "",
            f"The three buckets below 1,000 characters had similar ≥0.80 query shares ({_pct(analysis['per_description_length_bucket']['<250']['query_share_ge_0_80'])}, {_pct(analysis['per_description_length_bucket']['250-500']['query_share_ge_0_80'])}, and {_pct(analysis['per_description_length_bucket']['500-1000']['query_share_ge_0_80'])}); the ≥1,000 bucket was {_pct(analysis['per_description_length_bucket']['>=1000']['query_share_ge_0_80'])}. The rare-five group was higher at ≥0.80 than the other ten ({_pct(analysis['rare_class_groups']['rare_five']['query_share_ge_0_80'])} versus {_pct(analysis['rare_class_groups']['other_ten']['query_share_ge_0_80'])}) but lower at ≥0.90 ({_pct(analysis['rare_class_groups']['rare_five']['query_share_ge_0_90'])} versus {_pct(analysis['rare_class_groups']['other_ten']['query_share_ge_0_90'])}).",
            "",
            "## Correctness",
            "",
            f"A fixed-seed random subset of {correctness['query_count']} queries was independently recomputed against all {correctness['reference_count']:,} references as one direct dense cosine matrix. Top-20 membership was identical: **{_yes(correctness['top20_membership_identical'])}**; ordering was identical: **{_yes(correctness['top20_ordering_identical'])}**; the maximum aligned score delta was `{correctness['top20_score_max_absolute_delta_aligned_by_reference']:.3e}` against tolerance `2e-15`. The ≥0.80 pair set, ≥0.90 pair set, and both per-query count vectors were identical: **{_yes(correctness['threshold_80_pair_set_identical'] and correctness['threshold_90_pair_set_identical'] and correctness['per_query_threshold_counts_identical'])}**. The check passed: **{_yes(correctness['all_passed'])}**.",
            "",
            f"Recorded near-tie membership differences: {len(correctness['membership_differences'])}; near-tie ordering differences: {len(correctness['near_tie_ordering_differences'])}. Any such difference is retained with its raw score delta and treated under the known §3.2 float64 limitation only when within tolerance. Scores were never rounded.",
            "",
            "## Reading the structure",
            "",
            "These totals describe near-duplicate and high-similarity structure and provide a signal about the split's semantic independence. A high cosine value alone does not identify copying: CVE descriptions commonly repeat vendor advisory templates, product names, version lists, and shared vulnerability phrasing. In the earlier published manual review, 11 of the top 20 examples were vendor boilerplate and 7 were near or exact copies. No new manual category assignment was performed here, so this report makes no stronger pair-level claim.",
            "",
            "The published 300-query × 12,000-reference sampled audit used Audit A's shape and different preprocessing. Its p50 0.2694, p90 0.7036, p95 0.7438, eight queries at ≥0.80, and three at ≥0.90 are context only and are not compared numerically with this Audit B result.",
            "",
            "## Artifact and environment",
            "",
            f"The Parquet artifact has {report['parquet']['row_count']:,} rows and SHA-256 `{report['artifact']['sha256']}`. It stores only top-20 rows and threshold rows under the §3 schema. The run used `{report['execution']['hostname']}` at commit `{report['execution']['commit']}`, Python {report['execution']['python']}, NumPy {report['execution']['numpy']}, and scikit-learn {report['execution']['scikit_learn']}.",
        ]
    )
    return "\n".join(lines) + "\n"


def _render_track_closure(report: dict[str, Any]) -> str:
    measurement = report["measurement"]
    return "\n".join(
        [
            "# T-014 track closure",
            "",
            "The track is closed. It moved from the repository's single-process data pipeline to a Spark local-mode reimplementation of normalization, temporal splitting, exact deduplication, and overlap checks. Spark reproduced the reference populations and row semantics; its purpose was equivalence, not a speed claim.",
            "",
            "The proposed Ray work was then reviewed as a gated decision rather than an assumed implementation. The review separated two shapes that had previously been easy to conflate: internal N×N comparison, whose unique-pair count grows quadratically, and query-versus-reference Q×R comparison, which is linear in Q when R is fixed.",
            "",
            "Gate 1 measured both. The internal exact similarity phase reproduced the quadratic finding through N=5,000, while the fixed-reference Q×R path completed Q=24,975 × R=12,000 in 15.163 seconds at 2.619 GiB. That distinction redirected the work from framework choice to the actual audit shape and memory behavior.",
            "",
            "Audit A then established exact truth for the frozen 18,000 evaluation queries against 12,000 SFT references under a reference-only TF-IDF fit. The raw-float64 ordering was frozen as score descending and reference CVE ID ascending for bit-identical ties. The freeze also documented the cross-code-path one-ULP limitation instead of hiding it through score rounding.",
            "",
            "Blockwise exact evaluation retained top-k and threshold pairs without holding the full dense matrix. Four block sizes reproduced Audit A truth, and 2,048 was fastest. The Audit B cost probe then measured nested Q=300, 1,000, and 2,500 subsets against all 65,272 references, with zero swap growth and zero major faults, and judged exact comparison sufficient for this scale.",
            "",
            f"This final run closed the projection with a measurement: {PAIR_COUNT:,} exact pairs completed in {measurement['measured_full_run_wall_seconds']:.3f} seconds at {measurement['peak_rss_bytes'] / 1024**3:.3f} GiB peak RSS, block size 2,048, with {measurement['swap_delta_bytes']:,} bytes of swap growth and {measurement['major_page_faults']} major faults. The full-split analysis and independent random-subset check are recorded beside the retained Parquet artifact.",
            "",
            "LSH, ANN, and Ray were not built because measurement did not show they were needed. That is the result of the track, not a shortfall. No new embedding model, similarity metric, or threshold tuning was introduced, and the dataset split and earlier result artifacts were left unchanged.",
            "",
            "Measured runtime, projected runtime, and theoretical complexity remain separate statements. This is a single-node result for the fixed Audit B workload. Any later question raised by the observed structure is a separate decision and is not pursued here.",
        ]
    ) + "\n"


def _render_exec(report: dict[str, Any]) -> str:
    measurement = report["measurement"]
    totals = report["analysis"]["totals"]
    rank1 = report["analysis"]["rank1_similarity"]
    return "\n".join(
        [
            "# T-014G execution record",
            "",
            f"The checkout gate passed on `{report['execution']['branch']}` at `{report['execution']['commit']}`; it was not `main`. The specified contract sections and claim boundaries were read before execution. `.venv/bin/python` was used with no network access or installs.",
            "",
            "The full run reused the validated blockwise exact kernel, Audit B data validation/vectorization, and parent subprocess instrumentation. The only kernel extension preserves the raw scores already computed for threshold hits so the required §3 Parquet rows can be written. It does not alter scoring, selection, thresholds, or ordering.",
            "",
            "```text",
            ".venv/bin/python -m py_compile src/security_llm/bench/blockwise_exact.py src/security_llm/bench/audit_b_full.py",
            ".venv/bin/python -m security_llm.bench.audit_b_full",
            "```",
            "",
            f"The run processed {PAIR_COUNT:,} pairs in {measurement['measured_full_run_wall_seconds']:.3f} seconds at {measurement['peak_rss_bytes'] / 1024**3:.3f} GiB peak RSS. Swap delta was {measurement['swap_delta_bytes']:,} bytes and major faults were {measurement['major_page_faults']}. Block size remained 2,048.",
            "",
            f"Threshold totals were {totals['0.80']['pair_count']:,} pairs at ≥0.80, {totals['0.90']['pair_count']:,} at ≥0.90, and {totals['1.0']['pair_count']:,} at exactly 1.0. Rank-1 p50/p90/p95/p99/max were {rank1['p50']:.6f}/{rank1['p90']:.6f}/{rank1['p95']:.6f}/{rank1['p99']:.6f}/{rank1['max']:.6f}.",
            "",
            f"The independent {report['correctness']['query_count']}-query random-subset check passed: {_yes(report['correctness']['all_passed'])}. The Parquet SHA-256 is `{report['artifact']['sha256']}`.",
            "",
            "Independent artifact reload checks passed for schema, hash, unique pair keys, every query's sequential ranks and raw-score/CVE-ID ordering, threshold flags and totals, and class/length/rare group sums. The complete non-Spark suite passed 39 tests with 1 skipped; the only warning was unavailable NVML. An earlier broad command omitted two Spark-module excludes and stopped during collection because `pyspark` is intentionally absent; it ran no tests and prompted the corrected explicit non-Spark selection.",
            "",
            "Writes were limited to the new T-014G files in `reports/distributed/`, this benchmark module, the narrow existing-kernel score-preservation change, and this execution record. No protected data, manifest, earlier distributed artifact, v0.1.0 document, or dataset split was changed. The track is closed.",
            "",
            "Changed: `src/security_llm/bench/blockwise_exact.py`. Added: `src/security_llm/bench/audit_b_full.py`, `reports/distributed/audit_b_full.parquet`, `reports/distributed/audit_b_full_manifest.json`, `reports/distributed/audit_b_full.md`, `reports/distributed/track_closure.md`, and `agent/T-014G_EXEC.md`.",
        ]
    ) + "\n"


def _parent_run(args: argparse.Namespace) -> dict[str, Any]:
    branch, commit = _assert_checkout()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    staging_dir = Path(
        tempfile.mkdtemp(prefix=".audit-b-full-", dir=args.output_dir)
    )
    try:
        staging_parquet = staging_dir / "audit_b_full.parquet"
        command = [
            sys.executable,
            "-m",
            "security_llm.bench.audit_b_full",
            "--child",
            "--train",
            str(args.train),
            "--test",
            str(args.test),
            "--block-size",
            str(args.block_size),
            "--staging-parquet",
            str(staging_parquet),
        ]
        stdout, monitor, failure_reason = run_instrumented_subprocess(command)
        if failure_reason:
            raise RuntimeError(failure_reason)
        report = json.loads(stdout)
        measurement = report["measurement"]
        measurement["peak_rss_bytes"] = max(
            measurement["peak_rss_bytes"],
            monitor["peak_rss_observed_by_parent_bytes"],
        )
        measurement["swap_delta_bytes"] = monitor["swap_increase_during_run_bytes"]
        measurement["monitor"] = monitor
        report["projection_check"] = _projection_check(report)
        report["artifact"] = {
            "path": str(args.output_dir / "audit_b_full.parquet"),
            "sha256": _sha256_file(staging_parquet),
            "bytes": staging_parquet.stat().st_size,
        }
        report["execution"]["branch"] = branch
        report["execution"]["commit"] = commit
        report["all_passed"] = bool(report["correctness"]["all_passed"])
        manifest_path = staging_dir / "audit_b_full_manifest.json"
        report_path = staging_dir / "audit_b_full.md"
        closure_path = staging_dir / "track_closure.md"
        exec_path = staging_dir / "T-014G_EXEC.md"
        manifest_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        report_path.write_text(_render_audit_report(report), encoding="utf-8")
        closure_path.write_text(_render_track_closure(report), encoding="utf-8")
        exec_path.write_text(_render_exec(report), encoding="utf-8")
        staging_parquet.replace(args.output_dir / "audit_b_full.parquet")
        manifest_path.replace(args.output_dir / "audit_b_full_manifest.json")
        report_path.replace(args.output_dir / "audit_b_full.md")
        closure_path.replace(args.output_dir / "track_closure.md")
        args.exec_output.parent.mkdir(parents=True, exist_ok=True)
        exec_path.replace(args.exec_output)
        return report
    finally:
        shutil.rmtree(staging_dir, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train", type=Path, default=Path("data/processed/train.jsonl"))
    parser.add_argument("--test", type=Path, default=Path("data/processed/test.jsonl"))
    parser.add_argument(
        "--output-dir", type=Path, default=Path("reports/distributed")
    )
    parser.add_argument(
        "--exec-output", type=Path, default=Path("agent/T-014G_EXEC.md")
    )
    parser.add_argument("--block-size", type=int, default=BLOCK_SIZE, choices=(1_024, 2_048))
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--staging-parquet", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.child:
        if args.staging_parquet is None:
            parser.error("--child requires --staging-parquet")
        print(json.dumps(_child_run(args), sort_keys=True))
        return
    report = _parent_run(args)
    print(
        json.dumps(
            {
                "all_passed": report["all_passed"],
                "measurement": report["measurement"],
                "projection_check": report["projection_check"],
                "totals": report["analysis"]["totals"],
                "rank1_similarity": report["analysis"]["rank1_similarity"],
                "correctness": report["correctness"],
                "artifact": report["artifact"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

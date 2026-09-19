"""Measure blockwise exact Audit A top-k and verify it against frozen truth."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import resource
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import numpy as np
import pyarrow.parquet as pq
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from security_llm.bench.audit_a_exact_truth import (
    EXPECTED_QUERY_ROWS,
    EXPECTED_REFERENCE_ROWS,
    EXPECTED_VOCABULARY_SIZE,
    THRESHOLDS,
    TOP_K,
    VECTORIZER_KWARGS,
    _assert_checkout,
    _load_populations,
    _sha256_file,
    _top_k_indices,
)
from security_llm.bench.near_duplicate_scaling import (
    _rss_bytes,
    run_instrumented_subprocess,
)

BLOCK_SIZES = (256, 512, 1024, 2048)
SCORE_ABSOLUTE_TOLERANCE = 2e-15


def _sha256_array(values: np.ndarray) -> str:
    contiguous = np.ascontiguousarray(values)
    return hashlib.sha256(contiguous.view(np.uint8)).hexdigest()


def _merge_top_k(
    previous_scores: np.ndarray,
    previous_indices: np.ndarray,
    block_scores: np.ndarray,
    block_start: int,
    reference_ids: np.ndarray,
) -> tuple[np.ndarray, np.ndarray]:
    """Merge one reference block under (-raw score, reference CVE ID)."""

    query_count = block_scores.shape[0]
    block_indices = np.arange(
        block_start, block_start + block_scores.shape[1], dtype=np.int32
    )
    keep = min(TOP_K, previous_scores.shape[1] + block_scores.shape[1])
    next_scores = np.empty((query_count, keep), dtype=np.float64)
    next_indices = np.empty((query_count, keep), dtype=np.int32)
    for query_index in range(query_count):
        candidate_scores = np.concatenate(
            (previous_scores[query_index], block_scores[query_index])
        )
        candidate_indices = np.concatenate(
            (previous_indices[query_index], block_indices)
        )
        candidate_reference_ids = reference_ids[candidate_indices]
        selected = _top_k_indices(
            candidate_scores, keep, candidate_reference_ids
        )
        next_scores[query_index] = candidate_scores[selected]
        next_indices[query_index] = candidate_indices[selected]
    return next_scores, next_indices


def _blockwise_exact(
    query_matrix: Any,
    reference_matrix: Any,
    reference_ids: np.ndarray,
    block_size: int,
) -> dict[str, Any]:
    query_count = query_matrix.shape[0]
    reference_count = reference_matrix.shape[0]
    top_scores = np.empty((query_count, 0), dtype=np.float64)
    top_indices = np.empty((query_count, 0), dtype=np.int32)
    threshold_80_keys: list[int] = []
    threshold_90_keys: list[int] = []
    threshold_80_counts = np.zeros(query_count, dtype=np.int32)
    threshold_90_counts = np.zeros(query_count, dtype=np.int32)

    started = time.perf_counter()
    for block_start in range(0, reference_count, block_size):
        block_end = min(block_start + block_size, reference_count)
        scores = cosine_similarity(
            query_matrix,
            reference_matrix[block_start:block_end],
            dense_output=True,
        )
        if scores.dtype != np.float64:
            raise RuntimeError(f"expected float64 block scores, found {scores.dtype}")

        hit_queries, hit_local_references = np.nonzero(scores >= THRESHOLDS[0])
        hit_references = block_start + hit_local_references
        hit_keys = hit_queries.astype(np.int64) * reference_count + hit_references
        threshold_80_keys.extend(int(value) for value in hit_keys)
        np.add.at(threshold_80_counts, hit_queries, 1)
        hit_scores = scores[hit_queries, hit_local_references]
        at_90 = hit_scores >= THRESHOLDS[1]
        threshold_90_keys.extend(int(value) for value in hit_keys[at_90])
        np.add.at(threshold_90_counts, hit_queries[at_90], 1)

        top_scores, top_indices = _merge_top_k(
            top_scores,
            top_indices,
            scores,
            block_start,
            reference_ids,
        )
    wall_seconds = time.perf_counter() - started

    return {
        "top_scores": top_scores,
        "top_indices": top_indices,
        "threshold_80_keys": np.sort(
            np.asarray(threshold_80_keys, dtype=np.int64)
        ),
        "threshold_90_keys": np.sort(
            np.asarray(threshold_90_keys, dtype=np.int64)
        ),
        "threshold_80_counts": threshold_80_counts,
        "threshold_90_counts": threshold_90_counts,
        "wall_seconds": wall_seconds,
    }


def _load_truth(
    truth_path: Path,
    query_ids: np.ndarray,
    reference_ids: np.ndarray,
) -> dict[str, np.ndarray]:
    table = pq.read_table(
        truth_path,
        columns=[
            "query_cve_id",
            "reference_cve_id",
            "exact_similarity",
            "rank",
            "threshold_80",
            "threshold_90",
        ],
    )
    query_index = {value: index for index, value in enumerate(query_ids.tolist())}
    reference_index = {
        value: index for index, value in enumerate(reference_ids.tolist())
    }
    top_indices = np.full(
        (len(query_ids), TOP_K), -1, dtype=np.int32
    )
    top_scores = np.full(
        (len(query_ids), TOP_K), np.nan, dtype=np.float64
    )
    threshold_80_keys: list[int] = []
    threshold_90_keys: list[int] = []
    threshold_80_counts = np.zeros(len(query_ids), dtype=np.int32)
    threshold_90_counts = np.zeros(len(query_ids), dtype=np.int32)
    reference_count = len(reference_ids)
    for row in table.to_pylist():
        query = query_index[str(row["query_cve_id"])]
        reference = reference_index[str(row["reference_cve_id"])]
        rank = int(row["rank"])
        if rank <= TOP_K:
            top_indices[query, rank - 1] = reference
            top_scores[query, rank - 1] = float(row["exact_similarity"])
        key = query * reference_count + reference
        if bool(row["threshold_80"]):
            threshold_80_keys.append(key)
            threshold_80_counts[query] += 1
        if bool(row["threshold_90"]):
            threshold_90_keys.append(key)
            threshold_90_counts[query] += 1
    if np.any(top_indices < 0) or np.any(np.isnan(top_scores)):
        raise RuntimeError("truth artifact does not contain a complete top-20")
    return {
        "top_indices": top_indices,
        "top_scores": top_scores,
        "threshold_80_keys": np.sort(
            np.asarray(threshold_80_keys, dtype=np.int64)
        ),
        "threshold_90_keys": np.sort(
            np.asarray(threshold_90_keys, dtype=np.int64)
        ),
        "threshold_80_counts": threshold_80_counts,
        "threshold_90_counts": threshold_90_counts,
    }


def _tie_order_is_valid(
    scores: np.ndarray, indices: np.ndarray, reference_ids: np.ndarray
) -> bool:
    for query_scores, query_indices in zip(scores, indices, strict=True):
        tied = query_scores[:-1] == query_scores[1:]
        if np.any(
            reference_ids[query_indices[:-1]][tied]
            > reference_ids[query_indices[1:]][tied]
        ):
            return False
    return True


def _verify(
    result: dict[str, Any],
    truth: dict[str, np.ndarray],
    reference_ids: np.ndarray,
) -> dict[str, Any]:
    score_deltas = np.abs(result["top_scores"] - truth["top_scores"])
    max_score_delta = float(np.max(score_deltas))
    ids_identical = bool(
        np.array_equal(result["top_indices"], truth["top_indices"])
    )
    scores_bit_identical = bool(
        np.array_equal(result["top_scores"], truth["top_scores"])
    )
    scores_within_tolerance = max_score_delta <= SCORE_ABSOLUTE_TOLERANCE
    threshold_80_sets_identical = bool(
        np.array_equal(
            result["threshold_80_keys"], truth["threshold_80_keys"]
        )
    )
    threshold_90_sets_identical = bool(
        np.array_equal(
            result["threshold_90_keys"], truth["threshold_90_keys"]
        )
    )
    per_query_counts_identical = bool(
        np.array_equal(
            result["threshold_80_counts"], truth["threshold_80_counts"]
        )
        and np.array_equal(
            result["threshold_90_counts"], truth["threshold_90_counts"]
        )
    )
    tie_ordering_identical = bool(
        ids_identical
        and _tie_order_is_valid(
            result["top_scores"], result["top_indices"], reference_ids
        )
        and _tie_order_is_valid(
            truth["top_scores"], truth["top_indices"], reference_ids
        )
    )
    all_passed = bool(
        ids_identical
        and scores_within_tolerance
        and threshold_80_sets_identical
        and threshold_90_sets_identical
        and per_query_counts_identical
        and tie_ordering_identical
    )
    return {
        "top20_reference_id_ordering_identical": ids_identical,
        "top20_scores_bit_identical": scores_bit_identical,
        "top20_score_absolute_tolerance": SCORE_ABSOLUTE_TOLERANCE,
        "top20_score_max_absolute_delta": max_score_delta,
        "top20_scores_within_tolerance": scores_within_tolerance,
        "threshold_80_pair_set_identical": threshold_80_sets_identical,
        "threshold_90_pair_set_identical": threshold_90_sets_identical,
        "per_query_threshold_pair_counts_identical": per_query_counts_identical,
        "tie_ordering_identical": tie_ordering_identical,
        "all_passed": all_passed,
    }


def _child_run(args: argparse.Namespace) -> dict[str, Any]:
    started = time.perf_counter()
    usage_started = resource.getrusage(resource.RUSAGE_SELF)
    branch, commit = _assert_checkout()
    references, queries, _ = _load_populations(
        args.train, args.test, args.subset_manifest
    )
    reference_ids = np.asarray(
        [str(row["cve_id"]) for row in references], dtype=str
    )
    query_ids = np.asarray([str(row["cve_id"]) for row in queries], dtype=str)

    vectorizer = TfidfVectorizer(**VECTORIZER_KWARGS)
    reference_matrix = vectorizer.fit_transform(
        [str(row["description"]) for row in references]
    )
    if len(vectorizer.vocabulary_) != EXPECTED_VOCABULARY_SIZE:
        raise RuntimeError("blockwise vocabulary differs from frozen truth")
    query_matrix = vectorizer.transform(
        [str(row["description"]) for row in queries]
    )
    truth = _load_truth(args.truth, query_ids, reference_ids)
    result = _blockwise_exact(
        query_matrix,
        reference_matrix,
        reference_ids,
        args.block_size,
    )
    equivalence = _verify(result, truth, reference_ids)
    if not equivalence["all_passed"]:
        raise RuntimeError(f"blockwise equivalence failed: {equivalence}")

    np.savez(
        args.staging_result,
        top_scores=result["top_scores"],
        top_indices=result["top_indices"],
        threshold_80_keys=result["threshold_80_keys"],
        threshold_90_keys=result["threshold_90_keys"],
        threshold_80_counts=result["threshold_80_counts"],
        threshold_90_counts=result["threshold_90_counts"],
    )
    pair_count = EXPECTED_QUERY_ROWS * EXPECTED_REFERENCE_ROWS
    usage_finished = resource.getrusage(resource.RUSAGE_SELF)
    total_seconds = time.perf_counter() - started
    return {
        "block_size": args.block_size,
        "fitting_scope": "12,000 reference rows only; queries transformed",
        "ordering_key": (
            "(-raw float64 exact_similarity, reference_cve_id ascending as a string)"
        ),
        "processed_pair_count": pair_count,
        "threshold_pair_counts": {
            "0.80": int(len(result["threshold_80_keys"])),
            "0.90": int(len(result["threshold_90_keys"])),
        },
        "equivalence": equivalence,
        "fingerprints": {
            "top20_reference_indices_sha256": _sha256_array(
                result["top_indices"]
            ),
            "top20_scores_sha256": _sha256_array(result["top_scores"]),
            "threshold_80_pair_set_sha256": _sha256_array(
                result["threshold_80_keys"]
            ),
            "threshold_90_pair_set_sha256": _sha256_array(
                result["threshold_90_keys"]
            ),
        },
        "measurement": {
            "wall_time_seconds": total_seconds,
            "blockwise_exact_seconds": result["wall_seconds"],
            "throughput_pairs_per_second": pair_count / result["wall_seconds"],
            "peak_rss_bytes": _rss_bytes(),
            "major_page_faults": (
                usage_finished.ru_majflt - usage_started.ru_majflt
            ),
            "cpu_user_seconds": usage_finished.ru_utime - usage_started.ru_utime,
            "cpu_system_seconds": usage_finished.ru_stime - usage_started.ru_stime,
        },
        "execution": {
            "branch": branch,
            "commit": commit,
            "hostname": platform.node(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "python_executable": sys.executable,
            "numpy": np.__version__,
            "scikit_learn": sklearn.__version__,
            "logical_cpu_count": os.cpu_count(),
        },
    }


def _cross_block_invariance(
    staged_results: list[dict[str, np.ndarray]], runs: list[dict[str, Any]]
) -> dict[str, Any]:
    baseline = staged_results[0]
    ids_identical = True
    scores_bit_identical = True
    max_score_delta = 0.0
    threshold_sets_identical = True
    per_query_counts_identical = True
    for result in staged_results[1:]:
        ids_identical &= np.array_equal(
            result["top_indices"], baseline["top_indices"]
        )
        scores_bit_identical &= np.array_equal(
            result["top_scores"], baseline["top_scores"]
        )
        max_score_delta = max(
            max_score_delta,
            float(np.max(np.abs(result["top_scores"] - baseline["top_scores"]))),
        )
        threshold_sets_identical &= np.array_equal(
            result["threshold_80_keys"], baseline["threshold_80_keys"]
        ) and np.array_equal(
            result["threshold_90_keys"], baseline["threshold_90_keys"]
        )
        per_query_counts_identical &= np.array_equal(
            result["threshold_80_counts"], baseline["threshold_80_counts"]
        ) and np.array_equal(
            result["threshold_90_counts"], baseline["threshold_90_counts"]
        )
    all_passed = bool(
        ids_identical
        and max_score_delta <= SCORE_ABSOLUTE_TOLERANCE
        and threshold_sets_identical
        and per_query_counts_identical
        and all(run["equivalence"]["tie_ordering_identical"] for run in runs)
    )
    return {
        "block_sizes": [run["block_size"] for run in runs],
        "top20_reference_id_ordering_identical": bool(ids_identical),
        "top20_scores_bit_identical": bool(scores_bit_identical),
        "top20_score_absolute_tolerance": SCORE_ABSOLUTE_TOLERANCE,
        "top20_score_max_absolute_delta": max_score_delta,
        "threshold_pair_sets_identical": bool(threshold_sets_identical),
        "per_query_threshold_pair_counts_identical": bool(
            per_query_counts_identical
        ),
        "tie_ordering_identical": bool(
            all(run["equivalence"]["tie_ordering_identical"] for run in runs)
        ),
        "all_passed": all_passed,
    }


def _render_markdown(report: dict[str, Any]) -> str:
    fit = "12,000-reference-only fit; queries transformed"
    lines = [
        "# Blockwise exact Audit A top-k",
        "",
        f"All similarity figures use the **{fit}**. Each run processes all 18,000 × 12,000 = 216,000,000 exact cosine pairs without materializing the full dense similarity matrix. Similarity counts are lexical-similarity counts, not contamination findings.",
        "",
        "The frozen ordering key is raw float64 `(-exact_similarity, reference_cve_id)` with the CVE ID ascending as a string. The key is applied to every running top-20 merge.",
        "",
        "## Measurements and equivalence",
        "",
        "| Block | Fitting scope | Wall s | Blockwise s | Peak RSS GiB | Pairs | Pairs/s | IDs ordered | Scores | Max |Δ| | ≥0.80 set | ≥0.90 set | Per-query counts | Ties |",
        "|---:|---|---:|---:|---:|---:|---:|---|---|---:|---|---|---|---|",
    ]
    for run in report["runs"]:
        measurement = run["measurement"]
        equivalence = run["equivalence"]
        score_result = (
            "bit-identical"
            if equivalence["top20_scores_bit_identical"]
            else f"within {equivalence['top20_score_absolute_tolerance']:.1e}"
        )
        lines.append(
            f"| {run['block_size']} | {fit} | {measurement['wall_time_seconds']:.3f} | "
            f"{measurement['blockwise_exact_seconds']:.3f} | "
            f"{measurement['peak_rss_bytes'] / 1024**3:.3f} | "
            f"{run['processed_pair_count']:,} | {measurement['throughput_pairs_per_second']:,.0f} | "
            f"{'yes' if equivalence['top20_reference_id_ordering_identical'] else 'no'} | "
            f"{score_result} | {equivalence['top20_score_max_absolute_delta']:.3e} | "
            f"{'yes' if equivalence['threshold_80_pair_set_identical'] else 'no'} | "
            f"{'yes' if equivalence['threshold_90_pair_set_identical'] else 'no'} | "
            f"{'yes' if equivalence['per_query_threshold_pair_counts_identical'] else 'no'} | "
            f"{'yes' if equivalence['tie_ordering_identical'] else 'no'} |"
        )
    invariant = report["cross_block_invariance"]
    lines.extend(
        [
            "",
            f"All four block sizes are invariant: **{'yes' if invariant['all_passed'] else 'no'}**. Cross-block maximum top-20 score delta is `{invariant['top20_score_max_absolute_delta']:.3e}` under the **{fit}**.",
            "",
            "Threshold pair counts are 10,888 at ≥0.80 and 1,735 at ≥0.90 for the **12,000-reference-only fit; queries transformed** in every run. These are similarity counts, not contamination findings.",
            "",
            "## Environment",
            "",
        ]
    )
    first = report["runs"][0]["execution"]
    lines.append(
        f"Measured on `{first['hostname']}` at commit `{first['commit']}` using Python {first['python']}, NumPy {first['numpy']}, and scikit-learn {first['scikit_learn']}. Peak RSS uses the reused parent `/proc` monitor plus child `ru_maxrss`; no Ray or Spark was used."
    )
    lines.extend(
        [
            "",
            "## Scope boundary",
            "",
            "This remains O(Q × R): blockwise execution bounds the dense working matrix but does not reduce the 216,000,000 pair count. Audit B's order-of-minutes estimate in SPEC §6.2 is a projection from Audit A, not a measurement.",
            "",
        ]
    )
    return "\n".join(lines)


def _parent_run(args: argparse.Namespace) -> dict[str, Any]:
    branch, commit = _assert_checkout()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    staging_dir = Path(
        tempfile.mkdtemp(prefix=".blockwise-exact-", dir=args.output_dir)
    )
    runs: list[dict[str, Any]] = []
    staged_results: list[dict[str, np.ndarray]] = []
    try:
        for block_size in BLOCK_SIZES:
            staging_result = staging_dir / f"block-{block_size}.npz"
            command = [
                sys.executable,
                "-m",
                "security_llm.bench.blockwise_exact",
                "--child",
                "--block-size",
                str(block_size),
                "--train",
                str(args.train),
                "--test",
                str(args.test),
                "--subset-manifest",
                str(args.subset_manifest),
                "--truth",
                str(args.truth),
                "--staging-result",
                str(staging_result),
            ]
            stdout, monitor, failure_reason = run_instrumented_subprocess(command)
            if failure_reason:
                raise RuntimeError(
                    f"block size {block_size} failed: {failure_reason}"
                )
            run = json.loads(stdout)
            if run["measurement"]["major_page_faults"] > 0:
                raise RuntimeError(
                    f"block size {block_size} recorded "
                    f"{run['measurement']['major_page_faults']} major page faults"
                )
            run["measurement"]["monitor"] = monitor
            run["measurement"]["peak_rss_bytes"] = max(
                run["measurement"]["peak_rss_bytes"],
                monitor["peak_rss_observed_by_parent_bytes"],
            )
            runs.append(run)
            with np.load(staging_result) as loaded:
                staged_results.append(
                    {name: loaded[name].copy() for name in loaded.files}
                )

        invariance = _cross_block_invariance(staged_results, runs)
        if not invariance["all_passed"]:
            raise RuntimeError(f"cross-block invariance failed: {invariance}")
        for run in runs:
            run["equivalence"]["results_invariant_across_block_sizes"] = True
        report = {
            "schema_version": 1,
            "task": "T-014C blockwise exact top-k",
            "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "branch": branch,
            "commit": commit,
            "fitting_scope": "12,000 reference rows only; queries transformed",
            "truth": {
                "path": str(args.truth),
                "sha256": _sha256_file(args.truth),
            },
            "ordering_key": (
                "(-raw float64 exact_similarity, reference_cve_id ascending as a string)"
            ),
            "score_absolute_tolerance": SCORE_ABSOLUTE_TOLERANCE,
            "runs": runs,
            "cross_block_invariance": invariance,
            "all_passed": True,
        }
        json_path = staging_dir / "blockwise_exact.json"
        markdown_path = staging_dir / "blockwise_exact.md"
        json_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        markdown_path.write_text(_render_markdown(report), encoding="utf-8")
        json_path.replace(args.output_dir / json_path.name)
        markdown_path.replace(args.output_dir / markdown_path.name)
        return report
    finally:
        shutil.rmtree(staging_dir, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train", type=Path, default=Path("data/sft/train.jsonl"))
    parser.add_argument("--test", type=Path, default=Path("data/sft/test.jsonl"))
    parser.add_argument(
        "--subset-manifest",
        type=Path,
        default=Path("reports/eval_subset_manifest.json"),
    )
    parser.add_argument(
        "--truth",
        type=Path,
        default=Path("reports/distributed/audit_a_exact_truth.parquet"),
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("reports/distributed")
    )
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--block-size", type=int, choices=BLOCK_SIZES)
    parser.add_argument("--staging-result", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.child:
        if args.block_size is None or args.staging_result is None:
            parser.error("--child requires --block-size and --staging-result")
        print(json.dumps(_child_run(args), sort_keys=True))
        return
    report = _parent_run(args)
    print(
        json.dumps(
            {
                "all_passed": report["all_passed"],
                "cross_block_invariance": report["cross_block_invariance"],
                "runs": [
                    {
                        "block_size": run["block_size"],
                        "measurement": run["measurement"],
                        "equivalence": run["equivalence"],
                    }
                    for run in report["runs"]
                ],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

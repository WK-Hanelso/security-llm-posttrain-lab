"""Build the exact Audit A nearest-reference truth set."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
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
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from security_llm.bench.near_duplicate_scaling import (
    _matrix_storage_bytes,
    _rss_bytes,
    run_instrumented_subprocess,
)
from security_llm.data.dedup import text_hash

EXPECTED_BRANCH = "feat/distributed-pipeline"
EXPECTED_COMMIT = "d974db7031b26224015e9af350dc62853fc00402"
EXPECTED_QUERY_ROWS = 18_000
EXPECTED_REFERENCE_ROWS = 12_000
EXPECTED_VOCABULARY_SIZE = 42_488
EXPECTED_SUBSET_HASH = "229dd47c3cdeb532d47c2dd8c5962f2c9bff8ff2c6d89d8d2776ee6d09a7d707"
EXPECTED_TRAIN_SHA256_PREFIX = "1887fbb32b6af37f"
TOP_K = 20
THRESHOLDS = (0.80, 0.90)
VECTORIZER_KWARGS = {
    "ngram_range": (1, 2),
    "sublinear_tf": True,
    "min_df": 2,
    "stop_words": None,
}
CONTINUITY_EXPECTED = {
    "query_count": 300,
    "top1_reference_agreement_count": 258,
    "mean_absolute_score_delta_rounded_4dp": 0.0341,
    "max_absolute_score_delta_rounded_4dp": 0.3110,
    "reference_only_ge_0_80_query_count": 18,
}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_lines(values: list[str]) -> str:
    return hashlib.sha256("\n".join(values).encode("utf-8")).hexdigest()


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            for field in ("cve_id", "cwe_id", "description"):
                if field not in row:
                    raise ValueError(f"{path}:{line_number} has no {field}")
            rows.append(row)
    return rows


def _git_value(*args: str) -> str:
    return subprocess.run(
        ["git", *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def _assert_checkout() -> tuple[str, str]:
    branch = _git_value("branch", "--show-current")
    commit = _git_value("rev-parse", "HEAD")
    if branch != EXPECTED_BRANCH:
        raise RuntimeError(f"expected branch {EXPECTED_BRANCH}, found {branch}")
    if branch == "main":
        raise RuntimeError("refusing to run on main")
    if commit != EXPECTED_COMMIT:
        raise RuntimeError(f"expected commit {EXPECTED_COMMIT}, found {commit}")
    return branch, commit


def _load_populations(
    train_path: Path, test_path: Path, subset_manifest_path: Path
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    references = _read_jsonl(train_path)
    test_rows = _read_jsonl(test_path)
    subset_manifest = json.loads(subset_manifest_path.read_text(encoding="utf-8"))
    if len(references) != EXPECTED_REFERENCE_ROWS:
        raise ValueError(
            f"expected {EXPECTED_REFERENCE_ROWS} references, found {len(references)}"
        )
    if subset_manifest.get("count") != EXPECTED_QUERY_ROWS:
        raise ValueError(f"unexpected query manifest count: {subset_manifest.get('count')}")
    if subset_manifest.get("subset_hash") != EXPECTED_SUBSET_HASH:
        raise ValueError("query subset hash differs from the frozen Audit A subset")
    test_sha256 = _sha256_file(test_path)
    if subset_manifest.get("source_sha256") != test_sha256:
        raise ValueError("query manifest source hash differs from the test file")
    train_sha256 = _sha256_file(train_path)
    if not train_sha256.startswith(EXPECTED_TRAIN_SHA256_PREFIX):
        raise ValueError("reference source hash differs from the frozen v1.0 value")

    reference_ids = [str(row["cve_id"]) for row in references]
    if len(reference_ids) != len(set(reference_ids)):
        raise ValueError("reference CVE IDs are not unique")
    test_by_id = {str(row["cve_id"]): row for row in test_rows}
    if len(test_by_id) != len(test_rows):
        raise ValueError("test CVE IDs are not unique")
    query_ids = [str(value) for value in subset_manifest["row_ids"]]
    if len(query_ids) != len(set(query_ids)):
        raise ValueError("query CVE IDs are not unique")
    missing = [cve_id for cve_id in query_ids if cve_id not in test_by_id]
    if missing:
        raise ValueError(f"{len(missing)} frozen query IDs do not resolve")
    if _sha256_lines(query_ids) != EXPECTED_SUBSET_HASH:
        raise ValueError("ordered query CVE IDs do not reproduce subset_hash")
    queries = [test_by_id[cve_id] for cve_id in query_ids]

    reference_hashes = {text_hash(str(row["description"])) for row in references}
    query_hashes = {text_hash(str(row["description"])) for row in queries}
    if set(reference_ids) & set(query_ids):
        raise ValueError("query/reference CVE ID overlap is not zero")
    if reference_hashes & query_hashes:
        raise ValueError("query/reference normalized-text hash overlap is not zero")
    return references, queries, {
        "train_sha256": train_sha256,
        "test_sha256": test_sha256,
        "subset_manifest_sha256": _sha256_file(subset_manifest_path),
    }


def _continuity_check(
    vectorizer: TfidfVectorizer,
    reference_matrix: Any,
    references: list[dict[str, Any]],
    test_path: Path,
    sampled_audit_path: Path,
) -> dict[str, Any]:
    test_by_id = {str(row["cve_id"]): row for row in _read_jsonl(test_path)}
    published = json.loads(sampled_audit_path.read_text(encoding="utf-8"))["rows"]
    if len(published) != CONTINUITY_EXPECTED["query_count"]:
        raise ValueError("published sampled audit does not contain 300 rows")
    query_matrix = vectorizer.transform(
        [test_by_id[str(row["test_cve_id"])]["description"] for row in published]
    )
    similarities = cosine_similarity(query_matrix, reference_matrix, dense_output=True)
    nearest_indices = np.argmax(similarities, axis=1)
    scores = similarities[np.arange(len(published)), nearest_indices]
    published_scores = np.asarray(
        [float(row["similarity"]) for row in published], dtype=np.float64
    )
    deltas = np.abs(scores - published_scores)
    agreement = sum(
        str(references[int(reference_index)]["cve_id"])
        == str(published_row["nearest_train_cve_id"])
        for reference_index, published_row in zip(
            nearest_indices, published, strict=True
        )
    )
    result = {
        "query_count": len(published),
        "top1_reference_agreement_count": int(agreement),
        "top1_reference_agreement_fraction": float(agreement / len(published)),
        "mean_absolute_score_delta": float(np.mean(deltas)),
        "max_absolute_score_delta": float(np.max(deltas)),
        "reference_only_ge_0_80_query_count": int(np.count_nonzero(scores >= 0.80)),
        "published_fitting_scope": "12,000 references plus 300 sampled queries",
        "recomputed_fitting_scope": "12,000 references only; queries transformed",
        "passed": False,
    }
    passed = (
        result["query_count"] == CONTINUITY_EXPECTED["query_count"]
        and result["top1_reference_agreement_count"]
        == CONTINUITY_EXPECTED["top1_reference_agreement_count"]
        and round(result["mean_absolute_score_delta"], 4)
        == CONTINUITY_EXPECTED["mean_absolute_score_delta_rounded_4dp"]
        and round(result["max_absolute_score_delta"], 4)
        == CONTINUITY_EXPECTED["max_absolute_score_delta_rounded_4dp"]
        and result["reference_only_ge_0_80_query_count"]
        == CONTINUITY_EXPECTED["reference_only_ge_0_80_query_count"]
    )
    result["passed"] = passed
    if not passed:
        raise RuntimeError(f"continuity check differs from SPEC section 2: {result}")
    return result


def _top_k_indices(scores: np.ndarray, k: int) -> np.ndarray:
    """Return exact top-k indices ordered by score desc, then reference order."""

    cutoff = np.partition(scores, len(scores) - k)[len(scores) - k]
    above = np.flatnonzero(scores > cutoff)
    tied = np.flatnonzero(scores == cutoff)[: k - len(above)]
    selected = np.concatenate((above, tied))
    return selected[np.lexsort((selected, -scores[selected]))]


def _population_manifest(
    path: Path,
    rows: list[dict[str, Any]],
    source_sha256: str,
) -> dict[str, Any]:
    cve_ids = [str(row["cve_id"]) for row in rows]
    text_hashes = [text_hash(str(row["description"])) for row in rows]
    return {
        "source": str(path),
        "source_sha256": source_sha256,
        "rows": len(rows),
        "ordered_cve_id_sha256": _sha256_lines(cve_ids),
        "ordered_normalized_text_hash_sha256": _sha256_lines(text_hashes),
        "unique_cve_ids": len(set(cve_ids)),
        "unique_normalized_text_hashes": len(set(text_hashes)),
    }


def _write_truth_parquet(
    path: Path,
    similarities: np.ndarray,
    queries: list[dict[str, Any]],
    references: list[dict[str, Any]],
) -> tuple[dict[str, Any], np.ndarray]:
    query_hashes = [text_hash(str(row["description"])) for row in queries]
    reference_hashes = [text_hash(str(row["description"])) for row in references]
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
    top1_scores = np.empty(len(queries), dtype=np.float64)
    threshold_pair_counts = {"0.80": 0, "0.90": 0}
    threshold_query_counts = {"0.80": 0, "0.90": 0}
    threshold_labels = {
        "0.80": {"same_label": 0, "cross_label": 0},
        "0.90": {"same_label": 0, "cross_label": 0},
    }

    for query_index, query in enumerate(queries):
        scores = similarities[query_index]
        top_indices = _top_k_indices(scores, TOP_K)
        threshold_indices = np.flatnonzero(scores >= THRESHOLDS[0])
        selected = np.union1d(top_indices, threshold_indices)
        selected = selected[np.lexsort((selected, -scores[selected]))]
        top1_scores[query_index] = scores[selected[0]]
        query_label = str(query["cwe_id"])
        for rank, reference_index in enumerate(selected, start=1):
            reference = references[int(reference_index)]
            score = float(scores[reference_index])
            at_80 = score >= THRESHOLDS[0]
            at_90 = score >= THRESHOLDS[1]
            columns["query_cve_id"].append(str(query["cve_id"]))
            columns["reference_cve_id"].append(str(reference["cve_id"]))
            columns["query_label"].append(query_label)
            columns["reference_label"].append(str(reference["cwe_id"]))
            columns["exact_similarity"].append(score)
            columns["rank"].append(rank)
            columns["threshold_80"].append(at_80)
            columns["threshold_90"].append(at_90)
            columns["query_text_hash"].append(query_hashes[query_index])
            columns["reference_text_hash"].append(
                reference_hashes[int(reference_index)]
            )
            same_label = query_label == str(reference["cwe_id"])
            if at_80:
                threshold_pair_counts["0.80"] += 1
                threshold_labels["0.80"][
                    "same_label" if same_label else "cross_label"
                ] += 1
            if at_90:
                threshold_pair_counts["0.90"] += 1
                threshold_labels["0.90"][
                    "same_label" if same_label else "cross_label"
                ] += 1
        threshold_query_counts["0.80"] += int(np.any(scores >= THRESHOLDS[0]))
        threshold_query_counts["0.90"] += int(np.any(scores >= THRESHOLDS[1]))

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
    summary = {
        "result_rows": table.num_rows,
        "top_k_rows": len(queries) * TOP_K,
        "threshold_pair_counts": threshold_pair_counts,
        "threshold_query_counts": threshold_query_counts,
        "threshold_label_breakdown": threshold_labels,
        "top1_score_distribution": {
            "p50": float(np.percentile(top1_scores, 50)),
            "p90": float(np.percentile(top1_scores, 90)),
            "p95": float(np.percentile(top1_scores, 95)),
            "max": float(np.max(top1_scores)),
        },
    }
    return summary, top1_scores


def _child_run(args: argparse.Namespace) -> dict[str, Any]:
    started = time.perf_counter()
    usage_started = resource.getrusage(resource.RUSAGE_SELF)
    branch, commit = _assert_checkout()

    phase_started = time.perf_counter()
    references, queries, source_hashes = _load_populations(
        args.train, args.test, args.subset_manifest
    )
    input_seconds = time.perf_counter() - phase_started

    phase_started = time.perf_counter()
    vectorizer = TfidfVectorizer(**VECTORIZER_KWARGS)
    reference_matrix = vectorizer.fit_transform(
        [str(row["description"]) for row in references]
    )
    fit_seconds = time.perf_counter() - phase_started
    vocabulary_size = len(vectorizer.vocabulary_)
    if vocabulary_size != EXPECTED_VOCABULARY_SIZE:
        raise RuntimeError(
            f"expected vocabulary size {EXPECTED_VOCABULARY_SIZE}, found {vocabulary_size}"
        )
    if reference_matrix.dtype != np.float64:
        raise RuntimeError(f"expected float64 references, found {reference_matrix.dtype}")

    phase_started = time.perf_counter()
    continuity = _continuity_check(
        vectorizer,
        reference_matrix,
        references,
        args.test,
        args.sampled_audit,
    )
    continuity_seconds = time.perf_counter() - phase_started

    phase_started = time.perf_counter()
    query_matrix = vectorizer.transform(
        [str(row["description"]) for row in queries]
    )
    transform_seconds = time.perf_counter() - phase_started
    if query_matrix.dtype != np.float64:
        raise RuntimeError(f"expected float64 queries, found {query_matrix.dtype}")

    phase_started = time.perf_counter()
    similarities = cosine_similarity(
        query_matrix, reference_matrix, dense_output=True
    )
    similarity_seconds = time.perf_counter() - phase_started
    if similarities.shape != (EXPECTED_QUERY_ROWS, EXPECTED_REFERENCE_ROWS):
        raise RuntimeError(f"unexpected similarity shape: {similarities.shape}")
    if similarities.dtype != np.float64:
        raise RuntimeError(f"expected float64 similarities, found {similarities.dtype}")

    result_path = args.staging_dir / "audit_a_exact_truth.parquet"
    phase_started = time.perf_counter()
    summary, _ = _write_truth_parquet(
        result_path, similarities, queries, references
    )
    reduction_and_write_seconds = time.perf_counter() - phase_started

    usage_finished = resource.getrusage(resource.RUSAGE_SELF)
    total_seconds = time.perf_counter() - started
    return {
        "schema_version": 1,
        "audit": "Audit A exact truth",
        "branch": branch,
        "commit": commit,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": {
            "hostname": platform.node(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "python_executable": sys.executable,
            "numpy": np.__version__,
            "scikit_learn": sklearn.__version__,
            "pyarrow": pa.__version__,
            "logical_cpu_count": os.cpu_count(),
        },
        "populations": {
            "queries": {
                **_population_manifest(
                    args.test, queries, source_hashes["test_sha256"]
                ),
                "selection_manifest": str(args.subset_manifest),
                "selection_manifest_sha256": source_hashes[
                    "subset_manifest_sha256"
                ],
                "subset_hash": EXPECTED_SUBSET_HASH,
            },
            "references": _population_manifest(
                args.train, references, source_hashes["train_sha256"]
            ),
            "pair_count": EXPECTED_QUERY_ROWS * EXPECTED_REFERENCE_ROWS,
            "cve_id_overlap": 0,
            "normalized_text_hash_overlap": 0,
        },
        "vectorizer": {
            "class": "sklearn.feature_extraction.text.TfidfVectorizer",
            "settings": {
                "ngram_range": [1, 2],
                "sublinear_tf": True,
                "min_df": 2,
                "stop_words": None,
                "dtype": "float64",
            },
            "fitting_scope": "12,000 reference rows only; queries transformed",
            "vocabulary_size": vocabulary_size,
        },
        "similarity": {
            "metric": "cosine",
            "dtype": str(similarities.dtype),
            "shape": list(similarities.shape),
            "dense_bytes": int(similarities.nbytes),
            "exact": True,
            "k": TOP_K,
            "thresholds": list(THRESHOLDS),
            "tie_break": "descending exact similarity, then reference source order",
        },
        "summary": summary,
        "continuity_check": continuity,
        "result": {
            "path": str(args.output_dir / "audit_a_exact_truth.parquet"),
            "format": "parquet",
            "sha256": _sha256_file(result_path),
            "rows": summary["result_rows"],
            "schema": [
                "query_cve_id",
                "reference_cve_id",
                "query_label",
                "reference_label",
                "exact_similarity",
                "rank",
                "threshold_80",
                "threshold_90",
                "query_text_hash",
                "reference_text_hash",
            ],
        },
        "measurement": {
            "wall_time_seconds": total_seconds,
            "phases_seconds": {
                "input_load_and_validation": input_seconds,
                "reference_vectorizer_fit_transform": fit_seconds,
                "continuity_check": continuity_seconds,
                "query_transform": transform_seconds,
                "full_exact_similarity": similarity_seconds,
                "reduction_and_parquet_write": reduction_and_write_seconds,
                "total_child": total_seconds,
            },
            "cpu": {
                "user_seconds": usage_finished.ru_utime - usage_started.ru_utime,
                "system_seconds": usage_finished.ru_stime - usage_started.ru_stime,
            },
            "peak_rss_bytes": _rss_bytes(),
            "major_page_faults": usage_finished.ru_majflt - usage_started.ru_majflt,
            "minor_page_faults": usage_finished.ru_minflt - usage_started.ru_minflt,
            "rss_checkpoints": "child ru_maxrss plus parent /proc sampling",
        },
        "representation": {
            "reference_tfidf_shape": list(reference_matrix.shape),
            "reference_tfidf_nnz": int(reference_matrix.nnz),
            "reference_tfidf_storage_bytes": _matrix_storage_bytes(reference_matrix),
            "query_tfidf_shape": list(query_matrix.shape),
            "query_tfidf_nnz": int(query_matrix.nnz),
            "query_tfidf_storage_bytes": _matrix_storage_bytes(query_matrix),
        },
    }


def _render_markdown(manifest: dict[str, Any]) -> str:
    summary = manifest["summary"]
    distribution = summary["top1_score_distribution"]
    continuity = manifest["continuity_check"]
    measurement = manifest["measurement"]
    fit = "12,000-reference-only fit; queries transformed"
    lines = [
        "# Audit A exact similarity truth",
        "",
        f"All Audit A similarity figures in this report use the **{fit}**. The computation is exact float64 cosine over all 18,000 × 12,000 = 216,000,000 pairs.",
        "",
        "## Top-1 score distribution",
        "",
        "| Fitting scope | p50 | p90 | p95 | max |",
        "|---|---:|---:|---:|---:|",
        f"| {fit} | {distribution['p50']:.6f} | {distribution['p90']:.6f} | {distribution['p95']:.6f} | {distribution['max']:.6f} |",
        "",
        "The distribution is over each query's exact top-1 similarity.",
        "",
        "## Threshold counts",
        "",
        "| Fitting scope | Threshold | Pair count | Queries with ≥1 pair | Same-label pairs | Cross-label pairs |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for threshold in ("0.80", "0.90"):
        breakdown = summary["threshold_label_breakdown"][threshold]
        lines.append(
            f"| {fit} | ≥{threshold} | {summary['threshold_pair_counts'][threshold]} | "
            f"{summary['threshold_query_counts'][threshold]} | {breakdown['same_label']} | "
            f"{breakdown['cross_label']} |"
        )
    lines.extend(
        [
            "",
            "These are lexical-similarity counts, not claims of evaluation leakage. Repeated vendor templates and advisory boilerplate can produce high scores.",
            "",
            "## Continuity check",
            "",
            f"The 300 published sampled-audit queries were recomputed with the **{fit}** and compared with the published rows, whose scores use a **12,000-reference-plus-300-query fit**.",
            "",
            "| Recomputed fitting scope | Top-1 reference agreement | Mean |Δscore| | Max |Δscore| | Recomputed queries ≥0.80 | SPEC §2 expected |",
            "|---|---:|---:|---:|---:|---|",
            f"| {fit} | {continuity['top1_reference_agreement_count']}/{continuity['query_count']} | "
            f"{continuity['mean_absolute_score_delta']:.6f} | {continuity['max_absolute_score_delta']:.6f} | "
            f"{continuity['reference_only_ge_0_80_query_count']} | 258/300; 0.0341; 0.3110; 18 |",
            "",
            f"Continuity result: **{'passed' if continuity['passed'] else 'failed'}**.",
            "",
            "The published sampled-audit p50 0.2694, p90 0.7036, p95 0.7438, ≥0.80 count 8, and ≥0.90 count 3 remain correct for their **12,000-reference-plus-300-query fit**. They are not comparable with, and are not superseded by, the Audit A values above.",
            "",
            "## Measured execution",
            "",
            f"Measured on `{manifest['host']['hostname']}` at commit `{manifest['commit']}`: {measurement['wall_time_seconds']:.3f} s child wall time and {measurement['peak_rss_bytes'] / 1024**3:.3f} GiB peak RSS. Parent-observed peak RSS was {measurement['monitor']['peak_rss_observed_by_parent_bytes'] / 1024**3:.3f} GiB; swap growth was {measurement['monitor']['swap_increase_during_run_bytes']} bytes.",
            "",
            f"The Parquet truth set contains {manifest['result']['rows']:,} rows: exact top-20 rows for every query plus every exact pair at or above 0.80. Its SHA-256 is `{manifest['result']['sha256']}`.",
            "",
        ]
    )
    return "\n".join(lines)


def _parent_run(args: argparse.Namespace) -> dict[str, Any]:
    _assert_checkout()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    staging_dir = Path(
        tempfile.mkdtemp(prefix=".audit-a-exact-", dir=args.output_dir)
    )
    command = [
        sys.executable,
        "-m",
        "security_llm.bench.audit_a_exact_truth",
        "--child",
        "--train",
        str(args.train),
        "--test",
        str(args.test),
        "--subset-manifest",
        str(args.subset_manifest),
        "--sampled-audit",
        str(args.sampled_audit),
        "--output-dir",
        str(args.output_dir),
        "--staging-dir",
        str(staging_dir),
    ]
    try:
        stdout, monitor, failure_reason = run_instrumented_subprocess(command)
        if failure_reason:
            raise RuntimeError(failure_reason)
        try:
            manifest = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"child emitted invalid JSON: {stdout[:500]!r}") from exc
        if manifest["measurement"]["major_page_faults"] > 0:
            raise RuntimeError(
                "child recorded "
                f"{manifest['measurement']['major_page_faults']} major page faults"
            )
        if monitor["swap_increase_during_run_bytes"] > 0:
            raise RuntimeError(
                "host swap usage increased by "
                f"{monitor['swap_increase_during_run_bytes']} bytes"
            )
        manifest["measurement"]["monitor"] = monitor
        manifest["measurement"]["peak_rss_bytes"] = max(
            manifest["measurement"]["peak_rss_bytes"],
            monitor["peak_rss_observed_by_parent_bytes"],
        )
        staged_result = staging_dir / "audit_a_exact_truth.parquet"
        if _sha256_file(staged_result) != manifest["result"]["sha256"]:
            raise RuntimeError("staged Parquet hash changed after child completion")
        manifest_path = staging_dir / "audit_a_exact_truth_manifest.json"
        report_path = staging_dir / "audit_a_exact_truth.md"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        report_path.write_text(_render_markdown(manifest), encoding="utf-8")
        for name in (
            "audit_a_exact_truth.parquet",
            "audit_a_exact_truth_manifest.json",
            "audit_a_exact_truth.md",
        ):
            (staging_dir / name).replace(args.output_dir / name)
        return manifest
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
        "--sampled-audit",
        type=Path,
        default=Path("reports/near_duplicate_audit.json"),
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("reports/distributed")
    )
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--staging-dir", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.child:
        if args.staging_dir is None:
            parser.error("--child requires --staging-dir")
        args.staging_dir.mkdir(parents=True, exist_ok=True)
        print(json.dumps(_child_run(args), sort_keys=True))
        return
    manifest = _parent_run(args)
    print(
        json.dumps(
            {
                "result": manifest["result"],
                "summary": manifest["summary"],
                "continuity_check": manifest["continuity_check"],
                "measurement": manifest["measurement"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

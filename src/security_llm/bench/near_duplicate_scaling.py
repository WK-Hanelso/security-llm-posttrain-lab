"""Measure exact near-duplicate audit scaling in isolated child processes.

This module deliberately retains the dense cosine representation used by the
current audit.  It is a measurement harness, not an optimized implementation.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import inspect
import json
import math
import os
import platform
import random
import resource
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable

import numpy as np
import sklearn

from security_llm.eval import near_duplicate_audit as audit_impl

LADDER = (300, 1_000, 2_500, 5_000, 10_000, 24_975)
SHAPES = ("query_vs_reference", "internal_all_pairs")
REFERENCE_ROWS = 12_000
SEED = audit_impl.SEED
VECTORIZER_KWARGS = {
    "ngram_range": (1, 2),
    "sublinear_tf": True,
    "min_df": 2,
    "stop_words": None,
}
DENSE_DTYPE = np.dtype(np.float64)
RSS_CEILING_BYTES = 12 * 1024**3
WALL_CEILING_SECONDS = 30 * 60
MIN_AVAILABLE_BYTES = 2 * 1024**3
INITIAL_MEMORY_OVERHEAD_BYTES = 1024**3
INITIAL_WALL_SECONDS = 60.0
MONITOR_INTERVAL_SECONDS = 0.1
TREND_MIN_POINTS = 4
QUADRATIC_SLOPE_RANGE = (1.6, 2.4)
TREND_MIN_R_SQUARED = 0.95


def _read_jsonl_descriptions(path: Path) -> list[str]:
    descriptions: list[str] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            try:
                descriptions.append(row["description"])
            except KeyError as exc:
                raise ValueError(f"{path}:{line_number} has no description") from exc
    return descriptions


def _sample_texts(population: list[str], n: int) -> tuple[list[str], str]:
    if n > len(population):
        raise ValueError(f"requested {n} rows from a {len(population)}-row population")
    indices = random.Random(SEED).sample(range(len(population)), n)
    digest = hashlib.sha256(
        ",".join(str(index) for index in indices).encode("ascii")
    ).hexdigest()
    return [population[index] for index in indices], digest


def _rss_bytes() -> int:
    # Linux reports KiB; macOS reports bytes.  This benchmark's recorded host is Linux.
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value * 1024 if sys.platform.startswith("linux") else value)


def _proc_status(pid: int | None = None) -> dict[str, int]:
    target = Path(f"/proc/{pid or 'self'}/status")
    result: dict[str, int] = {}
    try:
        for line in target.read_text(encoding="utf-8").splitlines():
            key, _, raw_value = line.partition(":")
            if key in {"VmRSS", "VmHWM", "Threads"}:
                value = raw_value.strip().split()[0]
                result[key] = int(value) * 1024 if key != "Threads" else int(value)
    except (FileNotFoundError, ProcessLookupError):
        pass
    return result


def _memory_info() -> dict[str, int]:
    wanted = {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}
    values: dict[str, int] = {}
    with Path("/proc/meminfo").open(encoding="utf-8") as handle:
        for line in handle:
            key, _, raw_value = line.partition(":")
            if key in wanted:
                values[key] = int(raw_value.strip().split()[0]) * 1024
    values["SwapUsed"] = values["SwapTotal"] - values["SwapFree"]
    return values


def _load_average() -> dict[str, float]:
    one, five, fifteen = os.getloadavg()
    return {"one_minute": one, "five_minutes": five, "fifteen_minutes": fifteen}


def _audit_vectorizer_settings() -> dict[str, Any]:
    """Extract literal settings from the protected audit and fail on drift."""

    tree = ast.parse(inspect.getsource(audit_impl._nearest_train_rows))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "TfidfVectorizer"
    ]
    if len(calls) != 1:
        raise RuntimeError("could not identify exactly one audit TfidfVectorizer call")
    extracted = {
        keyword.arg: ast.literal_eval(keyword.value)
        for keyword in calls[0].keywords
        if keyword.arg is not None
    }
    if extracted != VECTORIZER_KWARGS:
        raise RuntimeError(
            f"benchmark vectorizer settings drifted: audit={extracted!r}, "
            f"benchmark={VECTORIZER_KWARGS!r}"
        )
    cosine_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "cosine_similarity"
    ]
    dense_values = {
        keyword.arg: ast.literal_eval(keyword.value)
        for call in cosine_calls
        for keyword in call.keywords
        if keyword.arg == "dense_output"
    }
    if len(cosine_calls) != 1 or dense_values != {"dense_output": True}:
        raise RuntimeError("audit no longer has one dense cosine_similarity call")
    return extracted


def _matrix_storage_bytes(matrix: Any) -> dict[str, int]:
    return {
        "data": int(matrix.data.nbytes),
        "indices": int(matrix.indices.nbytes),
        "indptr": int(matrix.indptr.nbytes),
        "total": int(
            matrix.data.nbytes + matrix.indices.nbytes + matrix.indptr.nbytes
        ),
    }


def _child_measure(
    shape: str,
    n: int,
    train_path: Path,
    test_path: Path,
) -> dict[str, Any]:
    started = time.perf_counter()
    usage_started = resource.getrusage(resource.RUSAGE_SELF)
    settings = _audit_vectorizer_settings()

    load_started = time.perf_counter()
    test_population = _read_jsonl_descriptions(test_path)
    query_text, sample_digest = _sample_texts(test_population, n)
    if shape == "query_vs_reference":
        reference_text = _read_jsonl_descriptions(train_path)
        if len(reference_text) != REFERENCE_ROWS:
            raise ValueError(
                f"expected {REFERENCE_ROWS} reference rows, found {len(reference_text)}"
            )
        corpus = reference_text + query_text
    elif shape == "internal_all_pairs":
        reference_text = []
        corpus = query_text
    else:
        raise ValueError(f"unknown shape: {shape}")
    load_seconds = time.perf_counter() - load_started
    rss_after_load = _rss_bytes()

    vectorizer_started = time.perf_counter()
    vectorizer = audit_impl.TfidfVectorizer(**settings)
    matrix = vectorizer.fit_transform(corpus)
    vectorizer_seconds = time.perf_counter() - vectorizer_started
    rss_after_vectorizer = _rss_bytes()

    similarity_started = time.perf_counter()
    if shape == "query_vs_reference":
        similarities = audit_impl.cosine_similarity(
            matrix[len(reference_text) :],
            matrix[: len(reference_text)],
            dense_output=True,
        )
    else:
        similarities = audit_impl.cosine_similarity(
            matrix,
            matrix,
            dense_output=True,
        )
    similarity_seconds = time.perf_counter() - similarity_started
    rss_after_similarity = _rss_bytes()

    reduction_started = time.perf_counter()
    if shape == "internal_all_pairs":
        # Exclude self-pairs without allocating another dense matrix.
        np.fill_diagonal(similarities, -np.inf)
    nearest_indices = np.argmax(similarities, axis=1)
    # Force a scalar read so neither the reduction nor its output is dead work.
    nearest_index_checksum = int(np.asarray(nearest_indices, dtype=np.int64).sum())
    reduction_seconds = time.perf_counter() - reduction_started
    rss_after_reduction = _rss_bytes()

    usage_finished = resource.getrusage(resource.RUSAGE_SELF)
    total_seconds = time.perf_counter() - started
    cpu_seconds = (usage_finished.ru_utime - usage_started.ru_utime) + (
        usage_finished.ru_stime - usage_started.ru_stime
    )
    if shape == "query_vs_reference":
        comparison_count = n * len(reference_text)
        computed_score_count = comparison_count
    else:
        comparison_count = n * (n - 1) // 2
        computed_score_count = n * n

    return {
        "shape": shape,
        "n": n,
        "reference_rows": len(reference_text) if reference_text else None,
        "comparison_count": comparison_count,
        "computed_score_count": computed_score_count,
        "status": "completed",
        "completed": True,
        "stop_reason": None,
        "sampling": {
            "population": str(test_path),
            "population_rows": len(test_population),
            "method": (
                "random.Random(42).sample(range(population_rows), N), preserving "
                "the sampled index order"
            ),
            "seed": SEED,
            "sample_index_sha256": sample_digest,
        },
        "phases_seconds": {
            "input_load_and_sample": load_seconds,
            "vectorizer_fit_transform": vectorizer_seconds,
            "similarity": similarity_seconds,
            "argmax_reduction": reduction_seconds,
            "total_child": total_seconds,
        },
        "cpu": {
            "user_seconds": usage_finished.ru_utime - usage_started.ru_utime,
            "system_seconds": usage_finished.ru_stime - usage_started.ru_stime,
            "total_seconds": cpu_seconds,
            "utilization_percent_of_one_core": 100.0 * cpu_seconds / total_seconds,
        },
        "major_page_faults": usage_finished.ru_majflt - usage_started.ru_majflt,
        "minor_page_faults": usage_finished.ru_minflt - usage_started.ru_minflt,
        "peak_rss_bytes": _rss_bytes(),
        "rss_checkpoints_bytes": {
            "after_load": rss_after_load,
            "after_vectorizer": rss_after_vectorizer,
            "after_similarity": rss_after_similarity,
            "after_reduction": rss_after_reduction,
        },
        "throughput": {
            "comparisons_per_second_total": comparison_count / total_seconds,
            "comparisons_per_second_similarity": (
                comparison_count / similarity_seconds
            ),
            "computed_scores_per_second_similarity": (
                computed_score_count / similarity_seconds
            ),
        },
        "representation": {
            "tfidf_format": matrix.getformat(),
            "tfidf_shape": list(matrix.shape),
            "tfidf_nnz": int(matrix.nnz),
            "tfidf_dtype": str(matrix.dtype),
            "tfidf_storage_bytes": _matrix_storage_bytes(matrix),
            "similarity_format": "dense_numpy_ndarray",
            "similarity_shape": list(similarities.shape),
            "similarity_dtype": str(similarities.dtype),
            "similarity_bytes": int(similarities.nbytes),
            "reduction_dtype": str(nearest_indices.dtype),
            "reduction_bytes": int(nearest_indices.nbytes),
            "nearest_index_checksum": nearest_index_checksum,
            "notable_temporary_allocations": (
                "sklearn sparse matrix multiplication materializes the complete dense "
                "float64 similarity matrix; internal_all_pairs changes its diagonal "
                "in place before argmax, avoiding a second dense mask"
            ),
        },
        "vectorizer": settings,
        "process": {
            "pid": os.getpid(),
            "threads_at_finish": _proc_status().get("Threads"),
        },
    }


def _log_fit(points: Iterable[tuple[float, float]]) -> dict[str, float] | None:
    positive = [(x, y) for x, y in points if x > 0 and y > 0]
    if len(positive) < 2:
        return None
    xs = np.log(np.asarray([point[0] for point in positive], dtype=float))
    ys = np.log(np.asarray([point[1] for point in positive], dtype=float))
    slope, intercept = np.polyfit(xs, ys, 1)
    predicted = intercept + slope * xs
    residual = float(np.sum((ys - predicted) ** 2))
    total = float(np.sum((ys - np.mean(ys)) ** 2))
    r_squared = 1.0 - residual / total if total else 1.0
    return {
        "slope": float(slope),
        "intercept": float(intercept),
        "r_squared": r_squared,
    }


def _project_run(
    shape: str,
    n: int,
    completed: list[dict[str, Any]],
) -> dict[str, Any]:
    score_count = n * REFERENCE_ROWS if shape == "query_vs_reference" else n * n
    dense_bytes = score_count * DENSE_DTYPE.itemsize
    if not completed:
        return {
            "method": "bootstrap_dense_plus_fixed_overhead",
            "peak_rss_bytes": dense_bytes + INITIAL_MEMORY_OVERHEAD_BYTES,
            "wall_time_seconds": INITIAL_WALL_SECONDS,
            "dense_output_bytes": dense_bytes,
            "note": "No measured point was available; this is a conservative bootstrap, not a measured trend.",
        }

    wall_fit = _log_fit(
        (record["n"], record["phases_seconds"]["total_child"])
        for record in completed
    )
    rss_fit = _log_fit(
        (record["n"], record["peak_rss_bytes"]) for record in completed
    )
    if wall_fit is None:
        previous = completed[-1]
        exponent = 1.0 if shape == "query_vs_reference" else 2.0
        wall_prediction = previous["phases_seconds"]["total_child"] * (
            n / previous["n"]
        ) ** exponent
        wall_method = f"one-point expected-order extrapolation (exponent={exponent:g})"
    else:
        wall_prediction = math.exp(
            wall_fit["intercept"] + wall_fit["slope"] * math.log(n)
        )
        wall_method = "log-log regression over completed points"

    if rss_fit is None:
        rss_prediction = completed[-1]["peak_rss_bytes"] * n / completed[-1]["n"]
    else:
        rss_prediction = math.exp(
            rss_fit["intercept"] + rss_fit["slope"] * math.log(n)
        )
    previous = completed[-1]
    previous_dense = previous["representation"]["similarity_bytes"]
    previous_rows = (
        previous["n"] + REFERENCE_ROWS
        if shape == "query_vs_reference"
        else previous["n"]
    )
    target_rows = n + REFERENCE_ROWS if shape == "query_vs_reference" else n
    observed_non_dense = max(0, previous["peak_rss_bytes"] - previous_dense)
    dense_plus_scaled_overhead = dense_bytes + observed_non_dense * (
        target_rows / previous_rows
    )
    memory_prediction = 1.10 * max(rss_prediction, dense_plus_scaled_overhead)
    return {
        "method": wall_method + "; RSS regression/dense floor with 10% guard",
        "peak_rss_bytes": int(memory_prediction),
        "wall_time_seconds": float(wall_prediction * 1.15),
        "dense_output_bytes": dense_bytes,
        "wall_log_fit": wall_fit,
        "rss_log_fit": rss_fit,
    }


def _quadratic_trend(completed: list[dict[str, Any]]) -> dict[str, Any]:
    fit = _log_fit(
        (record["n"], record["phases_seconds"]["similarity"])
        for record in completed
    )
    established = bool(
        len(completed) >= TREND_MIN_POINTS
        and fit is not None
        and QUADRATIC_SLOPE_RANGE[0] <= fit["slope"] <= QUADRATIC_SLOPE_RANGE[1]
        and fit["r_squared"] >= TREND_MIN_R_SQUARED
    )
    return {
        "established": established,
        "points": len(completed),
        "phase": "similarity",
        "accepted_slope_range": list(QUADRATIC_SLOPE_RANGE),
        "minimum_r_squared": TREND_MIN_R_SQUARED,
        "fit": fit,
    }


def _stop_decision(
    shape: str,
    projection: dict[str, Any],
    completed: list[dict[str, Any]],
    global_pressure_reason: str | None,
) -> tuple[str | None, dict[str, Any] | None]:
    if global_pressure_reason:
        return f"prior run triggered stability stop: {global_pressure_reason}", None
    if projection["peak_rss_bytes"] > RSS_CEILING_BYTES:
        return (
            f"projected peak RSS {projection['peak_rss_bytes']} exceeds the "
            f"{RSS_CEILING_BYTES}-byte ceiling",
            None,
        )
    if projection["wall_time_seconds"] > WALL_CEILING_SECONDS:
        return (
            f"projected wall time {projection['wall_time_seconds']:.3f}s exceeds the "
            f"{WALL_CEILING_SECONDS}s ceiling",
            None,
        )
    trend = _quadratic_trend(completed) if shape == "internal_all_pairs" else None
    if trend and trend["established"]:
        fit = trend["fit"]
        return (
            "quadratic similarity trend is already established across "
            f"{trend['points']} points (slope={fit['slope']:.3f}, "
            f"R^2={fit['r_squared']:.4f}); the next step adds no decision-relevant information",
            trend,
        )
    return None, trend


def _terminate_process(process: subprocess.Popen[str]) -> None:
    try:
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            process.kill()
        except ProcessLookupError:
            pass


def _run_child(
    shape: str,
    n: int,
    train_path: Path,
    test_path: Path,
) -> tuple[dict[str, Any], str | None]:
    command = [
        sys.executable,
        "-m",
        "security_llm.bench.near_duplicate_scaling",
        "--child",
        "--shape",
        shape,
        "--n",
        str(n),
        "--train",
        str(train_path),
        "--test",
        str(test_path),
    ]
    before_memory = _memory_info()
    before_load = _load_average()
    parent_started = time.perf_counter()
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    peak_observed_rss = 0
    peak_threads = 0
    minimum_available = before_memory["MemAvailable"]
    maximum_swap_used = before_memory["SwapUsed"]
    runtime_stop_reason: str | None = None
    while process.poll() is None:
        status = _proc_status(process.pid)
        peak_observed_rss = max(peak_observed_rss, status.get("VmRSS", 0))
        peak_threads = max(peak_threads, status.get("Threads", 0))
        memory = _memory_info()
        minimum_available = min(minimum_available, memory["MemAvailable"])
        maximum_swap_used = max(maximum_swap_used, memory["SwapUsed"])
        elapsed = time.perf_counter() - parent_started
        if peak_observed_rss > RSS_CEILING_BYTES:
            runtime_stop_reason = "observed process RSS crossed the 12 GiB hard ceiling"
        elif maximum_swap_used > before_memory["SwapUsed"]:
            runtime_stop_reason = "host swap usage increased during the run"
        elif memory["MemAvailable"] < MIN_AVAILABLE_BYTES:
            runtime_stop_reason = "host available memory fell below the 2 GiB stability floor"
        elif elapsed > WALL_CEILING_SECONDS:
            runtime_stop_reason = "run crossed the 30-minute wall-time ceiling"
        if runtime_stop_reason:
            _terminate_process(process)
            break
        time.sleep(MONITOR_INTERVAL_SECONDS)
    stdout, stderr = process.communicate()
    parent_seconds = time.perf_counter() - parent_started
    after_memory = _memory_info()
    swap_delta = maximum_swap_used - before_memory["SwapUsed"]
    monitor = {
        "parent_wall_seconds": parent_seconds,
        "command": command,
        "exit_code": process.returncode,
        "peak_rss_observed_by_parent_bytes": peak_observed_rss,
        "peak_thread_count": peak_threads,
        "swap_used_before_bytes": before_memory["SwapUsed"],
        "swap_used_after_bytes": after_memory["SwapUsed"],
        "maximum_swap_used_bytes": maximum_swap_used,
        "swap_increase_during_run_bytes": swap_delta,
        "minimum_mem_available_bytes": minimum_available,
        "load_average_before": before_load,
        "load_average_after": _load_average(),
        "stderr": stderr,
    }
    if runtime_stop_reason or process.returncode != 0:
        reason = runtime_stop_reason or (
            f"child failed with exit code {process.returncode}: {stderr.strip()[:500]}"
        )
        return {
            "shape": shape,
            "n": n,
            "reference_rows": REFERENCE_ROWS if shape == "query_vs_reference" else None,
            "comparison_count": (
                n * REFERENCE_ROWS
                if shape == "query_vs_reference"
                else n * (n - 1) // 2
            ),
            "computed_score_count": (
                n * REFERENCE_ROWS if shape == "query_vs_reference" else n * n
            ),
            "status": "failed",
            "completed": False,
            "stop_reason": reason,
            "monitor": monitor,
        }, reason
    try:
        record = json.loads(stdout)
    except json.JSONDecodeError as exc:
        reason = f"child emitted invalid JSON: {exc}; stdout={stdout[:500]!r}"
        record = {
            "shape": shape,
            "n": n,
            "status": "failed",
            "completed": False,
            "stop_reason": reason,
        }
        record["monitor"] = monitor
        return record, reason
    record["monitor"] = monitor
    if record["major_page_faults"] > 0:
        reason = f"child recorded {record['major_page_faults']} major page faults"
        record["pressure_stop_after_completion"] = reason
        return record, reason
    if swap_delta > 0:
        reason = f"host swap usage increased by {swap_delta} bytes"
        record["pressure_stop_after_completion"] = reason
        return record, reason
    return record, None


def _growth_ratios(records: list[dict[str, Any]]) -> None:
    previous_by_shape: dict[str, dict[str, Any]] = {}
    for record in records:
        previous = previous_by_shape.get(record["shape"])
        ratios: dict[str, float | None] = {
            "n": record["n"] / previous["n"] if previous else None,
            "wall_time_total": None,
            "peak_rss": None,
            "comparison_count": (
                record["comparison_count"] / previous["comparison_count"]
                if previous and previous.get("comparison_count")
                else None
            ),
        }
        if record["completed"] and previous and previous["completed"]:
            ratios["wall_time_total"] = (
                record["phases_seconds"]["total_child"]
                / previous["phases_seconds"]["total_child"]
            )
            ratios["peak_rss"] = record["peak_rss_bytes"] / previous["peak_rss_bytes"]
        record["growth_vs_previous_step"] = ratios
        previous_by_shape[record["shape"]] = record


def _environment(branch: str, commit: str) -> dict[str, Any]:
    memory = _memory_info()
    return {
        "branch": branch,
        "implementation_commit": commit,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "hostname": platform.node(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "python_executable": sys.executable,
        "numpy": np.__version__,
        "scikit_learn": sklearn.__version__,
        "logical_cpu_count": os.cpu_count(),
        "memory_total_bytes": memory["MemTotal"],
        "memory_available_at_start_bytes": memory["MemAvailable"],
        "swap_total_bytes": memory["SwapTotal"],
        "swap_used_at_start_bytes": memory["SwapUsed"],
        "thread_environment": {
            key: os.environ.get(key)
            for key in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS")
        },
    }


def _git_value(*args: str) -> str:
    return subprocess.run(
        ["git", *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def run_ladder(train_path: Path, test_path: Path) -> dict[str, Any]:
    branch = _git_value("branch", "--show-current")
    commit = _git_value("rev-parse", "HEAD")
    if branch == "main":
        raise RuntimeError("refusing to benchmark on main")
    _audit_vectorizer_settings()
    if sum(1 for _ in test_path.open(encoding="utf-8")) != LADDER[-1]:
        raise ValueError(f"{test_path} does not contain {LADDER[-1]} rows")
    if sum(1 for _ in train_path.open(encoding="utf-8")) != REFERENCE_ROWS:
        raise ValueError(f"{train_path} does not contain {REFERENCE_ROWS} rows")

    environment = _environment(branch, commit)
    records: list[dict[str, Any]] = []
    completed_by_shape: dict[str, list[dict[str, Any]]] = {
        shape: [] for shape in SHAPES
    }
    global_pressure_reason: str | None = None
    for n in LADDER:
        for shape in SHAPES:
            completed = completed_by_shape[shape]
            projection = _project_run(shape, n, completed)
            stop_reason, trend = _stop_decision(
                shape, projection, completed, global_pressure_reason
            )
            comparisons = (
                n * REFERENCE_ROWS
                if shape == "query_vs_reference"
                else n * (n - 1) // 2
            )
            scores = n * REFERENCE_ROWS if shape == "query_vs_reference" else n * n
            if stop_reason:
                record = {
                    "shape": shape,
                    "n": n,
                    "reference_rows": (
                        REFERENCE_ROWS if shape == "query_vs_reference" else None
                    ),
                    "comparison_count": comparisons,
                    "computed_score_count": scores,
                    "status": "stopped_preflight",
                    "completed": False,
                    "stop_reason": stop_reason,
                    "projection": projection,
                    "trend_at_decision": trend,
                }
            else:
                record, pressure_reason = _run_child(shape, n, train_path, test_path)
                record["projection"] = projection
                if pressure_reason:
                    global_pressure_reason = pressure_reason
                if record["completed"]:
                    completed.append(record)
            record["implementation_commit"] = commit
            record["execution_environment_ref"] = "execution_environment"
            records.append(record)
    _growth_ratios(records)
    trends = {
        shape: {
            "total_wall": _log_fit(
                (record["n"], record["phases_seconds"]["total_child"])
                for record in completed_by_shape[shape]
            ),
            "similarity": _log_fit(
                (record["n"], record["phases_seconds"]["similarity"])
                for record in completed_by_shape[shape]
            ),
            "peak_rss": _log_fit(
                (record["n"], record["peak_rss_bytes"])
                for record in completed_by_shape[shape]
            ),
        }
        for shape in SHAPES
    }
    return {
        "schema_version": 1,
        "benchmark": "Gate 1 exact near-duplicate audit scaling baseline",
        "execution_environment": environment,
        "inputs": {
            "train": str(train_path),
            "train_rows": REFERENCE_ROWS,
            "test": str(test_path),
            "test_rows": LADDER[-1],
        },
        "method": {
            "ladder": list(LADDER),
            "shapes": list(SHAPES),
            "seed": SEED,
            "vectorizer": VECTORIZER_KWARGS,
            "cosine_similarity_dense_output": True,
            "child_isolation": "one fresh subprocess per executed (N, shape)",
            "stop_limits": {
                "projected_peak_rss_bytes": RSS_CEILING_BYTES,
                "projected_wall_seconds": WALL_CEILING_SECONDS,
                "swap_increase_bytes": 0,
                "major_page_faults": 0,
                "minimum_available_memory_bytes_during_run": MIN_AVAILABLE_BYTES,
                "quadratic_trend_min_points": TREND_MIN_POINTS,
                "quadratic_similarity_slope_range": list(QUADRATIC_SLOPE_RANGE),
                "quadratic_trend_min_r_squared": TREND_MIN_R_SQUARED,
            },
        },
        "records": records,
        "observed_log_log_trends": trends,
        "global_pressure_stop_reason": global_pressure_reason,
    }


def _json_default(value: Any) -> Any:
    if isinstance(value, tuple):
        return list(value)
    raise TypeError(f"cannot serialize {type(value).__name__}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train", type=Path, default=Path("data/sft/train.jsonl"))
    parser.add_argument("--test", type=Path, default=Path("data/sft/test.jsonl"))
    parser.add_argument(
        "--output", type=Path, default=Path("reports/distributed/gate1_scaling.json")
    )
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--shape", choices=SHAPES, help=argparse.SUPPRESS)
    parser.add_argument("--n", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.child:
        if args.shape is None or args.n is None:
            parser.error("--child requires --shape and --n")
        result = _child_measure(args.shape, args.n, args.train, args.test)
        print(json.dumps(result, default=_json_default, sort_keys=True))
        return
    result = run_ladder(args.train, args.test)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, default=_json_default, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()

# T-014G execution record

The checkout gate passed on `feat/distributed-pipeline` at `be0f6e690e71e15bd49ee49a5d3acff79feb0a43`; it was not `main`. The specified contract sections and claim boundaries were read before execution. `.venv/bin/python` was used with no network access or installs.

The full run reused the validated blockwise exact kernel, Audit B data validation/vectorization, and parent subprocess instrumentation. The only kernel extension preserves the raw scores already computed for threshold hits so the required §3 Parquet rows can be written. It does not alter scoring, selection, thresholds, or ordering.

```text
.venv/bin/python -m py_compile src/security_llm/bench/blockwise_exact.py src/security_llm/bench/audit_b_full.py
.venv/bin/python -m security_llm.bench.audit_b_full
```

The run processed 1,630,168,200 pairs in 96.639 seconds at 1.411 GiB peak RSS. Swap delta was 0 bytes and major faults were 0. Block size remained 2,048.

Threshold totals were 54,440 pairs at ≥0.80, 8,098 at ≥0.90, and 314 at exactly 1.0. Rank-1 p50/p90/p95/p99/max were 0.358505/0.763898/0.846306/0.961955/1.000000.

The independent 100-query random-subset check passed: yes. The Parquet SHA-256 is `aa563fb43022a14b0c16644163fbc2371ac8500c7e6de0670b4f8d0857879d17`.

Independent artifact reload checks passed for schema, hash, unique pair keys, every query's sequential ranks and raw-score/CVE-ID ordering, threshold flags and totals, and class/length/rare group sums. The complete non-Spark suite passed 39 tests with 1 skipped; the only warning was unavailable NVML. An earlier broad command omitted two Spark-module excludes and stopped during collection because `pyspark` is intentionally absent; it ran no tests and prompted the corrected explicit non-Spark selection.

Writes were limited to the new T-014G files in `reports/distributed/`, this benchmark module, the narrow existing-kernel score-preservation change, and this execution record. No protected data, manifest, earlier distributed artifact, v0.1.0 document, or dataset split was changed. The track is closed.

Changed: `src/security_llm/bench/blockwise_exact.py`. Added: `src/security_llm/bench/audit_b_full.py`, `reports/distributed/audit_b_full.parquet`, `reports/distributed/audit_b_full_manifest.json`, `reports/distributed/audit_b_full.md`, `reports/distributed/track_closure.md`, and `agent/T-014G_EXEC.md`.

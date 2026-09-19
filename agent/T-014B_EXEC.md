# T-014B execution record

## Preconditions and constraints

I ran:

```text
git branch --show-current
git rev-parse HEAD
```

The results were `feat/distributed-pipeline` and
`d974db7031b26224015e9af350dc62853fc00402`, matching the requested branch and
HEAD (`d974db7`). The branch was not `main`. I used `.venv/bin/python`, did not
use the network, did not install anything, and did not write, install, or run
Ray or Spark.

I read `docs/SPEC_candidate_reduction.md` in full before implementation, then
read the complete protected audit and the scaling harness. The SPEC was
consistent with the inputs and measured continuity check, so I did not change
it or any v0.1.0 document.

## Implementation

I added `src/security_llm/bench/audit_a_exact_truth.py`. It:

- resolves the 18,000 manifest IDs in their frozen order against
  `data/sft/test.jsonl` and reads all 12,000 rows from `data/sft/train.jsonl`;
- checks source hashes, ordered subset hash, row counts, ID uniqueness, zero
  cross-population CVE-ID overlap, and zero normalized-text-hash overlap;
- fits `TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=2,
  stop_words=None)` on the 12,000 references only, checks vocabulary size
  42,488, and transforms the queries;
- gates the full run on the required 300-query continuity check;
- computes the complete dense float64 18,000 × 12,000 cosine matrix;
- retains exact top-20 rows plus every pair at or above 0.80 (which necessarily
  includes every pair at or above 0.90), with deterministic ties ordered by
  reference source order; and
- stages all output, verifies the Parquet hash, and promotes it only after the
  monitored child passes.

I factored `run_instrumented_subprocess` out of
`src/security_llm/bench/near_duplicate_scaling.py` and made its existing ladder
runner call that same helper. T-014B therefore reuses Gate 1's child-process
RSS, thread, swap, available-memory, wall-time, load, exit-code, and stderr
instrumentation rather than introducing another measurement implementation.

I added focused tests for descending exact-score order and deterministic
reference-order tie breaking.

## Commands and execution

Before writing task outputs I independently ran the continuity calculation. It
returned vocabulary size 42,488, agreement 258/300, mean absolute delta
0.034069134827614145, maximum absolute delta 0.31103686424728283, and 18
reference-only-fit queries at or above 0.80. This reproduced SPEC §2.

I compiled and checked the implementation:

```text
.venv/bin/python -m py_compile \
  src/security_llm/bench/near_duplicate_scaling.py \
  src/security_llm/bench/audit_a_exact_truth.py
git diff --check
```

I then ran:

```text
.venv/bin/python -m security_llm.bench.audit_a_exact_truth
```

The first cold child completed its computation but recorded 45 major page
faults, so the unchanged inherited pressure gate rejected it and no final
artifacts were promoted. This matches the cold-start behavior documented in
T-013. I reran the identical command after the local files and libraries were
warmed; I did not relax any gate. The accepted child recorded zero major page
faults and zero swap growth.

## Exact results

Every similarity figure in this section uses a **12,000-reference-only fit;
queries transformed**.

The exact top-1 score distribution over 18,000 queries was:

| p50 | p90 | p95 | max |
|---:|---:|---:|---:|
| 0.3351166136 | 0.7716625427 | 0.8376524234 | 1.0000000000000004 |

Threshold-pair counts and label breakdowns were:

| Threshold | Exact pairs | Queries with ≥1 | Same-label pairs | Cross-label pairs |
|---:|---:|---:|---:|---:|
| ≥0.80 | 10,888 | 1,326 | 10,578 | 310 |
| ≥0.90 | 1,735 | 424 | 1,714 | 21 |

These are lexical-similarity counts, not claims of evaluation leakage.

The Parquet file contains 362,631 rows: 360,000 rank-1-through-rank-20 rows and
2,631 additional threshold rows. Its SHA-256 is
`c6552a72c60b5643d73121c18991e7bb2f8dd41fb2f58f89c98f86d1641df0d3`.

## Continuity check and claim boundary

The recomputed 300-query figures use the **12,000-reference-only fit; queries
transformed**. Compared with the published rows, whose scores use a
**12,000-reference-plus-300-query fit**, the result was:

- top-1 reference agreement: 258/300;
- mean absolute score delta: 0.0340691348 (0.0341 at SPEC precision);
- maximum absolute score delta: 0.3110368642 (0.3110 at SPEC precision); and
- recomputed ≥0.80 query count: 18.

This exactly reproduces the SPEC §2 values. The published sampled-audit p50
0.2694, p90 0.7036, p95 0.7438, ≥0.80 count 8, and ≥0.90 count 3 remain correct
for their **12,000-reference-plus-300-query fit**. Those values are not
comparable with, and are not superseded by, this Audit A result.

## Measured execution

The accepted run measured 12.136107 s child wall time and 2,328,363,008 bytes
(2.168 GiB) peak RSS on `hanelso-GL73-8SE`. The parent wall time was 14.245203
s. The full exact-similarity phase measured 4.552359 s. These are measured
single-host values for this commit and workload.

## Verification

I independently loaded and checked the final Parquet artifact. Assertions
confirmed:

- the required ten-field schema, with float64 exact similarity and int32 rank;
- 362,631 rows, 18,000 query groups, and 362,631 unique query/reference pairs;
- contiguous ranks and non-increasing score order in every query group;
- exactly 360,000 rows at ranks 1–20;
- every row beyond rank 20 has exact similarity at or above 0.80;
- threshold booleans exactly match the stored float64 scores;
- threshold pair/query counts and top-1 percentiles reproduce the manifest;
  and
- the Parquet SHA-256 reproduces the manifest.

The non-Spark suite passed: **37 passed, 1 skipped**. A 10 × 12,000
`near_duplicate_scaling --child` smoke run also passed after the shared-monitor
refactor. `py_compile` and `git diff --check` passed.

## Files

Changed:

- `src/security_llm/bench/near_duplicate_scaling.py`

Added:

- `src/security_llm/bench/audit_a_exact_truth.py`
- `tests/test_audit_a_exact_truth.py`
- `reports/distributed/audit_a_exact_truth.parquet`
- `reports/distributed/audit_a_exact_truth_manifest.json`
- `reports/distributed/audit_a_exact_truth.md`
- `agent/T-014B_EXEC.md`

`agent/` is locally ignored, so the orchestrator must add the execution record
explicitly. Nothing needs a human decision.

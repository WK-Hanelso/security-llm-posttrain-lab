# T-014F execution record — Audit B blockwise exact cost probe

## Preconditions and scope

The hard checkout gate passed before any task action: branch `feat/distributed-pipeline`, HEAD
`e38df7f29cafe62ef96a84575ede76e8a850ce8f`; the checkout was not `main`. I read
`docs/SPEC_candidate_reduction.md` §§3.2, 8, and 10 first. The run used
`.venv/bin/python`, NumPy/scikit-learn on CPU, and made no network request or install. No LSH,
ANN, approximate retrieval, Ray, or Spark was implemented or run.

The protected processed data was read only. Writes were limited to the new Audit B files in
`reports/distributed/`, the new benchmark harness in `src/security_llm/bench/`, and this
execution record. No v0.1.0 document or Audit A truth artifact was modified.

## Query freeze before measurement

Before any similarity probe, I froze one full permutation of the 24,975 processed-test row
indices with `random.Random(20260919).sample(range(24975), 24975)`. Each subset is a prefix of
that permutation, so Q=300 is nested in Q=1,000, which is nested in Q=2,500. The manifest
stores all ordered query IDs, per-Q ordered-ID hashes, `cwe_id` distributions, untruncated
`description_en` character-length histograms and summary statistics, source hashes, and the
selection method.

- Manifest SHA-256: `71a4d37379df7b14cc6f94e00839176b052aa7ee075fc75f56d01423cd37132f`
- Train SHA-256: `99eeef47cc042bf9eaceaf68b50b67c8e547f35935accb3beb1388e33ea6d423`
- Test SHA-256: `f1160c6f5e2c5503b320d525a488121645f5405f1b2318a5b1ba4c3e21c9079b`

An independent reload reproduced every subset hash, confirmed each class and length histogram
sums to Q, and confirmed nesting. Queries were not reselected after results were observed.

## What ran

The harness imports the T-014C `_blockwise_exact` implementation rather than reimplementing
its kernel and uses `run_instrumented_subprocess` for parent-observed RSS and host-pressure
monitoring. Audit B fits TF-IDF on all 65,272 `data/processed/train.jsonl` references using
untruncated `description_en`, then transforms the frozen queries. Every child reproduced the
§8.3 vocabulary size of 169,215.

Block size 2,048 was held fixed across the ladder. Peak RSS stayed below 0.65 GiB, so there was
no reason to drop to 1,024. Each Q ran in an isolated child.

```text
.venv/bin/python -m py_compile src/security_llm/bench/audit_b_cost_probe.py
.venv/bin/python -m security_llm.bench.audit_b_cost_probe --freeze-manifest
.venv/bin/python -m security_llm.bench.audit_b_cost_probe
```

## Measured results

Wall time is end-to-end child time. Pairs/s and queries/s use the blockwise exact phase.
Absolute time is host/load dependent; growth ratios are the durable reading.

| Q | R | Audit B pairs | Block | Wall s | Exact s | Peak RSS GiB | Pairs/s | Queries/s | Q growth | Wall growth | RSS growth | Swap delta | Major faults | CPU | Status |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 300 | 65,272 | 19,581,600 | 2,048 | 7.694 | 1.213 | 0.598 | 16,145,628 | 247.36 | — | — | — | 0 B | 0 | 100.0% | success |
| 1,000 | 65,272 | 65,272,000 | 2,048 | 10.113 | 3.651 | 0.605 | 17,876,243 | 273.87 | 3.333× | 1.315× | 1.010× | 0 B | 0 | 100.0% | success |
| 2,500 | 65,272 | 163,180,000 | 2,048 | 15.724 | 9.111 | 0.645 | 17,911,176 | 274.41 | 2.500× | 1.555× | 1.068× | 0 B | 0 | 100.0% | success |

From Q=1,000 to Q=2,500, Q grew 2.500×, wall time grew 1.555×, and peak RSS grew
1.068×. The fixed reference load/vectorizer fit makes end-to-end growth sublinear over these
small Q values; the exact kernel remains O(Q × R). All ladder runs succeeded with zero swap
growth and zero major page faults.

Q=5,000 was not run. The three required points had stable decision-relevant behaviour, the
wall-time fit had R² 0.9997, the Q=1,000 and Q=2,500 kernel throughputs were nearly identical,
and the full-run classification was unambiguous.

## Correctness

The first 50 IDs from the already-frozen Q=300 subset were checked against all 65,272 Audit B
references. The comparison independently materialized one direct dense cosine matrix and used
a full `np.lexsort` per query for direct top-20 selection.

- Audit B top-20 membership matched for every query.
- Audit B top-20 ordering matched for every query; there were zero near-tie ordering
  differences to record.
- Audit B top-20 scores matched with maximum aligned absolute delta `0.0`, within `2e-15`.
- Audit B raw-float64 ≥0.80 and ≥0.90 pair sets matched exactly.
- Audit B per-query threshold counts matched exactly at both thresholds.
- The 50-query Audit B spot-check contained 225 similarity pairs at ≥0.80 and 34 at ≥0.90.
  These are similarity counts, not contamination findings.

No score was rounded to force agreement; all threshold decisions used raw float64 values.

## Labelled full-run projection

This is a **projection, not a measurement**. An ordinary least-squares line through the three
measured Q points, assuming linearity in Q at fixed R=65,272, block size 2,048, software, host,
and comparable load, projects full Q=24,975 Audit B to **98.1 seconds (1.63 minutes)** and
**1.144 GiB peak RSS**. The wall fit has R² 0.9997 and the peak-RSS fit R² 0.9621. A 31%
memory sensitivity, reflecting Gate 1's projection miss, is **1.499 GiB**. The full 1,630,169,200-
pair Audit B run was not executed in this task.

## §8.7 decision

Exact is sufficient at this scale; it is not the bottleneck. The decision rests on the
measured Q=2,500 result (15.724 seconds, 0.645 GiB peak RSS, zero swap growth, zero major page
faults), stable Q scaling, the passing dense correctness check, and the separately labelled
1.63-minute/1.144-GiB full-run projection. T-014D should not open, and candidate reduction is
not needed or built.

## Divergences and failures

There were no run failures and no contract divergence. The default block size remained 2,048.
The optional Q=5,000 point was deliberately omitted for the documented decision-relevance
reason. The full Audit B run was deliberately not executed, as required.

## Files

Added:

- `src/security_llm/bench/audit_b_cost_probe.py`
- `reports/distributed/audit_b_probe_queries.json`
- `reports/distributed/audit_b_cost_probe.json`
- `reports/distributed/audit_b_cost_probe.md`
- `agent/T-014F_EXEC.md`

No existing tracked file was modified.

# Data engineering learning track — technical record

Written for an engineer opening this repository for the first time and asking what was built on
top of the v0.1.0 dataset work, and why.

This is a record of decisions, not a feature list. Every number below is taken from a committed
artifact under `reports/`; nothing is re-derived from memory. `main` at `cb268c8` was never
modified.

The short version: the track started expecting to need Spark, Ray and approximate nearest
neighbour search. It measured first, and ended up keeping one of the three.

---

## 1. Decision timeline

Each row is a hypothesis, what was measured against it, and what was decided.

| # | Hypothesis | Measurement | Decision |
|---|---|---|---|
| 1 | A Spark reimplementation of the dataset pipeline can reproduce the reference exactly | E1–E12 row-level checks, all 12 passed | Keep Spark for the ETL half |
| 2 | Ray would help the near-duplicate audit | Pair counts: a full-population internal audit is 33.3 billion pairs, ~266 GB for upper-triangle float64 alone | **Ray not built** — the bottleneck is algorithmic, not worker count |
| 3 | The audit's cost grows quadratically | Gate 1, log-log slope **1.870** (R² 0.9995), independently re-measured at **1.940** (R² 0.9985) | Confirmed for internal all-pairs |
| 4 | …and the existing audit has the same shape | It does not: query-vs-fixed-reference is **linear in Q** (slope 1.086) | Measure both shapes separately, always |
| 5 | Approximate candidate reduction will be needed at Audit B's 1.63 billion pairs | Cost probe, then the full run: **96.639 s, 1.411 GiB** | **LSH and ANN not built** — exact is practical at this scale |
| 6 | Incremental downstream rebuild will save meaningful time | 90.7% of work stays global; verification costs more than the saving | **Case B** — keep the deterministic full rebuild |
| 7 | A CVSS-only change alters nothing | It alters intermediate artifacts but not composition or final bytes | Equivalence has **three** layers, not two |
| 8 | Incremental NVD ingest can replace a full fetch | Content observed changing while `lastModified` did not | **Redefined** as a freshness mechanism; full reconciliation is mandatory |
| 9 | Change volume is ~8,000 rows/day (from a 2-hour probe) | Wider measurement: **~1,240 rows/day** | Initial extrapolation was **6.5× too high**; stop extrapolating short bursts |

Rows 2, 5, 6, 7, 8 and 9 are hypotheses that failed or were corrected. They are kept.

---

## 2. Spark track

E1–E12 compare the Spark output against the reference pipeline at row level, not by row count:
normalized rows, CVE-ID sets, per-field equality, selected top-15 labels and their order, split
assignment, class distribution, dedup survivor identity, and cross-split overlap. **All twelve
passed.**

The check that mattered was E9 — the surviving `cve_id` set after deduplication. A bare
`dropDuplicates` gives the right row count with the wrong survivors; the reference keeps the
first row by `(published, cve_id)`, so Spark had to reproduce that with a window function.

| Run | Track A total |
|---|---:|
| `local[1]` | 85.798 s |
| `local[8]` | 45.363 s |

Running the same Spark workload in local mode, `local[8]` was **1.89×** faster than `local[1]`.
That is a local-mode observation. It is not a cluster claim, and it is not compared against the
single-process reference, whose post-ingest interval covers different work.

## 3. Near-duplicate scaling

Two shapes exist and they grow at different orders:

- **internal all-pairs**, `N(N−1)/2` — quadratic
- **query × fixed reference**, `Q × R` — linear in Q

Measuring only the second would have shown a clean linear curve and hidden the quadratic
problem entirely. This separation is the most reusable thing in the track.

## 4. Audit A — exact truth

The population that the contamination question actually concerns: the **18,000** frozen
evaluation IDs against the **12,000** actual SFT training rows, 216,000,000 potential pairs.
Exact truth in **12.136 s** at 2.168 GiB, keeping each query's top-20 plus every pair at or
above the thresholds — 362,631 unique pairs.

The vectorizer is fitted on the **12,000 references only**. The existing sampled audit fits on
references *plus* the query set, which means reference vectors change when the query set
changes — measured: scaling that recipe to 18,000 queries moves the nearest reference for 86 of
300 published queries. Under a query-dependent fit, an index over the references is not even
well defined, so candidate reduction could not have been built on it.

## 5. Deterministic ordering

Key: `(-exact_similarity, reference_cve_id)`, applied at **selection**, not only at display.

| Effect | Count |
|---|---:|
| Queries whose top-20 ordering changes | 4,125 |
| Positions moved | 14,871 |
| Queries whose top-20 **membership** changes | 533 |
| Membership changes involving unequal scores | **0** |

All 533 are ties spanning the rank-20 boundary. Threshold counts stayed invariant.

**Limitation found while verifying:** the key orders by `cve_id` only when scores are
bit-identical. Re-deriving the truth with a dense matmul instead of the generator's path
disagreed on 2 of 250 sampled queries, at deltas around 1.1e-16. Same-path runs are exact;
cross-implementation comparison carries a `2e-15` tolerance. Scores are never rounded to force
agreement.

## 6. Blockwise exact

| Block | Wall | Peak RSS |
|---:|---:|---:|
| 256 | 41.7 s | 0.571 GiB |
| 512 | 28.7 s | 0.580 GiB |
| 1024 | 21.0 s | 0.726 GiB |
| 2048 | 16.8 s | 0.999 GiB |
| dense | 12.136 s | 2.168 GiB |

Every block size produced scores **bit-identical** to the truth set, maximum delta exactly 0.0,
because blocking along the reference axis does not change any individual dot product.

This does **not** reduce pair count — complexity stays `O(Q × R)`. It bounds memory and gives an
exact verification primitive for reference populations where dense does not fit.

## 7. Full Audit B

24,975 queries × 65,272 references = **1,630,168,200** pairs.

| | Measured |
|---|---:|
| Full-run wall (comparable to the projection) | **96.639 s** |
| Exact kernel phase alone | 88.026 s |
| Total child wall incl. Parquet write and correctness check | 102.405 s |
| Peak RSS | **1.411 GiB** |
| Swap growth / major faults | 0 / 0 |

Against the projection: wall −1.44%, peak RSS +23.30% over the primary estimate but −5.90%
under the conservative one.

Structure, at the 65,272-reference-only fit on untruncated `description_en`:

| Threshold | Pairs | Queries | Same-label | Cross-label |
|---|---:|---:|---:|---:|
| ≥ 0.80 | 54,440 | 1,903 | 53,206 | 1,234 |
| ≥ 0.90 | 8,098 | 627 | 8,012 | 86 |
| = 1.0 | 314 | 92 | 314 | 0 |

Rank-1 similarity p50 0.358505, p90 0.763898, p95 0.846306, p99 0.961955.

These are **near-duplicate structure counts, not contamination findings**. CVE text repeats
vendor advisory templates, product naming and version lists; the published manual review of the
top 20 found 11 of 20 to be boilerplate against 7 near/exact copies. High-similarity mass sits
in short descriptions — 7.6–8.1% of queries at or above 0.80 below 1,000 characters against
1.56% at or above 1,000 — which is what template reuse looks like.

## 8. Downstream incremental (T-015)

Six raw fields can reach the dataset: `id`, `published`, `descriptions`, `vulnStatus`,
`weaknesses`, `cisaExploitAdd`. CVSS and `lastModified` are recorded but never read downstream.

Dependency classes, measured rather than argued:

| Stage | Class | Evidence |
|---|---|---|
| normalize, eligibility, split assignment, row serialization | local | per-record |
| label selection | global, bounded | rank-15 CWE-284 at 1,456 vs rank-16 CWE-77 at 1,325 — margin 131 |
| dedup survivor | global, group-scoped | 1,343 multi-row hash groups, 4,770 rows, 3,427 dropped |
| **SFT sampling** | **global, unbounded** | one insert into 65,272 replaces **4,492 of 12,000** sampled rows (37%) |

The sampling result is the constraint: `random.sample` draws indices as a function of
population size, so any size change forces a full redraw and the new dataset is a different
draw, not a superset.

**The three equivalence layers** came out of a failed negative control. A CVSS-only change was
predicted to alter nothing; it leaves `data/sft/*.jsonl` byte-identical but does change
`normalized.jsonl`, because `normalize_record` emits the CVSS fields and `to_sft_row` does not.
Composition, final bytes and intermediate bytes are three separate claims.

Decision: production `normalize` alone is 38.60 s of a 56.18 s post-ingest total — 69% of
downstream cost in the one fully local stage — but 90.7% of the row-visit proxy stays global,
and **verifying an incremental result needs a full rebuild**: checking every run projects
74.01 s against a 56.18 s rebuild. **Case B — keep the deterministic full rebuild.**

## 9. Incremental NVD ingest (T-016)

The real bottleneck: ingest is 2–2.5 hours, downstream is 56 seconds.

**The existing completeness gate cannot fail.** `ingest_nvd.py` appends `"complete": True` as a
literal, and `normalize()` skips windows on exactly that field. There is also no check that
summed page rows equal `totalResults`, no checkpoint before the final window, no revalidation of
cached pages, and no detection of `totalResults` drift.

### 9.1 API behaviour, probed (32 requests, no key, 7 s apart)

Confirmed: the lastMod interval is **`[start, end)`**; millisecond precision is honoured;
zone-less timestamps are UTC and `Z`, `+00:00` and shifted offsets are equivalent; newly
published CVEs appear (481 of 672 in a recent window); rejected records are returned by default;
refetching a window is a no-op down to canonical hashes and order; **pagination completeness
holds** — a 489-record window at 200 per page gave 200 + 200 + 89 with no cross-page duplicates
and the paged set and order matching a single request.

Observed only, and not relied on: adjacent-window duplication, result ordering, `totalResults`
stability under concurrent mutation.

**The boundary result has a cost attached.** Starting the next window one millisecond after the
last record omits everything sharing that millisecond. Normally timestamps are unique per
millisecond — an ordinary hour held 490 records with 490 distinct stamps — but one anchor
millisecond was shared by **139 records** from a bulk re-analysis. Reuse the previous last
record's exact timestamp; accept the duplicate.

### 9.2 The finding that redefined the track

A controlled merge reproduced everything it was given: gates passed, 33 updates applied, no
conflicts, idempotent, ID symmetric difference 0. Two records still differed —
`CVE-2026-84658` and `CVE-2026-84659` changed `vulnStatus` from `Awaiting Analysis` to
`Undergoing Analysis` while `lastModified` stayed at `2026-09-03T17:13:16.490` on both sides.
They never appeared in the modified window.

At larger scale over a 64.7-hour gap on 31,175 records:

| Layer | Count | Rate |
|---|---:|---:|
| D0 source drift | 356 | 1.14% |
| D1 dataset-relevant | 356 | 1.14% |
| **D2 composition impact** | **0** | 0.00% |

All 356 carry identical `lastModified`; all 356 are `vulnStatus`-only; no rejected transitions.
D2 was computed by running the pipeline's own `normalize_record` over both versions. The overlay
produced 959 INSERT, 1,900 UPDATE, 49 no-change and 14 `CONFLICT_REVIEW`, was idempotent, and had
ID symmetric difference 0 in both directions.

So `lastModified` is a **query hint**, not a content version, change log, or equivalence key.

### 9.3 Interval: undetermined

Only one gap was measurable — one full snapshot exists and no archived deltas, so the planned
1/3/7-day comparison could not run and no synthetic history was made. One gap cannot show how
risk accumulates. By the rule of three, 0 rejected transitions in 356 silent changes gives a 95%
upper bound near 0.84%; that is a bound from zero observations, not a measurement.

**No interval is claimed.** "Weekly is enough" has no evidence behind it.

---

## 10. Final architecture

```
periodic validated full fetch
  → immutable trusted base              published-date partitions, never rewritten
  → lastModified incremental windows    query hint only
  → validated update overlay            completeness gate, deterministic merge, conflicts surfaced
  → logical current source view
  → deterministic full downstream rebuild   ~56 s, no incremental (T-015 Case B)
  → periodic full reconciliation        mandatory; interval undetermined
```

Principles, each tied to a measurement: `lastModified` is a hint, not a version identity;
`MISSING` is not `DELETE`; windows are `[start, end)` and the next start reuses the previous
last record's exact timestamp; duplicate fetch is accepted and silent omission is not;
a literal completeness flag is not evidence — assert summed rows against `totalResults` with
equal first and last page totals; the base is never rewritten for a minority of updates (the
delta touched 13 published partitions but 95.4% landed in the newest, with 172 rows across
twelve frozen ones).

## 11. Claims and limitations

| Claim | Limitation |
|---|---|
| `local[8]` was 1.89× faster than `local[1]` on the same Spark workload | Local-mode observation. Not a cluster claim; not compared against the single-process reference |
| Internal all-pairs scales quadratically (slope 1.870 / 1.940) | Ratios are the durable result; absolute seconds are load-sensitive — the same point measured 0.658 s and 0.209 s in two runs |
| Blockwise exact keeps results bit-identical at lower peak RSS | Does not reduce pair count; complexity stays `O(Q × R)` |
| Full Audit B: 1,630,168,200 pairs in 96.639 s at 1.411 GiB | One machine, one workload, one run |
| Similarity counts at each threshold | Near-duplicate structure, **not** contamination findings |
| Downstream full rebuild beats incremental at this scale | This pipeline's semantics and cost structure; verification cost included |
| Incremental ingest cuts request and row volume | Does **not** guarantee full source truth |
| Full reconciliation is a correctness requirement | Interval **undetermined** |
| Silent drift 1.14%, D2 = 0 over 64.7 h | One gap, one population. Not generalised |

## 12. Artifact index

| Area | Documents | Data |
|---|---|---|
| Spark equivalence | `reports/distributed/equivalence_report.md`, `runtime.json` | `spark_overlap.json` |
| Scaling | `gate1_scaling.md`, `gate1_independent_verification.md` | `gate1_scaling.json` |
| Audit A | `audit_a_exact_truth.md`, `audit_a_truth_freeze_diff.md` | `audit_a_exact_truth.parquet` + manifest |
| Blockwise | `blockwise_exact.md` | `blockwise_exact.json` |
| Audit B | `audit_b_cost_probe.md`, `audit_b_full.md`, `track_closure.md` | `audit_b_full.parquet` + manifest, `audit_b_probe_queries.json` |
| Downstream incremental | `reports/incremental/dependency_validation.md`, `incremental_vs_full.md` | `fixture_manifest.json`, `change_cases.json`, `data/fixture/` |
| Ingest | `t016b_api_probe.md`, `t016b2_merge_vs_truth.md`, `t016c_drift_and_closure.md` | `t016b_probe{1,2,3}.json`, `t016b2_result.json`, `t016c_result.json` |
| Specifications | `docs/SPEC_distributed.md`, `SPEC_candidate_reduction.md`, `CHANGE_MODEL.md`, `INGEST_SEMANTICS.md`, `RAY_TRACK_B_PLAN.md` | |

## 13. Closed questions

| Question | Answer | Basis |
|---|---|---|
| Is Ray needed? | No | Bottleneck is candidate-space complexity, not workers |
| Are LSH or ANN needed? | No | Full exact Audit B ran in 96.639 s |
| Should downstream rebuild be incremental? | No | 90.7% global; verification exceeds the saving |
| Does `lastModified` incremental fetch replace a full fetch? | No | Content changes observed without it moving |
| Rewrite published partitions physically now? | No | 172 rows across twelve frozen partitions |

## 14. Open questions

Recorded, not pursued: the reconciliation interval; production scheduling; checkpoint
persistence; overlay storage format; operational alerting; a historical drift curve, which needs
snapshot history this repository does not have.

---

`main` stays the verified v0.1.0 baseline. This branch is the learning record. Whether any of it
merges is a separate decision and was not taken here.

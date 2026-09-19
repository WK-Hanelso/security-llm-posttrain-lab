# T-014F — Audit B blockwise exact cost probe

All similarity figures below are for **Audit B**: 65,272 processed-train references, untruncated `description_en`, with queries transformed under the reference-only TF-IDF fit. Similarity counts are similarity counts, not contamination findings.

## Measured ladder

Wall time is total child time. Pairs/s and queries/s use the blockwise exact phase. Absolute time depends on this machine and load; the growth ratios are the more durable result.

| Q | R | Audit B pairs | Block | Wall s | Exact s | Peak RSS GiB | Pairs/s | Queries/s | Q growth | Wall growth | RSS growth | Swap Δ | Majflt | CPU | Status |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 300 | 65,272 | 19,581,600 | 2,048 | 7.694 | 1.213 | 0.598 | 16,145,628 | 247.36 | — | — | — | 0 B | 0 | 100.0% | success |
| 1,000 | 65,272 | 65,272,000 | 2,048 | 10.113 | 3.651 | 0.605 | 17,876,243 | 273.87 | 3.333× | 1.315× | 1.010× | 0 B | 0 | 100.0% | success |
| 2,500 | 65,272 | 163,180,000 | 2,048 | 15.724 | 9.111 | 0.645 | 17,911,176 | 274.41 | 2.500× | 1.555× | 1.068× | 0 B | 0 | 100.0% | success |

## Q-scaling reading

From Q=1,000 to Q=2,500, Q grew 2.500×, total wall time grew 1.555×, and peak RSS grew 1.068×. Fixed reference loading and vectorizer fitting make end-to-end wall growth sublinear at these small Q values; the exact kernel remains O(Q × R). All runs completed; maximum swap growth was 0 bytes and the ladder recorded 0 total major page faults.

Q=5,000 was not run because the required ladder already gave stable, decision-relevant scaling and left the full-run classification unambiguous.

## Full Audit B projection — projection, not measurement

At Q=24,975 and R=65,272, the projected wall time is **98.1 seconds (1.63 minutes)** and projected peak RSS is **1.144 GiB**. Applying a 31% memory sensitivity gives **1.499 GiB**; this remains a projection, not a measurement.

Method: ordinary least-squares line through the three measured ladder points. Assumption: wall time and peak RSS remain linear in Q at fixed R=65,272, block size 2,048, software, host, and comparable load; no full Audit B run was executed. Wall-fit R²=0.9997; peak-RSS-fit R²=0.9621. Gate 1's memory projection missed by about 31%; this peak-RSS projection is lower-standing evidence than a measurement.

The full run was not executed in T-014F.

## Correctness spot-check

On 50 frozen Audit B queries × 65,272 references, blockwise exact was compared with a direct dense computation. Top-20 membership: **pass**; top-20 scores within `2e-15`: **pass** (maximum aligned delta `0.000e+00`); Audit B ≥0.80 pair set: **pass**; Audit B ≥0.90 pair set: **pass**; per-query threshold counts: **pass**.

Audit B similarity counts in this 50-query check were 225 pairs at ≥0.80 and 34 pairs at ≥0.90. They are similarity counts, not contamination findings. Raw float64 scores drove every threshold decision; no scores were rounded to force agreement.

Top-20 ordering was identical; 0 near-tie ordering differences were recorded. Any recorded differences are listed with raw score spans in the JSON report and treated as the §3.2 float64 limitation only when within `2e-15`.

## §8.7 answer

**Exact is sufficient at this scale; it is not the bottleneck.** The measured Q=2,500 point completed in 15.724 seconds at 0.645 GiB peak RSS; maximum measured swap growth was 0 bytes and the ladder recorded 0 major page faults. The labelled full-run projection is minutes, not 30 minutes or more, and its projected memory remains well inside this host's available RAM.

Therefore **T-014D should not open**: candidate reduction is not needed at this measured scale. No approximate retrieval technique was built.

## Environment

Measured on `hanelso-GL73-8SE` at commit `e38df7f29cafe62ef96a84575ede76e8a850ce8f` with Python 3.11.15, NumPy 2.4.6, scikit-learn 1.9.1, and 12 logical CPUs. No Ray, Spark, LSH, ANN, or approximate retrieval was used.

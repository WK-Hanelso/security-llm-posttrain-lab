# Audit A exact similarity truth

All Audit A similarity figures in this report use the **12,000-reference-only fit; queries transformed**. The computation is exact float64 cosine over all 18,000 × 12,000 = 216,000,000 pairs.

## Top-1 score distribution

| Fitting scope | p50 | p90 | p95 | max |
|---|---:|---:|---:|---:|
| 12,000-reference-only fit; queries transformed | 0.335117 | 0.771663 | 0.837652 | 1.000000 |

The distribution is over each query's exact top-1 similarity.

## Threshold counts

| Fitting scope | Threshold | Pair count | Queries with ≥1 pair | Same-label pairs | Cross-label pairs |
|---|---:|---:|---:|---:|---:|
| 12,000-reference-only fit; queries transformed | ≥0.80 | 10888 | 1326 | 10578 | 310 |
| 12,000-reference-only fit; queries transformed | ≥0.90 | 1735 | 424 | 1714 | 21 |

These are lexical-similarity counts, not claims of evaluation leakage. Repeated vendor templates and advisory boilerplate can produce high scores.

## Continuity check

The 300 published sampled-audit queries were recomputed with the **12,000-reference-only fit; queries transformed** and compared with the published rows, whose scores use a **12,000-reference-plus-300-query fit**.

| Recomputed fitting scope | Top-1 reference agreement | Mean |Δscore| | Max |Δscore| | Recomputed queries ≥0.80 | SPEC §2 expected |
|---|---:|---:|---:|---:|---|
| 12,000-reference-only fit; queries transformed | 258/300 | 0.034069 | 0.311037 | 18 | 258/300; 0.0341; 0.3110; 18 |

Continuity result: **passed**.

The published sampled-audit p50 0.2694, p90 0.7036, p95 0.7438, ≥0.80 count 8, and ≥0.90 count 3 remain correct for their **12,000-reference-plus-300-query fit**. They are not comparable with, and are not superseded by, the Audit A values above.

## Measured execution

Measured on `hanelso-GL73-8SE` at commit `1d420588cf1c696d38121eb3aac4b7d2d017340c`: 12.415 s child wall time and 2.174 GiB peak RSS. Parent-observed peak RSS was 2.172 GiB; swap growth was 0 bytes.

The Parquet truth set contains 362,631 rows: exact top-20 rows for every query plus every exact pair at or above 0.80. Its SHA-256 is `929ccdda1432851e7809ce6f4fb8a8513233dc9914ae4039bd25ab536753e657`.

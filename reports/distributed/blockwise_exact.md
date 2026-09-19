# Blockwise exact Audit A top-k

All similarity figures use the **12,000-reference-only fit; queries transformed**. Each run processes all 18,000 × 12,000 = 216,000,000 exact cosine pairs without materializing the full dense similarity matrix. Similarity counts are lexical-similarity counts, not contamination findings.

The frozen ordering key is raw float64 `(-exact_similarity, reference_cve_id)` with the CVE ID ascending as a string. The key is applied to every running top-20 merge.

## Measurements and equivalence

| Block | Fitting scope | Wall s | Blockwise s | Peak RSS GiB | Pairs | Pairs/s | IDs ordered | Scores | Max |Δ| | ≥0.80 set | ≥0.90 set | Per-query counts | Ties |
|---:|---|---:|---:|---:|---:|---:|---|---|---:|---|---|---|---|
| 256 | 12,000-reference-only fit; queries transformed | 41.692 | 36.636 | 0.571 | 216,000,000 | 5,895,874 | yes | bit-identical | 0.000e+00 | yes | yes | yes | yes |
| 512 | 12,000-reference-only fit; queries transformed | 28.712 | 23.679 | 0.580 | 216,000,000 | 9,121,856 | yes | bit-identical | 0.000e+00 | yes | yes | yes | yes |
| 1024 | 12,000-reference-only fit; queries transformed | 20.965 | 15.908 | 0.726 | 216,000,000 | 13,578,216 | yes | bit-identical | 0.000e+00 | yes | yes | yes | yes |
| 2048 | 12,000-reference-only fit; queries transformed | 16.835 | 11.736 | 0.999 | 216,000,000 | 18,404,468 | yes | bit-identical | 0.000e+00 | yes | yes | yes | yes |

All four block sizes are invariant: **yes**. Cross-block maximum top-20 score delta is `0.000e+00` under the **12,000-reference-only fit; queries transformed**.

Threshold pair counts are 10,888 at ≥0.80 and 1,735 at ≥0.90 for the **12,000-reference-only fit; queries transformed** in every run. These are similarity counts, not contamination findings.

## Environment

Measured on `hanelso-GL73-8SE` at commit `1d420588cf1c696d38121eb3aac4b7d2d017340c` using Python 3.11.15, NumPy 2.4.6, and scikit-learn 1.9.1. Peak RSS uses the reused parent `/proc` monitor plus child `ru_maxrss`; no Ray or Spark was used.

## Scope boundary

This remains O(Q × R): blockwise execution bounds the dense working matrix but does not reduce the 216,000,000 pair count. Audit B's order-of-minutes estimate in SPEC §6.2 is a projection from Audit A, not a measurement.

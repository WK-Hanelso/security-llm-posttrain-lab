# Audit A deterministic truth-freeze diff

All similarity figures in this document use the **12,000-reference-only fit; queries transformed**. Similarity counts are lexical-similarity counts, not contamination findings.

## Artifacts and ordering rule

- Superseded row-index-tie-break Parquet SHA-256: `c6552a72c60b5643d73121c18991e7bb2f8dd41fb2f58f89c98f86d1641df0d3`
- Current CVE-ID-tie-break Parquet SHA-256: `929ccdda1432851e7809ce6f4fb8a8513233dc9914ae4039bd25ab536753e657`
- Current top-20 ordered-ID SHA-256: `cf4366b8dd6eb3299fb51efac4470bee7210dd1cc44eecefdcfd5eb71f2260c1`
- Commit recorded by the generator: `1d420588cf1c696d38121eb3aac4b7d2d017340c`

The current artifact selects and orders references by raw float64 `(-exact_similarity, reference_cve_id)`, with `reference_cve_id` ascending as a string. Threshold decisions use the unrounded float64 score and do not depend on rank.

## Measured diff

| Effect | Expected before execution | Measured full-selection result | Comparison |
|---|---:|---:|---|
| Queries whose top-20 ordering changes | 4,033 of 18,000 | **4,125 of 18,000** | +92 |
| Individual top-20 positions that move | 14,649 | **14,871** | +222 |
| Queries whose top-20 membership changes | ~588, projected from 49/1,500 | **533**, measured over all 18,000 | −55 versus projection |
| Pairs ≥0.80, 12,000-reference-only fit | 10,888 | **10,888** | invariant |
| Pairs ≥0.90, 12,000-reference-only fit | 1,735 | **1,735** | invariant |

Ordering and membership are reported separately. All **533 of 533** changed-membership queries exchange only references whose raw float64 score equals the rank-20 boundary score. The unequal-score membership-change count is **zero**. The ≥0.80 and ≥0.90 pair sets themselves are also identical before and after the freeze, not merely equal in count.

The ordering-count discrepancy has a concrete cause. Re-sorting only the superseded artifact's existing 20 members by the new key reproduces **exactly 4,033 changed queries and 14,649 moved positions**. That is the fixed-membership calculation forbidden by SPEC §3.1. Applying the key during selection changes membership at the boundary and yields the complete-artifact figures 4,125 and 14,871. The projected membership row did anticipate this effect; its measured full-population value is 533.

## Independent and repeatability checks

The generator was run twice on identical input. Both complete Parquet files had SHA-256 `929ccdda1432851e7809ce6f4fb8a8513233dc9914ae4039bd25ab536753e657`, and both top-20 ordered-ID streams had SHA-256 `cf4366b8dd6eb3299fb51efac4470bee7210dd1cc44eecefdcfd5eb71f2260c1`.

An independent 200-query verification used `random.Random(20260919)`, whose ordered sampled-query-ID SHA-256 is `2a8eead7efeeddc89d08e41c1a77471b15d84e8a60b0c0ff1c6666c96b153967`. It refit the vectorizer on the **12,000 references only**, computed sparse TF-IDF dot products, and used a full Python sort on `(-raw_score, reference_cve_id)` rather than the generator's selection helper. Results:

- top-20 reference ID ordering: identical for 200/200 queries;
- top-20 scores: within absolute tolerance `2e-15`, measured maximum delta `1.1102230246251565e-15`;
- ≥0.80 pair sets and ≥0.90 pair sets: identical for all sampled queries;
- per-query threshold counts: identical; and
- vocabulary size: 42,488.

The generator's separate 300-query continuity check also passed: top-1 reference agreement 258/300, mean absolute score delta 0.0340691348, maximum absolute score delta 0.3110368642, and 18 recomputed queries at ≥0.80 under the **12,000-reference-only fit; queries transformed**. The comparison audit uses a different fitting scope, so these are continuity measurements rather than interchangeable similarity statistics.


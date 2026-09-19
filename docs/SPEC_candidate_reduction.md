# SPEC — Near-Duplicate Candidate Reduction and Recall Audit (T-014)

Implementation specification for the candidate-reduction track on
`feat/distributed-pipeline`. This document is the source of truth. Code must follow it; if the
implementation must diverge, update this file in the same commit and record the reason.

Status: v1 (2026-09-19). Baseline commit `6f699b1`. `main` at v0.1.0 is frozen and is not
modified by this track.

---

## 0. Fixed decisions (do not re-litigate)

| Item | Decision |
|---|---|
| Primary question | Is there train/evaluation near-duplication that could inflate the reported SFT result? |
| First target | **Audit A** — the 18,000 frozen evaluation IDs against the 12,000 actual SFT training rows |
| Truth for recall | Exact cosine similarity, computed in full for Audit A. Approximate output is never the truth set |
| Representation | Word TF-IDF, `ngram_range=(1, 2)`, `sublinear_tf=True`, `min_df=2`, `stop_words=None` |
| **Vectorizer fitting scope** | **Fit on the 12,000 reference rows only; transform queries.** See §2 |
| Candidate role | Candidate generation narrows what gets exact-scored. It never decides contamination |
| Ray | Not used in this track. Reconsidered only under the gate in §9 |
| Measurement honesty | Measured, projected and theoretical figures are labelled separately and never mixed |

---

## 1. Populations (T-014A — verified 2026-09-19)

All figures below were verified against the artifacts on disk, not copied from documents.

### Audit A — model-result contamination (primary)

| Side | Source | Rows |
|---|---|---:|
| Query | `reports/eval_subset_manifest.json` `row_ids` resolved against `data/sft/test.jsonl` | 18,000 |
| Reference | `data/sft/train.jsonl` | 12,000 |

- All 18,000 IDs resolve; 18,000 unique.
- `subset_hash` `229dd47c3cdeb532d47c2dd8c5962f2c9bff8ff2c6d89d8d2776ee6d09a7d707`;
  manifest `source_sha256` matches the frozen `data/sft/test.jsonl`.
- `data/sft/train.jsonl` sha256 begins `1887fbb32b6af37f`, the frozen v1.0 value.
- **Exact guard re-verified for these exact populations**: normalized-text hash overlap 0,
  `cve_id` overlap 0.
- Potential pairs: **216,000,000**.
- Query class distribution (top 5): CWE-79 3,771 / CWE-862 2,161 / CWE-284 1,863 /
  CWE-89 1,522 / CWE-416 1,419.

This is the population on which accuracy 0.8627 and macro F1 0.8332 were computed, so it is
the population the contamination question actually concerns.

### Audit B — dataset-design contamination (second)

Query `data/processed/test.jsonl` 24,975 against reference `data/processed/train.jsonl`
65,272. Potential pairs 1,630,169,200. Not started until Audit A's recall quality is
established. Truth comes from exact blockwise top-k on fixed query subsets (§8), not a full
matrix.

### Audit C — test-internal all-pairs (auxiliary)

24,975 internal, 311,862,825 unique pairs. A different question — redundancy inside the test
set, not train/test leakage. Not part of T-014's first goal.

---

## 2. Vectorizer fitting scope, and why it changed

The existing sampled audit fits the vectorizer on the references **plus the query set**
(12,000 + 300). With `min_df=2` and IDF computed over the fitted corpus, this means the
**reference vectors themselves change when the query set changes**.

Measured on the same 300 queries, against the published sampled-audit output:

| Fitting scope | Top-1 reference agreement | mean \|Δscore\| | max \|Δscore\| | count ≥ 0.80 |
|---|---:|---:|---:|---:|
| train + 300 (reproduces the published audit) | 300 / 300 | 0.0000 | 0.0000 | 8 |
| **reference only (this SPEC)** | 258 / 300 | 0.0341 | 0.3110 | **18** |
| train + 18,000 (naive extension) | 214 / 300 | 0.0608 | 0.3063 | 6 |

Two consequences follow, and they decide the design:

1. **Naively scaling the existing recipe to 18,000 queries changes the nearest reference for
   86 of 300 queries (29%) and moves the ≥ 0.80 count from 8 to 6.** The published numbers do
   not reproduce under it. They are not wrong — they are specific to a 300-query fit.
2. **Under a query-dependent fit, an index over the references is not well defined**, because
   the reference vectors change with each query batch. Candidate reduction (§6, §7) cannot
   exist on that footing.

Therefore the reference-only fit is fixed for this track. Vocabulary size on the 12,000
references: 42,488.

**Claim boundary.** Audit A's similarity values are not comparable to the published sampled
audit's values, and neither supersedes the other. The published p50 0.2694 / p90 0.7036 /
p95 0.7438 / ≥0.80 8 / ≥0.90 3 remain correct for what they measured. Every reported figure in
this track states its fitting scope. The v0.1.0 documents are not edited.

---

## 3. T-014B — exact ground truth for Audit A

Full exact cosine over 18,000 × 12,000. Gate 1 completed 24,975 × 12,000 in 15.163 s at
2.619 GiB peak RSS, so this is within reach on this host; the dense float64 result here is
about 1.73 GB.

Per query, record the top-20 by exact similarity plus every reference at or above each
threshold.

Output `reports/distributed/audit_a_exact_truth.parquet` (or JSONL if simpler), with:

| Field | Meaning |
|---|---|
| `query_cve_id` | evaluation row |
| `reference_cve_id` | SFT training row |
| `query_label`, `reference_label` | `cwe_id` on each side |
| `exact_similarity` | float64 cosine |
| `rank` | 1-based rank of this reference for this query |
| `threshold_80`, `threshold_90` | booleans |
| `query_text_hash`, `reference_text_hash` | normalized-text SHA-256 |

Plus `reports/distributed/audit_a_exact_truth_manifest.json`: population hashes, vectorizer
settings and fitting scope, vocabulary size, k, thresholds, row counts, result hash, wall time,
peak RSS, host, commit.

**Required continuity check.** Recompute the 300 published sampled-audit queries under this
SPEC's fitting scope and report top-1 agreement and score deltas against
`reports/near_duplicate_audit.json`, reproducing the §2 table from the actual run. If the
numbers differ from §2, the implementation differs from what was measured — stop and report.

---

## 4. Recall metrics

Defined against the §3 truth set. Candidate generation proposes, exact refinement scores.

- `candidate_recall@20` — of the truth top-20 pairs, the share surviving candidate generation.
- `threshold_recall_0.80`, `threshold_recall_0.90` — same, for pairs at or above each threshold.
- `reduction_ratio` — candidate pairs ÷ 216,000,000.
- `average_candidates_per_query`.
- Exact-refinement cost and end-to-end cost, each as wall time, peak RSS and pair count,
  measured separately.

A pair missed at candidate generation cannot be recovered by refinement. Recall is therefore
reported before any latency figure.

## 5. Quality gates

| Metric | Requirement |
|---|---|
| `threshold_recall_0.90` | **1.0.** The highest-similarity pairs matter most and may not be missed |
| `threshold_recall_0.80` | ≥ 0.99 initially; finalised once the score distribution is known |
| `candidate_recall@20` | ≥ 0.95 |

Speed is never traded for recall. A configuration that fails a gate is recorded with its
numbers, not tuned until it passes and reported as the first result.

---

## 6. T-014C — blockwise exact top-k

Exact top-k without materializing the dense matrix: stream reference blocks, keep a running
top-k and the threshold hits per query.

This does **not** reduce the pair count — cost stays O(Q × R). Its value is bounded peak
memory, no full dense materialization, and an exact verification primitive usable at reference
sizes where dense does not fit.

Verified against §3 by top-k ID set, top-k scores, threshold crossings and ordering. Ties at
equal scores must order deterministically; state the rule. Any floating-point tolerance is
stated numerically in the report. **If results differ from the exact baseline, the track stops
there.** Record block-size sensitivity for peak memory and wall time.

## 7. T-014D / T-014E — candidate generation and quality audit

Candidate generation runs on the §2 representation. Do not change the representation in the
same step as introducing candidate generation, or algorithmic and semantic effects cannot be
separated.

Candidates feed exact refinement on the original representation; the decision comes from the
exact score.

T-014E analyses what is missed, by: same-label versus cross-label, description length, rare
classes, and vendor-boilerplate concentration.

**Manual review categories are retained** — `near/exact copy`, `vendor boilerplate`,
`weakness phrase overlap`, `normal semantic similarity`. High lexical similarity is not
evaluation leakage. CVE text repeats vendor templates, product names and advisory boilerplate;
the published top-20 review found 11 of 20 to be vendor boilerplate against 7 near/exact
copies.

## 8. T-014F — Audit B scale-up decision

Truth comes from exact blockwise top-k over fixed query subsets (300 / 1,000 / 2,500) against
all 65,272 references — not a full 1.63-billion-pair matrix.

Subsets are chosen before looking at results: fixed seed, recorded class distribution, stored
query-ID manifest, recorded length distribution. Audit random, long-description and rare-class
subsets separately, so a candidate algorithm that loses recall on one data characteristic is
visible.

---

## 9. Measurement and wording

Three kinds of number, never interchangeable: **algorithmic complexity** (theory and scaling
curves), **measured runtime** (this host, this commit, this workload), and **projection**
(always labelled as such). Gate 1 showed absolute wall time varies with machine load — the same
point measured 0.658 s and 0.2087 s in two runs while peak RSS agreed — and that a memory
projection over-estimated by 31%. Ratios were stable; absolute seconds were not.

Forbidden: `production-ready`, `cluster-scalable`, `massive-scale`, `fully distributed`,
`proved scalability`, and any claim of demonstrated scalability. These are single-node
measurements on one machine.

**Ray gate.** Reopened only when all hold: candidate reduction complete; recall gates passed;
an Audit B full run compute-bound for 30 minutes or more; per-worker memory independently
affordable; natural task partitioning; a two-worker probe at 1.5x or better; and
single-worker/multi-worker equivalence verifiable. Any one unmet means Ray is not used.

## 10. Protected paths

Not modified by this track: `main`; `data/processed/`, `data/sft/`, `data/raw/`;
`manifests/dataset_manifest.json`; `reports/` except `reports/distributed/`;
`src/security_llm/{data,eval,train}/`; `configs/`; and the v0.1.0 documents (`README.md` model
results, `MODEL_CARD.md`, `DATASET_CARD.md`, `docs/SPEC.md`, `docs/claim-boundaries.md`,
`docs/data-layer.md`). A checksum baseline is taken before each run and re-verified after.

## 11. Done

Code alone is not done. Done is: population definition, exact truth, implementation,
execution, equivalence and recall audit, runtime, memory, failure analysis, limitations,
documentation, and an explanation someone else can follow.

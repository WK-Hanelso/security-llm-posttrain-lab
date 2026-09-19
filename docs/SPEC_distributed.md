# SPEC — Distributed Pipeline (Spark / Ray)

Implementation specification for the `feat/distributed-pipeline` branch. This document is the
source of truth for the distributed re-implementation. Code must follow it; if the
implementation must diverge, update this file in the same commit and record the reason.

Status: v1 (2026-09-19). Branch scope only — `main` at `v0.1.0` is a frozen artifact and is
not modified by this branch.

---

## 0. Fixed decisions (do not re-litigate)

| Item | Decision |
|---|---|
| Division of labor | Spark owns CPU-bound bulk transformation. Ray owns stages with a model in the loop |
| Track A (this branch, committed) | NVD parse → canonical record → temporal split → exact dedup → overlap invariant, in Spark |
| Track B (deferred) | Full-population near-duplicate audit and Base/SFT inference, in Ray |
| Goal | Equivalence with the existing single-process implementation, not speed |
| Source data | `data/raw/nvd` snapshot `2026-09-17`, reused as-is. NVD is not re-ingested |
| Execution | Spark local mode (`local[8]`). No cluster is claimed |
| Reference implementation | `main` at `cb268c8`. Its outputs are the expected values in §6 |
| Environment | Separate `requirements-distributed.txt` / `.venv-dist`. The frozen `.venv` is not touched |
| Output format | Parquet, partitioned by `split` and `published_year` |
| Honesty | Report what was actually run. A failed equivalence check is recorded, not silenced |

### Why the split is Spark here and Ray there

Spark is the right tool for the front half because every stage is a shuffle or a join:
description normalization, exact-duplicate removal by hash, temporal partitioning, and
cross-split overlap detection. None of them touch a model.

Ray is the right tool for the back half because every stage holds a model: embedding-based
near-duplicate detection, model-assisted labeling, Base and SFT generation over the frozen
18,000-row subset, and verifier scoring. These are GPU actor-pool problems; expressing them
as Spark stages would be awkward.

This boundary is the design argument, not the choice of one framework over the other.

---

## 1. Track A scope

### In scope

| Stage | Reference module | Spark responsibility |
|---|---|---|
| Parse | `data/ingest_nvd.py` (output only) | Read cached NVD page JSON from `data/raw/nvd` |
| Normalize | `data/normalize.py` | CVE/CWE extraction, English description, label status, `description_norm_hash` |
| Split | `data/split.py` | Temporal assignment, train-only top-K label selection |
| Dedup | `data/dedup.py` | Exact normalized-text duplicate removal |
| Overlap | `eval/contamination.py` | Cross-split `cve_id` and `description_norm_hash` overlap, fail-fast |

### Out of scope

- **NVD ingestion.** The raw snapshot (2.1 GB) is already on disk. Re-fetching would change the
  snapshot and make equivalence unverifiable. Ingestion is I/O-bound API paging and is a poor
  fit for Spark regardless.
- **`data/build_sft.py` sampling and prompt rendering.** `sample_records` calls
  `random.Random(42).sample` and `shuffle` against an ordered Python list; reproducing it in
  Spark would mean reproducing CPython's `random` state, which proves nothing about
  distributed processing. Track A stops at the deduplicated populations.
- **Training.** Unchanged.

---

## 2. Storage layout

```text
data/spark/
  normalized/              # Parquet, partitioned by published_year
  splits/
    split=train/published_year=2020..2024/
    split=val/published_year=2025/
    split=test/published_year=2026/
  deduped/                 # Parquet, same partitioning, post exact-dedup
  labels.json              # mirrors data/processed/labels.json
manifests/
  spark_dataset_manifest.json
reports/distributed/
  equivalence_report.md
  equivalence_report.json
  spark_overlap.json
  runtime.json
```

Existing `data/processed/*`, `data/sft/*`, `reports/*` and `manifests/dataset_manifest.json`
are read-only inputs to this branch. Nothing under them is overwritten.

### Partitioning rationale

`published_year` is the physical partition key. The temporal split then resolves to partition
pruning — a directory selection, not a row filter. Temporal leakage is prevented by the
storage layout rather than by a predicate that a later change could silently drop. This is the
point worth defending; the performance difference at this data size is not.

`split` is stored as a partition column as well so that a consumer reads one split without
scanning the others.

---

## 3. Stage specifications

### 3.1 Normalize

Input: `data/raw/nvd/<window>/page_*.json`, gated by `ingest_manifest.json` — only windows
with `complete == true` are read.

Read with `spark.read.json(..., multiLine=True)` and `explode(vulnerabilities)`. Field
extraction must match `normalize_record` exactly, including:

- `cve_id` must match `^CVE-\d{4}-\d{4,}$`, otherwise the row is dropped.
- `description_en` is the first `descriptions` entry with `lang == "en"`, stripped.
- `is_rejected` is `vulnStatus == "Rejected"` **or** the description starts with `** REJECT **`.
- `cwe_primary` / `cwe_secondary` are the sorted unique sets of `^CWE-\d+$` values from
  `weaknesses` entries typed `Primary` / otherwise, English descriptions only.
- `placeholder_only` is true when raw weakness values exist, no valid CWE was parsed, and every
  raw value is in `filter.placeholder_cwes`.
- `label_status` ∈ {`single`, `multi`, `placeholder_only`, `none`} by the same precedence.
- `description_norm_hash` = SHA-256 of `re.sub(r"\s+", " ", NFKC(value).lower()).strip()`.
  **The Python `normalize_text` is reused verbatim in a UDF.** Spark's `lower()` and
  `regexp_replace` do not reproduce NFKC normalization, and a re-implementation that drifts
  would silently change every downstream hash comparison.

Deduplication by `cve_id`: the reference writes into a dict keyed by `cve_id`, so a repeated
ID would be last-wins over window/page order. **This is a no-op on the 2026-09-17 snapshot** —
the recorded normalize funnel has `raw_cves == unique_cves == 257913`, so no `cve_id` appears
twice. Spark therefore does not implement last-wins; it asserts
`count() == countDistinct("cve_id") == 257913` and fails if that ever stops holding.

Output row count must equal 257,913.

### 3.2 Split and label selection

Eligibility filter, in order: not `is_rejected`, non-empty `description_en`,
`label_status == "single"`.

Temporal assignment uses config `split` ranges with `null` upper bound replaced by the
snapshot date `2026-09-17`. Boundaries are inclusive on both ends. Rows outside all three
ranges are dropped.

Label selection is computed on the **train partition only**: count `cwe_id`, rank by
`(-count, cwe_id)`, take the first `top_k` (15), keep those with `count >= 200`. Selected
labels must match the 15 CWE IDs in `manifests/dataset_manifest.json` exactly, in order.

Splits are then filtered to selected labels.

### 3.3 Exact dedup

**Keep-first semantics are mandatory.** The reference sorts by `(published, cve_id)` and keeps
the first row per `description_norm_hash`. A bare `dropDuplicates(["description_norm_hash"])`
produces the same row count but an arbitrary surviving `cve_id`, which fails the §6
row-identity check. Implement as:

```python
w = Window.partitionBy("description_norm_hash").orderBy("published", "cve_id")
deduped = df.withColumn("_rn", row_number().over(w)).filter(col("_rn") == 1).drop("_rn")
```

Applied to the train population only, matching `dedup.drop_train_exact_duplicates`.

### 3.4 Overlap invariant

Computed as joins against the deduped populations:

- `train` left-anti-join `val ∪ test` on `description_norm_hash` → the dropped count is
  `train_overlap_with_eval_dropped`.
- `val` left-anti-join `train ∪ test` on `description_norm_hash` → `val_overlap_with_eval_dropped`.
- After both drops, all three pairwise overlaps on `description_norm_hash` and on `cve_id` must
  be **0**. Non-zero raises and the job exits non-zero — the same fail-fast contract as
  `data/guard.py`.

Note the asymmetry in the reference: `_drop_val_overlaps` computes eval hashes from the
**pre-dedup** train population, not the deduped one. Reproduce the reference behaviour; do not
"fix" it on this branch.

---

## 4. Manifest

`manifests/spark_dataset_manifest.json` records, mirroring the existing manifest habit:

- `created_at`, `git_commit`, `dataset_snapshot`, `data_config_sha256`
- `labels` (selected, ordered)
- `partitions`: per `(split, published_year)` row count
- `files`: per Parquet part file, relative path, byte size, SHA-256
- `counts`: population counts per split, pre- and post-dedup
- `dedup`: the three drop counts
- `spark`: master string, `spark.sql.shuffle.partitions`, Spark version
- `reference_manifest_sha256`: SHA-256 of `manifests/dataset_manifest.json` the run was
  compared against

---

## 5. Runtime measurement

`reports/distributed/runtime.json` records wall-clock per stage for:

1. `local[8]`
2. `local[1]`
3. the existing single-process implementation (from `logs/prepare_data_*.log`, not re-run)

Reported as measurements on a single node. No cluster scaling is claimed or extrapolated. The
honest framing is that partitioning and shuffle behaviour were verified on one node.

---

## 6. Equivalence contract (definition of done)

Track A is done when `reports/distributed/equivalence_report.md` exists and every check below
passes. The comparison is **row-level by `cve_id`**, not file-hash identity — the Parquet
encoding and row ordering differ by design.

| # | Check | Expected |
|---|---|---:|
| E1 | normalized row count | 257,913 |
| E2 | normalized `cve_id` set == `data/processed/normalized.jsonl` `cve_id` set | symmetric difference 0 |
| E3 | per-row field equality on the normalized set (all schema fields) | 0 mismatched rows |
| E4 | selected labels, ordered | identical to manifest `labels` |
| E5 | split populations train / val / test (after temporal assignment, before cross-split overlap removal) | 65,272 / 21,151 / 24,975 |
| E6 | split assignment per `cve_id` | 0 disagreements |
| E7 | class distribution per split | identical |
| E8 | train exact duplicates dropped | 3,427 |
| E9 | surviving `cve_id` set after train dedup | symmetric difference 0 |
| E10 | train↔eval overlap dropped | 36 |
| E11 | val↔eval overlap dropped | 233 |
| E12 | post-drop pairwise overlaps (train↔test, train↔val, val↔test) | 0 / 0 / 0 |

The final validation population is 20,918 because E11 removes 233 cross-split overlaps from
the 21,151 rows assigned to validation (21,151 − 233 = 20,918).

E9 is the check that a naive `dropDuplicates` fails. It is the reason §3.3 is specified the way
it is.

If any check fails and the cause is a genuine semantic difference rather than a bug, the report
records the check, the delta, and the cause. A failed check is not removed from the table.

---

## 7. Track B — Ray (deferred, not required for this branch)

Specified here so the boundary is documented; implemented only if Track A lands with time to
spare.

**B1. Full-population near-duplicate audit.** `eval/near_duplicate_audit.py` currently samples
300 rows and uses TF-IDF cosine, and the repository already states it is not a formal
semantic-overlap detector. The Ray version computes sentence embeddings with
`ray.data.map_batches` over a GPU actor pool and retrieves near pairs through an ANN index
over the full population. This closes a limitation the repository states about itself, which is
a cleaner narrative than adding a new capability.

**B2. Base/SFT inference.** `eval/generate.py` runs 18,000 rows sequentially at `batch_size: 2`
with left padding. A Ray Data actor pool scales this across GPUs; the verifier is a pure
function and maps directly.

Equivalence constraint for B2: generation is greedy, but left padding means batch composition
affects fp16 numerics. Bit-identical predictions require preserving the frozen subset's row
order and a block size divisible by `batch_size`. If that is not held, the report states the
prediction-level delta rather than claiming identity.

---

## 8. Known scale limits

Recorded because the interesting question is where this design breaks, not that it ran.

- **Exact-dedup hash shuffle is the first thing to break.** The whole dataset crosses the
  network. Mitigation: reduce within partitions first and go global second, or narrow
  candidates with MinHash LSH and confirm with exact comparison.
- **Near-duplicate detection is quadratic in pairs** and does not survive scale at all. LSH or
  ANN is a precondition of the design, not an optimization.
- **Many small files.** Hundreds of millions of small objects make listing and per-task
  overhead exceed actual processing. Files must be packed into Parquet binary columns or tar
  shards. This does not appear in a CVE text pipeline; it appears with binary security data.
- **Expensive per-record CPU work** loses to serialization overhead in a row-at-a-time UDF.
  Batch it with a pandas UDF, or move it to Ray if a model is involved.
- **Stratified sampling for mixture design** needs the global distribution and so forces a
  shuffle. A two-pass approach — collect per-partition statistics, fix the ratios, then sample
  independently per partition — is the practical form.

---

## 9. Non-goals

- No new experimental results. No numbers on `main` are restated, recomputed, or superseded.
- No cluster deployment, no throughput extrapolation.
- No change to the dataset, the split policy, the label policy, or any reported metric.

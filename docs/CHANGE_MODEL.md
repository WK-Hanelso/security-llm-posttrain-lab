# T-015A — Change model, field dependencies and invalidation boundary

Specification for the incremental-pipeline track on `feat/incremental-pipeline`. This document
is the source of truth for what a source change is, what it can affect, and where incremental
processing can and cannot be correct. Code must follow it; if the implementation must diverge,
update this file in the same commit and record the reason.

Status: v1 (2026-09-19). Base commit `e63db41`. The T-014 track is closed; `main` at v0.1.0 and
every T-013/T-014 artifact are frozen inputs here, never modified.

The question: **can a changed subset be reprocessed to produce exactly what a full rebuild
would produce?** And separately — **even if it can, is that a better engineering choice than
rebuilding?**

---

## 1. Source fields that actually matter

Taken from `normalize_record` in `src/security_llm/data/normalize.py` and traced forward
through `split.py`, `dedup.py`, `build_sft.py` and `eval/contamination.py`. Nothing here is
assumed from documentation.

| Raw NVD field | Normalized field | Affects dataset **composition** | Affects output **bytes** |
|---|---|---|---|
| `id` | `cve_id` | yes — identity, dedup tie-break, overlap keys | yes |
| `published` | `published` | yes — split assignment, dedup keep-first order, normalized sort order | yes |
| `descriptions[lang=en].value` | `description_en`, `description_norm_hash` | yes — eligibility (non-empty), dedup, cross-split overlap | yes |
| `vulnStatus` | `vuln_status`, `is_rejected` | yes — eligibility | no |
| `weaknesses[].type`, `.description[lang=en].value` | `cwe_primary/secondary/all`, `cwe_id`, `label_status`, `placeholder_only` | yes — eligibility, label selection, class distribution | yes |
| `cisaExploitAdd` | `is_kev`, `kev_date_added` | no | **yes** — `is_kev` is written into every SFT row |
| `metrics.cvssMetricV31[0].cvssData` | `cvss_v31_base_score`, `cvss_v31_severity` | no | no |
| `lastModified` | `last_modified` | no | no |

Two consequences:

- **Change detection compares only the composition and byte fields**: `id`, `published`,
  `descriptions`, `vulnStatus`, `weaknesses`, `cisaExploitAdd`. A CVE whose only change is a
  CVSS rescoring cannot alter the dataset.
- **`lastModified` is a cheap change *hint*, not the equivalence key.** NVD moves it for
  changes that do not affect us. Use it to narrow candidates; never to conclude equality.

`is_kev` is the awkward case: it changes the bytes of `data/sft/*.jsonl`, and therefore the
manifest sha256, without changing which rows are selected. Composition equivalence and byte
equivalence are separate claims and are reported separately.

## 2. Change types

| Type | Definition |
|---|---|
| `INSERT` | `cve_id` present in B, absent in A |
| `UPDATE` | `cve_id` in both, at least one field from §1 differs |
| `UNCHANGED` | `cve_id` in both, every §1 field identical |
| `MISSING` | `cve_id` present in A, absent in B |

**`MISSING` is not treated as a delete.** NVD snapshots are assembled from paged windows, and
a record absent from a later snapshot is more likely a windowing or completeness artifact than
a removal — `normalize()` already skips windows without `complete == true`. Withdrawal is
expressed through `vulnStatus` becoming `Rejected`, which is an `UPDATE`, not an absence. A
`MISSING` row is therefore **recorded and surfaced, and the run stops for a human decision**
rather than silently dropping data. The real NVD deletion semantics are confirmed before any
policy is written.

## 3. Identity

**Snapshot identity** — the snapshot date from `ingest_manifest.json`, the set of complete
windows, and a hash over the ordered per-window page hashes. Two snapshots with equal identity
must produce equal output.

**Row identity** — `cve_id`, which `normalize()` already treats as unique; the funnel recorded
`raw_cves == unique_cves == 257,913`, so no CVE appears twice.

**Row content identity** — a SHA-256 over the §1 fields in a fixed canonical order. This is the
`UPDATE` versus `UNCHANGED` decision. It is *not* `description_norm_hash`, which covers only
the description and is used for deduplication.

## 4. Local versus global transformations

This is the core of the track. A stage is **local** if one row's output depends only on that
row, and **global** if it depends on other rows.

| Stage | Class | Dependency scope |
|---|---|---|
| `normalize_record` | **local** | the record alone |
| eligibility filter (rejected / empty description / `label_status`) | **local** | the record alone |
| temporal split assignment | **local** | the record plus the fixed snapshot date |
| `to_sft_row` (prompt rendering, truncation) | **local** | the record plus the selected label list |
| top-15 label selection | **global, bounded** | counts over the whole train period |
| exact dedup survivor | **global, group-scoped** | rows sharing a `description_norm_hash` |
| cross-split overlap drop | **global, group-scoped** | rows sharing a hash across splits |
| **SFT sampling** | **global, unbounded** | the entire ordered population |

### 4.1 Measured sensitivity

Each global stage was measured rather than reasoned about.

**Label selection is bounded and robust.** Over the 105,612 eligible train-period rows there
are 597 distinct CWEs. At the selection boundary: rank 15 is CWE-284 with 1,456, rank 16 is
CWE-77 with 1,325 — a **margin of 131**. The top-15 set changes only if CWE-77 gains 132 or
more net train-period rows, or CWE-284 loses that many. Maintaining per-class counts detects
this cheaply and exactly.

**Dedup is group-scoped and small.** Of 65,272 train rows, 1,343 hash groups contain more than
one row, covering 4,770 rows, largest group 101, and 3,427 rows are dropped — matching the
manifest exactly. An `INSERT` or `UPDATE` can only change survivorship inside the group whose
`description_norm_hash` it touches, and `keep_first` orders by `(published, cve_id)`, so the
new row wins only if it sorts earlier.

**SFT sampling is unbounded, and this is the finding that constrains the whole track.**
`sample_records` calls `random.Random(42).sample(rows, k)` on the ordered population, and
`random.sample` draws indices as a function of population size. Measured on the real shape,
12,000 sampled from 65,272:

| Change to the population | Sampled rows still in common | Rows replaced |
|---|---:|---:|
| one row inserted mid-list | 7,508 of 12,000 (62.57%) | 4,492 |
| one row appended at the end | 11,035 of 12,000 | 965 |

A single insert anywhere therefore replaces about **37%** of the training set. No invalidation
analysis avoids this: if the population size changes at all, the sample must be recomputed in
full, and the resulting dataset is not a superset or subset of the old one — it is a different
draw.

## 5. Invalidation boundary (draft)

```
raw pages ──local──> normalized rows ──local──> eligibility ──local──> split assignment
                                                                            │
                                            ┌───────────────────────────────┤
                                            ▼                               ▼
                              label counts (global, bounded)     hash groups (global, scoped)
                                            │                               │
                                            └───────────────┬───────────────┘
                                                            ▼
                                            SFT sampling (global, unbounded)
                                                            ▼
                                                    manifest + outputs
```

Everything above the sampling line can be incrementally invalidated with a precise, bounded
blast radius. The sampling line itself cannot.

## 6. What this implies before any prototype is written

The recorded full-pipeline cost splits sharply. Ingestion took roughly 2 to 2.5 hours and
dominates everything; it is I/O-bound API paging, and NVD exposes `lastModStartDate`, so it is
the one stage where incremental fetching is both possible and clearly worth it. Everything
downstream is cheap — the Spark reimplementation ran normalize, split, dedup and overlap over
all 257,913 records in **45.4 seconds** at `local[8]`.

So the honest shape of the problem is:

- **Incremental ingestion**: clearly valuable, and independent of every correctness hazard in
  §4, because it only decides which raw pages to fetch.
- **Incremental downstream assembly**: has to redo the sampling draw on any population change
  anyway, and the stages it could skip already complete in under a minute.

This is a live candidate for the §22 stop condition — that a full deterministic rebuild from
cached raw pages is the better engineering choice — but it is **not yet a conclusion**. It is
measured against a full rebuild in T-015C before anything is decided.

## 7. Equivalence plan

Incremental output is never the truth. The truth is a full rebuild of snapshot B using the
existing reference pipeline, compared using the E1–E12 structure from
`docs/SPEC_distributed.md` §6, which already compares at row level rather than by row count.

Reported as two separate claims:

- **Composition equivalence** — normalized row count; `cve_id` symmetric difference; per-row
  field equality; selected labels and their order; split assignment per `cve_id`; class
  distribution; dedup survivor set; cross-split overlap counts; final train/val/test ID sets.
- **Byte equivalence** — `data/sft/*.jsonl` sha256 and the manifest values.

Composition can hold while bytes differ, for example through `is_kev` alone. A run that
achieves composition equivalence but not byte equivalence reports both and explains which
field moved. Row-count agreement alone is never sufficient.

## 8. Fixture plan (T-015B)

A controlled fixture of roughly 1,000 CVEs drawn deterministically from the existing cached
snapshot, not a live NVD fetch, so snapshot A is reproducible and offline.

Snapshot B applies changes whose **expected downstream effect is written down before the run**
and is not revised afterwards:

| Case | Expected effect |
|---|---|
| `INSERT`, new `cve_id` in the train period | eligibility and split local; label counts +1; sampling fully redrawn |
| `UPDATE` to `description` only | `description_norm_hash` changes; dedup group membership may move on both the old and new hash; composition may change; prompt bytes change |
| `UPDATE` to `weaknesses` changing `cwe_id` | class counts move on two classes; eligibility unchanged |
| `UPDATE` to `weaknesses` making it multi-label | row leaves eligibility entirely |
| `UPDATE` to `vulnStatus` → `Rejected` | row leaves eligibility |
| `UPDATE` to `cisaExploitAdd` only | composition unchanged; **bytes change** via `is_kev` |
| `UPDATE` to CVSS only | **nothing changes** — the negative control |
| `UNCHANGED` | nothing changes |
| `MISSING` | recorded, surfaced, run stops for a decision |

The CVSS case is deliberately included as a negative control: a change-detection
implementation that reprocesses it is over-triggering, and that is a defect the fixture is
designed to catch.

## 9. Not in this track

No Kafka, Airflow, Spark Streaming, Delta Lake, Iceberg, Hudi, Ray, Kubernetes, new database,
or deployment. There is no measured evidence any of them is needed. Two files on disk are
enough to define the problem precisely, and the problem is defined first.

## 10. Protected

Unchanged by this track: `main`; all v0.1.0 results, model metrics and documents; the processed
and SFT dataset baselines; the fixed evaluation IDs; the Audit A truth; the Gate 1 artifacts;
and every T-014 artifact. A checksum baseline is taken before each run and re-verified after.
Existing results are never adjusted to fit this track.

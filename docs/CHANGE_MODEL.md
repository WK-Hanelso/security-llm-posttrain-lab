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
| `metrics.cvssMetricV31[0].cvssData` | `cvss_v31_base_score`, `cvss_v31_severity` | no | **corrected — see §17** |
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

---

# T-015B — Fixture specification

Everything in this section is fixed **before** Snapshot B is built or run, and is not revised
after seeing results.

## 11. Why a plain random sample will not do

The fixture has to exercise structures that a random 1,000-row draw would probably miss.
Measured over the 194,794 eligible records: 3,879 duplicate hash groups covering 13,631 rows
(largest 222), of which only **242 groups span two splits** — the cross-split overlap case.
KEV is rare at 923 eligible rows. A uniform 1,000-row sample would contain roughly five
duplicate-group rows and no complete group, so survivorship could not be tested at all.

Selection is therefore **stratified, with whole duplicate groups**, under this rule, fixed here:

| Stratum | Target rows | Purpose |
|---|---:|---|
| train-period eligible, top-15 label | 500 | main population |
| train-period eligible, non-top-15 label | 150 | label-selection boundary |
| val-period eligible | 150 | split coverage |
| test-period eligible | 200 | split coverage |
| within-split duplicate groups, taken whole | ~80 | dedup survivorship |
| cross-split duplicate groups, taken whole | ~40 | cross-split overlap drop |
| `is_rejected` | 30 | eligibility exclusion |
| `is_kev` eligible | 40 | byte-vs-composition |
| ineligible (`multi` / `placeholder_only` / no description) | 30 | filter coverage |

Seed `20260919`. Duplicate groups are taken **entire** — a partial group makes survivorship
untestable. Strata are filled in the order listed and a record already selected is not counted
twice, so the total is approximate; the exact ID list is what counts and is frozen in the
manifest with its hash.

## 12. Config overrides, and why each is needed

The fixture runs the unmodified reference pipeline with an overridden config. Production
config values are not edited.

| Key | Production | Fixture | Reason |
|---|---|---|---|
| `nvd.raw_dir` | `data/raw/nvd` | `data/fixture/<snapshot>/raw` | isolation; the real raw tree is read-only input |
| `paths.processed_dir`, `paths.sft_dir`, `paths.manifest`, `paths.stats`, `paths.contamination`, `paths.labels_file` | `data/…`, `manifests/…`, `reports/…` | under `data/fixture/<snapshot>/` | **never write to the protected baselines** |
| `labels.min_train_samples_per_class` | 200 | 5 | at fixture scale no class reaches 200, and `create_splits` raises if fewer than two labels survive |
| `sft.train_max_samples` | 12,000 | **300** | **critical** — `sample_records` returns the whole list when `maximum >= len(rows)`, so with the production value the fixture would never sample and hypothesis H5 would be invisible. It must sit below the fixture's train population |
| `sft.val_max_samples` | 1,000 | 80 | same reason, validation side |
| `sft.test_max_samples` | null | null | unchanged; the real pipeline keeps the whole test split, and H5 is exercised on the train side |
| `split.*`, `labels.top_k`, `seed`, `dedup.*`, `sft.max_description_chars`, `sft.sampling` | — | **unchanged** | these are the behaviour under test |

The `train_max_samples` override is the one that decides whether this fixture can answer its
own question. Record the resulting fixture train population next to it, and confirm
`train_max_samples < population` before the run.

## 13. Change-detector categories

Classified on the §1 dataset-relevant fields, never on `lastModified` alone:

`INSERT`, `UPDATE_DATASET_RELEVANT`, `UPDATE_DATASET_IRRELEVANT`, `UNCHANGED`, `MISSING_REVIEW`.

Each `UPDATE` records `changed_fields`, `before_hash`, `after_hash`,
`dataset_relevant_change`, and `expected_downstream_scope`.

## 14. Stage-level propagation table

For every case, each stage is labelled with one of `UNCHANGED`, `LOCAL_RECOMPUTE`,
`GROUP_RECOMPUTE`, `GLOBAL_RECOMPUTE`, `REVIEW_REQUIRED`, across: raw, normalization,
eligibility, label extraction, label selection, temporal split, dedup, cross-split overlap,
SFT sampling, SFT row serialization, manifest.

## 15. Hypotheses under test

| | Hypothesis |
|---|---|
| H1 | A CVSS-only change does not alter dataset composition |
| H2 | A dataset-relevant `UPDATE` changes downstream output from the stage the model predicts |
| H3 | Dedup effects are explained within the duplicate group, not globally |
| H4 | Top-label selection is global but bounded by the count margin at this snapshot |
| H5 | SFT sampling requires global recomputation when the population size changes |
| H6 | An `is_kev` change can break byte equivalence while composition is unchanged |
| H7 | `MISSING` cannot be safely auto-deleted |

H4's margin of 131 is an observation about this snapshot, not a rule. If the fixture cannot
flip the boundary with a realistic change, that is the expected outcome and is recorded as
such; a synthetic count setup may be used to show the mechanism, and is then explicitly
labelled synthetic rather than described as a real top-15 change.

## 16. Truth, and what happens when a prediction fails

Snapshot B is **fully rebuilt** with the reference pipeline. That rebuild is the truth. The
fixture's expected effects and any incremental prediction are the things being judged, never
the standard.

When expectation and result disagree, the expected value in this document is **not** edited to
match. The run reports `prediction failed`, and identifies whether the cause was the fixture,
the dependency model, a misreading of the pipeline, or an implementation bug. A failed
prediction that is understood is a result of this task, not a defect in it.


---

## 17. Correction after T-015B: the CVSS row in §1 was wrong

**H1 failed, and the cause was this document, not the implementation.**

§1 recorded a CVSS-only change as affecting neither composition nor output bytes, and §8 used
it as a negative control whose expected effect was "nothing changes". The full rebuild of
Snapshot B showed otherwise.

What is actually true, measured:

- `to_sft_row` does not carry CVSS, so `data/sft/*.jsonl` and the SFT file hashes are
  **byte-identical** across a CVSS-only change.
- `normalize_record` **does** emit `cvss_v31_base_score` and `cvss_v31_severity`, and those
  fields are serialized into `data/processed/normalized.jsonl` and carried through into
  `data/processed/{train,val,test}.jsonl`.
- §7's composition equivalence includes per-row field equality over the normalized schema,
  which contains those two fields. So the rebuilt intermediate artifacts differ, and a strict
  reading of §7 reports a difference.

The error was mine: I scoped "output bytes" to the final SFT files and did not account for the
intermediate artifacts. The correct statement is narrower and needs to name the artifact:

> A CVSS-only change does not alter **dataset composition** — which records are selected, their
> labels, splits, dedup survivors or SFT membership — and does not alter the **SFT output
> bytes**. It does alter the **normalized and processed intermediate rows**, and therefore
> their hashes.

H1 is restated accordingly for later use:

> **H1'** — A CVSS-only change alters no composition property and no SFT output byte, while
> intermediate artifacts that serialize CVSS do change.

This is also the negative control doing its job, just not the job I expected. It was placed to
catch an implementation that over-triggers; it caught a dependency model that under-specified
what "output" meant. That distinction — composition, final bytes, and intermediate bytes as
three separate things rather than two — is the substantive result of T-015B, and it changes
what an incremental implementation would have to promise.

The original §1 and §8 text is left in place above, marked, rather than rewritten, so the
failed prediction stays visible.

---

# T-015C — Minimal incremental prototype versus full deterministic rebuild

## 18. Three equivalence layers

T-015B's H1 failure showed two layers are not enough. Every comparison in T-015C reports
three, each with its own PASS/FAIL, never merged into one verdict:

| Layer | Question | Artifacts |
|---|---|---|
| **A. Composition** | is the dataset logically the same? | selected CVE IDs, labels and their order, split assignment, dedup survivor set, cross-split overlap, SFT membership |
| **B. Final byte** | is the training artifact serialized identically? | `sft/*.jsonl` row content, field values, row ordering, file hashes, manifest values |
| **C. Intermediate byte** | are the intermediate rows identical? | `normalized.jsonl`, `processed/{train,val,test}.jsonl`, their serialized fields and hashes |

Expected per case, carried forward from T-015B's measured truth and **not** re-derived:

| Case | A | B | C |
|---|---|---|---|
| CVSS-only | SAME | SAME | **DIFFERENT — expected** |
| KEV (`cisaExploitAdd`) | SAME | **DIFFERENT** | DIFFERENT |
| UNCHANGED | SAME | SAME | SAME |

Making layer C match on the CVSS case by ignoring the CVSS change is a failure, not a fix.

## 19. Measured cost structure — what incrementality could actually win

Measured before the prototype was written, so the target is known rather than discovered
afterwards.

**Production downstream**, 257,913 normalized rows, plain Python:

| Stage | Wall | Dependency class |
|---|---:|---|
| `normalize` | **38.60 s** (peak 1.88 GiB) | **LOCAL** |
| `split` + `build_sft` + `contamination` | ≈ 17.6 s | mostly **GLOBAL** |
| recorded post-ingest total | 56.18 s | |

So roughly **69% of downstream cost sits in the one stage that is fully local**, and the
remainder is dominated by stages that §13 and §14 require to be recomputed globally for
correctness. That bounds the achievable saving before any code is written.

**Fixture downstream**, 1,216 normalized rows: normalize 0.19 s, split 0.11 s, build_sft
0.13 s, contamination 0.07 s — **0.50 s total**, most of it interpreter startup.

### 19.1 Consequence for the experiment design

**A runtime comparison at fixture scale cannot decide anything.** At half a second dominated
by process startup, any incremental/full difference is noise. Do not report a fixture-scale
speedup as evidence either way.

The experiment therefore splits:

- **Correctness at fixture scale** — all nine cases, three layers. This is where the decision
  about *what can be reused* is made, and it is scale-independent.
- **Work accounting at fixture scale** — reused rows, locally recomputed rows,
  group-recomputed rows, globally recomputed stages. Ratios, not seconds. Also
  scale-independent.
- **Runtime at production scale for the full rebuild only** — the 38.60 s and 56.18 s above are
  the real denominator. Any statement about what incremental *would* save at production scale
  is a **projection** from the work accounting and is labelled as one.

### 19.2 The cost that is easy to forget

Verifying that an incremental result is correct requires a full rebuild to compare against.
If equivalence is checked on every run, the check costs more than the saving. Any conclusion
that incremental is worthwhile must say how often correctness would actually be verified, and
count that cost honestly.

## 20. Scope limits

Implement LOCAL and GROUP recomputation. **Do not force GLOBAL stages to be incremental** —
where full recomputation is simpler and correct, run it and record it as `GLOBAL_RECOMPUTE`.

Specifically, and not negotiable for this task:

- **SFT sampling** is recomputed globally whenever the population size changes. The sampling
  algorithm is **not** replaced — no consistent hashing, no reservoir sampling, no stable-hash
  sampling. Those are a different design change and would invalidate every baseline.
- **Label selection** is recomputed globally. The rank-15/16 margin of 131 is an observation
  about this snapshot, not a licence to skip the recomputation. Bounded optimisation is a
  separate later decision.
- **Dedup** invalidates **both** the old and the new hash group of an updated row, since an
  update can leave one group and join another.
- **MISSING** keeps `apply_status = REVIEW_REQUIRED` and the run does not reach a completed
  state. Quietly dropping a missing row to make equivalence pass is a failure.

No dataset rule changes: split ranges, top-15 policy, dedup rules and sampling strategy stay
exactly as they are.

## 21. Order of work

Correctness first, and completely, before any timing is taken. A speed comparison on a
prototype that does not yet reproduce the full rebuild measures nothing.

## 22. The decision, and both valid answers

Judged on wall-time reduction, recomputed-row reduction, peak memory, the share of work that
is global, implementation complexity, how hard equivalence is to keep, the number of failure
modes, and auditability — not on a single speedup number.

**Case A** — downstream incremental rebuild holds all three equivalence layers and saves
enough to justify its complexity, so it is worth extending.

**Case B** — incremental source ingestion is worth pursuing, but downstream is better served
by a deterministic full rebuild at this scale: it is simpler, safer, and already cheap.

Both are legitimate results. Neither the baselines nor the measurements are adjusted to reach
either one.

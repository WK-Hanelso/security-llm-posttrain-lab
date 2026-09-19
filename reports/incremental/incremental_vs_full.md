# T-015C — minimal incremental prototype versus full rebuild

## Result

**Case B.** Incremental source ingestion is worth pursuing; downstream should remain a deterministic full rebuild at this scale. The applyable changes demonstrate exact LOCAL/GROUP reuse, but the real combined run correctly stops at `REVIEW_REQUIRED` for `CVE-2007-6070` and writes nothing.

Snapshot B remains the truth. All nonvolatile fixture artifacts match its recorded hashes. The current worktree's protected `dataset_manifest.json` was already modified in `created_at` and `git_commit`; its committed HEAD blob matches the recorded hash, and the prototype did not alter it.

## Change classification (canonical nine cases)

| Classification | Count |
|---|---:|
| INSERT | 1 |
| MISSING_REVIEW | 1 |
| UNCHANGED | 1 |
| UPDATE_DATASET_RELEVANT | 5 |
| UPDATE_INTERMEDIATE_ONLY | 1 |

## Stage dependency map

| Stage | Action |
|---|---|
| normalization | LOCAL |
| eligibility | LOCAL |
| temporal_split | LOCAL |
| row_serialization | LOCAL |
| exact_dedup | GROUP_RECOMPUTE (old and new description hash) |
| cross_split_overlap | GROUP_RECOMPUTE (old and new description hash) |
| label_selection | GLOBAL_RECOMPUTE |
| sft_sampling | GLOBAL_RECOMPUTE (reference random.sample semantics) |

`label_selection` is always recomputed; the rank-15/16 margin is not used as a shortcut. `sft_sampling` calls the unchanged `random.sample` implementation.

## Three-layer correctness by case

`Relation` is Snapshot A versus that case's isolated full-rebuild truth. `Verdict` is incremental versus that truth. C09 passes the required guard; artifact comparison is not run.

| Case | Class | A relation/verdict | B relation/verdict | C relation/verdict | Expectation |
|---|---|---|---|---|---|
| C01_INSERT | INSERT | DIFFERENT / PASS | DIFFERENT / PASS | DIFFERENT / PASS | PASS |
| C02_DESCRIPTION_UPDATE | UPDATE_DATASET_RELEVANT | DIFFERENT / PASS | DIFFERENT / PASS | DIFFERENT / PASS | PASS |
| C03_CWE_UPDATE | UPDATE_DATASET_RELEVANT | DIFFERENT / PASS | DIFFERENT / PASS | DIFFERENT / PASS | PASS |
| C04_MULTI_LABEL_UPDATE | UPDATE_DATASET_RELEVANT | DIFFERENT / PASS | DIFFERENT / PASS | DIFFERENT / PASS | PASS |
| C05_REJECTED_UPDATE | UPDATE_DATASET_RELEVANT | DIFFERENT / PASS | DIFFERENT / PASS | DIFFERENT / PASS | PASS |
| C06_KEV_UPDATE | UPDATE_DATASET_RELEVANT | SAME / PASS | DIFFERENT / PASS | DIFFERENT / PASS | PASS |
| C07_CVSS_NEGATIVE_CONTROL | UPDATE_INTERMEDIATE_ONLY | SAME / PASS | SAME / PASS | DIFFERENT / PASS | PASS |
| C08_UNCHANGED | UNCHANGED | SAME / PASS | SAME / PASS | SAME / PASS | PASS |
| C09_MISSING_REVIEW | MISSING_REVIEW | SAME / PASS | SAME / PASS | DIFFERENT / PASS | PASS |
| C10_PUBLISHED_BOUNDARY_UPDATE | UPDATE_DATASET_RELEVANT | DIFFERENT / PASS | DIFFERENT / PASS | DIFFERENT / PASS | PASS |

The CVSS-only case is therefore A SAME / B SAME / C DIFFERENT, the KEV case is A SAME / B DIFFERENT / C DIFFERENT, and UNCHANGED is SAME at all three layers. Intermediate CVSS bytes are preserved rather than ignored.

## Work accounting

This is a diagnostic plan over all eight non-missing changed records in the ten-case fixture (seven canonical plus C10), retaining the unresolved missing row; it is not presented as a completed B run. Of 1217 rows, normalization reuses 1209 and recomputes 8. Processed artifacts reuse 814 rows and locally recompute 6. The two group stages touch 9 old/new hash groups covering 18 split rows. Final serialization reuses 351 existing SFT rows, locally recomputes 3 source-changed rows, and materializes 137 unchanged rows that became members after the global draw (there was no prior SFT cache entry for them).

Two of eight transformation stages are global (25% by stage count), and both global stages are fully recomputed (100%). They account for 1959/2159 = 90.7% of a scale-independent row-visit proxy. The proxy is not a runtime fraction because stage costs differ.

## Production projection (not fixture timing)

Measured denominators are 38.60 s for normalization (1.88 GiB peak) and 56.18 s post-ingest. A linear row-work projection puts normalization at 0.25 s and total downstream work at 17.83 s before incremental bookkeeping, a maximum saving of 38.35 s. No fixture-scale speedup is reported.

Peak-memory savings are not claimed: global label selection and sampling still require full-population state. Verification would run on every code/config release and weekly for daily routine runs. Weekly verification amortizes 8.03 s per daily run, bringing the projection to 25.86 s before bookkeeping. Verification every run would cost 74.01 s, more than the 56.18 s full rebuild.

## §22 decision

**Case B:** pursue incremental ingestion, but use a deterministic downstream full rebuild. The projected downstream saving is at most about 38 seconds against hours of ingestion, while two global stages remain unavoidable. The prototype adds state/version compatibility, field-classification, old/new-group invalidation, cache completeness, ordering, manifest, missing-row, and verification failure modes. A full rebuild is simpler to audit, has a smaller correctness surface, and is already cheap. Exact equivalence is feasible for non-missing changes, but the saving does not justify operating the added machinery.

## Mismatch and stop condition

The real combined run produces no incremental Snapshot B artifacts: `CVE-2007-6070` is `MISSING_REVIEW`, so `apply_status=REVIEW_REQUIRED`, `completed=false`, and `writes_performed=false`. This is the required behavior, not an equivalence failure to hide. Dropping that row would make a comparison easier and would be incorrect.

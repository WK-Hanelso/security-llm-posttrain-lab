# T-015B — controlled snapshot dependency validation

## Result

**Not completely.** The dependency model correctly predicts final SFT behavior for the dataset-relevant cases, including group-scoped dedup and global sampling. The CVSS negative control exposes one boundary error: its final SFT row is byte-identical, but a full rebuild changes CVSS fields retained in `normalized.jsonl` and the processed split. That violates §7's strict per-row equality even though final training composition is unchanged.

Snapshot B was rebuilt fully with the unmodified reference pipeline. No incremental application was performed after the detector found `MISSING_REVIEW`.

## Fixture and rebuilds

- Selection seed: `20260919`
- Snapshot A frozen IDs: 1216 (`958d3d8455126163bab9027b4b8986c7f88aedc5f6fc068a7742a2b3c14b167c`)
- Train sampling assertion: `300 < 541` — passed before Snapshot A was written
- Effective train pools: A=541, B=542
- Processed split populations: A={'train': 602, 'val': 108, 'test': 111}; B={'train': 602, 'val': 107, 'test': 111}
- Reference-pipeline overlap guard: zero CVE-ID and normalized-text overlaps after both builds

Final stratum coverage: train_top15=602, train_non_top15=158, val_eligible=175, test_eligible=221, is_rejected=30, is_kev_eligible=40, ineligible_multi_placeholder_no_description=30.

## Change detector

| Category | Count |
|---|---:|
| INSERT | 1 |
| UPDATE_DATASET_RELEVANT | 6 |
| UPDATE_DATASET_IRRELEVANT | 1 |
| UNCHANGED | 1208 |
| MISSING_REVIEW | 1 |

Detector action: **STOPPED_MISSING_REVIEW**; `applied=false`. Missing ID: `CVE-2007-6070`.

## Per-case result

| Case | Detector | Actual full-rebuild result | Prediction |
|---|---|---|---|
| C01_INSERT | INSERT | eligible train singleton added; INSERT-only sample replaced 36/300 (12.0%) | passed |
| C02_DESCRIPTION_UPDATE | UPDATE_DATASET_RELEVANT | old survivor `CVE-2022-30677` -> `CVE-2022-30678`; target becomes new-group survivor | passed |
| C03_CWE_UPDATE | UPDATE_DATASET_RELEVANT | single-label eligibility retained; class assignment and two train counts move | passed |
| C04_MULTI_LABEL_UPDATE | UPDATE_DATASET_RELEVANT | label_status single -> multi; row leaves train eligibility | passed |
| C05_REJECTED_UPDATE | UPDATE_DATASET_RELEVANT | is_rejected false -> true; row leaves train eligibility | passed |
| C06_KEV_UPDATE | UPDATE_DATASET_RELEVANT | membership unchanged; serialized test is_kev false -> true | passed |
| C07_CVSS_NEGATIVE_CONTROL | UPDATE_DATASET_IRRELEVANT | normalized/processed CVSS fields change; SFT row is byte-identical | FAILED |
| C08_UNCHANGED | UNCHANGED | normalized, processed, and SFT rows remain identical | passed |
| C09_MISSING_REVIEW | MISSING_REVIEW | absence surfaced; incremental application stops without deleting | passed |
| C10_PUBLISHED_BOUNDARY_UPDATE | UPDATE_DATASET_RELEVANT | processed assignment moves val -> train | passed |

## Actual propagation table

`U` = UNCHANGED, `L` = LOCAL_RECOMPUTE, `D` = GROUP_RECOMPUTE, `G` = GLOBAL_RECOMPUTE, `R` = REVIEW_REQUIRED.

| Case | raw | norm | elig | label ext | label sel | split | dedup | overlap | sample | serialize | manifest |
|---|---|---|---|---|---|---|---|---|---|---|---|
| C01_INSERT | L | L | L | L | G | L | D | D | G | G | G |
| C02_DESCRIPTION_UPDATE | L | L | U | U | U | U | D | D | G | G | G |
| C03_CWE_UPDATE | L | L | U | L | G | U | U | U | U | L | G |
| C04_MULTI_LABEL_UPDATE | L | L | L | L | G | U | D | D | G | G | G |
| C05_REJECTED_UPDATE | L | L | L | U | G | U | D | D | G | G | G |
| C06_KEV_UPDATE | L | L | U | U | U | U | U | U | U | L | G |
| C07_CVSS_NEGATIVE_CONTROL | L | L | U | U | U | L | L | L | L | U | U |
| C08_UNCHANGED | U | U | U | U | U | U | U | U | U | U | U |
| C09_MISSING_REVIEW | R | R | R | R | R | R | R | R | R | R | R |
| C10_PUBLISHED_BOUNDARY_UPDATE | L | L | U | U | G | L | D | D | G | G | G |

For C07, the pre-declared model expected every stage after normalization to remain unchanged. The full rebuild instead requires local propagation through the processed split, dedup/overlap pass-through, and pre-serialization sampled row so those intermediate artifacts equal the truth. Serialization drops CVSS, so the final SFT row and manifest dependency remain unchanged.

## Dedup and sampling evidence

C02 old-group members before: `CVE-2022-30677, CVE-2022-30678, CVE-2022-30680, CVE-2022-30681, CVE-2022-30682, CVE-2022-30684, CVE-2022-30685, CVE-2022-30686, CVE-2022-34218, CVE-2022-35664, CVE-2022-38438, CVE-2022-38439, CVE-2022-28851`.

The survivor changes from `CVE-2022-30677` to `CVE-2022-30678`. The changed target `CVE-2022-30677` moves to new hash `c720e7e997d76c76ad015cd016b5c7949fa9c1a7ff8595236d64f9e3cc684cd2` and survives there. No unrelated hash group is affected.

C01 INSERT-only sensitivity: pool 541 -> 542; 264/300 sampled IDs remain in common and 36/300 (12.0%) are replaced. The combined A->B comparison replaces 137/300, but that number includes all ten cases.

## Composition equivalence

Combined A vs B composition equivalence: **false**. Normalized counts are {'snapshot_a': 1216, 'snapshot_b': 1216}; the ID symmetric difference is one INSERT and one MISSING. Ordered labels remain equal: `True`. Detailed split-ID, class-distribution, survivor, and overlap comparisons are in the JSON report.

The CVSS-only target has unchanged final SFT membership and class composition, but strict §7 composition equivalence is false because normalized and processed per-row fields differ.

## Byte equivalence

Combined A vs B SFT byte equivalence: **false**.

| Split | Equal | Snapshot A SHA-256 | Snapshot B SHA-256 |
|---|---|---|---|
| train | False | `d373d92466e119c635439dfdd1085019671b43f89332c3606426d62d416ba75c` | `7dc18ec0c81d4bc269329816ff8b68b73e437d14d267d1fa7e8ea1bdd734668e` |
| val | False | `912eb4d438afd2ad0d5dc565cbc2bd81319e30abcb114e9d41f4b294837fe3d0` | `b3303c2679026acb55ed1d317479a8e51c2b75010137b51f913bb9fb65eb1ebf` |
| test | False | `a91010bb9e340eb21eb4b8d04594bbe633f9be1ee6eb6eb3d2b2e398973e5b0f` | `3c0fc0cfe26c37d962c7a95b3b62d763fe3f1f8da24da8e74e460b5482b68199` |

The KEV case is the clean byte-without-composition example: its test membership is unchanged and only `is_kev` changes in the serialized row. The CVSS-only SFT row is byte-identical.

## H1–H7

| Hypothesis | Verdict | Evidence |
|---|---|---|
| H1 | **FAIL** | Final SFT membership is unchanged, but §7 composition equivalence also requires normalized per-row field equality; the rebuilt normalized and processed rows retain the changed CVSS fields. |
| H2 | **PASS** | Every dataset-relevant UPDATE changed the predicted local or downstream artifact. |
| H3 | **PASS** | Description survivorship changes are confined to the recorded old and new description-hash groups. |
| H4 | **PASS** | Ordered top-15 labels stayed stable. Fixture rank-15/rank-16 margins were 7 in A and 7 in B. |
| H5 | **PASS** | INSERT-only changed 36 of 300 sampled memberships (12.0%). |
| H6 | **PASS** | KEV target retained membership and only its serialized is_kev field changed. |
| H7 | **PASS** | MISSING was classified MISSING_REVIEW and incremental application stopped without applying deletion. |

## MISSING behavior

`CVE-2007-6070` is recorded as `MISSING_REVIEW`. The incremental application did not run and no auto-delete was applied. The independently required full rebuild naturally lacks the absent raw row; that truth observation is not treated as permission to delete it incrementally.

## Failed predictions

- **C07_CVSS_NEGATIVE_CONTROL — prediction failed (dependency model).** Predicted: §8 says nothing changes and §7 requires normalized/processed per-row field equality. Actual: CVSS fields changed in normalized.jsonl and the processed test row; SFT row stayed byte-identical.

The expected values in `docs/CHANGE_MODEL.md` were not edited. The failure is caused by the dependency model's definition boundary, not by the fixture: the reference pipeline intentionally persists CVSS fields in normalized and processed rows while omitting them from SFT serialization.

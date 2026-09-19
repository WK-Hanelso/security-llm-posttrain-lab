# T-015B execution record

Date: 2026-09-19 (Asia/Seoul)

## Starting state

- Required branch: `feat/incremental-pipeline`
- Observed branch: `feat/incremental-pipeline`
- Required HEAD: `6d936f5`
- Observed HEAD: `6d936f5332d65043b4505db990b5b045bdd3dc54`
- Initial `git status --short`: clean
- Python: `.venv/bin/python` (CPU only)
- Network/install activity: none

The production pipeline under `src/security_llm/` and `configs/data.yaml` was read but not
modified. No Kafka, Airflow, Spark Streaming, Delta Lake, Iceberg, Hudi, Ray, database, or
production incremental pipeline was added.

## Fixture construction

`PYTHONPATH=src .venv/bin/python agent/t015b_fixture.py select` selected 1,216 raw CVEs with
seed `20260919`, using singleton records for ordinary strata and complete eligible duplicate
groups for the duplicate strata. The frozen ordered ID list is
`data/fixture/snapshot_a/selected_ids.txt`; SHA-256:

`958d3d8455126163bab9027b4b8986c7f88aedc5f6fc068a7742a2b3c14b167c`

Final matching stratum counts:

| Stratum | Rows |
|---|---:|
| train-period eligible, production top-15 | 602 |
| train-period eligible, non-production-top-15 | 158 |
| val-period eligible | 175 |
| test-period eligible | 221 |
| rejected | 30 |
| eligible KEV | 40 |
| other ineligible (multi / placeholder / no description) | 30 |

Before Snapshot A pages were written, the builder calculated the exact reference-pipeline
sampling input and asserted:

`sft.train_max_samples = 300 < effective train sampling population = 541`

The corresponding pre-dedup selected-label train population was 602; exact train duplicate
drops were 59 and train/eval overlap drops were 2.

Each snapshot has 21 complete raw-page windows. Raw page hashes and the ordered page-hash
identity are recorded in each `raw/ingest_manifest.json`. The complete per-file hashes are in
each snapshot's `hashes.json`.

## Reference rebuild commands

Both snapshots ran the unchanged modules below with the §12 overrides pointing every output
under the corresponding `data/fixture/snapshot_{a,b}/` tree:

```text
.venv/bin/python -m security_llm.data.normalize --config configs/data.yaml <overrides>
.venv/bin/python -m security_llm.data.stats --config configs/data.yaml <overrides>
.venv/bin/python -m security_llm.data.split --config configs/data.yaml <overrides>
.venv/bin/python -m security_llm.data.stats --config configs/data.yaml <overrides>
.venv/bin/python -m security_llm.data.build_sft --config configs/data.yaml <overrides>
.venv/bin/python -m security_llm.eval.contamination --config configs/data.yaml <overrides>
.venv/bin/python -m security_llm.data.guard --config configs/data.yaml --stage sft <overrides>
```

Snapshot A was rebuilt before cases were declared. Then
`agent/t015b_fixture.py declare-and-build-b` persisted all old/new values and expectations to
`reports/incremental/change_cases.json` before it wrote Snapshot B. That file contains the nine
canonical §8 cases and the separately identified published-boundary extension (ten total).

The detector ran before the B rebuild:

`PYTHONPATH=src .venv/bin/python agent/t015b_validate.py detect`

It stopped incremental application on `MISSING_REVIEW`. Snapshot B was then independently
rebuilt in full as the truth baseline.

## Rebuild results

| Measurement | Snapshot A | Snapshot B |
|---|---:|---:|
| Raw / normalized rows | 1,216 | 1,216 |
| Processed train | 602 | 602 |
| Processed val | 108 | 107 |
| Processed test | 111 | 111 |
| Effective train sampling pool | 541 | 542 |
| SFT train | 300 | 300 |
| SFT val | 80 | 80 |
| SFT test | 111 | 111 |
| Post-build ID/text overlap guard | zero | zero |

Detector counts: INSERT 1; UPDATE_DATASET_RELEVANT 6;
UPDATE_DATASET_IRRELEVANT 1; UNCHANGED 1,208; MISSING_REVIEW 1.

The INSERT-only counterfactual uses the reference `sample_records` function. Increasing the
effective pool from 541 to 542 retains 264/300 sampled IDs and replaces 36/300 (12.0%). The
combined ten-case A-to-B comparison replaces 137/300, so it is not attributed to INSERT alone.

The description target is `CVE-2022-30677`. Its complete 13-member old group and both hashes
are in the JSON report. The old-hash survivor changes from `CVE-2022-30677` to
`CVE-2022-30678`; the edited target survives as the only member of its new hash group.

## Verdicts and failed prediction

H1 FAIL; H2 PASS; H3 PASS; H4 PASS; H5 PASS; H6 PASS; H7 PASS.

The one failed prediction is the CVSS negative control, caused by the dependency model's
boundary rather than the fixture. The detector correctly classifies it as
`UPDATE_DATASET_IRRELEVANT`, and its final SFT row is byte-identical. However, a full rebuild
changes `cvss_v31_base_score` and `cvss_v31_severity` in both `normalized.jsonl` and the
processed test row. Therefore §8's “nothing changes” claim conflicts with §7's requirement for
normalized per-row field equality. `docs/CHANGE_MODEL.md` was not edited.

The MISSING target `CVE-2007-6070` was recorded and surfaced. Detector status is
`STOPPED_MISSING_REVIEW`, `applied=false`; no incremental deletion was applied. The required
independent full rebuild naturally lacks the absent raw record, and that observation was not
used as deletion authorization.

Full expected/actual details, the propagation table, separate composition and byte comparisons,
and failure attribution are in `reports/incremental/dependency_validation.{json,md}`.

## Verification

- Full `.venv` pytest attempted: collection stopped because the environment has no optional
  `pyspark` dependency for the three existing `tests/test_spark_*` modules. No install was made.
- CPU/non-Spark suite: 39 passed, 1 skipped.
- Both snapshot hash manifests independently re-read and verified every recorded file.
- Every raw page matched its ingest-manifest SHA-256; every listed window was complete and
  window totals equaled snapshot totals.
- Report assertions verified detector counts, stopped MISSING behavior, the CVSS processed/SFT
  distinction, and exactly one failed prediction.
- A SHA-256 baseline of all 166 pre-existing tracked files was checked after execution. Only
  `.gitignore` differs, intentionally; all protected pre-existing files are byte-identical.

## Worktree inventory

Modified:

- `.gitignore`

Added and visible to Git:

- `agent/T-015B_EXEC.md`
- `agent/t015b_fixture.py`
- `agent/t015b_validate.py`
- `data/fixture/README.md`
- `data/fixture/snapshot_a/{config_overrides.json,dataset_manifest.json,hashes.json,selected_ids.txt}`
- `data/fixture/snapshot_a/raw/ingest_manifest.json`
- `data/fixture/snapshot_b/{config_overrides.json,dataset_manifest.json,hashes.json,selected_ids.txt}`
- `data/fixture/snapshot_b/raw/ingest_manifest.json`
- `reports/incremental/change_cases.json`
- `reports/incremental/dependency_validation.json`
- `reports/incremental/dependency_validation.md`
- `reports/incremental/detector_output.json`
- `reports/incremental/fixture_manifest.json`

Generated and intentionally ignored as bulky rebuild material (every individual file and hash
is enumerated in the corresponding committed `hashes.json`):

- `data/fixture/snapshot_{a,b}/raw/<21 windows>/page_0000000.json`
- `data/fixture/snapshot_{a,b}/processed/{normalized,train,val,test}.jsonl`
- `data/fixture/snapshot_{a,b}/sft/{train,val,test}.jsonl`
- `data/fixture/snapshot_{a,b}/{labels,stats,contamination}.json`

No commit was attempted because `.git` is read-only for this task.

# T-015C execution record

Date: 2026-09-19  
Branch precondition: `feat/incremental-pipeline`  
HEAD precondition: `fdf3a519e1ce5c6ec165652f48aead68ffd28306` (`fdf3a51`)

## Scope

Implemented a CPU-Python prototype under `src/security_llm/incremental/`. It keeps the
reference dataset rules and sampling implementation. No network access, package install,
distributed system, database, deployment, or protected fixture write was used.

The prototype:

- classifies `INSERT`, `UPDATE_DATASET_RELEVANT`, `UPDATE_INTERMEDIATE_ONLY`, `UNCHANGED`,
  and `MISSING_REVIEW` from dataset fields rather than `lastModified`;
- reuses unchanged normalized and processed rows;
- invalidates both old and new description-hash groups;
- recomputes label selection and reference `random.sample` sampling globally;
- stops before all output writes when any `MISSING_REVIEW` is present.

## Precondition and input checks

```text
$ git branch --show-current
feat/incremental-pipeline

$ git rev-parse HEAD
fdf3a519e1ce5c6ec165652f48aead68ffd28306
```

Snapshot A: all 35 entries in `hashes.json` matched. Snapshot B: 34 of 35 current files
matched. The sole mismatch was the already-dirty protected
`data/fixture/snapshot_b/dataset_manifest.json`; its diff changes only `created_at` and
`git_commit`. The committed HEAD blob SHA-256 is
`e1b58fd530cf6cd600ee79746a04af2c1022a0601f52651a3bd97953f60c1266`, exactly the
value recorded in `snapshot_b/hashes.json`. The prototype did not alter this file.

## Correctness execution

Command:

```text
.venv/bin/python -m security_llm.incremental.evaluate
```

The harness applies each case alone to Snapshot A in a temporary directory, runs a full
rebuild through the unmodified `normalize`, `create_splits`, and `build` functions, then
runs the incremental prototype and compares the artifacts directly. It does not use row
counts as the equivalence criterion. The C10 published-boundary extension is reported in
addition to the canonical C01-C09 set.

Result: A/B/C all PASS against full-rebuild truth for C01-C08 and C10. C09 passes its
required guard independently at each layer: comparison is not run, `apply_status` is
`REVIEW_REQUIRED`, `completed=false`, and no writes occur.

The real combined A-to-B run produced:

```json
{
  "apply_status": "REVIEW_REQUIRED",
  "completed": false,
  "writes_performed": false,
  "missing_ids": ["CVE-2007-6070"]
}
```

No fixture-scale timing was taken or used as evidence. The report contains work accounting
and a labelled projection from the measured production denominators in §19.

## Tests

Compilation:

```text
.venv/bin/python -m py_compile \
  src/security_llm/incremental/__init__.py \
  src/security_llm/incremental/prototype.py \
  src/security_llm/incremental/evaluate.py
```

Result: PASS.

CPU/non-Spark suite:

```text
.venv/bin/pytest -q \
  --ignore=tests/test_spark_dedup.py \
  --ignore=tests/test_spark_normalize.py \
  --ignore=tests/test_spark_split.py
```

Result: `42 passed, 1 skipped`.

The unrestricted suite cannot collect in this environment because `pyspark` is absent from
`.venv`; no install was attempted, as required. The collection errors are limited to the
three ignored Spark test modules.

## Decision

Case B: pursue incremental source ingestion, but retain the deterministic downstream full
rebuild. The detailed numbers, verification cadence, failure modes, and reasoning are in
`reports/incremental/incremental_vs_full.{json,md}`.

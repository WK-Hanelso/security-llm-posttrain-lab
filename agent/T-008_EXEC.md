# T-008 + T-009 Execution Record — Spark Track A

Date: 2026-09-19 (Asia/Seoul)

## Repository gate and constraints

- Verified branch `feat/distributed-pipeline` and starting HEAD
  `e35c6be7d03bb0b665a8dc841c6a2cdef9b4730c` before doing any work.
- Used `.venv-dist/bin/python` only. No packages were installed and `.venv` was not used or
  modified.
- Set `SPARK_LOCAL_IP=127.0.0.1` for every Spark invocation.
- No GPU workload or Docker command was run.
- Existing raw, processed, SFT, report, configuration, and reference-manifest paths listed as
  protected in the task were not written, moved, or deleted.

## Implementation review and corrections

The prior-run implementation was retained. It uses the reference `normalize_record`, inclusive
temporal ranges, train-only label selection, deterministic `(published, cve_id)` keep-first
deduplication, and the reference's pre-dedup-train asymmetry for validation overlap removal.

Two execution issues were corrected:

1. A driver launched through the absolute `.venv-dist/bin/python` path did not put the venv's
   `bin` directory first on `PATH`, so Spark selected host Python 3.9 for workers while the driver
   used Python 3.11. The Spark session now pins worker and driver Python to `sys.executable`, and
   the Spark tests use the production session builder.
2. Spark's declared input schema materializes absent optional JSON fields as `None`. The reference
   `json.load` representation omits those keys and relies on `dict.get(..., default)`. The Spark
   adapter now recursively omits schema-generated null fields before passing a CVE to the unchanged
   reference normalizer. A regression test covers this conversion.

These are implementation corrections, not deviations from `docs/SPEC_distributed.md`. The SPEC
was not changed.

## Commands run

```text
git branch --show-current
git rev-parse HEAD
SPARK_LOCAL_IP=127.0.0.1 .venv-dist/bin/python -m pytest tests/test_spark_*.py
PYTHONPATH=src SPARK_LOCAL_IP=127.0.0.1 .venv-dist/bin/python -m security_llm.spark.pipeline --config configs/data.yaml --master 'local[1]'
bash scripts/prepare_data_spark.sh
SPARK_LOCAL_IP=127.0.0.1 .venv-dist/bin/python -m pytest
```

The final required Spark test run passed: **3 passed, 0 failed** in 9.44 seconds.

The additional full-suite attempt in `.venv-dist` stopped during collection because the minimal
distributed environment intentionally lacks `torch` and `scikit-learn`; four legacy test modules
import those packages. No dependencies were installed. The previous run's frozen-environment
result remains **35 passed, 1 skipped**. This collection limitation does not affect the required
Spark tests or E1-E12.

## Pipeline populations

| Stage | Train | Validation | Test |
|---|---:|---:|---:|
| Selected-label population | 65,272 | 21,151 | 24,975 |
| Post exact train dedup | 61,845 | 21,151 | 24,975 |
| Post overlap removal | 61,809 | 20,918 | 24,975 |

Drop counts were 3,427 train-internal exact duplicates, 36 train-to-evaluation overlaps, and 233
validation-to-train/test overlaps. The normalized population was 257,913 rows with 257,913 unique
`cve_id` values.

## Equivalence results

Comparison was row-level by `cve_id`; Parquet byte identity and row order were intentionally not
compared.

| Check | Expected | Actual | Result |
|---|---|---|:---:|
| E1 normalized row count | 257,913 | 257,913 | PASS |
| E2 normalized `cve_id` symmetric difference | 0 | 0 | PASS |
| E3 normalized per-row field mismatches | 0 | 0 | PASS |
| E4 selected labels, ordered | Reference 15-label list | Identical | PASS |
| E5 split populations train / val / test | 65,272 / 21,151 / 24,975 | 65,272 / 21,151 / 24,975 | PASS |
| E6 split assignment disagreements | 0 | 0 | PASS |
| E7 class distribution per split | Identical | Identical | PASS |
| E8 train exact duplicates dropped | 3,427 | 3,427 | PASS |
| E9 post-train-dedup `cve_id` symmetric difference | 0 | 0 | PASS |
| E10 train-to-evaluation overlap dropped | 36 | 36 | PASS |
| E11 validation-to-evaluation overlap dropped | 233 | 233 | PASS |
| E12 post-drop hash overlaps train-test / train-val / val-test | 0 / 0 / 0 | 0 / 0 / 0 | PASS |

E12's corresponding pairwise `cve_id` overlap counts were also 0 / 0 / 0. No equivalence check
failed.

## Single-node wall-clock measurements

| Stage | `local[1]` seconds | `local[8]` seconds |
|---|---:|---:|
| Normalize | 37.507 | 25.765 |
| Split | 6.171 | 2.734 |
| Dedup | 3.537 | 1.657 |
| Overlap | 34.849 | 13.692 |
| Manifest | 3.734 | 1.515 |
| **Measured Track A total** | **85.798** | **45.363** |

On this one node, the measured `local[8]` stage total was 1.89x faster than `local[1]`. This is a
local-mode observation only; no cluster scaling is claimed or extrapolated.

The existing reference log `logs/prepare_data_20260917T083019Z.log` yields:

- Full single-process preparation: **11,796.520 seconds** (3 h 16 m 36.520 s), from the UTC
  timestamp in its filename to file mtime. This includes NVD ingestion.
- Post-ingest remainder: **56.182 seconds**, from the final timestamped ingest event to file mtime.
  The log has untimestamped stage markers, so this necessarily includes normalization, statistics,
  split, SFT construction, and contamination work and is broader than Spark Track A. It is retained
  as the closest available reference-log interval, not presented as a controlled benchmark.

## Produced artifacts

- `data/spark/normalized`, `data/spark/splits`, `data/spark/deduped`, and
  `data/spark/labels.json`
- `manifests/spark_dataset_manifest.json`
- `reports/distributed/equivalence_report.json`
- `reports/distributed/equivalence_report.md`
- `reports/distributed/spark_overlap.json`
- `reports/distributed/runtime.json`

The final manifest records `local[8]`, 64 shuffle partitions, Spark 3.5.3, seven final physical
split/year partitions, and 585 Parquet part files across all three Spark output stages. Every listed
file was independently checked after generation: no file was missing and every byte size and
SHA-256 matched.

## Human decisions

None required for equivalence or the distributed implementation. If maintainers want the entire
legacy suite runnable from `.venv-dist`, adding its ML/evaluation dependencies would expand the
purpose and lockstep requirements of `requirements-distributed.txt`; this task intentionally did
not do that.

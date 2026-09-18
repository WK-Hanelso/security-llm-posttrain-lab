# Dataset Card

## Source

The source is the NVD CVE API 2.0. The dataset snapshot is 2026-09-17. Raw API pages are retained as the
source evidence; normalization produces one canonical record per CVE ID.

## Purpose

This dataset supports a reproducible, closed-set experiment that maps an English CVE description to one CWE
ID. It also provides a model-independent canonical security record, explicit label and split policies, and
artifacts for auditing the data preparation steps. The SFT view is an adapter derived from the canonical
records and is not part of the canonical schema.

## Canonical record schema

Schema version: `1.0`.

| Field | Type | Meaning |
|---|---|---|
| `cve_id` | string | CVE identifier matching `CVE-YYYY-NNNN+` |
| `published` | date string | NVD publication date |
| `last_modified` | date or datetime string | NVD last-modified value |
| `vuln_status` | string | NVD vulnerability status |
| `description_en` | string | First English description, stripped |
| `description_norm_hash` | string | SHA-256 of the normalized English description |
| `cwe_primary` | list of strings | Unique valid Primary CWE values |
| `cwe_secondary` | list of strings | Unique valid Secondary CWE values |
| `cwe_all` | list of strings | Sorted unique union of valid Primary and Secondary values |
| `placeholder_only` | boolean | Weakness entries exist but contain placeholders only |
| `cwe_id` | string or null | Sole CWE when exactly one valid CWE exists |
| `label_status` | string | `single`, `multi`, `placeholder_only`, or `none` |
| `cvss_v31_base_score` | number or null | First CVSS v3.1 base score |
| `cvss_v31_severity` | string or null | First CVSS v3.1 base severity |
| `is_kev` | boolean | Whether an NVD CISA exploit-add date is present |
| `kev_date_added` | string or null | NVD CISA exploit-add date |
| `is_rejected` | boolean | Rejected status or rejection-description marker |

The validator checks required fields, identifiers, dates, label-state consistency, normalized-description
hashes, and KEV field consistency. Prompt, tokenizer, template, and model fields are excluded from this record.

## Label policy

| Item | Policy |
|---|---|
| Task shape | Single-label classification |
| Label selection | Top 15 CWE IDs by eligible training-period frequency |
| Selection period | 2020-01-01 through 2024-12-31 |
| Minimum class count | 200 training records |
| Placeholder handling | `NVD-CWE-noinfo` and `NVD-CWE-Other` excluded |
| Output space | Fixed 15-label closed set |

Labels are selected using the training period only. Records with multiple distinct valid CWE IDs are excluded.

## Split policy

| Split | Published-date range | Selected-class population | SFT rows |
|---|---|---:|---:|
| Train | 2020-01-01 through 2024-12-31 | 65,272 | 12,000 |
| Validation | 2025-01-01 through 2025-12-31 | 21,151 | 1,000 |
| Test | 2026-01-01 through 2026-09-17 | 24,975 | 24,975 |

The train and validation SFT views are reproducible natural-distribution samples. The test SFT view retains
the full selected-class population.

## Deduplication and overlap checks

Training duplicates are identified by an exact SHA-256 hash after Unicode NFKC normalization, lowercasing,
and whitespace collapse. The earliest published training record is kept. Training records whose normalized
description hash occurs in validation or test are dropped before SFT sampling. Evaluation-split overlap is
reported and not removed.

The overlap check between fine-tuning splits is exact-hash only. It does not measure semantic similarity or
verify what data the base model encountered during its original training.

| Check before SFT sampling | Count |
|---|---:|
| Duplicate CVE IDs in canonical records | 0 |
| Training internal normalized-description duplicates | 3,427 |
| Train–validation normalized-description overlap | 92 |
| Train–test normalized-description overlap | 7 |
| Validation–test normalized-description overlap | 190 |

## Statistics

| Measure | Records |
|---|---:|
| Raw API records | 257,913 |
| Unique canonical records | 257,913 |
| Rejected | 10,709 |
| No English description | 0 |
| No weakness | 17,166 |
| Placeholder only | 15,867 |
| Multi-label | 30,083 |
| Single-label | 194,797 |

Class distributions and description-length percentiles are in `reports/dataset_report.md`. The dataset hash
is `d4abf16beb51c55804d6756e3aa4110b30b536a51827f7dce0dfe52e664b45d9`.

## Known limitations

- NVD weakness labels can be noisy, incomplete, or revised after the snapshot.
- The task covers only the top 15 training-period CWE classes and excludes other valid CWE IDs.
- CNA and NVD weakness disagreement that yields multiple distinct CWE IDs is excluded as multi-label.
- A description alone can be insufficient to resolve the most appropriate weakness category.
- Base-model exposure to NVD records during its original training cannot be verified.
- The 2026 test period is partial and has fewer NVD-enriched records than a completed calendar-year snapshot
  may eventually contain.
- Normalized-description matching is an exact-hash check and does not detect paraphrases.

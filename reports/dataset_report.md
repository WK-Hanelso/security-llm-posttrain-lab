# Dataset Report

Snapshot: `2026-09-17`  
Canonical schema: `1.0`

## Record funnel

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

## Split counts

| Split | Selected-class population | SFT rows | Placeholder only | Multi-label | Single-label outside selected set |
|---|---:|---:|---:|---:|---:|
| train | 65,272 | 12,000 | 13,032 | 12,713 | 40,340 |
| val | 21,151 | 1,000 | 1,638 | 7,455 | 16,382 |
| test | 24,975 | 24,975 | 1,197 | 9,915 | 26,674 |

## Class distribution

Tail is the bottom third of selected labels by training-period count.

| CWE | Tier | Train population | Train sample | Val population | Val sample | Test population | Test sample |
|---|---|---:|---:|---:|---:|---:|---:|
| CWE-79 | head | 19,261 | 3,479 | 7,362 | 323 | 5,244 | 5,244 |
| CWE-89 | head | 7,294 | 1,424 | 1,685 | 92 | 2,151 | 2,151 |
| CWE-787 | head | 6,304 | 1,091 | 722 | 32 | 1,065 | 1,065 |
| CWE-352 | head | 4,010 | 750 | 1,812 | 82 | 775 | 775 |
| CWE-125 | head | 3,811 | 619 | 849 | 35 | 1,277 | 1,277 |
| CWE-862 | head | 3,354 | 614 | 2,199 | 115 | 2,971 | 2,971 |
| CWE-416 | head | 3,215 | 574 | 1,016 | 49 | 1,932 | 1,932 |
| CWE-22 | head | 2,984 | 599 | 981 | 50 | 1,894 | 1,894 |
| CWE-20 | head | 2,707 | 499 | 444 | 17 | 1,087 | 1,087 |
| CWE-78 | head | 2,554 | 465 | 690 | 31 | 1,184 | 1,184 |
| CWE-476 | tail | 2,191 | 415 | 1,135 | 56 | 802 | 802 |
| CWE-120 | tail | 2,149 | 413 | 361 | 22 | 444 | 444 |
| CWE-434 | tail | 2,061 | 418 | 558 | 31 | 488 | 488 |
| CWE-200 | tail | 1,921 | 385 | 627 | 22 | 1,056 | 1,056 |
| CWE-284 | tail | 1,456 | 255 | 710 | 43 | 2,605 | 2,605 |

## Description lengths

Character counts are for selected-class population records before SFT truncation.

| Split | p50 | p90 | p99 | Maximum |
|---|---:|---:|---:|---:|
| train | 244 | 531 | 1,498 | 3,998 |
| val | 270 | 588 | 2,954 | 3,998 |
| test | 352 | 783 | 1,748 | 3,998 |

## Duplicate and overlap checks

| Check before SFT sampling | Count |
|---|---:|
| Duplicate CVE IDs in canonical records | 0 |
| Training internal normalized-description duplicates | 3,427 |
| Train–validation normalized-description overlap | 92 |
| Train–test normalized-description overlap | 7 |
| Validation–test normalized-description overlap | 190 |

The canonical record is keyed by CVE ID and normalization keeps the last occurrence.
The overlap check between fine-tuning splits uses exact hashes of normalized descriptions only.

## Policy summary

| Policy | Value |
|---|---|
| Source | NVD CVE API 2.0 |
| Label set | Top 15 from the training period; single-label records only |
| Minimum training records per class | 200 |
| Train | 2020-01-01 to 2024-12-31 |
| Validation | 2025-01-01 to 2025-12-31 |
| Test | 2026-01-01 to 2026-09-17 |
| Training duplicate policy | Drop normalized-description duplicates, keeping the earliest record |
| Training overlap policy | Drop training records matching validation or test normalized-description hashes |
| Evaluation overlap policy | Report only |

# T-014G — full Audit B exact run

This report measures exact high-similarity structure for all 24,975 processed-test queries against all 65,272 processed-train references: 1,630,168,200 potential pairs. TF-IDF was fit on the references only; queries used untruncated `description_en`. Blockwise exact cosine used block size 2,048 and retained only each query's top 20 plus all pairs at or above 0.80.

## Measurement

| Status | Pairs | Block | Full-run wall s | Exact phase s | Peak RSS GiB | Pairs/s | Queries/s | Swap delta | Major faults |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| success | 1,630,168,200 | 2,048 | 96.639 | 88.026 | 1.411 | 18,519,077 | 283.72 | 0 B | 0 |

The full-run wall time ends after the exact kernel and is the measurement comparable with the T-014F projection. Parquet writing took 4.250 s and the independent correctness check took 1.433 s afterward; total child wall time was 102.405 s. Block size remained 2,048 because no memory problem occurred.

## Projection check

| Quantity | Projection | Measured | Absolute error | Relative error |
|---|---:|---:|---:|---:|
| Wall time | 98.050 s | 96.639 s | 1.411 s (-1.411 s) | -1.44% |
| Peak RSS | 1.144 GiB | 1.411 GiB | 0.267 GiB (+0.267 GiB) | +23.30% |
| Conservative peak RSS | 1.499 GiB | 1.411 GiB | 0.088 GiB (-0.088 GiB) | -5.90% |

Absolute wall time is load-sensitive: the same probe point measured 10.113 s in the probe and 7.88 s in an independent rerun, so a wall-time miss alone is not a performance regression. Peak RSS reproduced exactly between those runs, making the memory comparison the more meaningful test. The full child also built the required Parquet string/hash columns and ran the direct correctness matrix after the exact kernel, while the probe children only fingerprinted retained arrays. That broader retained-output scope likely explains part of the primary memory projection miss; measured RSS still remained below the conservative projection with no swap growth or major faults.

## Threshold totals

| Similarity | Pair count | Query count | Same-label | Cross-label |
|---:|---:|---:|---:|---:|
| ≥0.80 | 54,440 | 1,903 | 53,206 | 1,234 |
| ≥0.90 | 8,098 | 627 | 8,012 | 86 |
| =1.0 (raw) | 314 | 92 | 314 | 0 |

## Rank-1 similarity

| Queries | p50 | p90 | p95 | p99 | max | mean |
|---:|---:|---:|---:|---:|---:|---:|
| 24,975 | 0.358505 | 0.763898 | 0.846306 | 0.961955 | 1.000000 | 0.418819 |

The maximum raw float64 value was `1.0000000000000007`; its tiny excursion above the mathematical cosine bound is floating-point accumulation, and scores were neither clipped nor rounded.

## Per CWE class

Pair splits are same-label / cross-label within the named query class.

| CWE | Queries | Rank-1 p50 | Rank-1 p90 | Queries ≥0.80 | Queries ≥0.90 | ≥0.80 pair split | ≥0.90 pair split |
|---|---:|---:|---:|---:|---:|---:|---:|
| CWE-120 | 444 | 0.309974 | 0.725768 | 5.63% | 1.13% | 10 / 114 | 0 / 10 |
| CWE-125 | 1,277 | 0.287955 | 0.656671 | 1.41% | 0.47% | 641 / 40 | 21 / 1 |
| CWE-20 | 1,087 | 0.464828 | 0.675925 | 0.92% | 0.00% | 9 / 5 | 0 / 0 |
| CWE-200 | 1,056 | 0.292011 | 0.688722 | 2.94% | 1.04% | 18 / 112 | 2 / 9 |
| CWE-22 | 1,894 | 0.240717 | 0.572782 | 1.37% | 0.37% | 117 / 0 | 7 / 0 |
| CWE-284 | 2,605 | 0.660172 | 0.824990 | 14.09% | 1.84% | 258 / 546 | 22 / 51 |
| CWE-352 | 775 | 0.387445 | 0.771352 | 7.48% | 2.06% | 327 / 21 | 31 / 5 |
| CWE-416 | 1,932 | 0.510635 | 0.728633 | 2.74% | 0.31% | 266 / 24 | 31 / 0 |
| CWE-434 | 488 | 0.299421 | 0.671663 | 4.30% | 2.46% | 211 / 1 | 76 / 0 |
| CWE-476 | 802 | 0.255425 | 0.512758 | 1.00% | 0.50% | 32 / 0 | 7 / 0 |
| CWE-78 | 1,184 | 0.232360 | 0.553875 | 0.51% | 0.00% | 12 / 27 | 0 / 0 |
| CWE-787 | 1,065 | 0.309121 | 0.827212 | 13.62% | 5.35% | 2,412 / 208 | 228 / 3 |
| CWE-79 | 5,244 | 0.413800 | 0.846355 | 13.98% | 5.74% | 46,617 / 53 | 7,222 / 7 |
| CWE-862 | 2,971 | 0.376099 | 0.771026 | 8.35% | 4.31% | 1,070 / 49 | 319 / 0 |
| CWE-89 | 2,151 | 0.312880 | 0.762126 | 7.16% | 1.21% | 1,206 / 34 | 46 / 0 |

## Description length

The buckets come unchanged from `failure_analysis.py::_description_bucket`.

| Length | Queries | Rank-1 p50 | Rank-1 p90 | Queries ≥0.80 | Queries ≥0.90 | ≥0.80 pair split | ≥0.90 pair split |
|---|---:|---:|---:|---:|---:|---:|---:|
| <250 | 8,014 | 0.499651 | 0.763842 | 7.64% | 3.44% | 5,825 / 131 | 1,364 / 5 |
| 250-500 | 9,460 | 0.264638 | 0.755969 | 7.98% | 2.49% | 43,696 / 296 | 6,258 / 17 |
| 500-1000 | 6,412 | 0.315442 | 0.780266 | 8.09% | 1.78% | 3,648 / 784 | 389 / 63 |
| >=1000 | 1,089 | 0.185211 | 0.409453 | 1.56% | 0.09% | 37 / 23 | 1 / 1 |

## Rare-class comparison

The pre-declared rare group is CWE-476, CWE-120, CWE-434, CWE-200, and CWE-284; the other ten classes are the comparison group.

| Group | Queries | Rank-1 p50 | Rank-1 p90 | Queries ≥0.80 | Queries ≥0.90 | ≥0.80 pair split | ≥0.90 pair split |
|---|---:|---:|---:|---:|---:|---:|---:|
| Rare five | 5,395 | 0.435128 | 0.783683 | 8.38% | 1.48% | 529 / 773 | 107 / 70 |
| Other ten | 19,580 | 0.345001 | 0.752949 | 7.41% | 2.79% | 52,677 / 461 | 7,905 / 16 |

## Analysis headlines

At ≥0.80, 1,234 of 54,440 pairs (2.27%) were cross-label; at ≥0.90, 86 of 8,098 (1.06%) were cross-label. All 314 raw-exact-1.0 pairs were same-label. These are structural counts, not pair-level judgments.

The largest class-level query shares at ≥0.80 were CWE-284 (14.09%), CWE-79 (13.98%), and CWE-787 (13.62%). At ≥0.90, CWE-79 (5.74%) and CWE-787 (5.35%) were highest.

The three buckets below 1,000 characters had similar ≥0.80 query shares (7.64%, 7.98%, and 8.09%); the ≥1,000 bucket was 1.56%. The rare-five group was higher at ≥0.80 than the other ten (8.38% versus 7.41%) but lower at ≥0.90 (1.48% versus 2.79%).

## Correctness

A fixed-seed random subset of 100 queries was independently recomputed against all 65,272 references as one direct dense cosine matrix. Top-20 membership was identical: **yes**; ordering was identical: **yes**; the maximum aligned score delta was `0.000e+00` against tolerance `2e-15`. The ≥0.80 pair set, ≥0.90 pair set, and both per-query count vectors were identical: **yes**. The check passed: **yes**.

Recorded near-tie membership differences: 0; near-tie ordering differences: 0. Any such difference is retained with its raw score delta and treated under the known §3.2 float64 limitation only when within tolerance. Scores were never rounded.

## Reading the structure

These totals describe near-duplicate and high-similarity structure and provide a signal about the split's semantic independence. A high cosine value alone does not identify copying: CVE descriptions commonly repeat vendor advisory templates, product names, version lists, and shared vulnerability phrasing. In the earlier published manual review, 11 of the top 20 examples were vendor boilerplate and 7 were near or exact copies. No new manual category assignment was performed here, so this report makes no stronger pair-level claim.

The published 300-query × 12,000-reference sampled audit used Audit A's shape and different preprocessing. Its p50 0.2694, p90 0.7036, p95 0.7438, eight queries at ≥0.80, and three at ≥0.90 are context only and are not compared numerically with this Audit B result.

## Artifact and environment

The Parquet artifact has 538,761 rows and SHA-256 `aa563fb43022a14b0c16644163fbc2371ac8500c7e6de0670b4f8d0857879d17`. It stores only top-20 rows and threshold rows under the §3 schema. The run used `hanelso-GL73-8SE` at commit `be0f6e690e71e15bd49ee49a5d3acff79feb0a43`, Python 3.11.15, NumPy 2.4.6, and scikit-learn 1.9.1.

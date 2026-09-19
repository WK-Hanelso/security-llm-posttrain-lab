# Spark Track A equivalence report

Comparison is row-level by `cve_id`; Parquet byte identity and row order are not compared.
The E5 populations are measured after temporal assignment and before cross-split overlap removal; the final validation population is 20,918 because E11 removes 233 rows from the 21,151 assigned rows.

| Check | Expected | Actual | Pass |
|---|---|---|:---:|
| E1 — normalized row count | `257913` | `257913` | yes |
| E2 — normalized cve_id symmetric difference | `0` | `0` | yes |
| E3 — normalized per-row field mismatches | `0` | `0` | yes |
| E4 — selected labels (ordered) | `["CWE-79", "CWE-89", "CWE-787", "CWE-352", "CWE-125", "CWE-862", "CWE-416", "CWE-22", "CWE-20", "CWE-78", "CWE-476", "CWE-120", "CWE-434", "CWE-200", "CWE-284"]` | `["CWE-79", "CWE-89", "CWE-787", "CWE-352", "CWE-125", "CWE-862", "CWE-416", "CWE-22", "CWE-20", "CWE-78", "CWE-476", "CWE-120", "CWE-434", "CWE-200", "CWE-284"]` | yes |
| E5 — split populations after temporal assignment, before cross-split overlap removal | `{"test": 24975, "train": 65272, "val": 21151}` | `{"test": 24975, "train": 65272, "val": 21151}` | yes |
| E6 — split assignment disagreements | `0` | `0` | yes |
| E7 — class distribution per split | `{"test": {"CWE-120": 444, "CWE-125": 1277, "CWE-20": 1087, "CWE-200": 1056, "CWE-22": 1894, "CWE-284": 2605, "CWE-352": 775, "CWE-416": 1932, "CWE-434": 488, "CWE-476": 802, "CWE-78": 1184, "CWE-787": 1065, "CWE-79": 5244, "CWE-862": 2971, "CWE-89": 2151}, "train": {"CWE-120": 2149, "CWE-125": 3811, "CWE-20": 2707, "CWE-200": 1921, "CWE-22": 2984, "CWE-284": 1456, "CWE-352": 4010, "CWE-416": 3215, "CWE-434": 2061, "CWE-476": 2191, "CWE-78": 2554, "CWE-787": 6304, "CWE-79": 19261, "CWE-862": 3354, "CWE-89": 7294}, "val": {"CWE-120": 361, "CWE-125": 849, "CWE-20": 444, "CWE-200": 627, "CWE-22": 981, "CWE-284": 710, "CWE-352": 1812, "CWE-416": 1016, "CWE-434": 558, "CWE-476": 1135, "CWE-78": 690, "CWE-787": 722, "CWE-79": 7362, "CWE-862": 2199, "CWE-89": 1685}}` | `{"test": {"CWE-120": 444, "CWE-125": 1277, "CWE-20": 1087, "CWE-200": 1056, "CWE-22": 1894, "CWE-284": 2605, "CWE-352": 775, "CWE-416": 1932, "CWE-434": 488, "CWE-476": 802, "CWE-78": 1184, "CWE-787": 1065, "CWE-79": 5244, "CWE-862": 2971, "CWE-89": 2151}, "train": {"CWE-120": 2149, "CWE-125": 3811, "CWE-20": 2707, "CWE-200": 1921, "CWE-22": 2984, "CWE-284": 1456, "CWE-352": 4010, "CWE-416": 3215, "CWE-434": 2061, "CWE-476": 2191, "CWE-78": 2554, "CWE-787": 6304, "CWE-79": 19261, "CWE-862": 3354, "CWE-89": 7294}, "val": {"CWE-120": 361, "CWE-125": 849, "CWE-20": 444, "CWE-200": 627, "CWE-22": 981, "CWE-284": 710, "CWE-352": 1812, "CWE-416": 1016, "CWE-434": 558, "CWE-476": 1135, "CWE-78": 690, "CWE-787": 722, "CWE-79": 7362, "CWE-862": 2199, "CWE-89": 1685}}` | yes |
| E8 — train exact duplicates dropped | `3427` | `3427` | yes |
| E9 — post-train-dedup cve_id symmetric difference | `0` | `0` | yes |
| E10 — train↔eval overlap dropped | `36` | `36` | yes |
| E11 — val↔eval overlap dropped | `233` | `233` | yes |
| E12 — post-drop pairwise overlaps | `[0, 0, 0]` | `[0, 0, 0]` | yes |

Overall: **PASS**.

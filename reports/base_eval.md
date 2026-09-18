# Base Model Evaluation

This report covers the unadapted `Qwen/Qwen3-0.6B` evaluation only. The evaluation used a reproducible
18,000-record subset of the 24,975-record test set.

## Headline metrics

| Metric | Value |
|---|---:|
| Evaluated records | 18,000 |
| Accuracy | 0.3969 |
| Macro F1 | 0.3048 |
| Weighted F1 | 0.3891 |
| Invalid-output rate | 0.0237 |
| Accuracy on valid outputs | 0.4066 |

## Per-class results

Tail marks the bottom third of selected labels by training-period count. Rows are sorted by evaluation
support.

| CWE | Tier | Support | Precision | Recall | F1 |
|---|---|---:|---:|---:|---:|
| CWE-79 | head | 3,771 | 0.9669 | 0.8054 | 0.8788 |
| CWE-862 | head | 2,161 | 0.4947 | 0.0652 | 0.1153 |
| CWE-284 | tail | 1,863 | 0.7857 | 0.0059 | 0.0117 |
| CWE-89 | head | 1,522 | 0.8209 | 0.8706 | 0.8450 |
| CWE-416 | head | 1,419 | 0.3333 | 0.0014 | 0.0028 |
| CWE-22 | head | 1,368 | 0.9606 | 0.6067 | 0.7437 |
| CWE-125 | head | 914 | 0.0811 | 0.0197 | 0.0317 |
| CWE-78 | head | 879 | 0.6774 | 0.0239 | 0.0462 |
| CWE-20 | head | 788 | 0.8750 | 0.0089 | 0.0176 |
| CWE-200 | tail | 786 | 0.1004 | 0.9631 | 0.1819 |
| CWE-787 | head | 749 | 0.3519 | 0.0254 | 0.0473 |
| CWE-476 | tail | 587 | 0.9953 | 0.3595 | 0.5282 |
| CWE-352 | head | 550 | 0.8099 | 0.7745 | 0.7918 |
| CWE-434 | tail | 344 | 0.0832 | 0.1948 | 0.1166 |
| CWE-120 | tail | 299 | 0.1211 | 0.9130 | 0.2139 |

## Invalid outputs

| Reason | Count |
|---|---:|
| Not JSON | 0 |
| Missing `cwe_id` | 0 |
| Multiple CWE values | 0 |
| Bad CWE format | 1 |
| Label outside the allowed set | 425 |

## KEV slice

| Slice | Records | Accuracy |
|---|---:|---:|
| KEV | 35 | 0.3143 |
| Non-KEV | 17,965 | 0.3971 |

KEV is an evaluation slice only.

## Generation and throughput

| Setting | Value |
|---|---:|
| Sampling | false |
| Temperature | null |
| Maximum new tokens | 32 |
| Batch size | 2 |
| Maximum sequence length | 1,536 |
| Samples per second | 3.3037 |
| Wall time, seconds | 5,448.3592 |
| Peak VRAM, MiB | 1,503.5142 |

## Observations

1. Generated output was almost always a JSON object with a `cwe_id`; the only malformed output count was 1.
   Most invalid outputs were valid-looking CWE IDs outside the allowed label set (425 records).
2. The highest per-class F1 values were CWE-79 (0.8788), CWE-89 (0.8450), CWE-352 (0.7918), CWE-22
   (0.7437), and CWE-476 (0.5282).
3. Recall was below 0.03 for CWE-416 (0.0014), CWE-284 (0.0059), CWE-20 (0.0089), CWE-125 (0.0197),
   CWE-78 (0.0239), and CWE-787 (0.0254); CWE-862 recall was 0.0652.
4. CWE-200 and CWE-120 were prediction sinks: their recall was 0.9631 and 0.9130, while precision was
   0.1004 and 0.1211, respectively.

## Failure taxonomy (Base)

Error categories are deterministic rules over the stored predictions; excerpts are capped at 200 characters.

### Error types

| Error type | Count |
|---|---:|
| invalid format | 0 |
| unknown cwe | 426 |
| nearby cwe confusion | 1,828 |
| semantic confusion | 8,601 |

### Top confusions

| Gold | Prediction | Count |
|---|---|---:|
| CWE-862 | CWE-200 | 1,976 |
| CWE-284 | CWE-200 | 1,573 |
| CWE-416 | CWE-434 | 724 |
| CWE-20 | CWE-200 | 678 |
| CWE-787 | CWE-120 | 619 |
| CWE-79 | CWE-200 | 596 |
| CWE-125 | CWE-120 | 519 |
| CWE-22 | CWE-200 | 462 |
| CWE-125 | CWE-200 | 371 |
| CWE-416 | CWE-444 | 297 |
| CWE-78 | CWE-200 | 269 |
| CWE-416 | CWE-120 | 237 |
| CWE-284 | CWE-120 | 217 |
| CWE-476 | CWE-200 | 200 |
| CWE-78 | CWE-89 | 188 |

### Head and long-tail accuracy

| Tier | Records | Accuracy |
|---|---:|---:|
| head | 14,121 | 0.4126 |
| tail | 3,879 | 0.3400 |

### Accuracy by description length

| Characters | Records | Accuracy |
|---|---:|---:|
| <250 | 5,804 | 0.4049 |
| 250-500 | 6,802 | 0.4850 |
| 500-1000 | 4,589 | 0.2975 |
| >=1000 | 805 | 0.1627 |

### Accuracy by token length

| Tokens | Records | Accuracy |
|---|---:|---:|
| <480 | 15,917 | 0.4279 |
| 480-1536 | 2,083 | 0.1603 |

### KEV slice

| Slice | Records | Accuracy |
|---|---:|---:|
| kev | 35 | 0.3143 |
| non-kev | 17,965 | 0.3971 |

# SFT Model Evaluation

This report covers `exp_002_sft_v1` and compares it with the unadapted run on the same ordered 18,000-record subset of the 24,975-record test set.

## Headline metrics

| Metric | Base | SFT | Base→SFT delta |
|---|---:|---:|---:|
| Evaluated records | 18,000 | 18,000 | 0 |
| Accuracy | 0.3969 | 0.8627 | +0.4657 |
| Macro F1 | 0.3048 | 0.8332 | +0.5284 |
| Weighted F1 | 0.3891 | 0.8636 | +0.4745 |
| Invalid-output rate | 0.0237 | 0.0000 | -0.0237 |
| Accuracy on valid outputs | 0.4066 | 0.8627 | +0.4561 |

## Per-class results

Tail marks the bottom third of selected labels by training-period count. Rows are sorted by evaluation support.

| CWE | Tier | Support | Base P | SFT P | ΔP | Base R | SFT R | ΔR | Base F1 | SFT F1 | ΔF1 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| CWE-79 | head | 3,771 | 0.9669 | 0.9417 | -0.0252 | 0.8054 | 0.9851 | +0.1798 | 0.8788 | 0.9629 | +0.0842 |
| CWE-862 | head | 2,161 | 0.4947 | 0.8874 | +0.3926 | 0.0652 | 0.6927 | +0.6275 | 0.1153 | 0.7781 | +0.6628 |
| CWE-284 | tail | 1,863 | 0.7857 | 0.7326 | -0.0532 | 0.0059 | 0.7381 | +0.7322 | 0.0117 | 0.7353 | +0.7236 |
| CWE-89 | head | 1,522 | 0.8209 | 0.9802 | +0.1593 | 0.8706 | 0.9777 | +0.1071 | 0.8450 | 0.9789 | +0.1339 |
| CWE-416 | head | 1,419 | 0.3333 | 0.9729 | +0.6396 | 0.0014 | 0.9612 | +0.9598 | 0.0028 | 0.9670 | +0.9642 |
| CWE-22 | head | 1,368 | 0.9606 | 0.9064 | -0.0543 | 0.6067 | 0.9554 | +0.3487 | 0.7437 | 0.9302 | +0.1865 |
| CWE-125 | head | 914 | 0.0811 | 0.9172 | +0.8361 | 0.0197 | 0.8972 | +0.8775 | 0.0317 | 0.9071 | +0.8754 |
| CWE-78 | head | 879 | 0.6774 | 0.9390 | +0.2615 | 0.0239 | 0.9101 | +0.8862 | 0.0462 | 0.9243 | +0.8782 |
| CWE-20 | head | 788 | 0.8750 | 0.5495 | -0.3255 | 0.0089 | 0.7462 | +0.7373 | 0.0176 | 0.6329 | +0.6154 |
| CWE-200 | tail | 786 | 0.1004 | 0.6225 | +0.5220 | 0.9631 | 0.6628 | -0.3003 | 0.1819 | 0.6420 | +0.4601 |
| CWE-787 | head | 749 | 0.3519 | 0.8098 | +0.4580 | 0.0254 | 0.7276 | +0.7023 | 0.0473 | 0.7665 | +0.7192 |
| CWE-476 | tail | 587 | 0.9953 | 0.9318 | -0.0635 | 0.3595 | 0.8842 | +0.5247 | 0.5282 | 0.9073 | +0.3792 |
| CWE-352 | head | 550 | 0.8099 | 0.9551 | +0.1452 | 0.7745 | 0.8891 | +0.1145 | 0.7918 | 0.9209 | +0.1291 |
| CWE-434 | tail | 344 | 0.0832 | 0.7861 | +0.7029 | 0.1948 | 0.8547 | +0.6599 | 0.1166 | 0.8189 | +0.7023 |
| CWE-120 | tail | 299 | 0.1211 | 0.5722 | +0.4511 | 0.9130 | 0.6890 | -0.2241 | 0.2139 | 0.6252 | +0.4113 |

## Invalid outputs

| Reason | Base | SFT | Base→SFT delta |
|---|---:|---:|---:|
| Not JSON | 0 | 0 | +0 |
| Missing `cwe_id` | 0 | 0 | +0 |
| Multiple CWE values | 0 | 0 | +0 |
| Bad CWE format | 1 | 0 | -1 |
| Label outside the allowed set | 425 | 0 | -425 |

## KEV slice

| Slice | Records | Base accuracy | SFT accuracy | Base→SFT delta |
|---|---:|---:|---:|---:|
| KEV | 35 | 0.3143 | 0.8857 | +0.5714 |
| Non-KEV | 17,965 | 0.3971 | 0.8626 | +0.4655 |

KEV is an evaluation slice only.

## Generation and throughput

| Setting | Base | SFT | Base→SFT delta |
|---|---:|---:|---:|
| Sampling | false | false | same |
| Temperature | null | null | same |
| Maximum new tokens | 32 | 32 | +0 |
| Batch size | 2 | 8 | +6 |
| Maximum sequence length | 1,536 | 1,536 | +0 |
| Samples per second | 3.3037 | 8.8871 | +5.5833 |
| Wall time, seconds | 5448.3592 | 2025.4122 | -3422.9471 |
| Peak VRAM, MiB | 1503.5142 | 2574.8198 | +1071.3057 |

The decoding configuration matches Base: greedy decoding, null temperature, 32 maximum new tokens, and a 1,536-token sequence limit. Evaluation batch size is an execution setting; it was 2 for Base and 8 for SFT.

## Identical CVE-ID set check

The complete ordered CVE-ID sequence matches exactly: 18,000 of 18,000 IDs, including order. Both metric files use subset hash `229dd47c3cdeb532d47c2dd8c5962f2c9bff8ff2c6d89d8d2776ee6d09a7d707`.

## Observations

1. Accuracy changed from 0.3969 to 0.8627, macro F1 from 0.3048 to 0.8332, and invalid-output rate from 0.0237 to 0.0000.
2. All 15 classes gained F1. The largest gain was CWE-416 at +0.9642.
3. Recall decreased for CWE-200 (-0.3003) and CWE-120 (-0.2241); no other class had a recall decrease.
4. Top-three prediction concentration changed from 0.7185 to 0.4172.

## Failure taxonomy

### Error types

| Error type | Base | SFT | Base→SFT delta |
|---|---:|---:|---:|
| invalid format | 0 | 0 | +0 |
| unknown cwe | 426 | 0 | -426 |
| nearby cwe confusion | 1,828 | 852 | -976 |
| semantic confusion | 8,601 | 1,620 | -6,981 |

### Top SFT confusions

| Gold | Prediction | Base | SFT | Base→SFT delta |
|---|---|---:|---:|---:|
| CWE-862 | CWE-284 | 0 | 367 | +367 |
| CWE-284 | CWE-200 | 1,573 | 138 | -1,435 |
| CWE-862 | CWE-200 | 1,976 | 138 | -1,838 |
| CWE-284 | CWE-20 | 0 | 133 | +133 |
| CWE-787 | CWE-120 | 619 | 133 | -486 |
| CWE-284 | CWE-862 | 1 | 106 | +105 |
| CWE-200 | CWE-284 | 0 | 91 | +91 |
| CWE-20 | CWE-79 | 31 | 79 | +48 |
| CWE-862 | CWE-20 | 0 | 75 | +75 |
| CWE-200 | CWE-862 | 0 | 64 | +64 |

### Head and long-tail accuracy

| Tier | Records | Base | SFT | Base→SFT delta |
|---|---:|---:|---:|---:|
| long tail | 3,879 | 0.3400 | 0.7515 | +0.4114 |
| head | 14,121 | 0.4126 | 0.8932 | +0.4806 |

### Accuracy by description length

| Bucket | Records | Base | SFT | Base→SFT delta |
|---|---:|---:|---:|---:|
| <250 | 5,804 | 0.4049 | 0.8672 | +0.4623 |
| 250-500 | 6,802 | 0.4850 | 0.8664 | +0.3814 |
| 500-1000 | 4,589 | 0.2975 | 0.8533 | +0.5559 |
| >=1000 | 805 | 0.1627 | 0.8522 | +0.6894 |

### Accuracy by token length

| Bucket | Records | Base | SFT | Base→SFT delta |
|---|---:|---:|---:|---:|
| <480 | 15,917 | 0.4279 | 0.8657 | +0.4378 |
| 480-1536 | 2,083 | 0.1603 | 0.8397 | +0.6793 |

Lower accuracy was observed together with longer descriptions in the Base buckets; the slice comparison does not establish causation.

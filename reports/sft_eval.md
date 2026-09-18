# SFT Evaluation

## Status

| Result | Value |
|---|---|
| Experiment | `exp_002_sft_v1` |
| Run status | TBD (pending exp_002_sft_v1) |
| Adapter identity | TBD (pending exp_002_sft_v1) |
| Evaluation timestamp | TBD (pending exp_002_sft_v1) |

## Evaluation protocol

The pending evaluation uses the same fixed prompt, label order, deterministic evaluation verifier, and greedy generation settings as `exp_001_baseline`. IDs and order are pinned by `reports/eval_subset_manifest.json` (`n=18,000`, subset hash `229dd47c3cdeb532d47c2dd8c5962f2c9bff8ff2c6d89d8d2776ee6d09a7d707`).

| Setting | Value |
|---|---|
| Model | `Qwen/Qwen3-0.6B` plus pending LoRA adapter |
| Sampling | false |
| Maximum new tokens | 32 |
| Maximum sequence length | 1,536 |
| Evaluation records | 18,000 |

## Headline results

| Metric | Base | SFT | Delta |
|---|---:|---:|---:|
| Accuracy | 0.3969 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| Macro F1 | 0.3048 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| Weighted F1 | 0.3891 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| Invalid-output rate | 0.0237 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| Accuracy on valid outputs | 0.4066 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |

## Per-class results

| CWE | Base support | Base F1 | SFT F1 | Delta |
|---|---:|---:|---:|---:|
| CWE-79 | 3,771 | 0.8788 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| CWE-862 | 2,161 | 0.1153 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| CWE-284 | 1,863 | 0.0117 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| CWE-89 | 1,522 | 0.8450 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| CWE-416 | 1,419 | 0.0028 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| CWE-22 | 1,368 | 0.7437 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| CWE-125 | 914 | 0.0317 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| CWE-78 | 879 | 0.0462 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| CWE-20 | 788 | 0.0176 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| CWE-200 | 786 | 0.1819 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| CWE-787 | 749 | 0.0473 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| CWE-476 | 587 | 0.5282 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| CWE-352 | 550 | 0.7918 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| CWE-434 | 344 | 0.1166 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| CWE-120 | 299 | 0.2139 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |

## Invalid outputs

| Reason | Base count | SFT count |
|---|---:|---:|
| Not JSON | 0 | TBD (pending exp_002_sft_v1) |
| Missing key | 0 | TBD (pending exp_002_sft_v1) |
| Multiple CWE values | 0 | TBD (pending exp_002_sft_v1) |
| Bad CWE format | 1 | TBD (pending exp_002_sft_v1) |
| Label outside allowed set | 425 | TBD (pending exp_002_sft_v1) |

## Slices and throughput

| Measurement | Base | SFT |
|---|---:|---:|
| KEV accuracy (n=35) | 0.3143 | TBD (pending exp_002_sft_v1) |
| Non-KEV accuracy (n=17,965) | 0.3971 | TBD (pending exp_002_sft_v1) |
| Samples per second | 3.3037 | TBD (pending exp_002_sft_v1) |
| Wall seconds | 5,448.3592 | TBD (pending exp_002_sft_v1) |
| Peak VRAM MiB | 1,503.5142 | TBD (pending exp_002_sft_v1) |

## Interpretation

TBD (pending exp_002_sft_v1)

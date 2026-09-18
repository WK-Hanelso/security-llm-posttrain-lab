# Comparative Failure Analysis

## Status and method

The comparison joins Base and pending SFT predictions by CVE ID on the frozen 18,000-record subset. Error types use deterministic rules: invalid format, unknown CWE, same-family nearby confusion, and semantic confusion. Long-tail labels are the bottom third by training-period count.

| Item | Value |
|---|---|
| SFT prediction artifact | TBD (pending exp_002_sft_v1) |
| Joined record count | TBD (pending exp_002_sft_v1) |
| Residual failure rows | TBD (pending exp_002_sft_v1) |

## Transitions

| Transition | Count |
|---|---:|
| Both right | TBD (pending exp_002_sft_v1) |
| Fixed by SFT | TBD (pending exp_002_sft_v1) |
| Broken by SFT | TBD (pending exp_002_sft_v1) |
| Both wrong | TBD (pending exp_002_sft_v1) |

## Error types

| Error type | Base | SFT |
|---|---:|---:|
| Invalid format | 0 | TBD (pending exp_002_sft_v1) |
| Unknown CWE | 426 | TBD (pending exp_002_sft_v1) |
| Nearby CWE confusion | 1,828 | TBD (pending exp_002_sft_v1) |
| Semantic confusion | 8,601 | TBD (pending exp_002_sft_v1) |

## Top confusions

| Rank | Base confusion | Base count | SFT confusion | SFT count |
|---:|---|---:|---|---:|
| 1 | CWE-862→CWE-200 | 1,976 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| 2 | CWE-284→CWE-200 | 1,573 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| 3 | CWE-416→CWE-434 | 724 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| 4 | CWE-20→CWE-200 | 678 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| 5 | CWE-787→CWE-120 | 619 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |

## Long-tail and KEV slices

| Slice | Base accuracy | SFT accuracy | Delta |
|---|---:|---:|---:|
| Head labels (n=14,121) | 0.4126 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| Long-tail labels (n=3,879) | 0.3400 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| KEV (n=35) | 0.3143 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| Non-KEV (n=17,965) | 0.3971 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |

## Per-class deltas

TBD (pending exp_002_sft_v1)

## Interpretation and representative cases

TBD (pending exp_002_sft_v1)

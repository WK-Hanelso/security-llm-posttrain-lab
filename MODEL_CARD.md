# Model Card — CVE-to-CWE LoRA adapter

## Base model

`Qwen/Qwen3-0.6B` at revision `c1899de289a04d12100db370d81485cdf75e47ca`. This is the same open-weight chat-model revision used for the unadapted comparison and as the LoRA base.

## Training method

LoRA supervised fine-tuning uses completion-only loss over the target JSON. Prompt tokens are masked, the training sample order is seeded, and validation loss is reported once per epoch without checkpoint selection.

Adapter weights are not committed. A reproduction writes them to `experiments/exp_002_sft_v1/adapter/`.

## Training dataset

The training data is a seed-42 natural-distribution sample of 12,000 rows from a 65,272-record selected-class population. The validation view contains 1,000 rows from a 20,918-record population. Labels are the 15 most frequent eligible training-period CWE IDs, and only single-label English CVE records are included.

Training dates are 2020-01-01–2024-12-31; validation dates are 2025-01-01–2025-12-31. Exact CVE-ID and normalized-description overlap between fine-tuning splits is 0 after build.

## LoRA configuration

| Setting | Value |
|---|---|
| Rank | 16 |
| Alpha | 32 |
| Dropout | 0.05 |
| Target modules | `q_proj`, `k_proj`, `v_proj`, `o_proj` |
| Epochs | 3 |
| Learning rate | 0.0002 |
| Device batch / gradient accumulation / effective batch | 2 / 8 / 16 |
| Maximum sequence length | 1,536 |
| Precision | fp16 |
| Quantization | None |
| Trainable parameters | 4,587,520 |

## Evaluation dataset

The temporal test population contains 24,975 rows dated 2026-01-01–2026-09-17. Evaluation uses an ordered seed-42 subset of 18,000 rows; the Base and SFT CVE-ID sequences are identical. Generation is greedy with 32 maximum new tokens and the same fixed prompt and deterministic evaluation verifier.

KEV is an evaluation slice only.

## Metrics

| Metric | Base | SFT | Delta |
|---|---:|---:|---:|
| Accuracy | 0.3969 | 0.8627 | +0.4657 |
| Macro F1 | 0.3048 | 0.8332 | +0.5284 |
| Weighted F1 | 0.3891 | 0.8636 | +0.4745 |
| Invalid-output rate | 0.0237 | 0.0000 | -0.0237 |

### Per-class F1

Rows are sorted by evaluation support.

| CWE ID | Name | Test support | Base F1 | SFT F1 | Delta |
|---|---|---:|---:|---:|---:|
| CWE-79 | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') | 3,771 | 0.8788 | 0.9629 | +0.0842 |
| CWE-862 | Missing Authorization | 2,161 | 0.1153 | 0.7781 | +0.6628 |
| CWE-284 | Improper Access Control | 1,863 | 0.0117 | 0.7353 | +0.7236 |
| CWE-89 | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') | 1,522 | 0.8450 | 0.9789 | +0.1339 |
| CWE-416 | Use After Free | 1,419 | 0.0028 | 0.9670 | +0.9642 |
| CWE-22 | Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | 1,368 | 0.7437 | 0.9302 | +0.1865 |
| CWE-125 | Out-of-bounds Read | 914 | 0.0317 | 0.9071 | +0.8754 |
| CWE-78 | Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') | 879 | 0.0462 | 0.9243 | +0.8782 |
| CWE-20 | Improper Input Validation | 788 | 0.0176 | 0.6329 | +0.6154 |
| CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | 786 | 0.1819 | 0.6420 | +0.4601 |
| CWE-787 | Out-of-bounds Write | 749 | 0.0473 | 0.7665 | +0.7192 |
| CWE-476 | NULL Pointer Dereference | 587 | 0.5282 | 0.9073 | +0.3792 |
| CWE-352 | Cross-Site Request Forgery (CSRF) | 550 | 0.7918 | 0.9209 | +0.1291 |
| CWE-434 | Unrestricted Upload of File with Dangerous Type | 344 | 0.1166 | 0.8189 | +0.7023 |
| CWE-120 | Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') | 299 | 0.2139 | 0.6252 | +0.4113 |

## Failure modes

Of 18,000 test rows, 8,715 were fixed by SFT, 332 were broken by SFT, 2,140 remained wrong, and 6,813 were correct in both runs.

Residual SFT errors comprise 852 nearby-CWE confusions and 1,620 semantic confusions, with 0 unknown-CWE outputs and 0 invalid-format outputs. The most frequent SFT confusion is CWE-862→CWE-284 (367 rows). Long-tail accuracy is 0.7515 over 3,879 rows.

CWE-200 and CWE-120 F1 improved, but their recall changed by -0.3003 and -0.2241, respectively.

## Limitations

- Single-label English CVE descriptions and a closed set of 15 CWE IDs only.
- One temporal snapshot and one seed.
- NVD weakness labels can be noisy, incomplete, or ambiguous from description text alone.
- Multi-label records and labels outside the selected set are excluded.
- Exact normalized-description checks do not detect semantic paraphrases.
- Prior exposure of the unadapted model to NVD text cannot be verified.
- KEV is an evaluation slice only, not a separate task or training target.
- No Natural-vs-Balanced ablation, continued-domain adaptation, or reinforcement-learning phase was run.

## Intended use

Research reproduction of a domain-SFT experiment and closed-set CWE suggestion from English CVE text. Predictions should be treated as experiment outputs for analysis, not authoritative classifications.

## Non-intended use

Production vulnerability triage, security decisions, any use outside the 15-label closed set, or non-English text.

# Model Card — CWE instruction adapter

## Status

| Item | Value |
|---|---|
| Base evaluation | Complete (`exp_001_baseline`) |
| LoRA SFT run | TBD (pending exp_002_sft_v1) |
| Adapter artifact | TBD (pending exp_002_sft_v1) |
| Comparative evaluation | TBD (pending exp_002_sft_v1) |

## Model

The configured model is the open-weight chat model `Qwen/Qwen3-0.6B`. The task is closed-set classification from one English vulnerability description to JSON of the form `{"cwe_id": "CWE-79"}`. The same fixed prompt, selected-label order, generation settings, and deterministic evaluation verifier apply to Base and the pending adapter evaluation.

## Intended use

This experiment measures CVE-description classification within 15 selected CWE labels. It is a research pipeline for reproducible data transformation and evaluation, not an operational security system. It does not evaluate incident response, autonomous action, or labels outside the closed set.

## Dataset

Dataset version `1.1` uses NVD CVE API 2.0 records through 2026-09-17. Labels are selected using training-period counts only. The temporal ranges are 2020–2024 for training, 2025 for validation, and 2026 through the snapshot for test.

| Split | Population after required split dedup | SFT rows |
|---|---:|---:|
| Train | 65,272 | 12,000 |
| Validation | 20,918 | 1,000 |
| Test | 24,975 | 24,975 |

The overlap check between fine-tuning splits uses exact CVE IDs and exact normalized-description hashes. The post-build invariant is zero overlap for train–validation, train–test, and validation–test.

## LoRA SFT configuration

| Setting | Configured value |
|---|---|
| Epochs | 3 |
| Learning rate | 2e-4 |
| Scheduler | cosine |
| Maximum sequence length | 1,536 |
| Device batch size | 2 |
| Gradient accumulation | 8 |
| Precision | fp16 |
| Rank / alpha / dropout | 16 / 32 / 0.05 |
| Target modules | `q_proj`, `k_proj`, `v_proj`, `o_proj` |
| Completion-only loss | true |
| Quantization | false in the configured run |

## Evaluation protocol

Evaluation is greedy (`do_sample=false`) with 32 maximum new tokens and the fixed top-15 label prompt. The evaluation subset contains 18,000 test IDs pinned in Base prediction order by `reports/eval_subset_manifest.json`; its subset hash is `229dd47c3cdeb532d47c2dd8c5962f2c9bff8ff2c6d89d8d2776ee6d09a7d707`.

## Results

| Metric | Base | SFT | Delta |
|---|---:|---:|---:|
| Accuracy | 0.3969 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| Macro F1 | 0.3048 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| Weighted F1 | 0.3891 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| Invalid-output rate | 0.0237 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |
| KEV accuracy | 0.3143 | TBD (pending exp_002_sft_v1) | TBD (pending exp_002_sft_v1) |

## Training and adapter measurements

| Measurement | Result |
|---|---|
| Final training loss | TBD (pending exp_002_sft_v1) |
| Validation loss | TBD (pending exp_002_sft_v1) |
| Runtime | TBD (pending exp_002_sft_v1) |
| Peak VRAM | TBD (pending exp_002_sft_v1) |
| Adapter parameters | TBD (pending exp_002_sft_v1) |

## Limitations

- Single-label CVEs and a top-15 closed set only.
- One dataset snapshot and one seed.
- NVD weakness labels can be noisy or incomplete; multi-label records are excluded.
- Descriptions alone can be ambiguous.
- Exact-hash overlap checks do not detect semantic paraphrases.
- Exposure of the unadapted model weights to NVD content cannot be verified.
- KEV is an evaluation slice only.

See [docs/claim-boundaries.md](docs/claim-boundaries.md) for the complete scope statement.

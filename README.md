# Security-domain LLM Post-training & Evaluation

*CVE-to-CWE domain SFT with reproducible evaluation*

The repository cleans public vulnerability data (NVD) into a CWE classification dataset and compares an open-weight LLM's base and LoRA-SFT performance on the same temporal held-out set.
Raw NVD records and model-specific prompt formatting are kept separate so dataset construction and model adaptation are verified independently.

## Problem

The task maps one English CVE description to one JSON CWE label in a fixed closed set.

```text
NVD CVE → Canonical Security Record → CWE Label Policy → Temporal Split + Overlap Check
→ Model Adapter → Qwen3-0.6B Base → LoRA SFT → Same Held-out Test
→ Deterministic Evaluation Verifier → Failure Analysis (→ Data Distribution Ablation, if present)
```

## Dataset

The NVD snapshot date is `2026-09-17`. The source funnel contains 257,913 raw records and 194,797 single-label records.

Selected CWE IDs: `CWE-79`, `CWE-89`, `CWE-787`, `CWE-352`, `CWE-125`, `CWE-862`, `CWE-416`, `CWE-22`, `CWE-20`, `CWE-78`, `CWE-476`, `CWE-120`, `CWE-434`, `CWE-200`, `CWE-284`.

| Split | Selected-class population | Sampled rows |
|---|---:|---:|
| Train | 65,272 | 12,000 |
| Validation | 20,918 | 1,000 |
| Test | 24,975 | 24,975 |

The training and validation views use seeded natural-distribution samples; the test view retains the full selected-class population. See the [dataset card](DATASET_CARD.md) and [dataset report](reports/dataset_report.md).

## Temporal split and leakage guard

| Split | Published-date range |
|---|---|
| Train | 2020-01-01–2024-12-31 |
| Validation | 2025-01-01–2025-12-31 |
| Test | 2026-01-01–2026-09-17 |

Temporal splits use the NVD `published` timestamp rather than the year embedded in the CVE identifier. An older CVE ID can therefore appear in the 2026 test split when that record was published by NVD during the test period.

Exact CVE-ID and normalized-description overlap between fine-tuning splits: 0 after build. This is an exact check, not a semantic-similarity claim.

## Base model

The unadapted run uses `Qwen/Qwen3-0.6B` at revision `c1899de289a04d12100db370d81485cdf75e47ca`. It is evaluated with the same prompt, ordered CVE-ID subset, generation settings, and deterministic evaluation verifier as the adapted run.

## LoRA SFT

| Setting | Recorded value |
|---|---|
| Model / revision | `Qwen/Qwen3-0.6B` / `c1899de289a04d12100db370d81485cdf75e47ca` |
| LoRA rank / alpha / dropout | 16 / 32 / 0.05 |
| Target modules | `q_proj`, `k_proj`, `v_proj`, `o_proj` |
| Epochs / learning rate | 3 / 0.0002 |
| Device batch / gradient accumulation / effective batch | 2 / 8 / 16 |
| Maximum sequence length | 1,536 tokens |
| Precision / quantization | fp16 / no quantization |
| GPU | NVIDIA GeForce RTX 2060 |
| Training wall time | 7835.1 s |
| Peak allocated VRAM | 2001.4 MiB |
| Trainable parameters | 4,587,520 |

The 1,536-token limit was used because the recorded rendered prompt-plus-completion maxima are 1,371 for train, 1,189 for validation, and 1,322 for test, with no rows over the configured limit.

## Base vs SFT

| Metric | Base | SFT | Delta |
|---|---:|---:|---:|
| Accuracy | 0.3969 | 0.8627 | +0.4657 |
| Macro F1 | 0.3048 | 0.8332 | +0.5284 |
| Invalid-output rate | 0.0237 | 0.0000 | -0.0237 |

n = 18,000: a seed-42 subsample of the 24,975-row 2026 test split.

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

## Failure analysis

### Outcome transitions

| Transition | Count |
|---|---:|
| `both_right` | 6,813 |
| `fixed_by_sft` | 8,715 |
| `broken_by_sft` | 332 |
| `both_wrong` | 2,140 |

### Error types

| Outcome or error type | Base | SFT |
|---|---:|---:|
| `correct` | 7,145 | 15,528 |
| `invalid_format` | 0 | 0 |
| `unknown_cwe` | 426 | 0 |
| `nearby_cwe_confusion` | 1,828 | 852 |
| `semantic_confusion` | 8,601 | 1,620 |

### Most frequent SFT confusions

| Gold → prediction | Count |
|---|---:|
| CWE-862 → CWE-284 | 367 |
| CWE-284 → CWE-200 | 138 |
| CWE-862 → CWE-200 | 138 |
| CWE-284 → CWE-20 | 133 |
| CWE-787 → CWE-120 | 133 |

### Representative residual examples

The comparison artifact stores residual failures, so the available examples are broken or still wrong rather than fixed cases.

| Transition | CVE ID | Gold | Base | SFT | Description excerpt |
|---|---|---|---|---|---|
| `broken_by_sft` | CVE-2018-25276 | CWE-120 | CWE-120 | CWE-20 | RoboImport 1.2.0.72 contains a denial of service vulnerability that allows local attackers to crash the application by submitting oversized input to registrati… |
| `broken_by_sft` | CVE-2018-25330 | CWE-89 | CWE-89 | CWE-79 | Joomla! extension EkRishta 2.10 contains persistent cross-site scripting and SQL injection vulnerabilities that allow attackers to inject malicious code throug… |
| `both_wrong` | CVE-2013-20005 | CWE-79 | CWE-352 | CWE-352 | Qool CMS 2.0 RC2 contains a cross-site request forgery vulnerability that allows attackers to perform administrative actions by tricking logged-in users into v… |

See [the full failure analysis](reports/failure_analysis.md) for the top confusions, long-tail results, and quoted records.

## Reproduction

Run these commands from the repository root, in order:

```bash
bash scripts/setup_env.sh       # create the Python environment and install pinned dependencies
bash scripts/prepare_data.sh    # fetch NVD pages and build canonical, split, and SFT views
bash scripts/eval_base.sh       # evaluate the unadapted model on the frozen subset
bash scripts/train_sft.sh       # train and write the LoRA adapter
bash scripts/eval_sft.sh        # evaluate the adapter on the identical frozen subset
bash scripts/build_report.sh    # rebuild comparison and failure-analysis JSON/Markdown artifacts
```

`NVD_API_KEY` is optional and is never written to a file; setting it increases the NVD API rate limit. Model execution also requires access to the model weights or a populated local cache.

Measured on an RTX 2060 6 GB: Base evaluation used batch 2 and took 5448.4 s; training used device batch 2 with 8 accumulation steps and took 7835.1 s; SFT evaluation used batch 8 and took 2025.4 s. Setup, NVD ingestion, and report-rendering time depend on cache and API state and were not recorded in the cited JSON artifacts.

The mandatory smoke run completed before the full run. Earlier runs next to a GPU co-tenant included two fp16 LoRA OOM probes and an OOM in the quantized fallback; a separate attempt was stopped when the host CUDA driver could not initialize. The successful run started only after the GPU and driver checks passed.

## Scope and limitations

See [claim boundaries](docs/claim-boundaries.md) for the fixed wording and complete scope.

- The dataset includes single-label CVEs only; multi-label CVEs are excluded.
- The output space is a closed set of 15 CWE IDs.
- Results cover one temporal snapshot and one seed.
- Prior exposure of the unadapted model to NVD text cannot be verified.
- KEV is an evaluation slice only.
- No continued-domain adaptation or reinforcement-learning phase was run.
- Exact normalized-description matching does not detect paraphrases.
- Exact CVE-ID and normalized-description overlap between splits is blocked by a fail-fast guard. In addition, a sampled audit of high text-similarity train/test pairs was run to check for template reuse; this is not a formal semantic-contamination detector. Audit (`reports/near_duplicate_audit.md`, word TF-IDF 1–2-gram cosine, 300 evaluated test rows = 200 `fixed_by_sft` + 100 `both_wrong`, class-stratified, seed 42): nearest-train similarity p50 0.27 / p90 0.70 / p95 0.74 / max 1.00; 8 rows ≥ 0.80 (5 same-label, 3 different-label), 3 rows ≥ 0.90; all 8 fall in the `fixed_by_sft` sample (5 same-label = 2.5% of the 200 sampled fixes), 0 in `both_wrong`. Manual review of the top 20: 7 exact-or-near copies, 11 vendor-boilerplate-only, 2 repeated weakness phrases. These sampled counts do not establish template reuse as a material shortcut for the 8,715 `fixed_by_sft` transitions.
- The Natural-vs-Balanced ablation was not run. It is a conditional follow-up if tail recall remains low, predictions remain concentrated, and failures continue to co-occur with class imbalance.
- Future work: Residual errors are concentrated around semantically adjacent or generic CWE boundaries, particularly CWE-862 vs CWE-284 and generic classes such as CWE-20, CWE-120, and CWE-200. A follow-up study could evaluate hierarchical or revised label policies before changing the model architecture.

## Repository map

| Directory | Responsibility |
|---|---|
| `src/security_llm/data/` | NVD ingestion, canonical records, validation, statistics, temporal splits, exact deduplication, SFT views, and manifests |
| `src/security_llm/adapters/` | Fixed CWE instruction, closed-set labels, output schema, and model-facing serialization |
| `src/security_llm/eval/` | Generation, deterministic evaluation verifier, metrics, exact overlap checks, failure analysis, and documentation rendering |
| `src/security_llm/train/` | LoRA SFT execution and training-artifact capture |
| `src/security_llm/utils/` | Atomic I/O, metadata, and seed helpers |
| `configs/` | Data, training, and evaluation configuration |
| `data/` | Raw cache, canonical records, split populations, and derived SFT JSONL |
| `manifests/` | Versioned dataset identity, row counts, policies, and file hashes |
| `experiments/` | Run-specific metadata, logs, predictions, metrics, and local adapter output |
| `reports/` | Dataset, Base/SFT evaluation, comparison, and failure-analysis artifacts |
| `docs/` | Specification, data/model boundary, and claim boundaries |
| `scripts/` | End-to-end setup, data preparation, training, evaluation, and report commands |
| `tests/` | Schema, split, verifier, deduplication, metric, and completion-mask checks |

License: MIT. Vulnerability records are sourced from the [NIST National Vulnerability Database](https://nvd.nist.gov/); CWE identifiers and names are from [MITRE CWE](https://cwe.mitre.org/).

## Data engineering learning track

The v0.1.0 result above is the baseline and is unchanged. This branch records a series of
experiments extending the data pipeline, each one measured against that baseline before any
technology was adopted.

- **Spark reimplementation** of the dataset processing, checked against the reference at row
  level rather than by row count — CVE-ID sets, per-row fields, split assignment, class
  distribution, and the IDs surviving deduplication. Running the same Spark workload in local
  mode, `local[8]` was 1.89x faster than `local[1]`.
- **Near-duplicate scaling**, separating internal all-pairs (quadratic) from query-vs-fixed-
  reference (linear in queries), then an exact audit of all 1,630,168,200 train/test pairs in
  96.639 s.
- **Incremental downstream rebuild**, measured and then declined: most of the work stays global
  and verifying an incremental result costs more than it saves.
- **Incremental NVD ingest**, where the API's modified-window semantics were probed directly and
  source content was observed changing without `lastModified` moving.

Several starting hypotheses were wrong — Ray, LSH and ANN were expected to be necessary and were
not built. The reasoning, the measurements and the corrections are in
[the learning track record](docs/LEARNING_TRACK.md), with specifications in
[distributed pipeline](docs/SPEC_distributed.md),
[candidate reduction](docs/SPEC_candidate_reduction.md),
[change model](docs/CHANGE_MODEL.md) and [ingest semantics](docs/INGEST_SEMANTICS.md).

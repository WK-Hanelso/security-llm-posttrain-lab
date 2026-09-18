# security-llm-posttrain-lab

A reproducible security data and evaluation pipeline for mapping English NVD CVE descriptions to one CWE ID in a top-15 closed set. The repository separates the canonical security record from the Qwen3 instruction adapter and records exact overlap checks, dataset versions, and deterministic evaluation artifacts.

The completed evidence covers dataset construction and the unadapted `Qwen/Qwen3-0.6B` evaluation. The LoRA SFT and comparative failure-analysis stages are pending `exp_002_sft_v1`.

## Pipeline

```text
NVD CVE API 2.0
  -> cached raw pages
  -> canonical security records
  -> validate / exact-hash dedup / temporal split
  -> fixed CWE instruction adapter
  -> versioned SFT JSONL
  -> Base evaluation (complete; frozen 18,000-ID subset)
  -> LoRA SFT (pending exp_002_sft_v1)
  -> SFT evaluation and comparative failure analysis (pending exp_002_sft_v1)
```

## Dataset at a glance

Snapshot: `2026-09-17`; dataset version: `1.1`; canonical schema: `1.0`.

| Split | Date range | Selected-class population after required split dedup | SFT rows |
|---|---|---:|---:|
| Train | 2020-01-01–2024-12-31 | 65,272 | 12,000 |
| Validation | 2025-01-01–2025-12-31 | 20,918 | 1,000 |
| Test | 2026-01-01–2026-09-17 | 24,975 | 24,975 |

The project checked exact CVE-ID and normalized-description overlap between fine-tuning splits. The post-build guard passes all pairs. See the [dataset report](reports/dataset_report.md), [dataset card](DATASET_CARD.md), and [claim boundaries](docs/claim-boundaries.md).

## Evaluation results

The Base evaluation uses the ID-pinned 18,000-record subset in `reports/eval_subset_manifest.json`.

| Metric | Base | SFT | Delta |
|---|---:|---:|---:|
| Accuracy | 0.3969 | pending | pending |
| Macro F1 | 0.3048 | pending | pending |
| Weighted F1 | 0.3891 | pending | pending |
| Invalid-output rate | 0.0237 | pending | pending |
| KEV accuracy (n=35) | 0.3143 | pending | pending |

The most frequent Base confusions are CWE-862→CWE-200 (1,976), CWE-284→CWE-200 (1,573), CWE-416→CWE-434 (724), CWE-20→CWE-200 (678), and CWE-787→CWE-120 (619). Full Base details are in [reports/base_eval.md](reports/base_eval.md).

## Reproduce completed artifacts

Use the existing environment and cached tokenizer; these commands do not run training:

```bash
export HF_HOME=$PWD/data/hf_cache
export TRANSFORMERS_OFFLINE=1

.venv/bin/python -m security_llm.data.validate --config configs/data.yaml
.venv/bin/python -m security_llm.data.guard --config configs/data.yaml --stage sft
.venv/bin/python -m security_llm.eval.contamination --config configs/data.yaml
.venv/bin/python -m security_llm.data.report --config configs/data.yaml
.venv/bin/python -m security_llm.eval.failure_analysis --single \
  --base experiments/exp_001_baseline/predictions.jsonl \
  --test data/sft/test.jsonl \
  --labels data/processed/labels.json
.venv/bin/pytest -q -k "not completion_mask"
```

## Repository map

| Path | Responsibility |
|---|---|
| `src/security_llm/data/` | ingestion, canonical schema, splitting, dedup, guard, SFT build, reports |
| `src/security_llm/adapters/` | canonical-record to fixed prompt/completion adapter |
| `src/security_llm/eval/` | generation, deterministic evaluation verifier, metrics, overlap checks, failure rules |
| `configs/` | data, LoRA SFT, and evaluation configuration |
| `manifests/` | versioned dataset identity and file hashes |
| `reports/` | dataset, Base evaluation, taxonomy, and pending comparison documents |
| `experiments/` | immutable run artifacts by experiment ID |
| `docs/` | binding specification, data-layer design, and claim boundaries |

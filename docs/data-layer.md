# Data Layer and Model Adapter

```text
NVD CVE API 2.0
       │
       ▼
raw page cache
       │ normalize
       ▼
canonical security records (schema 1.0)
       │
       ├── validate ──► schema summary
       │
       └── deduplicate / temporal split / select labels
                         │
                         ▼
                  CWE instruction adapter
                         │
                         ▼
                    SFT JSONL views
                         │
                         ▼
                Qwen/Qwen3-0.6B LoRA SFT
```

## Responsibility boundary

| Data layer | Model adapter |
|---|---|
| Stores source-derived security facts | Builds the fixed user instruction |
| Defines and validates the canonical schema | Lists the selected closed-set labels |
| Normalizes description text for exact hashing | Serializes the target CWE as JSON |
| Selects labels using the training period | Renders the model chat template |
| Applies temporal splits and deduplication policy | Defines the expected output JSON schema |
| Records file hashes, counts, and policies | Contains model-facing fields only in SFT JSONL |

The canonical record contains no prompt, template, tokenizer, or model fields. The adapter is a derived view:
it may change for another model family without changing the source security facts.

## File-to-responsibility map

| File or package | Responsibility |
|---|---|
| `security_llm.data.ingest_nvd` | Fetch and cache NVD API pages |
| `security_llm.data.normalize` | Convert raw CVEs into canonical records |
| `security_llm.data.schema` | Define schema 1.0 and validate records/files |
| `security_llm.data.validate` | Expose canonical validation as a CLI |
| `security_llm.data.stats` | Compute source funnel and population statistics |
| `security_llm.data.split` | Select training-only labels and make temporal splits |
| `security_llm.data.dedup` | Normalize text, hash it, and check exact overlap |
| `security_llm.data.build_sft` | Sample splits and write model-facing JSONL |
| `security_llm.data.manifest` | Build and upgrade the versioned dataset manifest |
| `security_llm.data.report` | Assemble JSON and Markdown dataset reports |
| `security_llm.adapters.cwe_instruction` | Define the CWE prompt, output schema, and label serialization |
| `security_llm.prompt` | Preserve the original prompt import path |
| `security_llm.eval.verifier` | Deterministic evaluation verifier for generated output |
| `security_llm.eval.metrics` | Compute closed-set evaluation metrics |
| `security_llm.eval.contamination` | Run the exact overlap check between fine-tuning splits |
| `security_llm.eval.generate` | Generate predictions under the fixed evaluation settings |
| `security_llm.eval.failure_analysis` | Compare baseline and adapted-model errors |
| `security_llm.train.sft` | Run LoRA SFT of an open-weight 0.6B model |
| `security_llm.utils` | Shared atomic I/O, metadata, and seed helpers |

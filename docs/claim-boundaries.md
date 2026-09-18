# Claim Boundaries

## What the project demonstrates

- A reproducible transformation from NVD CVE API 2.0 pages to a versioned canonical security record.
- A documented training-only label-selection policy and temporal split policy.
- A fixed adapter from canonical records to prompt/completion JSONL for LoRA SFT of an open-weight 0.6B model.
- A deterministic evaluation verifier for parsing generated CWE JSON and computing closed-set metrics.
- The following precise overlap statement: “checked exact CVE-ID and normalized-description overlap between fine-tuning splits”.

The verifier is a *deterministic evaluation verifier*, not an RL reward.

## What the project does not demonstrate

| Boundary | Scope |
|---|---|
| Taxonomy | Single-label CVEs in a top-15 closed set only |
| Generalization | One temporal dataset snapshot and one seed |
| KEV | An evaluation slice only; it is not a training target or a separate task |
| Verifier | A deterministic evaluation verifier, not an RL reward |
| Overlap | Exact CVE-ID and normalized-description hashes between fine-tuning splits; no semantic match search |
| Model history | The data used to train the unadapted model is not observable here |
| Operational use | No deployment, incident response, alerting, or autonomous action is evaluated |

## Prohibited descriptions

The following phrases are forbidden as descriptions of this project or its results:

- “contamination-free benchmark”
- “base-model/pretraining contamination removed or verified”
- “foundation model”
- “CPT”
- “RLVR”
- “malware detection”
- “threat intelligence model”
- “SOC automation”
- “large-scale Ray cluster”

Results should instead name the exact data transformation, split, adapter, verifier, and measured metric.

# SPEC — security-llm-posttrain-lab

Implementation specification for the CVE→CWE domain SFT experiment. This document is the
source of truth for file layouts, schemas, and algorithms. Code must follow it; if the
implementation must diverge, update this file in the same commit and record the reason.

Status: v1 (2026-09-17). Sections marked **[P2]** are stretch goals and are not required.

---

## 0. Fixed decisions (do not re-litigate)

| Item | Decision |
|---|---|
| Task | CVE English description → single CWE ID, emitted as JSON `{"cwe_id": "CWE-79"}` |
| Model | `Qwen/Qwen3-0.6B` (post-trained chat model, not `-Base`). Same weights for baseline and as the LoRA base |
| Split | Temporal by NVD `published` date. TRAIN 2020-01-01..2024-12-31, VAL 2025-01-01..2025-12-31, TEST 2026-01-01..snapshot |
| Labels | Top-K CWE by frequency **computed on TRAIN period only**; K from config (initial 15), each class must have ≥ `min_train_samples_per_class` (initial 200) else K shrinks |
| Multi-label | Excluded in MVP (single-label CVEs only) |
| Adapter | LoRA first. QLoRA (4-bit) only if LoRA does not fit in VRAM; reason recorded in `EXPERIMENT.md` |
| Loss | Completion tokens only. Verified by a test that inspects `labels == -100` on prompt positions |
| Generation | Greedy (`do_sample=false`), `max_new_tokens=32`, identical for Base and SFT |
| Prompt | One fixed instruction template (§6). Never changed between Base and SFT |
| Order | Baseline metrics must exist on disk before SFT training starts |
| Metrics | Exact accuracy, macro F1, invalid-output rate, per-class P/R/F1, confusion matrix |
| Honesty | Only report what was actually run. Failed experiments are kept, never deleted |

---

## 1. Repository layout

```
security-llm-posttrain-lab/
├── README.md                     # filled with real numbers at the end (Phase 10)
├── DATASET_CARD.md
├── MODEL_CARD.md
├── LICENSE                       # MIT
├── pyproject.toml                # package: security_llm (src layout)
├── requirements.txt
├── .gitignore                    # data/, experiments/*/adapter, .venv, logs/, *.gguf, __pycache__
├── configs/
│   ├── data.yaml
│   ├── sft.yaml
│   └── eval.yaml
├── docs/
│   └── SPEC.md                   # this file
├── src/security_llm/
│   ├── __init__.py
│   ├── config.py                 # load_yaml(path) -> dict; deep merge with CLI overrides
│   ├── prompt.py                 # fixed instruction template + chat rendering
│   ├── cwe_names.py              # static {CWE-ID: short name} for common CWEs
│   ├── data/
│   │   ├── ingest_nvd.py         # NVD API 2.0 → raw page cache
│   │   ├── normalize.py          # raw pages → normalized.jsonl
│   │   ├── stats.py              # normalized.jsonl → reports/dataset_stats.json
│   │   ├── split.py              # temporal split + label selection → train/val/test.jsonl + labels.json
│   │   ├── dedup.py              # text normalization, hashing, overlap detection
│   │   └── build_sft.py          # splits → data/sft/*.jsonl + manifest
│   ├── train/
│   │   └── sft.py                # LoRA / QLoRA SFT with TRL
│   ├── eval/
│   │   ├── generate.py           # batched greedy generation → predictions.jsonl
│   │   ├── verifier.py           # deterministic output verifier
│   │   ├── metrics.py            # predictions.jsonl → metrics.json
│   │   ├── contamination.py      # train↔val/test overlap report
│   │   └── failure_analysis.py   # base vs sft join → failures.jsonl + failure_summary.json
│   └── utils/
│       ├── io.py                 # read_jsonl / write_jsonl / sha256_file / atomic write
│       ├── meta.py               # collect_env(): git commit, versions, GPU
│       └── seed.py               # set_seed(seed)
├── scripts/
│   ├── setup_env.sh              # uv venv + install
│   ├── prepare_data.sh           # ingest → normalize → stats → split → build_sft → contamination
│   ├── eval_base.sh
│   ├── train_sft.sh
│   ├── eval_sft.sh
│   └── build_report.sh           # metrics + failure analysis → reports/
├── tests/
│   ├── fixtures/nvd_sample.json  # small hand-written page in NVD 2.0 schema (≥ 8 CVEs)
│   ├── test_schema.py
│   ├── test_split.py
│   ├── test_verifier.py
│   ├── test_dedup.py
│   ├── test_metrics.py
│   └── test_completion_mask.py   # needs tokenizer download; skipped when offline
├── manifests/
│   └── dataset_manifest.json
├── reports/
│   ├── dataset_stats.json
│   ├── contamination.json
│   ├── baseline_metrics.json     # copy of experiments/exp_001_baseline/metrics.json
│   ├── sft_metrics.json          # copy of experiments/exp_002_sft_v1/metrics.json
│   ├── failures.jsonl
│   ├── failure_summary.json
│   └── EXPERIMENT.md
├── experiments/                  # one directory per experiment id (adapter weights git-ignored)
│   ├── exp_001_baseline/
│   └── exp_002_sft_v1/
├── data/                         # git-ignored except data/README.md
│   ├── raw/nvd/
│   ├── processed/
│   └── sft/
└── logs/                         # git-ignored
```

---

## 2. Environment

- Python 3.11 via `uv` (`uv venv .venv --python 3.11`). Driver on the dev GPU is 535 → CUDA runtime must be ≤ 12.2, so **torch wheels from the `cu121` index**.
- `requirements.txt` (pin the versions that were actually installed; write them back after install):

```
torch                      # from https://download.pytorch.org/whl/cu121
transformers>=4.51         # Qwen3 support
trl>=0.19
peft>=0.15
datasets>=2.20
accelerate>=1.0
bitsandbytes>=0.43         # only used when quantization.load_in_4bit is true
scikit-learn>=1.4
numpy
pyyaml
requests
tqdm
pytest
```

- `scripts/setup_env.sh`:
  1. `uv venv .venv --python 3.11` (skip if exists)
  2. `uv pip install --python .venv/bin/python torch --index-url https://download.pytorch.org/whl/cu121`
  3. `uv pip install --python .venv/bin/python -r requirements.txt -e .`
  4. `.venv/bin/python -c "import torch; print(torch.__version__, torch.cuda.is_available(), torch.cuda.get_device_name(0))"`
- `NVD_API_KEY` environment variable is optional. Never written to any file.
- `HF_HOME` may be set to keep the model cache inside `data/hf_cache` (git-ignored). Default HF cache is fine.

---

## 3. Configs

### 3.1 `configs/data.yaml`

```yaml
seed: 42
nvd:
  base_url: https://services.nvd.nist.gov/rest/json/cves/2.0
  start_date: "2020-01-01"       # inclusive, pubStartDate
  end_date: null                 # null → today's date at run time; recorded as dataset_snapshot
  window_days: 119               # API limit is 120 days per request
  results_per_page: 2000         # API max
  sleep_seconds_without_key: 6.5 # 5 requests / 30 s public limit
  sleep_seconds_with_key: 0.7    # 50 requests / 30 s with key
  max_retries: 6
  raw_dir: data/raw/nvd
filter:
  require_english_description: true
  exclude_rejected: true         # vulnStatus == "Rejected" or description startswith "** REJECT **"
  placeholder_cwes: ["NVD-CWE-noinfo", "NVD-CWE-Other"]
  single_label_only: true
labels:
  top_k: 15
  min_train_samples_per_class: 200
split:                           # inclusive date ranges on `published` (YYYY-MM-DD)
  train: ["2020-01-01", "2024-12-31"]
  val:   ["2025-01-01", "2025-12-31"]
  test:  ["2026-01-01", null]    # null → snapshot date
dedup:
  drop_train_exact_duplicates: true      # same description_norm_hash inside TRAIN → keep earliest published
  drop_train_overlap_with_eval: true     # TRAIN records whose hash appears in VAL or TEST are dropped
sft:
  max_description_chars: 1500    # descriptions are truncated at this many characters (recorded in manifest)
  train_max_samples: 12000       # null → all. Uniform random subsample with `seed` (keeps natural distribution)
  val_max_samples: 1000
  test_max_samples: null         # null → full TEST split
  sampling: natural              # natural | balanced   (balanced is [P2])
  balanced_max_per_class: 800    # only used when sampling == balanced
paths:
  processed_dir: data/processed
  sft_dir: data/sft
  labels_file: data/processed/labels.json
  manifest: manifests/dataset_manifest.json
  stats: reports/dataset_stats.json
  contamination: reports/contamination.json
```

### 3.2 `configs/sft.yaml`

```yaml
experiment_id: exp_002_sft_v1
seed: 42
model:
  name: Qwen/Qwen3-0.6B
  revision: null                 # resolved commit hash is recorded in metadata.json
data:
  train_file: data/sft/train.jsonl
  val_file: data/sft/val.jsonl
training:
  epochs: 3
  learning_rate: 2.0e-4
  lr_scheduler_type: cosine
  warmup_ratio: 0.03
  max_seq_length: 512
  per_device_train_batch_size: 2
  gradient_accumulation_steps: 8
  fp16: true                     # dev GPU is Turing (no bf16)
  bf16: false
  gradient_checkpointing: true
  logging_steps: 10
  eval_strategy: epoch           # val loss only; never used to pick checkpoints in v1
  save_strategy: "no"            # adapter saved once at the end
  weight_decay: 0.0
  max_grad_norm: 1.0
  completion_only_loss: true
lora:
  rank: 16
  alpha: 32
  dropout: 0.05
  target_modules: [q_proj, k_proj, v_proj, o_proj]
  bias: none
quantization:
  load_in_4bit: false            # true → QLoRA (nf4, double quant, fp16 compute). Set only when LoRA OOMs.
output:
  root: experiments
```

### 3.3 `configs/eval.yaml`

```yaml
experiment_id: exp_001_baseline  # overridden by scripts (exp_002_sft_v1 for the adapter run)
seed: 42
model:
  name: Qwen/Qwen3-0.6B
  revision: null
  adapter_path: null             # experiments/exp_002_sft_v1/adapter for the SFT run
  dtype: float16
data:
  file: data/sft/test.jsonl
  labels_file: data/processed/labels.json
  limit: null                    # int → evaluate only the first N rows (smoke runs); recorded in metrics.json
generation:
  do_sample: false
  temperature: null              # not passed when do_sample is false
  max_new_tokens: 32
  batch_size: 8
output:
  root: experiments
```

`security_llm/config.py`
```
load_config(path, overrides: list[str]) -> dict
  cfg = yaml.safe_load(open(path))
  for "a.b.c=value" in overrides: set nested key; value parsed with yaml.safe_load(value)
  return cfg
```

---

## 4. Data files and schemas

All JSONL files are UTF-8, one object per line, written atomically (tmp file + rename).

### 4.1 Raw cache — `data/raw/nvd/<pubStart>_<pubEnd>/page_<startIndex:07d>.json`

Verbatim NVD API 2.0 response body for one page. `pubStart`/`pubEnd` are `YYYY-MM-DD`.
Sidecar `data/raw/nvd/ingest_manifest.json`:

| field | type | meaning |
|---|---|---|
| `snapshot_date` | str `YYYY-MM-DD` | the `end_date` actually used |
| `start_date` | str | config start |
| `fetched_at` | str ISO-8601 | when the ingest run finished |
| `windows[]` | list | one entry per date window: `{pub_start, pub_end, total_results, pages, complete: bool}` |
| `total_cves` | int | sum of `total_results` |
| `api_key_used` | bool | whether `NVD_API_KEY` was set (never the key itself) |

### 4.2 Normalized — `data/processed/normalized.jsonl`

One record per CVE (deduplicated by `cve_id`, last occurrence wins).

| field | type | meaning |
|---|---|---|
| `cve_id` | str | `CVE-YYYY-NNNN+`, validated by `^CVE-\d{4}-\d{4,}$` |
| `published` | str `YYYY-MM-DD` | from `cve.published` (first 10 chars) |
| `last_modified` | str | `cve.lastModified` |
| `vuln_status` | str | `cve.vulnStatus` |
| `description_en` | str | first `descriptions[]` entry with `lang == "en"`, whitespace-stripped |
| `description_norm_hash` | str | sha256 hex of `normalize_text(description_en)` (§5.5) |
| `cwe_primary` | list[str] | unique `CWE-\d+` values from weaknesses with `type == "Primary"` |
| `cwe_secondary` | list[str] | same for `type == "Secondary"` |
| `cwe_all` | list[str] | sorted unique union of primary+secondary, placeholders removed |
| `placeholder_only` | bool | weaknesses existed but every value was a placeholder |
| `cwe_id` | str or null | `cwe_all[0]` iff `len(cwe_all) == 1`, else null |
| `label_status` | str | one of `single`, `multi`, `placeholder_only`, `none` |
| `cvss_v31_base_score` | float or null | first `metrics.cvssMetricV31[].cvssData.baseScore` |
| `cvss_v31_severity` | str or null | first `metrics.cvssMetricV31[].cvssData.baseSeverity` |
| `is_kev` | bool | `cisaExploitAdd` present |
| `kev_date_added` | str or null | `cisaExploitAdd` |
| `is_rejected` | bool | filter.exclude_rejected rule |

### 4.3 Labels — `data/processed/labels.json`

```json
{
  "selected": ["CWE-79", "CWE-89", "..."],          // ordered by TRAIN frequency, descending
  "train_counts": {"CWE-79": 12345, "...": 0},
  "top_k_requested": 15,
  "top_k_effective": 15,
  "min_train_samples_per_class": 200,
  "train_period": ["2020-01-01", "2024-12-31"],
  "names": {"CWE-79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"}
}
```

### 4.4 Split files — `data/processed/{train,val,test}.jsonl`

Normalized records (§4.2) with `label_status == single` and `cwe_id ∈ selected`, plus `split: str`.
No sampling yet (full population of the split).

### 4.5 SFT files — `data/sft/{train,val,test}.jsonl`

| field | type | meaning |
|---|---|---|
| `cve_id` | str | |
| `cwe_id` | str | gold label |
| `published` | str | |
| `description` | str | `description_en` truncated to `max_description_chars` |
| `truncated` | bool | whether truncation happened |
| `prompt` | str | **user-turn text** (not the chat-rendered string), produced by `build_user_prompt(description, labels)` (§6) |
| `completion` | str | `{"cwe_id": "CWE-79"}` (compact JSON, no trailing newline) |
| `is_kev` | bool | evaluation slice metadata |
| `split` | str | |

### 4.6 Manifest — `manifests/dataset_manifest.json`

| field | type | meaning |
|---|---|---|
| `created_at` | str | ISO-8601 |
| `git_commit` | str | commit of the code that built the dataset |
| `dataset_snapshot` | str | NVD snapshot date |
| `data_config_sha256` | str | hash of `configs/data.yaml` |
| `prompt_template_sha256` | str | hash of `PROMPT_TEMPLATE` string + selected label list |
| `labels` | list[str] | selected labels |
| `files` | dict | per file in `data/sft/`: `{path, rows, sha256}` |
| `counts` | dict | `{train, val, test}` row counts after sampling |
| `population_counts` | dict | row counts before sampling |
| `class_distribution` | dict | `{split: {cwe: count}}` after sampling |
| `sampling` | dict | copy of `data.yaml: sft` |
| `dedup` | dict | `{train_exact_duplicates_dropped, train_overlap_with_eval_dropped}` |

### 4.7 Dataset stats — `reports/dataset_stats.json`

```json
{
  "snapshot_date": "...",
  "funnel": {
    "raw_cves": 0, "unique_cves": 0, "rejected": 0, "no_english_description": 0,
    "no_weakness": 0, "placeholder_only": 0, "multi_label": 0, "single_label": 0
  },
  "per_year": {"2020": {"total": 0, "single_label": 0}},
  "train_period_cwe_frequency_top50": {"CWE-79": 0},
  "selected_labels": ["..."],
  "coverage": {
    "train": {"single_label_total": 0, "in_selected": 0, "fraction": 0.0},
    "val":   {"...": 0},
    "test":  {"...": 0}
  },
  "split_class_distribution": {"train": {"CWE-79": 0}, "val": {}, "test": {}},
  "description_length_chars": {"train": {"p50": 0, "p90": 0, "p99": 0, "max": 0}},
  "kev": {"train": 0, "val": 0, "test": 0}
}
```

### 4.8 Contamination — `reports/contamination.json`

```json
{
  "computed_on": "data/processed/{train,val,test}.jsonl (before sampling) and data/sft/*.jsonl (after)",
  "train_val_cve_id_overlap": 0,
  "train_test_cve_id_overlap": 0,
  "train_val_exact_text_overlap": 0,
  "train_test_exact_text_overlap": 0,
  "val_test_exact_text_overlap": 0,
  "train_internal_exact_duplicates": 0,
  "examples": {"train_test_exact_text_overlap": [["CVE-A", "CVE-B"]]},
  "policy": "train records overlapping val/test by normalized-text hash were dropped before SFT build",
  "post_build": {"train_test_exact_text_overlap": 0, "train_val_exact_text_overlap": 0},
  "limitations": "Exact-hash only. Pretraining-corpus contamination of the base model cannot be verified."
}
```

### 4.9 Predictions — `experiments/<exp_id>/predictions.jsonl`

| field | type | meaning |
|---|---|---|
| `cve_id` | str | |
| `gold` | str | |
| `raw_output` | str | decoded generated text (special tokens removed, prompt excluded) |
| `pred` | str or null | normalized predicted CWE (null when unparsable) |
| `valid_json` | bool | |
| `has_key` | bool | JSON object contained key `cwe_id` |
| `valid_label` | bool | `pred ∈ selected` |
| `exact_match` | bool | |
| `score` | float | 1.0 / 0.0 |
| `error_flags` | list[str] | subset of `["not_json","missing_key","multiple_cwe","bad_cwe_format","label_not_allowed","think_block_present","truncated_generation"]` |
| `is_kev` | bool | |
| `n_new_tokens` | int | generated token count |

### 4.10 Metrics — `experiments/<exp_id>/metrics.json` (copied to `reports/*_metrics.json`)

```json
{
  "experiment_id": "exp_001_baseline",
  "n": 0, "limit": null,
  "accuracy": 0.0,                 // exact_match / n  (invalid outputs count as wrong)
  "macro_f1": 0.0,                 // sklearn f1_score(average="macro", labels=selected, zero_division=0)
  "weighted_f1": 0.0,
  "invalid_rate": 0.0,             // (not valid_json or not has_key or not valid_label) / n
  "invalid_breakdown": {"not_json": 0, "missing_key": 0, "multiple_cwe": 0, "bad_cwe_format": 0, "label_not_allowed": 0},
  "accuracy_on_valid": 0.0,        // exact_match / n_valid
  "per_class": {"CWE-79": {"precision": 0, "recall": 0, "f1": 0, "support": 0}},
  "confusion_matrix": {"labels": ["...", "INVALID"], "matrix": [[0]]},   // rows = gold, cols = pred
  "slices": {"kev": {"n": 0, "accuracy": 0.0}, "non_kev": {"n": 0, "accuracy": 0.0}},
  "generation": {"max_new_tokens": 32, "do_sample": false, "batch_size": 8},
  "throughput": {"samples_per_second": 0.0, "wall_seconds": 0.0, "peak_vram_mib": 0}
}
```

### 4.11 Experiment metadata — `experiments/<exp_id>/metadata.json`

Every key from the brief §24: `experiment_id, git_commit, created_at, model_name, model_revision,
dataset_snapshot, dataset_manifest_sha256, train_count, val_count, test_count, class_distribution,
seed, learning_rate, epochs, batch_size, gradient_accumulation, max_seq_length, lora_rank, lora_alpha,
lora_dropout, target_modules, precision, quantization, gpu, cuda, pytorch, transformers, trl, peft,
python, prompt_template_sha256`. For the baseline, training keys are `null`. Produced by
`utils/meta.py: build_metadata(cfg, manifest)`.

### 4.12 Training log — `experiments/<exp_id>/train_log.jsonl`

One line per `trainer.state.log_history` entry (`step, epoch, loss, learning_rate, eval_loss, grad_norm`),
plus a final line `{"event": "end", "train_runtime_s", "train_samples_per_second", "peak_vram_mib", "total_steps"}`.

### 4.13 Failures — `reports/failures.jsonl`

| field | type | meaning |
|---|---|---|
| `cve_id` | str | |
| `description` | str | |
| `gold` | str | |
| `prediction` | str or null | SFT prediction |
| `base_prediction` | str or null | |
| `sft_raw_output` | str | |
| `base_raw_output` | str | |
| `transition` | str | `both_wrong` / `broken_by_sft` (base right → sft wrong) |
| `error_type` | str | `invalid_format`, `unknown_cwe`, `nearby_cwe_confusion`, `semantic_confusion` |
| `gold_is_long_tail` | bool | gold in the bottom third of selected labels by TRAIN frequency |
| `is_kev` | bool | |

`reports/failure_summary.json`:
```json
{
  "n_test": 0,
  "transitions": {"both_right": 0, "fixed_by_sft": 0, "broken_by_sft": 0, "both_wrong": 0},
  "error_type_counts": {"base": {"invalid_format": 0}, "sft": {"invalid_format": 0}},
  "per_class_delta": {"CWE-79": {"base_f1": 0, "sft_f1": 0, "delta": 0}},
  "top_confusions_sft": [{"gold": "CWE-79", "pred": "CWE-80", "count": 0}],
  "top_confusions_base": [],
  "long_tail": {"base_accuracy": 0, "sft_accuracy": 0, "n": 0}
}
```

---

## 5. Data modules

### 5.1 `data/ingest_nvd.py`

CLI: `python -m security_llm.data.ingest_nvd --config configs/data.yaml [--start YYYY-MM-DD --end YYYY-MM-DD] [--force]`

```
main():
  cfg = load_config; start, end = args or cfg (end null → date.today())
  windows = date_windows(start, end, window_days)      # [(s, e)], e = min(s + window_days - 1, end); next s = e + 1
  session = requests.Session(); headers = {"apiKey": key} if NVD_API_KEY else {}
  sleep = with_key / without_key
  for (s, e) in windows:
    dir = raw_dir / f"{s}_{e}"; mkdir
    start_index = 0; total = None; pages = 0
    loop:
      page_file = dir / f"page_{start_index:07d}.json"
      if page_file exists and not force: body = json.load(page_file)
      else:
        body = fetch_page(session, s, e, start_index)        # see below; sleeps after every network call
        atomic_write_json(page_file, body)
      total = body["totalResults"]; pages += 1
      start_index += body["resultsPerPage"]
      if start_index >= total or body["resultsPerPage"] == 0: break
    manifest.windows.append({pub_start: s, pub_end: e, total_results: total, pages, complete: True})
    log one line per window: "window s..e total=.. pages=.."
  write ingest_manifest.json (snapshot_date=end, api_key_used=bool)

fetch_page(session, s, e, start_index):
  params = {pubStartDate: f"{s}T00:00:00.000", pubEndDate: f"{e}T23:59:59.999",
            resultsPerPage: cfg, startIndex: start_index}
  for attempt in range(max_retries):
    r = session.get(base_url, params, headers, timeout=60)
    time.sleep(sleep)
    if r.status_code == 200: return r.json()
    if r.status_code in (403, 429, 503, 500, 502, 504): time.sleep(sleep * (2 ** attempt)); continue
    raise RuntimeError(status, r.text[:200])
  raise RuntimeError("max retries")
```
Edge cases: window with `totalResults == 0` writes one page file and `pages == 1`. Re-running is idempotent (page files reused). `--force` refetches.

### 5.2 `data/normalize.py`

CLI: `python -m security_llm.data.normalize --config configs/data.yaml` → `data/processed/normalized.jsonl`

```
normalize_record(cve: dict, cfg) -> dict | None      # cve = vulnerabilities[i]["cve"]
  cve_id = cve["id"]; if not CVE_RE.fullmatch(cve_id): return None
  desc = first d["value"].strip() for d in cve.get("descriptions", []) if d["lang"] == "en"  (else "")
  is_rejected = cve.get("vulnStatus") == "Rejected" or desc.startswith("** REJECT **")
  primary, secondary = [], []
  for w in cve.get("weaknesses", []):
     for d in w.get("description", []):
        if d["lang"] != "en": continue
        v = d["value"].strip()
        target = primary if w.get("type") == "Primary" else secondary
        target.append(v)
  placeholders = set(cfg.filter.placeholder_cwes)
  raw_all = primary + secondary
  cwe_all = sorted({v for v in raw_all if CWE_RE.fullmatch(v)})           # CWE_RE = ^CWE-\d+$
  placeholder_only = len(raw_all) > 0 and len(cwe_all) == 0 and all(v in placeholders for v in raw_all)
  label_status = "single" if len(cwe_all)==1 else "multi" if len(cwe_all)>1 else "placeholder_only" if placeholder_only else "none"
  return {... fields of §4.2 ..., cwe_primary: uniq(primary ∩ CWE_RE), cwe_secondary: uniq(secondary ∩ CWE_RE)}

main():
  iterate every data/raw/nvd/*/page_*.json (sorted), for each vulnerabilities[i].cve → normalize_record
  keep dict by cve_id (later file overwrites earlier); write normalized.jsonl sorted by (published, cve_id)
  print funnel counts
```

Note: NVD sometimes lists the same CWE as both Primary and Secondary (from CNA and NVD). Because
`cwe_all` is a set, that is still single-label. A CVE whose CNA says CWE-79 and NVD says CWE-80 is
multi-label and is excluded; count it in the funnel.

### 5.3 `data/stats.py`

CLI: `python -m security_llm.data.stats --config configs/data.yaml` → `reports/dataset_stats.json`

Computes the funnel from `normalized.jsonl`, per-year totals, TRAIN-period CWE frequency (single-label,
non-rejected, with English description), and — if `labels.json` and split files exist — coverage and
per-split distributions and description-length percentiles (numpy percentile on char lengths). Must be
runnable before the split exists (then only the funnel / frequency parts are filled).

### 5.4 `data/split.py`

CLI: `python -m security_llm.data.split --config configs/data.yaml` → `labels.json`, `{train,val,test}.jsonl`

```
assign_split(published: str, split_cfg, snapshot) -> str | None
  for name in (train, val, test): lo, hi = split_cfg[name]; hi = hi or snapshot
    if lo <= published <= hi: return name
  return None                                       # outside all ranges (e.g. before 2020) → dropped

select_labels(train_records, top_k, min_count) -> (selected, counts)
  counts = Counter(r.cwe_id for r in train_records)
  ranked = counts.most_common()
  selected = [c for c, n in ranked[:top_k] if n >= min_count]
  return selected, dict(counts)

main():
  eligible = [r for r in normalized if not r.is_rejected and r.description_en and r.label_status == "single"]
  for r in eligible: r.split = assign_split(...)
  train_all = [r for r in eligible if r.split == "train"]
  selected, counts = select_labels(train_all, cfg.labels.top_k, cfg.labels.min_train_samples_per_class)
  assert len(selected) >= 2
  for name in (train, val, test): write records with split == name and cwe_id in selected
  write labels.json (names from cwe_names.CWE_NAMES; missing name → raise, so the table must be extended)
```
Test-set information is never used to pick labels.

### 5.5 `data/dedup.py`

```
normalize_text(s) -> str: unicode NFKC → lowercase → collapse all whitespace runs to one space → strip
text_hash(s) -> str: sha256(normalize_text(s).encode()).hexdigest()
find_overlap(a: list[rec], b: list[rec], key) -> list[tuple[cve_id_a, cve_id_b]]   # key ∈ {cve_id, description_norm_hash}
  index = {r[key]: r.cve_id for r in b}; return [(r.cve_id, index[r[key]]) for r in a if r[key] in index]
drop_internal_duplicates(recs) -> (kept, n_dropped)     # sort by (published, cve_id); keep first per hash
```

### 5.6 `data/build_sft.py`

CLI: `python -m security_llm.data.build_sft --config configs/data.yaml` → `data/sft/*.jsonl`, manifest

```
main():
  labels = load labels.json; train, val, test = load split files
  if dedup.drop_train_exact_duplicates: train, n_dup = drop_internal_duplicates(train)
  if dedup.drop_train_overlap_with_eval:
      eval_hashes = {r.hash for r in val+test}; before=len(train); train=[r for r in train if r.hash not in eval_hashes]; n_ovl = before-len(train)
  rng = random.Random(seed)
  train = sample(train, sft.train_max_samples, sft.sampling, rng)     # natural: rng.sample; balanced [P2]: per-class cap then shuffle
  val   = sample(val, sft.val_max_samples, "natural", rng)
  test  = sample(test, sft.test_max_samples, "natural", rng)         # null → keep all, but still shuffled with rng for batching neutrality
  for split: rows = [to_sft_row(r, labels.selected, max_chars) for r in recs]; write_jsonl
  write manifest (§4.6) with sha256 of each output file
to_sft_row(r, selected, max_chars):
  desc = r.description_en[:max_chars]; truncated = len(r.description_en) > max_chars
  return {cve_id, cwe_id, published, description: desc, truncated, prompt: build_user_prompt(desc, selected),
          completion: json.dumps({"cwe_id": r.cwe_id}, separators=(",", ": ")), is_kev, split}
```
Completion string is exactly `{"cwe_id": "CWE-79"}` (one space after the colon, no trailing newline).

---

## 6. Prompt (`security_llm/prompt.py`)

The instruction is fixed for the whole project. The allowed-label list is part of the prompt so the
task is a closed-set classification for both Base and SFT (otherwise the base model would emit
arbitrary CWE IDs and the invalid-output rate would measure taxonomy coverage, not formatting).

```
PROMPT_TEMPLATE = (
  "Classify the vulnerability description into the most appropriate CWE ID.\n"
  "Choose exactly one CWE ID from this list:\n"
  "{label_lines}\n\n"
  "Return only JSON with key `cwe_id`, for example {{\"cwe_id\": \"CWE-79\"}}.\n\n"
  "Description: {description}"
)
label_lines = "\n".join(f"- {cwe}: {CWE_NAMES[cwe]}" for cwe in selected)   # order = labels.json order

build_user_prompt(description, selected) -> str
render_chat_prompt(tokenizer, user_text) -> str:
  tokenizer.apply_chat_template([{"role": "user", "content": user_text}], tokenize=False,
                                add_generation_prompt=True, enable_thinking=False)
prompt_template_sha256(selected) -> sha256(PROMPT_TEMPLATE + "\n" + "\n".join(selected))
```
`enable_thinking=False` is mandatory (Qwen3 template then appends an empty `<think>\n\n</think>\n\n`
block to the generation prompt). Training and evaluation both call `render_chat_prompt`, so the token
prefix is identical in both.

---

## 7. Evaluation modules

### 7.1 `eval/verifier.py`

```
CWE_TOKEN_RE = re.compile(r"CWE[\s_\-]*(\d{1,5})", re.IGNORECASE)
normalize_cwe(value) -> str | None
  if isinstance(value, int): return f"CWE-{value}"
  if not isinstance(value, str): return None
  s = value.strip()
  ms = CWE_TOKEN_RE.findall(s)
  if len(ms) == 1 and re.fullmatch(r"\s*CWE[\s_\-]*\d{1,5}\s*", s, re.I): return f"CWE-{int(ms[0])}"
  if re.fullmatch(r"\d{1,5}", s): return f"CWE-{int(s)}"
  return None                                       # multiple tokens, extra words, empty → None

extract_json(raw) -> (obj | None, flags)
  text = raw
  if "<think>" in text: flags += think_block_present; text = re.sub(r"<think>.*?</think>", "", text, flags=S)
  text = strip code fences (```json ... ``` or ``` ... ```), then strip()
  try json.loads(text) → obj
  except: m = first balanced-brace candidate via re.search(r"\{.*?\}", text, S); try json.loads(m.group(0)); else None
  return obj, flags

verify(raw_output, gold, allowed: set[str]) -> dict   # fields of §4.9 minus cve_id/gold/raw_output
  obj, flags = extract_json(raw_output)
  valid_json = isinstance(obj, dict)
  if not valid_json: flags += not_json; pred=None; has_key=False
  else:
    has_key = "cwe_id" in obj
    if not has_key: flags += missing_key; pred=None
    else:
      v = obj["cwe_id"]
      if isinstance(v, list): flags += multiple_cwe; pred=None
      else:
        pred = normalize_cwe(v)
        if pred is None: flags += (multiple_cwe if len(CWE_TOKEN_RE.findall(str(v))) > 1 else bad_cwe_format)
  valid_label = pred is not None and pred in allowed
  if pred is not None and not valid_label: flags += label_not_allowed
  exact = valid_label and pred == gold
  return {pred, valid_json, has_key, valid_label, exact_match: exact, score: 1.0 if exact else 0.0, error_flags: flags}
```
Test cases (tests/test_verifier.py) must cover at least: clean JSON; JSON inside ```json fence;
`<think>…</think>` prefix; `{"cwe_id": "cwe-79"}`; `{"cwe_id": 79}`; `{"cwe_id": "CWE-79, CWE-89"}` → invalid;
`{"cwe_id": ["CWE-79"]}` → invalid; `{"id": "CWE-79"}` → missing_key; plain text `CWE-79` → not_json;
valid CWE not in allowed → label_not_allowed; trailing text after JSON.

### 7.2 `eval/generate.py`

CLI: `python -m security_llm.eval.generate --config configs/eval.yaml [--override key=value ...]`

```
main():
  set_seed; tokenizer = AutoTokenizer(name, revision); tokenizer.padding_side = "left"
  model = AutoModelForCausalLM.from_pretrained(name, torch_dtype=float16, device_map={"": 0})
  if adapter_path: model = PeftModel.from_pretrained(model, adapter_path); model = model.merge_and_unload()  # merge for speed; record "merged": true
  model.eval(); rows = read_jsonl(data.file)[:limit]; allowed = set(labels.selected)
  eos_ids = [tokenizer.convert_tokens_to_ids("<|im_end|>"), tokenizer.eos_token_id]  (unique)
  torch.cuda.reset_peak_memory_stats(); t0 = time
  for batch in chunks(rows, batch_size):
     prompts = [render_chat_prompt(tokenizer, r.prompt) for r in batch]
     enc = tokenizer(prompts, return_tensors="pt", padding=True, add_special_tokens=False).to(cuda)
     with torch.no_grad(): out = model.generate(**enc, do_sample=False, max_new_tokens=N, eos_token_id=eos_ids, pad_token_id=tokenizer.pad_token_id)
     gen = out[:, enc.input_ids.shape[1]:]
     for r, g in zip(batch, gen):
        text = tokenizer.decode(g, skip_special_tokens=True)
        v = verify(text, r.cwe_id, allowed)
        n_new = count of non-pad tokens in g; if n_new >= N and not v.valid_json: v.error_flags += truncated_generation
        write {cve_id, gold: r.cwe_id, raw_output: text, **v, is_kev: r.is_kev, n_new_tokens: n_new}
  write predictions.jsonl; call metrics.compute → metrics.json (with throughput + peak_vram_mib); write metadata.json; copy metrics to reports/<baseline|sft>_metrics.json (name chosen by experiment_id prefix, via --report-name)
```
Prompt token length must be checked once: assert every rendered prompt ≤ `max_seq_length - max_new_tokens`
tokens; otherwise raise with the offending cve_id (build_sft's `max_description_chars` is the knob).

### 7.3 `eval/metrics.py`

```
compute(predictions: list[dict], selected: list[str]) -> dict   (§4.10)
  y_true = [p.gold]; y_pred = [p.pred if p.valid_label else "INVALID"]
  accuracy = mean(exact_match); invalid_rate = mean(not valid_label)
  macro_f1 = f1_score(y_true, y_pred, labels=selected, average="macro", zero_division=0)
  per_class from precision_recall_fscore_support(labels=selected)
  confusion_matrix(labels = selected + ["INVALID"])
  slices by is_kev
```
Invalid outputs are therefore counted as wrong predictions for accuracy and as false negatives for
the gold class in macro F1 (never as a false positive for any real class).

### 7.4 `eval/contamination.py`

CLI writes `reports/contamination.json` (§4.8) from split files (pre-sampling) and from `data/sft/*.jsonl`
(post-build). Uses `dedup.find_overlap` on `cve_id` and `description_norm_hash` (recomputed with
`text_hash(description)` for sft rows).

### 7.5 `eval/failure_analysis.py`

CLI: `--base experiments/exp_001_baseline/predictions.jsonl --sft experiments/exp_002_sft_v1/predictions.jsonl --test data/sft/test.jsonl --labels data/processed/labels.json`

```
CWE_FAMILIES = {
  "injection": {"CWE-79","CWE-80","CWE-89","CWE-77","CWE-78","CWE-94","CWE-91","CWE-74","CWE-116","CWE-1336"},
  "memory": {"CWE-119","CWE-120","CWE-121","CWE-122","CWE-125","CWE-787","CWE-416","CWE-415","CWE-476","CWE-190","CWE-191","CWE-401","CWE-786","CWE-788"},
  "access_control": {"CWE-284","CWE-285","CWE-287","CWE-306","CWE-862","CWE-863","CWE-269","CWE-266","CWE-639","CWE-732","CWE-276"},
  "input_validation": {"CWE-20","CWE-1284","CWE-129"},
  "path": {"CWE-22","CWE-23","CWE-36","CWE-73"},
  "info_exposure": {"CWE-200","CWE-209","CWE-532","CWE-312","CWE-319"},
  "request_forgery": {"CWE-352","CWE-918"},
  "crypto": {"CWE-327","CWE-326","CWE-330","CWE-338","CWE-295","CWE-347"},
  "file_upload": {"CWE-434","CWE-494"},
  "xml": {"CWE-611","CWE-776"},
  "deserialization": {"CWE-502"},
  "race": {"CWE-362","CWE-367"},
  "resource": {"CWE-400","CWE-770","CWE-772","CWE-835","CWE-834"},
  "credentials": {"CWE-798","CWE-522","CWE-521","CWE-256","CWE-259"},
  "redirect": {"CWE-601"},
  "ssti_expression": {"CWE-1321","CWE-917"},
}
family(cwe) -> name | None

error_type(pred_row, gold, families, allowed):
  if not pred_row.valid_json or not pred_row.has_key: return "invalid_format"
  if pred_row.pred is None or pred_row.pred not in allowed: return "unknown_cwe"
  if pred_row.exact_match: return None
  if family(pred) is not None and family(pred) == family(gold): return "nearby_cwe_confusion"
  return "semantic_confusion"

main():
  join base/sft by cve_id (assert same set of ids and same gold); test rows give description/is_kev
  long_tail = bottom third of selected by train_counts (labels.json)
  for each id: transition by (base.exact_match, sft.exact_match)
  failures = rows where sft.exact_match is False, sorted by transition (broken_by_sft first) then cve_id
  write reports/failures.jsonl (all SFT failures; at least 30 must exist or the script warns)
  write failure_summary.json (§4.13): per_class_delta from the two metrics.json files; top confusions = Counter((gold,pred)) most_common(15) excluding correct
```

---

## 8. Training module — `train/sft.py`

CLI: `python -m security_llm.train.sft --config configs/sft.yaml [--override ...]`

```
main():
  cfg; set_seed; out_dir = experiments/<experiment_id>; mkdir; save resolved config → out_dir/config_resolved.yaml
  tokenizer = AutoTokenizer(name); tokenizer.padding_side = "right"
  if quantization.load_in_4bit:
      bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=float16)
      model = AutoModelForCausalLM.from_pretrained(name, quantization_config=bnb, device_map={"": 0}); model = prepare_model_for_kbit_training(model)
  else:
      model = AutoModelForCausalLM.from_pretrained(name, torch_dtype=float16, device_map={"": 0})
  model.config.use_cache = False
  lora = LoraConfig(r, lora_alpha, lora_dropout, target_modules, bias, task_type="CAUSAL_LM")
  ds = load train/val jsonl → map: {"prompt": render_chat_prompt(tokenizer, row.prompt), "completion": row.completion + "<|im_end|>"}   # keep only these two columns
  args = SFTConfig(output_dir=out_dir/"trainer", num_train_epochs, learning_rate, lr_scheduler_type, warmup_ratio,
                   per_device_train_batch_size, gradient_accumulation_steps, fp16, bf16, gradient_checkpointing,
                   logging_steps, eval_strategy, save_strategy, weight_decay, max_grad_norm, seed,
                   max_length=max_seq_length, completion_only_loss=True, report_to=[], dataloader_num_workers=2,
                   remove_unused_columns=True)
  trainer = SFTTrainer(model=model, args=args, train_dataset=ds_train, eval_dataset=ds_val, processing_class=tokenizer, peft_config=lora)
  # fp16 guard: after PEFT wrapping, cast trainable params to fp32 (LoRA weights) so GradScaler can unscale
  for p in trainer.model.parameters(): if p.requires_grad and p.dtype == float16: p.data = p.data.float()
  print trainable parameter count (trainer.model.print_trainable_parameters()) → also saved in metadata
  sanity check (once, before training): take one batch from trainer.get_train_dataloader();
     assert (labels == -100) on every prompt position and labels != -100 on completion tokens; log the counts
  trainer.train(); trainer.model.save_pretrained(out_dir/"adapter"); tokenizer.save_pretrained(out_dir/"adapter")
  write train_log.jsonl from trainer.state.log_history + end event (peak_vram_mib from torch.cuda.max_memory_allocated)
  write metadata.json (§4.11) including manifest sha256 and trainable_params
```
If `SFTConfig`/`SFTTrainer` argument names differ in the installed TRL version, adapt and record the
installed version in `requirements.txt` and `EXPERIMENT.md`. The completion-mask check must stay.

`tests/test_completion_mask.py` builds a 4-row dataset, constructs the trainer exactly as above on CPU
with a tiny `max_steps`, and asserts the mask property on one collated batch. Skipped when the
tokenizer cannot be loaded (offline).

---

## 9. Scripts

All scripts: `set -euo pipefail`, `cd "$(dirname "$0")/.."`, `source .venv/bin/activate`, log to `logs/<name>_<timestamp>.log` via `tee`.

| script | steps |
|---|---|
| `prepare_data.sh` | ingest_nvd → normalize → stats → split → stats (again, now with splits) → build_sft → contamination |
| `eval_base.sh [--limit N]` | generate with `experiment_id=exp_001_baseline adapter_path=null`, report name `baseline_metrics.json` |
| `train_sft.sh` | refuses to run unless `reports/baseline_metrics.json` exists; then `train.sft` |
| `eval_sft.sh` | generate with `experiment_id=exp_002_sft_v1 adapter_path=experiments/exp_002_sft_v1/adapter`, report `sft_metrics.json` |
| `build_report.sh` | failure_analysis → reports/failures.jsonl, failure_summary.json; prints the Base/SFT/Delta table to stdout and to `reports/comparison.md` |

---

## 10. Tests (pytest, run with `.venv/bin/pytest -q`)

| file | what it asserts |
|---|---|
| `test_schema.py` | `normalize_record` on the fixture: English description picked, placeholders → `placeholder_only`, Primary+Secondary same CWE → single, two different CWEs → multi, rejected flag, KEV fields, invalid CVE id → None |
| `test_split.py` | boundary dates (2024-12-31 → train, 2025-01-01 → val, 2026-01-01 → test, 2019-12-31 → None); `select_labels` ignores anything not in the train list and applies min_count |
| `test_dedup.py` | `normalize_text` equivalences (case, NFKC, whitespace); `find_overlap` on both keys; `drop_internal_duplicates` keeps the earliest |
| `test_verifier.py` | cases listed in §7.1 |
| `test_metrics.py` | 6 synthetic predictions with one invalid → accuracy, invalid_rate, macro_f1 hand-computed |
| `test_completion_mask.py` | §8 mask property (skipped offline) |

---

## 11. Experiment protocol

| Phase | Command | Output that must exist before moving on |
|---|---|---|
| 1 | `scripts/setup_env.sh`, `pytest` | all tests green (mask test may skip offline) |
| 2 | `ingest_nvd --start 2026-09-01 --end 2026-09-10` smoke | raw pages, then full `prepare_data.sh` |
| 3 | `stats` | `reports/dataset_stats.json`; decide `top_k` (log the reasoning in `EXPERIMENT.md`) |
| 4 | `split`, `build_sft`, `contamination` | `data/sft/*.jsonl`, manifest, contamination.json |
| 5 | `eval_base.sh --limit 64` then full | `reports/baseline_metrics.json` |
| 6 | `train_sft.sh` | `experiments/exp_002_sft_v1/adapter`, `train_log.jsonl` |
| 7 | `eval_sft.sh` | `reports/sft_metrics.json` |
| 8 | `build_report.sh` | `reports/failures.jsonl`, `failure_summary.json`, `comparison.md` |
| 9 | (already produced in 4/5) | verifier + contamination reviewed in `EXPERIMENT.md` |
| 10 | write README / cards | real numbers only |

`reports/EXPERIMENT.md` is an append-only log: one section per experiment id with date, git commit,
config diff vs previous, hardware, wall time, headline metrics, and observations. Failed or aborted
runs get a section too.

---

## 12. Git hygiene

`.gitignore` must contain: `data/` (except `data/README.md`), `experiments/*/adapter/`,
`experiments/*/trainer/`, `logs/`, `.venv/`, `__pycache__/`, `*.pyc`, `.pytest_cache/`, `*.gguf`, `*.safetensors`, `*.bin`.
`predictions.jsonl`, `metrics.json`, `metadata.json`, `train_log.jsonl`, `config_resolved.yaml` **are committed**
(they are the evidence). Commit messages: `T-XXX: summary`.

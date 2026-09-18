#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate
mkdir -p logs reports
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
{
  python -m security_llm.eval.failure_analysis \
    --base experiments/exp_001_baseline/predictions.jsonl \
    --sft experiments/exp_002_sft_v1/predictions.jsonl \
    --test data/sft/test.jsonl --labels data/processed/labels.json
  python - <<'PY'
import json
from pathlib import Path
b = json.loads(Path("reports/baseline_metrics.json").read_text())
s = json.loads(Path("reports/sft_metrics.json").read_text())
f = json.loads(Path("reports/failure_summary.json").read_text())
lines = ["# Base vs SFT comparison", "", "## Headline metrics", "", "| Metric | Base | SFT | Delta |", "|---|---:|---:|---:|"]
for key in ("accuracy", "macro_f1", "weighted_f1", "invalid_rate"):
    lines.append(f"| {key} | {b[key]:.4f} | {s[key]:.4f} | {s[key]-b[key]:+.4f} |")
lines += ["", "## Transitions", "", "| Transition | Count |", "|---|---:|"]
for key, value in f["transitions"].items():
    lines.append(f"| {key} | {value:,} |")
lines += ["", "## Tracked confusions", "", "| Pair | Base | SFT | Delta |", "|---|---:|---:|---:|"]
for key, value in f["tracked_confusions"].items():
    lines.append(f"| {key} | {value['base']:,} | {value['sft']:,} | {value['sft']-value['base']:+,} |")
lines += ["", "## Prediction concentration", "", "| Model | Top-3 predicted classes | Share |", "|---|---|---:|"]
for name in ("base", "sft"):
    values = f["prediction_distribution_concentration"][name]
    labels = ", ".join(f"{row['pred']} ({row['count']:,})" for row in values["top_3"])
    lines.append(f"| {name} | {labels} | {values['top_3_share']:.4f} |")
lines += ["", "## Accuracy slices", "", "Longer-description and longer-token buckets are reported as co-occurring slices; these comparisons do not establish causation.", ""]
for bucket_key, title in (("token_length_buckets", "Token length"), ("description_length_buckets", "Description characters")):
    lines += [f"### {title}", "", "| Bucket | Base | SFT | Delta |", "|---|---:|---:|---:|"]
    for bucket, base_values in f["slices"]["base"][bucket_key].items():
        sft_values = f["slices"]["sft"][bucket_key][bucket]
        lines.append(f"| {bucket} | {base_values['accuracy']:.4f} | {sft_values['accuracy']:.4f} | {sft_values['accuracy']-base_values['accuracy']:+.4f} |")
    lines.append("")
lines += ["### KEV", "", "| Slice | Base | SFT | Delta |", "|---|---:|---:|---:|"]
for key in ("kev", "non_kev"):
    bv, sv = f["slices"]["base"]["kev"][key], f["slices"]["sft"]["kev"][key]
    lines.append(f"| {key} (n={bv['n']:,}) | {bv['accuracy']:.4f} | {sv['accuracy']:.4f} | {sv['accuracy']-bv['accuracy']:+.4f} |")
lines += ["", "## Per-class metrics", "", "| CWE | Base P | SFT P | ΔP | Base R | SFT R | ΔR | Base F1 | SFT F1 | ΔF1 |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
for cwe, values in f["per_class"].items():
    lines.append(
        f"| {cwe} | {values['base']['precision']:.4f} | {values['sft']['precision']:.4f} | {values['delta']['precision']:+.4f} | "
        f"{values['base']['recall']:.4f} | {values['sft']['recall']:.4f} | {values['delta']['recall']:+.4f} | "
        f"{values['base']['f1']:.4f} | {values['sft']['f1']:.4f} | {values['delta']['f1']:+.4f} |"
    )
text = "\n".join(lines) + "\n"
Path("reports/comparison.md").write_text(text, encoding="utf-8")
print(text, end="")
PY
} 2>&1 | tee "logs/build_report_${timestamp}.log"

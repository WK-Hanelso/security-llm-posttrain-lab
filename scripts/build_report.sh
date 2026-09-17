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
lines = ["| Metric | Base | SFT | Delta |", "|---|---:|---:|---:|"]
for key in ("accuracy", "macro_f1", "weighted_f1", "invalid_rate"):
    lines.append(f"| {key} | {b[key]:.4f} | {s[key]:.4f} | {s[key]-b[key]:+.4f} |")
text = "\n".join(lines) + "\n"
Path("reports/comparison.md").write_text(text, encoding="utf-8")
print(text, end="")
PY
} 2>&1 | tee "logs/build_report_${timestamp}.log"


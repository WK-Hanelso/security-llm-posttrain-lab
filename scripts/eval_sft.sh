#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate
mkdir -p logs
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
python -m security_llm.eval.generate --config configs/eval.yaml \
  --override experiment_id=exp_002_sft_v1 \
  --override model.adapter_path=experiments/exp_002_sft_v1/adapter \
  --report-name sft_metrics.json 2>&1 | tee "logs/eval_sft_${timestamp}.log"


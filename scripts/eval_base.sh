#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate
mkdir -p logs
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
extra=()
if [[ "${1:-}" == "--limit" ]]; then extra+=(--override "data.limit=$2"); fi
python -m security_llm.eval.generate --config configs/eval.yaml \
  --override experiment_id=exp_001_baseline --override model.adapter_path=null \
  --report-name baseline_metrics.json "${extra[@]}" 2>&1 | tee "logs/eval_base_${timestamp}.log"


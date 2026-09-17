#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate
mkdir -p logs
[[ -f reports/baseline_metrics.json ]] || { echo "Baseline metrics must exist before training" >&2; exit 1; }
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
python -m security_llm.train.sft --config configs/sft.yaml 2>&1 | tee "logs/train_sft_${timestamp}.log"


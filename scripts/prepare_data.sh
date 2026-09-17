#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate
mkdir -p logs
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
exec > >(tee "logs/prepare_data_${timestamp}.log") 2>&1

run_step() {
  local name="$1"
  shift
  echo "=== STEP ${name} START ==="
  "$@"
  echo "=== STEP ${name} END ==="
}

run_step ingest python -m security_llm.data.ingest_nvd --config configs/data.yaml
run_step normalize python -m security_llm.data.normalize --config configs/data.yaml
run_step stats_pre_split python -m security_llm.data.stats --config configs/data.yaml
run_step split python -m security_llm.data.split --config configs/data.yaml
run_step stats_post_split python -m security_llm.data.stats --config configs/data.yaml
run_step build_sft python -m security_llm.data.build_sft --config configs/data.yaml
run_step contamination python -m security_llm.eval.contamination --config configs/data.yaml
echo "=== PREPARE_DATA DONE ==="


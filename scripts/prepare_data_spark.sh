#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source .venv-dist/bin/activate
export SPARK_LOCAL_IP=127.0.0.1
export PYTHONPATH="$PWD/src${PYTHONPATH:+:$PYTHONPATH}"
mkdir -p logs reports/distributed
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
exec > >(tee "logs/prepare_data_spark_${timestamp}.log") 2>&1

echo "=== STEP spark_track_a START ==="
python -m security_llm.spark.pipeline --config configs/data.yaml --master 'local[8]'
echo "=== STEP spark_track_a END ==="
echo "=== STEP equivalence START ==="
python -m security_llm.spark.equivalence --master 'local[8]'
echo "=== STEP equivalence END ==="
echo "=== PREPARE_DATA_SPARK DONE ==="

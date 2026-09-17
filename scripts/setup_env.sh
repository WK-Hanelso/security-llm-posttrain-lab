#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export UV_CACHE_DIR="${UV_CACHE_DIR:-$PWD/.uv-cache}"
mkdir -p logs
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
exec > >(tee "logs/setup_env_${timestamp}.log") 2>&1

if [[ ! -x .venv/bin/python ]]; then
  uv venv .venv --python 3.11
fi
source .venv/bin/activate
uv pip install --python .venv/bin/python torch --index-url https://download.pytorch.org/whl/cu121
uv pip install --python .venv/bin/python -r requirements.txt -e .
.venv/bin/python -c 'import torch; print(torch.__version__, torch.cuda.is_available(), torch.cuda.get_device_name(0) if torch.cuda.is_available() else "no CUDA device")'

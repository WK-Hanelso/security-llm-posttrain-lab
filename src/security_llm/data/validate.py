"""Command-line validation for the canonical normalized dataset."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from security_llm.config import load_config
from security_llm.data.schema import validate_file


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--sample", type=int)
    parser.add_argument("--override", action="append", default=[])
    args = parser.parse_args()
    if args.sample is not None and args.sample < 1:
        parser.error("--sample must be a positive integer")
    cfg = load_config(args.config, args.override)
    path = Path(cfg["paths"]["processed_dir"]) / "normalized.jsonl"
    result = validate_file(path, args.sample)
    print(json.dumps({"path": str(path), **result}, ensure_ascii=False, indent=2))
    raise SystemExit(1 if result["invalid"] else 0)


if __name__ == "__main__":
    main()

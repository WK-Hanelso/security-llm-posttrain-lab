"""Configuration loading and command-line override support."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_config(path: str | Path, overrides: list[str] | None = None) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as handle:
        cfg = yaml.safe_load(handle) or {}
    if not isinstance(cfg, dict):
        raise ValueError(f"Configuration root must be a mapping: {path}")
    for override in overrides or []:
        if "=" not in override:
            raise ValueError(f"Override must have key=value form: {override}")
        dotted_key, raw_value = override.split("=", 1)
        keys = dotted_key.split(".")
        if any(not key for key in keys):
            raise ValueError(f"Invalid override key: {dotted_key}")
        target: dict[str, Any] = cfg
        for key in keys[:-1]:
            value = target.get(key)
            if value is None:
                value = {}
                target[key] = value
            if not isinstance(value, dict):
                raise ValueError(f"Cannot set nested key below non-mapping: {dotted_key}")
            target = value
        target[keys[-1]] = yaml.safe_load(raw_value)
    return cfg


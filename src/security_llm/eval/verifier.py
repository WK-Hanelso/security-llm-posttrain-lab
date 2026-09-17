"""Deterministic parsing and verification of generated CWE JSON."""

from __future__ import annotations

import json
import re
from typing import Any

CWE_TOKEN_RE = re.compile(r"CWE[\s_\-]*(\d{1,5})", re.IGNORECASE)


def normalize_cwe(value: Any) -> str | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return f"CWE-{value}"
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    matches = CWE_TOKEN_RE.findall(stripped)
    if len(matches) == 1 and re.fullmatch(r"\s*CWE[\s_\-]*\d{1,5}\s*", stripped, re.I):
        return f"CWE-{int(matches[0])}"
    if re.fullmatch(r"\d{1,5}", stripped):
        return f"CWE-{int(stripped)}"
    return None


def extract_json(raw: str) -> tuple[Any | None, list[str]]:
    text = raw
    flags: list[str] = []
    if "<think>" in text:
        flags.append("think_block_present")
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    text = text.strip()
    fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", text, flags=re.DOTALL | re.I)
    if fenced:
        text = fenced.group(1).strip()
    try:
        return json.loads(text), flags
    except (json.JSONDecodeError, TypeError):
        candidate = re.search(r"\{.*?\}", text, flags=re.DOTALL)
        if candidate:
            try:
                return json.loads(candidate.group(0)), flags
            except json.JSONDecodeError:
                pass
    return None, flags


def verify(raw_output: str, gold: str, allowed: set[str]) -> dict[str, Any]:
    obj, flags = extract_json(raw_output)
    valid_json = isinstance(obj, dict)
    has_key = False
    pred: str | None = None
    if not valid_json:
        flags.append("not_json")
    else:
        has_key = "cwe_id" in obj
        if not has_key:
            flags.append("missing_key")
        else:
            value = obj["cwe_id"]
            if isinstance(value, list):
                flags.append("multiple_cwe")
            else:
                pred = normalize_cwe(value)
                if pred is None:
                    flag = "multiple_cwe" if len(CWE_TOKEN_RE.findall(str(value))) > 1 else "bad_cwe_format"
                    flags.append(flag)
    valid_label = pred is not None and pred in allowed
    if pred is not None and not valid_label:
        flags.append("label_not_allowed")
    exact = valid_label and pred == gold
    return {
        "pred": pred,
        "valid_json": valid_json,
        "has_key": has_key,
        "valid_label": valid_label,
        "exact_match": exact,
        "score": 1.0 if exact else 0.0,
        "error_flags": list(dict.fromkeys(flags)),
    }


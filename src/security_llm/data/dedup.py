"""Exact normalized-text deduplication."""

from __future__ import annotations

import hashlib
import re
import unicodedata
from typing import Any


def normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKC", value).lower()).strip()


def text_hash(value: str) -> str:
    return hashlib.sha256(normalize_text(value).encode("utf-8")).hexdigest()


def find_overlap(
    a: list[dict[str, Any]], b: list[dict[str, Any]], key: str
) -> list[tuple[str, str]]:
    if key not in {"cve_id", "description_norm_hash"}:
        raise ValueError(f"Unsupported overlap key: {key}")
    index = {row[key]: row["cve_id"] for row in b}
    return [(row["cve_id"], index[row[key]]) for row in a if row[key] in index]


def drop_internal_duplicates(
    records: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    kept: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in sorted(records, key=lambda item: (item["published"], item["cve_id"])):
        digest = row["description_norm_hash"]
        if digest in seen:
            continue
        seen.add(digest)
        kept.append(row)
    return kept, len(records) - len(kept)


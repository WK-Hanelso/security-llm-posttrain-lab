"""Typed canonical security record and validation helpers."""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

from security_llm.data.dedup import text_hash

SCHEMA_VERSION = "1.0"

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
CWE_RE = re.compile(r"^CWE-\d+$")
LABEL_STATUSES = {"single", "multi", "placeholder_only", "none"}


@dataclass(frozen=True)
class CanonicalRecord:
    """The model-independent record written to ``normalized.jsonl``."""

    cve_id: str
    published: str
    last_modified: str
    vuln_status: str
    description_en: str
    description_norm_hash: str
    cwe_primary: list[str]
    cwe_secondary: list[str]
    cwe_all: list[str]
    placeholder_only: bool
    cwe_id: str | None
    label_status: str
    cvss_v31_base_score: float | None
    cvss_v31_severity: str | None
    is_kev: bool
    kev_date_added: str | None
    is_rejected: bool


REQUIRED = [field.name for field in CanonicalRecord.__dataclass_fields__.values()]


def _is_iso_date(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 10:
        return False
    try:
        return date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def _is_iso_date_or_datetime(value: object) -> bool:
    if not isinstance(value, str):
        return False
    if _is_iso_date(value):
        return True
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _validate_cwe_list(name: str, value: object, problems: list[str]) -> bool:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        problems.append(f"invalid_type:{name}")
        return False
    if any(CWE_RE.fullmatch(item) is None for item in value):
        problems.append(f"invalid_cwe:{name}")
    return True


def validate_record(record: dict[str, Any]) -> list[str]:
    """Return validation problems for one canonical record."""

    problems: list[str] = []
    for field_name in REQUIRED:
        if field_name not in record:
            problems.append(f"missing_field:{field_name}")

    cve_id = record.get("cve_id")
    if not isinstance(cve_id, str) or CVE_RE.fullmatch(cve_id) is None:
        problems.append("invalid_cve_id")
    if not _is_iso_date(record.get("published")):
        problems.append("invalid_published")
    if not _is_iso_date_or_datetime(record.get("last_modified")):
        problems.append("invalid_last_modified")

    for field_name in ("vuln_status", "description_en", "description_norm_hash", "label_status"):
        if not isinstance(record.get(field_name), str):
            problems.append(f"invalid_type:{field_name}")
    for field_name in ("placeholder_only", "is_kev", "is_rejected"):
        if not isinstance(record.get(field_name), bool):
            problems.append(f"invalid_type:{field_name}")
    score = record.get("cvss_v31_base_score")
    if score is not None and (isinstance(score, bool) or not isinstance(score, (int, float))):
        problems.append("invalid_type:cvss_v31_base_score")
    severity = record.get("cvss_v31_severity")
    if severity is not None and not isinstance(severity, str):
        problems.append("invalid_type:cvss_v31_severity")
    kev_date = record.get("kev_date_added")
    if kev_date is not None and not isinstance(kev_date, str):
        problems.append("invalid_type:kev_date_added")

    _validate_cwe_list("cwe_primary", record.get("cwe_primary"), problems)
    _validate_cwe_list("cwe_secondary", record.get("cwe_secondary"), problems)
    cwe_all_valid = _validate_cwe_list("cwe_all", record.get("cwe_all"), problems)
    cwe_all = record.get("cwe_all") if cwe_all_valid else []
    if cwe_all_valid and cwe_all != sorted(set(cwe_all)):
        problems.append("cwe_all_not_sorted_unique")

    cwe_id = record.get("cwe_id")
    expected_cwe_id = cwe_all[0] if len(cwe_all) == 1 else None
    if cwe_id != expected_cwe_id:
        problems.append("inconsistent_cwe_id")

    placeholder_only = record.get("placeholder_only")
    status = record.get("label_status")
    if status not in LABEL_STATUSES:
        problems.append("invalid_label_status")
    elif cwe_all_valid and isinstance(placeholder_only, bool):
        expected_status = (
            "single"
            if len(cwe_all) == 1
            else "multi"
            if len(cwe_all) > 1
            else "placeholder_only"
            if placeholder_only
            else "none"
        )
        if status != expected_status:
            problems.append("inconsistent_label_status")
        if cwe_all and placeholder_only:
            problems.append("inconsistent_placeholder_only")

    description = record.get("description_en")
    digest = record.get("description_norm_hash")
    if isinstance(description, str) and isinstance(digest, str) and digest != text_hash(description):
        problems.append("description_norm_hash_mismatch")
    if isinstance(record.get("is_kev"), bool) and record["is_kev"] != (kev_date is not None):
        problems.append("inconsistent_is_kev")
    return problems


def validate_file(path: str | Path, sample: int | None = None) -> dict[str, Any]:
    """Validate up to ``sample`` JSONL records, or the entire file when unset."""

    rows = 0
    invalid = 0
    problem_counts: Counter[str] = Counter()
    examples: list[dict[str, Any]] = []
    with Path(path).open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            if sample is not None and rows >= sample:
                break
            rows += 1
            try:
                value = json.loads(line)
                if not isinstance(value, dict):
                    problems = ["record_not_object"]
                    value = {}
                else:
                    problems = validate_record(value)
            except json.JSONDecodeError:
                value = {}
                problems = ["invalid_json"]
            if not problems:
                continue
            invalid += 1
            problem_counts.update(problem.split(":", 1)[0] for problem in problems)
            if len(examples) < 20:
                examples.append(
                    {"line": line_number, "cve_id": value.get("cve_id"), "problems": problems}
                )
    return {
        "rows": rows,
        "invalid": invalid,
        "problems_by_type": dict(sorted(problem_counts.items())),
        "examples": examples,
    }

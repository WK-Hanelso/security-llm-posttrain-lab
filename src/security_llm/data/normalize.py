"""Normalize cached NVD API responses into the project schema."""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from pathlib import Path
from typing import Any

from security_llm.config import load_config
from security_llm.data.dedup import text_hash
from security_llm.utils.io import read_jsonl, write_jsonl

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
CWE_RE = re.compile(r"^CWE-\d+$")
LOG = logging.getLogger(__name__)


def _unique_cwes(values: list[str]) -> list[str]:
    return sorted({value for value in values if CWE_RE.fullmatch(value)})


def normalize_record(cve: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any] | None:
    cve_id = str(cve.get("id", ""))
    if not CVE_RE.fullmatch(cve_id):
        return None
    description = next(
        (
            str(item.get("value", "")).strip()
            for item in cve.get("descriptions", [])
            if item.get("lang") == "en"
        ),
        "",
    )
    is_rejected = cve.get("vulnStatus") == "Rejected" or description.startswith("** REJECT **")
    primary_raw: list[str] = []
    secondary_raw: list[str] = []
    for weakness in cve.get("weaknesses", []):
        target = primary_raw if weakness.get("type") == "Primary" else secondary_raw
        for item in weakness.get("description", []):
            if item.get("lang") == "en":
                target.append(str(item.get("value", "")).strip())
    raw_all = primary_raw + secondary_raw
    cwe_primary = _unique_cwes(primary_raw)
    cwe_secondary = _unique_cwes(secondary_raw)
    cwe_all = sorted(set(cwe_primary + cwe_secondary))
    placeholders = set(cfg["filter"]["placeholder_cwes"])
    placeholder_only = bool(raw_all) and not cwe_all and all(v in placeholders for v in raw_all)
    if len(cwe_all) == 1:
        label_status = "single"
    elif len(cwe_all) > 1:
        label_status = "multi"
    elif placeholder_only:
        label_status = "placeholder_only"
    else:
        label_status = "none"
    cvss_items = cve.get("metrics", {}).get("cvssMetricV31", [])
    cvss_data = cvss_items[0].get("cvssData", {}) if cvss_items else {}
    kev_date = cve.get("cisaExploitAdd")
    return {
        "cve_id": cve_id,
        "published": str(cve.get("published", ""))[:10],
        "last_modified": str(cve.get("lastModified", "")),
        "vuln_status": str(cve.get("vulnStatus", "")),
        "description_en": description,
        "description_norm_hash": text_hash(description),
        "cwe_primary": cwe_primary,
        "cwe_secondary": cwe_secondary,
        "cwe_all": cwe_all,
        "placeholder_only": placeholder_only,
        "cwe_id": cwe_all[0] if len(cwe_all) == 1 else None,
        "label_status": label_status,
        "cvss_v31_base_score": cvss_data.get("baseScore"),
        "cvss_v31_severity": cvss_data.get("baseSeverity"),
        "is_kev": kev_date is not None,
        "kev_date_added": kev_date,
        "is_rejected": is_rejected,
    }


def normalize(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    raw_dir = Path(cfg["nvd"]["raw_dir"])
    manifest_file = raw_dir / "ingest_manifest.json"
    with manifest_file.open(encoding="utf-8") as handle:
        manifest = json.load(handle)
    records: dict[str, dict[str, Any]] = {}
    raw_count = 0
    for window in manifest["windows"]:
        if not window.get("complete"):
            continue
        window_dir = raw_dir / f"{window['pub_start']}_{window['pub_end']}"
        for page_file in sorted(window_dir.glob("page_*.json")):
            with page_file.open(encoding="utf-8") as handle:
                page = json.load(handle)
            for vulnerability in page.get("vulnerabilities", []):
                raw_count += 1
                row = normalize_record(vulnerability.get("cve", {}), cfg)
                if row is not None:
                    records[row["cve_id"]] = row
    rows = sorted(records.values(), key=lambda row: (row["published"], row["cve_id"]))
    output = Path(cfg["paths"]["processed_dir"]) / "normalized.jsonl"
    write_jsonl(output, rows)
    funnel = {
        "raw_cves": raw_count,
        "unique_cves": len(rows),
        "rejected": sum(row["is_rejected"] for row in rows),
        "no_english_description": sum(not row["description_en"] for row in rows),
        "no_weakness": sum(row["label_status"] == "none" for row in rows),
        "placeholder_only": sum(row["label_status"] == "placeholder_only" for row in rows),
        "multi_label": sum(row["label_status"] == "multi" for row in rows),
        "single_label": sum(row["label_status"] == "single" for row in rows),
    }
    LOG.info("funnel %s", json.dumps(funnel, sort_keys=True))
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--override", action="append", default=[])
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)
    normalize(load_config(args.config, args.override))


if __name__ == "__main__":
    main()

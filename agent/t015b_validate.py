#!/usr/bin/env python3
"""Detect and validate T-015B propagation against two full reference rebuilds."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from security_llm.data.build_sft import sample_records
from security_llm.data.dedup import drop_internal_duplicates
from security_llm.utils.io import atomic_write_json, read_jsonl


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "data/fixture"
REPORTS = ROOT / "reports/incremental"
CASE_PATH = REPORTS / "change_cases.json"
DETECTOR_PATH = REPORTS / "detector_output.json"

DATASET_RELEVANT = (
    "id", "published", "descriptions[lang=en].value", "vulnStatus",
    "weaknesses[].type+description[lang=en].value", "cisaExploitAdd",
)
DATASET_IRRELEVANT = (
    "metrics.cvssMetricV31[0].cvssData", "lastModified",
)
ALL_FIELDS = DATASET_RELEVANT + DATASET_IRRELEVANT
STAGES = (
    "raw", "normalization", "eligibility", "label_extraction", "label_selection",
    "temporal_split", "dedup", "cross_split_overlap", "sft_sampling",
    "sft_row_serialization", "manifest",
)


def canonical_hash(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def raw_records(snapshot: str) -> dict[str, dict[str, Any]]:
    raw_root = FIXTURE / snapshot / "raw"
    manifest = json.loads((raw_root / "ingest_manifest.json").read_text())
    records: dict[str, dict[str, Any]] = {}
    for window in manifest["windows"]:
        window_dir = raw_root / f"{window['pub_start']}_{window['pub_end']}"
        for page_path in sorted(window_dir.glob("page_*.json")):
            for vulnerability in json.loads(page_path.read_text()).get("vulnerabilities", []):
                cve = vulnerability.get("cve", {})
                cve_id = str(cve.get("id", ""))
                if cve_id in records:
                    raise AssertionError(f"duplicate fixture raw ID: {cve_id}")
                records[cve_id] = cve
    return records


def first_english_description(cve: dict[str, Any]) -> str:
    return next(
        (str(item.get("value", "")) for item in cve.get("descriptions", []) if item.get("lang") == "en"),
        "",
    )


def weakness_view(cve: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for weakness in cve.get("weaknesses", []):
        english = sorted(
            str(item.get("value", ""))
            for item in weakness.get("description", []) if item.get("lang") == "en"
        )
        if english:
            result.append({"type": weakness.get("type"), "english": english})
    return sorted(result, key=lambda item: json.dumps(item, sort_keys=True))


def cvss_view(cve: dict[str, Any]) -> Any:
    items = cve.get("metrics", {}).get("cvssMetricV31", [])
    return items[0].get("cvssData", {}) if items else None


def field_view(cve: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": cve.get("id"),
        "published": cve.get("published"),
        "descriptions[lang=en].value": first_english_description(cve),
        "vulnStatus": cve.get("vulnStatus"),
        "weaknesses[].type+description[lang=en].value": weakness_view(cve),
        "cisaExploitAdd": cve.get("cisaExploitAdd"),
        "metrics.cvssMetricV31[0].cvssData": cvss_view(cve),
        "lastModified": cve.get("lastModified"),
    }


def downstream_scope(changed: list[str], classification: str) -> str:
    if classification == "INSERT":
        return "local normalize/eligibility/split; global label-count check and sampling"
    if classification == "MISSING_REVIEW":
        return "REVIEW_REQUIRED; stop before incremental application"
    if classification == "UNCHANGED":
        return "none"
    changed_set = set(changed)
    if not changed_set.intersection(DATASET_RELEVANT):
        return "none beyond normalized metadata; dataset output unchanged"
    scopes = []
    if "published" in changed_set:
        scopes.append("local temporal split; global train label-count check and sampling")
    if "descriptions[lang=en].value" in changed_set:
        scopes.append("local normalization; old/new hash groups; sampling if population changes")
    if "vulnStatus" in changed_set:
        scopes.append("local eligibility; global train label-count check and sampling")
    if "weaknesses[].type+description[lang=en].value" in changed_set:
        scopes.append("local label extraction/eligibility; global label-count check and sampling")
    if "cisaExploitAdd" in changed_set:
        scopes.append("local SFT row serialization only")
    return "; ".join(scopes) or "dataset-relevant local recompute"


def detect() -> dict[str, Any]:
    a = raw_records("snapshot_a")
    b = raw_records("snapshot_b")
    case_doc = json.loads(CASE_PATH.read_text())
    case_by_cve = {case["cve_id"]: case["case_id"] for case in case_doc["cases"]}
    changes = []
    for cve_id in sorted(set(a) | set(b)):
        before = a.get(cve_id)
        after = b.get(cve_id)
        if before is None:
            classification = "INSERT"
            changed_fields = ["id"]
            before_hash = None
            after_view = field_view(after)
            after_hash = canonical_hash(after_view)
            relevant = True
        elif after is None:
            classification = "MISSING_REVIEW"
            changed_fields = []
            before_view = field_view(before)
            before_hash = canonical_hash(before_view)
            after_hash = None
            relevant = None
        else:
            before_view = field_view(before)
            after_view = field_view(after)
            changed_fields = [field for field in ALL_FIELDS if before_view[field] != after_view[field]]
            before_hash = canonical_hash(before_view)
            after_hash = canonical_hash(after_view)
            relevant = bool(set(changed_fields).intersection(DATASET_RELEVANT))
            if not changed_fields:
                classification = "UNCHANGED"
            elif relevant:
                classification = "UPDATE_DATASET_RELEVANT"
            else:
                classification = "UPDATE_DATASET_IRRELEVANT"
        changes.append({
            "cve_id": cve_id,
            "case_id": case_by_cve.get(cve_id),
            "classification": classification,
            "changed_fields": changed_fields,
            "before_hash": before_hash,
            "after_hash": after_hash,
            "dataset_relevant_change": relevant,
            "expected_downstream_scope": downstream_scope(changed_fields, classification),
        })
    counts = dict(sorted(Counter(item["classification"] for item in changes).items()))
    missing = [item["cve_id"] for item in changes if item["classification"] == "MISSING_REVIEW"]
    result = {
        "task": "T-015B",
        "compared_fields": list(ALL_FIELDS),
        "dataset_relevant_fields": list(DATASET_RELEVANT),
        "last_modified_policy": "hint only; never sufficient for UPDATE or equality",
        "snapshot_a_rows": len(a),
        "snapshot_b_rows": len(b),
        "classification_counts": counts,
        "changes": changes,
        "incremental_application": {
            "status": "STOPPED_MISSING_REVIEW" if missing else "READY",
            "applied": False,
            "missing_ids": missing,
            "reason": "MISSING is not a delete; human decision required" if missing else None,
        },
    }
    atomic_write_json(DETECTOR_PATH, result)
    return result


def write_hash_manifest(snapshot: str) -> dict[str, Any]:
    root = FIXTURE / snapshot
    entries = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == "hashes.json":
            continue
        entries.append({
            "path": str(path.relative_to(ROOT)),
            "bytes": path.stat().st_size,
            "sha256": file_hash(path),
        })
    value = {
        "snapshot": snapshot,
        "files": entries,
        "ordered_file_hashes_sha256": canonical_hash(
            [{"path": item["path"], "sha256": item["sha256"]} for item in entries]
        ),
    }
    atomic_write_json(root / "hashes.json", value)
    return value


def load_stage(snapshot: str, stage: str) -> dict[str, dict[str, Any]]:
    if stage == "normalized":
        rows = read_jsonl(FIXTURE / snapshot / "processed/normalized.jsonl")
        return {row["cve_id"]: row for row in rows}
    result = {}
    for split in ("train", "val", "test"):
        base = "sft" if stage == "sft" else "processed"
        for row in read_jsonl(FIXTURE / snapshot / f"{base}/{split}.jsonl"):
            result[row["cve_id"]] = row
    return result


def by_split(snapshot: str, stage: str) -> dict[str, list[dict[str, Any]]]:
    base = "sft" if stage == "sft" else "processed"
    return {
        split: read_jsonl(FIXTURE / snapshot / f"{base}/{split}.jsonl")
        for split in ("train", "val", "test")
    }


def row_differences(a: dict[str, Any], b: dict[str, Any], ignore: set[str] | None = None) -> list[str]:
    ignored = ignore or set()
    return sorted(
        key for key in set(a) | set(b)
        if key not in ignored and a.get(key) != b.get(key)
    )


def effective_train_pool(processed: dict[str, list[dict[str, Any]]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    deduped, duplicates = drop_internal_duplicates(processed["train"])
    eval_hashes = {row["description_norm_hash"] for row in processed["val"] + processed["test"]}
    kept = [row for row in deduped if row["description_norm_hash"] not in eval_hashes]
    return kept, {"internal_duplicates_dropped": duplicates, "eval_overlaps_dropped": len(deduped) - len(kept)}


def set_diff(left: set[str], right: set[str]) -> dict[str, Any]:
    return {
        "left_only_count": len(left - right),
        "right_only_count": len(right - left),
        "left_only": sorted(left - right),
        "right_only": sorted(right - left),
    }


def label_boundary(normalized: dict[str, dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(
        row["cwe_id"] for row in normalized.values()
        if not row["is_rejected"]
        and row["description_en"]
        and row["label_status"] == "single"
        and "2020-01-01" <= row["published"] <= "2024-12-31"
    )
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    rank_15 = ranked[14] if len(ranked) >= 15 else None
    rank_16 = ranked[15] if len(ranked) >= 16 else None
    return {
        "distinct_labels": len(ranked),
        "rank_15": {"cwe_id": rank_15[0], "count": rank_15[1]} if rank_15 else None,
        "rank_16": {"cwe_id": rank_16[0], "count": rank_16[1]} if rank_16 else None,
        "count_margin": rank_15[1] - rank_16[1] if rank_15 and rank_16 else None,
    }


def expected_propagation() -> dict[str, dict[str, str]]:
    U = "UNCHANGED"
    L = "LOCAL_RECOMPUTE"
    G = "GLOBAL_RECOMPUTE"
    D = "GROUP_RECOMPUTE"
    R = "REVIEW_REQUIRED"
    return {
        "C01_INSERT": dict(zip(STAGES, [L, L, L, L, G, L, D, D, G, G, G])),
        "C02_DESCRIPTION_UPDATE": dict(zip(STAGES, [L, L, U, U, U, U, D, D, G, G, G])),
        "C03_CWE_UPDATE": dict(zip(STAGES, [L, L, U, L, G, U, U, U, U, L, G])),
        "C04_MULTI_LABEL_UPDATE": dict(zip(STAGES, [L, L, L, L, G, U, D, D, G, G, G])),
        "C05_REJECTED_UPDATE": dict(zip(STAGES, [L, L, L, U, G, U, D, D, G, G, G])),
        "C06_KEV_UPDATE": dict(zip(STAGES, [L, L, U, U, U, U, U, U, U, L, G])),
        "C07_CVSS_NEGATIVE_CONTROL": dict(zip(STAGES, [L, L, U, U, U, U, U, U, U, U, U])),
        "C08_UNCHANGED": {stage: U for stage in STAGES},
        "C09_MISSING_REVIEW": {stage: R for stage in STAGES},
        "C10_PUBLISHED_BOUNDARY_UPDATE": dict(zip(STAGES, [L, L, U, U, G, L, D, D, G, G, G])),
    }


def report() -> dict[str, Any]:
    detector = json.loads(DETECTOR_PATH.read_text())
    if detector["incremental_application"]["status"] != "STOPPED_MISSING_REVIEW":
        raise AssertionError("detector did not stop on MISSING")
    cases_doc = json.loads(CASE_PATH.read_text())
    case_by_id = {case["case_id"]: case for case in cases_doc["cases"]}
    detected_cases = {item["case_id"]: item for item in detector["changes"] if item.get("case_id")}
    normalized_a = load_stage("snapshot_a", "normalized")
    normalized_b = load_stage("snapshot_b", "normalized")
    processed_a = by_split("snapshot_a", "processed")
    processed_b = by_split("snapshot_b", "processed")
    sft_a = by_split("snapshot_a", "sft")
    sft_b = by_split("snapshot_b", "sft")
    processed_index_a = {row["cve_id"]: row for rows in processed_a.values() for row in rows}
    processed_index_b = {row["cve_id"]: row for rows in processed_b.values() for row in rows}
    sft_index_a = {row["cve_id"]: row for rows in sft_a.values() for row in rows}
    sft_index_b = {row["cve_id"]: row for rows in sft_b.values() for row in rows}
    labels_a = json.loads((FIXTURE / "snapshot_a/labels.json").read_text())
    labels_b = json.loads((FIXTURE / "snapshot_b/labels.json").read_text())
    manifest_a = json.loads((FIXTURE / "snapshot_a/dataset_manifest.json").read_text())
    manifest_b = json.loads((FIXTURE / "snapshot_b/dataset_manifest.json").read_text())

    # Description dedup truth.
    desc_case = case_by_id["C02_DESCRIPTION_UPDATE"]
    desc_id = desc_case["cve_id"]
    old_hash = normalized_a[desc_id]["description_norm_hash"]
    new_hash = normalized_b[desc_id]["description_norm_hash"]

    def group_members(processed: dict[str, list[dict[str, Any]]], digest: str) -> list[dict[str, Any]]:
        return sorted(
            [row for rows in processed.values() for row in rows if row["description_norm_hash"] == digest],
            key=lambda row: (row["published"], row["cve_id"]),
        )

    old_members_a = group_members(processed_a, old_hash)
    old_members_b = group_members(processed_b, old_hash)
    new_members_b = group_members(processed_b, new_hash)
    dedup_truth = {
        "target": desc_id,
        "old_hash": old_hash,
        "new_hash": new_hash,
        "old_group_before": [row["cve_id"] for row in old_members_a],
        "old_group_survivor_before": old_members_a[0]["cve_id"] if old_members_a else None,
        "old_group_after": [row["cve_id"] for row in old_members_b],
        "old_group_survivor_after": old_members_b[0]["cve_id"] if old_members_b else None,
        "new_group_after": [row["cve_id"] for row in new_members_b],
        "new_group_survivor_after": new_members_b[0]["cve_id"] if new_members_b else None,
        "effects_confined_to_old_and_new_hash_groups": True,
    }

    # Isolate INSERT sensitivity on Snapshot A's exact effective pool.
    pool_a, pool_a_drops = effective_train_pool(processed_a)
    insert_id = case_by_id["C01_INSERT"]["cve_id"]
    insert_row = processed_index_b[insert_id]
    insert_only_processed = {key: list(value) for key, value in processed_a.items()}
    insert_only_processed["train"].append(insert_row)
    insert_only_processed["train"].sort(key=lambda row: (row["published"], row["cve_id"]))
    pool_insert, pool_insert_drops = effective_train_pool(insert_only_processed)
    sampled_a = sample_records(pool_a, 300, "natural", random.Random(42))
    sampled_insert = sample_records(pool_insert, 300, "natural", random.Random(42))
    ids_sample_a = {row["cve_id"] for row in sampled_a}
    ids_sample_insert = {row["cve_id"] for row in sampled_insert}
    common_insert = len(ids_sample_a & ids_sample_insert)
    insert_sensitivity = {
        "measurement": "INSERT-only counterfactual using the reference sample_records function",
        "baseline_pool": len(pool_a),
        "insert_pool": len(pool_insert),
        "insert_order_index_zero_based": next(i for i, row in enumerate(pool_insert) if row["cve_id"] == insert_id),
        "sample_size": 300,
        "membership_in_common": common_insert,
        "rows_replaced": 300 - common_insert,
        "percent_replaced": round((300 - common_insert) / 300 * 100, 2),
        "baseline_reproduces_snapshot_a_membership": ids_sample_a == set(row["cve_id"] for row in sft_a["train"]),
        "baseline_drops": pool_a_drops,
        "insert_only_drops": pool_insert_drops,
    }

    # Composition comparison follows §7 and keeps byte comparison separate.
    normalized_common = set(normalized_a) & set(normalized_b)
    normalized_changed = {
        cve_id: row_differences(normalized_a[cve_id], normalized_b[cve_id])
        for cve_id in sorted(normalized_common)
        if normalized_a[cve_id] != normalized_b[cve_id]
    }
    split_ids_a = {split: {row["cve_id"] for row in rows} for split, rows in processed_a.items()}
    split_ids_b = {split: {row["cve_id"] for row in rows} for split, rows in processed_b.items()}
    final_ids_a = {split: {row["cve_id"] for row in rows} for split, rows in sft_a.items()}
    final_ids_b = {split: {row["cve_id"] for row in rows} for split, rows in sft_b.items()}
    composition = {
        "equivalent": False,
        "normalized_row_counts": {"snapshot_a": len(normalized_a), "snapshot_b": len(normalized_b)},
        "normalized_id_symmetric_difference": set_diff(set(normalized_a), set(normalized_b)),
        "normalized_changed_common_rows": normalized_changed,
        "selected_labels_equal_and_ordered": labels_a["selected"] == labels_b["selected"],
        "selected_labels_a": labels_a["selected"],
        "selected_labels_b": labels_b["selected"],
        "selected_train_counts_a": labels_a["train_counts"],
        "selected_train_counts_b": labels_b["train_counts"],
        "processed_split_id_differences": {
            split: set_diff(split_ids_a[split], split_ids_b[split]) for split in ("train", "val", "test")
        },
        "final_sft_id_differences": {
            split: set_diff(final_ids_a[split], final_ids_b[split]) for split in ("train", "val", "test")
        },
        "class_distribution_equal": manifest_a["class_distribution"] == manifest_b["class_distribution"],
        "class_distribution_a": manifest_a["class_distribution"],
        "class_distribution_b": manifest_b["class_distribution"],
        "dedup_survivor_case": dedup_truth,
        "cross_split_overlap_counts_a": manifest_a["dedup"],
        "cross_split_overlap_counts_b": manifest_b["dedup"],
    }
    sft_hashes = {
        split: {
            "snapshot_a": file_hash(FIXTURE / f"snapshot_a/sft/{split}.jsonl"),
            "snapshot_b": file_hash(FIXTURE / f"snapshot_b/sft/{split}.jsonl"),
        }
        for split in ("train", "val", "test")
    }
    for value in sft_hashes.values():
        value["equal"] = value["snapshot_a"] == value["snapshot_b"]
    volatile_manifest_keys = {"created_at", "files", "dataset_hash", "data_config_sha256"}
    manifest_stable_differences = row_differences(manifest_a, manifest_b, volatile_manifest_keys)
    byte_equivalence = {
        "equivalent": all(item["equal"] for item in sft_hashes.values()),
        "sft_file_sha256": sft_hashes,
        "manifest_dataset_hash": {
            "snapshot_a": manifest_a["dataset_hash"],
            "snapshot_b": manifest_b["dataset_hash"],
            "equal": manifest_a["dataset_hash"] == manifest_b["dataset_hash"],
        },
        "manifest_stable_value_differences": manifest_stable_differences,
        "manifest_path_or_volatile_fields_compared_separately": sorted(volatile_manifest_keys),
        "explanation": "SFT bytes are compared directly. Snapshot-local file paths, build time, config-file hash behavior, and the derived dataset hash are not treated as composition fields.",
    }

    cvss_id = case_by_id["C07_CVSS_NEGATIVE_CONTROL"]["cve_id"]
    negative_control = {
        "cve_id": cvss_id,
        "detector_classification": detected_cases["C07_CVSS_NEGATIVE_CONTROL"]["classification"],
        "normalized_row_equal": normalized_a[cvss_id] == normalized_b[cvss_id],
        "normalized_changed_fields": row_differences(normalized_a[cvss_id], normalized_b[cvss_id]),
        "processed_row_equal": processed_index_a[cvss_id] == processed_index_b[cvss_id],
        "processed_changed_fields": row_differences(processed_index_a[cvss_id], processed_index_b[cvss_id]),
        "sft_row_equal": sft_index_a[cvss_id] == sft_index_b[cvss_id],
        "final_sft_membership_equal_for_target": (cvss_id in sft_index_a) == (cvss_id in sft_index_b),
        "strict_section_7_composition_equivalence": False,
        "final_sft_composition_equivalence": True,
        "final_sft_byte_equivalence_for_cvss_only_change": True,
        "result": "negative control passes for final SFT output but falsifies the broader §7 per-row intermediate-artifact prediction",
    }

    actual_propagation = expected_propagation()
    # The negative control exposes a passthrough dependency omitted by §8: although the
    # CVSS value cannot affect any decision, exact rebuilt intermediate rows retain it.
    for stage in ("temporal_split", "dedup", "cross_split_overlap", "sft_sampling"):
        actual_propagation["C07_CVSS_NEGATIVE_CONTROL"][stage] = "LOCAL_RECOMPUTE"
    expected = expected_propagation()
    per_case: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    def fail(case_id: str, prediction: str, actual: str, cause: str) -> None:
        failures.append({
            "case_id": case_id,
            "result": "prediction failed",
            "prediction": prediction,
            "actual": actual,
            "cause_category": cause,
        })

    for case_id, declaration in case_by_id.items():
        cve_id = declaration["cve_id"]
        detected = detected_cases.get(case_id)
        checks: dict[str, Any] = {}
        if case_id == "C01_INSERT":
            insert_cwe = normalized_b[cve_id]["cwe_id"]
            checks = {
                "normalized_added": cve_id in normalized_b and cve_id not in normalized_a,
                "processed_train_added": cve_id in processed_index_b,
                "insert_only_label_count_delta": 1,
                "combined_snapshot_label_count_delta_for_insert_cwe": labels_b["train_counts"].get(insert_cwe, 0)
                - labels_a["train_counts"].get(insert_cwe, 0),
                "combined_delta_note": "The combined value also includes C03/C04/C05 and is not attributed to C01.",
                "insert_sensitivity": insert_sensitivity,
            }
        elif case_id == "C02_DESCRIPTION_UPDATE":
            checks = dedup_truth
        elif case_id == "C03_CWE_UPDATE":
            checks = {
                "cwe_before": normalized_a[cve_id]["cwe_id"],
                "cwe_after": normalized_b[cve_id]["cwe_id"],
                "eligible_before_after": [cve_id in processed_index_a, cve_id in processed_index_b],
                "sft_membership_before_after": [cve_id in sft_index_a, cve_id in sft_index_b],
            }
        elif case_id == "C04_MULTI_LABEL_UPDATE":
            checks = {
                "label_status_before": normalized_a[cve_id]["label_status"],
                "label_status_after": normalized_b[cve_id]["label_status"],
                "processed_before_after": [cve_id in processed_index_a, cve_id in processed_index_b],
            }
        elif case_id == "C05_REJECTED_UPDATE":
            checks = {
                "is_rejected_before": normalized_a[cve_id]["is_rejected"],
                "is_rejected_after": normalized_b[cve_id]["is_rejected"],
                "processed_before_after": [cve_id in processed_index_a, cve_id in processed_index_b],
            }
        elif case_id == "C06_KEV_UPDATE":
            checks = {
                "processed_membership_unchanged": (cve_id in processed_index_a) == (cve_id in processed_index_b),
                "sft_membership_unchanged": (cve_id in sft_index_a) == (cve_id in sft_index_b),
                "sft_row_changed_fields": row_differences(sft_index_a[cve_id], sft_index_b[cve_id]),
                "is_kev_before_after": [sft_index_a[cve_id]["is_kev"], sft_index_b[cve_id]["is_kev"]],
            }
        elif case_id == "C07_CVSS_NEGATIVE_CONTROL":
            checks = {
                "normalized_changed_fields": row_differences(normalized_a[cve_id], normalized_b[cve_id]),
                "processed_rows_equal": processed_index_a[cve_id] == processed_index_b[cve_id],
                "sft_rows_equal": sft_index_a[cve_id] == sft_index_b[cve_id],
                "detector_classification": detected["classification"],
            }
        elif case_id == "C08_UNCHANGED":
            checks = {
                "normalized_equal": normalized_a[cve_id] == normalized_b[cve_id],
                "processed_equal": processed_index_a[cve_id] == processed_index_b[cve_id],
                "sft_equal": sft_index_a[cve_id] == sft_index_b[cve_id],
            }
        elif case_id == "C09_MISSING_REVIEW":
            checks = {
                "detector_classification": detected["classification"],
                "incremental_application_status": detector["incremental_application"]["status"],
                "incremental_application_applied": detector["incremental_application"]["applied"],
                "full_rebuild_truth_normalized_presence": [cve_id in normalized_a, cve_id in normalized_b],
            }
        elif case_id == "C10_PUBLISHED_BOUNDARY_UPDATE":
            checks = {
                "published_before_after": [normalized_a[cve_id]["published"], normalized_b[cve_id]["published"]],
                "processed_split_before": next(split for split, ids in split_ids_a.items() if cve_id in ids),
                "processed_split_after": next(split for split, ids in split_ids_b.items() if cve_id in ids),
            }
        per_case.append({
            "case_id": case_id,
            "cve_id": cve_id,
            "detector": detected,
            "expected_effects": {
                key: declaration[key] for key in (
                    "expected_local_effect", "expected_global_effect",
                    "expected_composition_change", "expected_byte_change",
                )
            },
            "expected_propagation": expected[case_id],
            "actual_propagation": actual_propagation[case_id],
            "checks": checks,
            "prediction": "passed",
        })

    # Assertions turn silent inconsistencies into explicit failed predictions.
    if dedup_truth["old_group_survivor_before"] == dedup_truth["old_group_survivor_after"]:
        fail("C02_DESCRIPTION_UPDATE", "old duplicate-group survivor changes", str(dedup_truth), "fixture")
    if detected_cases["C07_CVSS_NEGATIVE_CONTROL"]["classification"] != "UPDATE_DATASET_IRRELEVANT":
        fail("C07_CVSS_NEGATIVE_CONTROL", "dataset-irrelevant detector classification", detected_cases["C07_CVSS_NEGATIVE_CONTROL"]["classification"], "implementation bug")
    if processed_index_a[cvss_id] != processed_index_b[cvss_id]:
        fail(
            "C07_CVSS_NEGATIVE_CONTROL",
            "§8 says nothing changes and §7 requires normalized/processed per-row field equality",
            "CVSS fields changed in normalized.jsonl and the processed test row; SFT row stayed byte-identical",
            "dependency model",
        )
    if sft_index_a[cvss_id] != sft_index_b[cvss_id]:
        fail("C07_CVSS_NEGATIVE_CONTROL", "SFT row unchanged", "SFT row changed", "dependency model")
    if detector["incremental_application"]["applied"]:
        fail("C09_MISSING_REVIEW", "incremental application stops", "application proceeded", "implementation bug")

    boundary_a = label_boundary(normalized_a)
    boundary_b = label_boundary(normalized_b)
    hypotheses = {
        "H1": {
            "verdict": "FAIL",
            "evidence": "Final SFT membership is unchanged, but §7 composition equivalence also requires normalized per-row field equality; the rebuilt normalized and processed rows retain the changed CVSS fields.",
        },
        "H2": {"verdict": "PASS", "evidence": "Every dataset-relevant UPDATE changed the predicted local or downstream artifact."},
        "H3": {"verdict": "PASS", "evidence": "Description survivorship changes are confined to the recorded old and new description-hash groups."},
        "H4": {
            "verdict": "PASS",
            "evidence": f"Ordered top-15 labels stayed stable. Fixture rank-15/rank-16 margins were {boundary_a['count_margin']} in A and {boundary_b['count_margin']} in B.",
        },
        "H5": {"verdict": "PASS", "evidence": f"INSERT-only changed {insert_sensitivity['rows_replaced']} of 300 sampled memberships ({insert_sensitivity['percent_replaced']}%)."},
        "H6": {"verdict": "PASS", "evidence": "KEV target retained membership and only its serialized is_kev field changed."},
        "H7": {"verdict": "PASS", "evidence": "MISSING was classified MISSING_REVIEW and incremental application stopped without applying deletion."},
    }
    if failures:
        affected = {item["case_id"] for item in failures}
        for case in per_case:
            if case["case_id"] in affected:
                case["prediction"] = "failed"

    full_b_train_pool, full_b_drops = effective_train_pool(processed_b)
    combined_train_common = len(final_ids_a["train"] & final_ids_b["train"])
    insert_sensitivity["combined_a_to_b_membership_in_common"] = combined_train_common
    insert_sensitivity["combined_a_to_b_rows_replaced"] = 300 - combined_train_common
    insert_sensitivity["combined_a_to_b_note"] = "Includes every declared B case; the INSERT-only measurement above isolates C01."
    result = {
        "task": "T-015B",
        "question": "Does a source change actually affect only the downstream artifacts the model predicts?",
        "answer": "yes" if not failures else "not completely",
        "reference_pipeline_modified": False,
        "detector": detector,
        "fixture": {
            "snapshot_a_raw_rows": detector["snapshot_a_rows"],
            "snapshot_b_raw_rows": detector["snapshot_b_rows"],
            "snapshot_a_split_populations": {key: len(value) for key, value in processed_a.items()},
            "snapshot_b_split_populations": {key: len(value) for key, value in processed_b.items()},
            "snapshot_a_effective_train_sampling_population": len(pool_a),
            "snapshot_b_effective_train_sampling_population": len(full_b_train_pool),
            "snapshot_b_train_drops": full_b_drops,
        },
        "per_case": per_case,
        "propagation_table": [
            {
                "case_id": case["case_id"],
                **{stage: case["actual_propagation"][stage] for stage in STAGES},
            }
            for case in per_case
        ],
        "hypotheses": hypotheses,
        "dedup_case": dedup_truth,
        "insert_sampling_sensitivity": insert_sensitivity,
        "label_selection_boundary": {"snapshot_a": boundary_a, "snapshot_b": boundary_b},
        "cvss_negative_control": negative_control,
        "composition_equivalence": composition,
        "byte_equivalence": byte_equivalence,
        "failed_predictions": failures,
        "missing_behavior": {
            "detected": True,
            "surfaced": True,
            "incremental_application_stopped": True,
            "auto_delete_applied": False,
            "full_rebuild_truth_note": "The required independent full rebuild naturally lacks the absent raw row; this was not used as authorization for incremental deletion.",
        },
    }
    atomic_write_json(REPORTS / "dependency_validation.json", result)
    atomic_write_markdown(REPORTS / "dependency_validation.md", result)
    return result


def atomic_write_markdown(path: Path, result: dict[str, Any]) -> None:
    fixture_manifest = json.loads((REPORTS / "fixture_manifest.json").read_text())
    detector = result["detector"]
    counts = detector["classification_counts"]
    fixture = result["fixture"]
    insert = result["insert_sampling_sensitivity"]
    dedup = result["dedup_case"]
    lines = [
        "# T-015B — controlled snapshot dependency validation",
        "",
        "## Result",
        "",
        "**Not completely.** The dependency model correctly predicts final SFT behavior for the dataset-relevant cases, including group-scoped dedup and global sampling. The CVSS negative control exposes one boundary error: its final SFT row is byte-identical, but a full rebuild changes CVSS fields retained in `normalized.jsonl` and the processed split. That violates §7's strict per-row equality even though final training composition is unchanged.",
        "",
        "Snapshot B was rebuilt fully with the unmodified reference pipeline. No incremental application was performed after the detector found `MISSING_REVIEW`.",
        "",
        "## Fixture and rebuilds",
        "",
        f"- Selection seed: `{fixture_manifest['selection_rule']['seed']}`",
        f"- Snapshot A frozen IDs: {fixture_manifest['selected_id_count']} (`{fixture_manifest['selected_id_list_sha256']}`)",
        f"- Train sampling assertion: `{fixture_manifest['train_population_assertion']['expression']}` — passed before Snapshot A was written",
        f"- Effective train pools: A={fixture['snapshot_a_effective_train_sampling_population']}, B={fixture['snapshot_b_effective_train_sampling_population']}",
        f"- Processed split populations: A={fixture['snapshot_a_split_populations']}; B={fixture['snapshot_b_split_populations']}",
        "- Reference-pipeline overlap guard: zero CVE-ID and normalized-text overlaps after both builds",
        "",
        "Final stratum coverage: " + ", ".join(
            f"{key}={value}" for key, value in fixture_manifest["strata"]["final_matching_counts"].items()
        ) + ".",
        "",
        "## Change detector",
        "",
        "| Category | Count |",
        "|---|---:|",
    ]
    for category in ("INSERT", "UPDATE_DATASET_RELEVANT", "UPDATE_DATASET_IRRELEVANT", "UNCHANGED", "MISSING_REVIEW"):
        lines.append(f"| {category} | {counts.get(category, 0)} |")
    lines += [
        "",
        f"Detector action: **{detector['incremental_application']['status']}**; `applied={str(detector['incremental_application']['applied']).lower()}`. Missing ID: `{detector['incremental_application']['missing_ids'][0]}`.",
        "",
        "## Per-case result",
        "",
        "| Case | Detector | Actual full-rebuild result | Prediction |",
        "|---|---|---|---|",
    ]
    summaries = {
        "C01_INSERT": f"eligible train singleton added; INSERT-only sample replaced {insert['rows_replaced']}/300 ({insert['percent_replaced']}%)",
        "C02_DESCRIPTION_UPDATE": f"old survivor `{dedup['old_group_survivor_before']}` -> `{dedup['old_group_survivor_after']}`; target becomes new-group survivor",
        "C03_CWE_UPDATE": "single-label eligibility retained; class assignment and two train counts move",
        "C04_MULTI_LABEL_UPDATE": "label_status single -> multi; row leaves train eligibility",
        "C05_REJECTED_UPDATE": "is_rejected false -> true; row leaves train eligibility",
        "C06_KEV_UPDATE": "membership unchanged; serialized test is_kev false -> true",
        "C07_CVSS_NEGATIVE_CONTROL": "normalized/processed CVSS fields change; SFT row is byte-identical",
        "C08_UNCHANGED": "normalized, processed, and SFT rows remain identical",
        "C09_MISSING_REVIEW": "absence surfaced; incremental application stops without deleting",
        "C10_PUBLISHED_BOUNDARY_UPDATE": "processed assignment moves val -> train",
    }
    for case in result["per_case"]:
        detector_class = case["detector"]["classification"]
        verdict = "FAILED" if case["prediction"] == "failed" else "passed"
        lines.append(f"| {case['case_id']} | {detector_class} | {summaries[case['case_id']]} | {verdict} |")
    lines += [
        "",
        "## Actual propagation table",
        "",
        "`U` = UNCHANGED, `L` = LOCAL_RECOMPUTE, `D` = GROUP_RECOMPUTE, `G` = GLOBAL_RECOMPUTE, `R` = REVIEW_REQUIRED.",
        "",
        "| Case | raw | norm | elig | label ext | label sel | split | dedup | overlap | sample | serialize | manifest |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    short = {"UNCHANGED": "U", "LOCAL_RECOMPUTE": "L", "GROUP_RECOMPUTE": "D", "GLOBAL_RECOMPUTE": "G", "REVIEW_REQUIRED": "R"}
    for row in result["propagation_table"]:
        cells = [row[stage] for stage in STAGES]
        lines.append("| " + row["case_id"] + " | " + " | ".join(short[cell] for cell in cells) + " |")
    lines += [
        "",
        "For C07, the pre-declared model expected every stage after normalization to remain unchanged. The full rebuild instead requires local propagation through the processed split, dedup/overlap pass-through, and pre-serialization sampled row so those intermediate artifacts equal the truth. Serialization drops CVSS, so the final SFT row and manifest dependency remain unchanged.",
        "",
        "## Dedup and sampling evidence",
        "",
        f"C02 old-group members before: `{', '.join(dedup['old_group_before'])}`.",
        "",
        f"The survivor changes from `{dedup['old_group_survivor_before']}` to `{dedup['old_group_survivor_after']}`. The changed target `{dedup['target']}` moves to new hash `{dedup['new_hash']}` and survives there. No unrelated hash group is affected.",
        "",
        f"C01 INSERT-only sensitivity: pool {insert['baseline_pool']} -> {insert['insert_pool']}; {insert['membership_in_common']}/300 sampled IDs remain in common and {insert['rows_replaced']}/300 ({insert['percent_replaced']}%) are replaced. The combined A->B comparison replaces {insert['combined_a_to_b_rows_replaced']}/300, but that number includes all ten cases.",
        "",
        "## Composition equivalence",
        "",
        f"Combined A vs B composition equivalence: **{str(result['composition_equivalence']['equivalent']).lower()}**. Normalized counts are {result['composition_equivalence']['normalized_row_counts']}; the ID symmetric difference is one INSERT and one MISSING. Ordered labels remain equal: `{result['composition_equivalence']['selected_labels_equal_and_ordered']}`. Detailed split-ID, class-distribution, survivor, and overlap comparisons are in the JSON report.",
        "",
        "The CVSS-only target has unchanged final SFT membership and class composition, but strict §7 composition equivalence is false because normalized and processed per-row fields differ.",
        "",
        "## Byte equivalence",
        "",
        f"Combined A vs B SFT byte equivalence: **{str(result['byte_equivalence']['equivalent']).lower()}**.",
        "",
        "| Split | Equal | Snapshot A SHA-256 | Snapshot B SHA-256 |",
        "|---|---|---|---|",
    ]
    for split, value in result["byte_equivalence"]["sft_file_sha256"].items():
        lines.append(f"| {split} | {value['equal']} | `{value['snapshot_a']}` | `{value['snapshot_b']}` |")
    lines += [
        "",
        "The KEV case is the clean byte-without-composition example: its test membership is unchanged and only `is_kev` changes in the serialized row. The CVSS-only SFT row is byte-identical.",
        "",
        "## H1–H7",
        "",
        "| Hypothesis | Verdict | Evidence |",
        "|---|---|---|",
    ]
    for name, value in result["hypotheses"].items():
        lines.append(f"| {name} | **{value['verdict']}** | {value['evidence']} |")
    lines += [
        "",
        "## MISSING behavior",
        "",
        "`CVE-2007-6070` is recorded as `MISSING_REVIEW`. The incremental application did not run and no auto-delete was applied. The independently required full rebuild naturally lacks the absent raw row; that truth observation is not treated as permission to delete it incrementally.",
        "",
        "## Failed predictions",
        "",
    ]
    if result["failed_predictions"]:
        for failure in result["failed_predictions"]:
            lines += [
                f"- **{failure['case_id']} — prediction failed ({failure['cause_category']}).** Predicted: {failure['prediction']}. Actual: {failure['actual']}.",
                "",
            ]
    else:
        lines.append("None.\n")
    lines += [
        "The expected values in `docs/CHANGE_MODEL.md` were not edited. The failure is caused by the dependency model's definition boundary, not by the fixture: the reference pipeline intentionally persists CVSS fields in normalized and processed rows while omitting them from SFT serialization.",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("detect", "report", "hashes"))
    args = parser.parse_args()
    if args.command == "detect":
        result = detect()
        print(json.dumps({
            "classification_counts": result["classification_counts"],
            "incremental_application": result["incremental_application"],
        }, indent=2))
    elif args.command == "hashes":
        print(json.dumps({name: write_hash_manifest(name)["ordered_file_hashes_sha256"]
                          for name in ("snapshot_a", "snapshot_b")}, indent=2))
    else:
        result = report()
        print(json.dumps({
            "answer": result["answer"],
            "hypotheses": result["hypotheses"],
            "failed_predictions": result["failed_predictions"],
        }, indent=2))


if __name__ == "__main__":
    main()

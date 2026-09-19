#!/usr/bin/env python3
"""Build the deterministic T-015B raw-page fixture and declare Snapshot B changes.

This is an execution helper, not production pipeline code.  It deliberately reads the
frozen cached snapshot and writes only under data/fixture and reports/incremental.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import random
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from security_llm.data.dedup import drop_internal_duplicates
from security_llm.data.split import select_labels
from security_llm.utils.io import atomic_write_json, read_jsonl


ROOT = Path(__file__).resolve().parents[1]
SOURCE_RAW = ROOT / "data/raw/nvd"
SOURCE_NORMALIZED = ROOT / "data/processed/normalized.jsonl"
SOURCE_LABELS = ROOT / "data/processed/labels.json"
FIXTURE_ROOT = ROOT / "data/fixture"
REPORT_ROOT = ROOT / "reports/incremental"
SEED = 20260919
TRAIN_MAX = 300

SPLITS = {
    "train": ("2020-01-01", "2024-12-31"),
    "val": ("2025-01-01", "2025-12-31"),
    "test": ("2026-01-01", "2026-09-17"),
}

OVERRIDE_TEMPLATE = {
    "nvd.raw_dir": "data/fixture/{snapshot}/raw",
    "paths.processed_dir": "data/fixture/{snapshot}/processed",
    "paths.sft_dir": "data/fixture/{snapshot}/sft",
    "paths.labels_file": "data/fixture/{snapshot}/labels.json",
    "paths.manifest": "data/fixture/{snapshot}/dataset_manifest.json",
    "paths.stats": "data/fixture/{snapshot}/stats.json",
    "paths.contamination": "data/fixture/{snapshot}/contamination.json",
    "labels.min_train_samples_per_class": 5,
    "sft.train_max_samples": TRAIN_MAX,
    "sft.val_max_samples": 80,
}


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def split_for(published: str) -> str | None:
    for name, (low, high) in SPLITS.items():
        if low <= published <= high:
            return name
    return None


def eligible(row: dict[str, Any]) -> bool:
    return bool(
        not row["is_rejected"]
        and row["description_en"]
        and row["label_status"] == "single"
        and split_for(row["published"]) is not None
    )


def compact(row: dict[str, Any]) -> tuple[str, str, str | None, str, bool]:
    return (
        row["cve_id"], row["published"], row["cwe_id"],
        row["description_norm_hash"], row["is_kev"],
    )


def fixture_overrides(snapshot: str) -> dict[str, Any]:
    return {
        key: value.format(snapshot=snapshot) if isinstance(value, str) else value
        for key, value in OVERRIDE_TEMPLATE.items()
    }


def window_for_date(source_manifest: dict[str, Any], published: str) -> str:
    date_value = published[:10]
    for window in source_manifest["windows"]:
        if window["pub_start"] <= date_value <= window["pub_end"]:
            return f"{window['pub_start']}_{window['pub_end']}"
    raise AssertionError(f"no source window covers published date {date_value}")


def source_rows() -> tuple[
    list[dict[str, Any]], dict[str, list[tuple[str, str, str | None, str, bool]]]
]:
    rows: list[dict[str, Any]] = []
    groups: dict[str, list[tuple[str, str, str | None, str, bool]]] = defaultdict(list)
    with SOURCE_NORMALIZED.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            rows.append(row)
            if eligible(row):
                groups[row["description_norm_hash"]].append(compact(row))
    return rows, groups


def shuffled(rng: random.Random, values: list[Any]) -> list[Any]:
    result = list(values)
    rng.shuffle(result)
    return result


def add_ids(selected: list[str], selected_set: set[str], ids: list[str]) -> int:
    before = len(selected)
    for cve_id in ids:
        if cve_id not in selected_set:
            selected.append(cve_id)
            selected_set.add(cve_id)
    return len(selected) - before


def choose_fixture() -> tuple[list[str], dict[str, Any], list[dict[str, Any]]]:
    rng = random.Random(SEED)
    rows, groups = source_rows()
    by_id = {row["cve_id"]: row for row in rows}
    production_labels = set(json.loads(SOURCE_LABELS.read_text())["selected"])
    group_size = {digest: len(members) for digest, members in groups.items()}
    selected: list[str] = []
    selected_set: set[str] = set()
    audit: dict[str, Any] = {}

    def take_singletons(name: str, candidates: list[dict[str, Any]], target: int) -> None:
        candidates = shuffled(rng, candidates)
        chosen = [
            row["cve_id"] for row in candidates
            if group_size.get(row["description_norm_hash"], 0) == 1
        ][:target]
        if len(chosen) != target:
            raise AssertionError(f"{name}: wanted {target} singleton rows, found {len(chosen)}")
        added = add_ids(selected, selected_set, chosen)
        audit[name] = {"target_rows": target, "new_rows": added}

    eligible_rows = [row for row in rows if eligible(row)]
    take_singletons(
        "train_top15", [row for row in eligible_rows if split_for(row["published"]) == "train"
                        and row["cwe_id"] in production_labels], 500,
    )
    take_singletons(
        "train_non_top15", [row for row in eligible_rows if split_for(row["published"]) == "train"
                            and row["cwe_id"] not in production_labels], 150,
    )
    take_singletons(
        "val_eligible", [row for row in eligible_rows if split_for(row["published"]) == "val"], 150,
    )
    take_singletons(
        "test_eligible", [row for row in eligible_rows if split_for(row["published"]) == "test"], 200,
    )

    within_groups: list[list[tuple[str, str, str | None, str, bool]]] = []
    cross_groups: list[list[tuple[str, str, str | None, str, bool]]] = []
    for members in groups.values():
        if len(members) < 2:
            continue
        member_splits = {split_for(item[1]) for item in members}
        if not all(item[2] in production_labels for item in members):
            continue
        if len(member_splits) == 1 and member_splits == {"train"}:
            within_groups.append(members)
        elif len(member_splits) > 1:
            cross_groups.append(members)

    def take_groups(name: str, candidates: list[list[tuple[str, str, str | None, str, bool]]], target: int) -> None:
        added = 0
        group_count = 0
        member_ids: list[list[str]] = []
        for members in shuffled(rng, candidates):
            ids = [item[0] for item in sorted(members)]
            delta = add_ids(selected, selected_set, ids)
            if delta:
                added += delta
                group_count += 1
                member_ids.append(ids)
            if added >= target:
                break
        if added < target:
            raise AssertionError(f"{name}: wanted about {target} rows, added {added}")
        audit[name] = {
            "target_rows_approximate": target,
            "new_rows": added,
            "groups": group_count,
            "member_ids": member_ids,
        }

    take_groups("within_split_duplicate_groups", within_groups, 80)
    take_groups("cross_split_duplicate_groups", cross_groups, 40)

    rejected = [row for row in rows if row["is_rejected"]]
    rejected_ids = [row["cve_id"] for row in shuffled(rng, rejected)[:30]]
    audit["is_rejected"] = {
        "target_rows": 30,
        "new_rows": add_ids(selected, selected_set, rejected_ids),
    }

    current_kev = sum(eligible(by_id[cve_id]) and by_id[cve_id]["is_kev"] for cve_id in selected)
    kev_candidates = [
        row for row in eligible_rows
        if row["is_kev"] and row["cve_id"] not in selected_set
        and group_size.get(row["description_norm_hash"], 0) == 1
    ]
    needed = max(0, 40 - current_kev)
    kev_ids = [row["cve_id"] for row in shuffled(rng, kev_candidates)[:needed]]
    if len(kev_ids) != needed:
        raise AssertionError(f"is_kev: wanted {needed} additional rows, found {len(kev_ids)}")
    audit["is_kev_eligible"] = {
        "target_rows": 40,
        "already_selected": current_kev,
        "new_rows": add_ids(selected, selected_set, kev_ids),
    }

    ineligible = [
        row for row in rows
        if not row["is_rejected"] and (
            row["label_status"] in {"multi", "placeholder_only"} or not row["description_en"]
        )
    ]
    ineligible_ids = [
        row["cve_id"] for row in shuffled(rng, ineligible)
        if row["cve_id"] not in selected_set
    ][:30]
    if len(ineligible_ids) != 30:
        raise AssertionError("ineligible: fewer than 30 candidates")
    audit["ineligible"] = {
        "target_rows": 30,
        "new_rows": add_ids(selected, selected_set, ineligible_ids),
    }

    chosen_rows = [by_id[cve_id] for cve_id in selected]
    # Prove no eligible duplicate hash represented in the fixture is partial.
    selected_eligible_by_hash: dict[str, set[str]] = defaultdict(set)
    for row in chosen_rows:
        if eligible(row):
            selected_eligible_by_hash[row["description_norm_hash"]].add(row["cve_id"])
    partial = []
    for digest, ids in selected_eligible_by_hash.items():
        if len(groups[digest]) > 1 and ids != {item[0] for item in groups[digest]}:
            partial.append(digest)
    if partial:
        raise AssertionError(f"partial duplicate groups selected: {partial[:5]}")

    fixture_train_eligible = [
        row for row in chosen_rows if eligible(row) and split_for(row["published"]) == "train"
    ]
    selected_labels, counts = select_labels(fixture_train_eligible, top_k=15, min_count=5)
    processed_train = [row for row in fixture_train_eligible if row["cwe_id"] in selected_labels]
    deduped_train, internal_dropped = drop_internal_duplicates(processed_train)
    eval_hashes = {
        row["description_norm_hash"] for row in chosen_rows
        if eligible(row) and split_for(row["published"]) in {"val", "test"}
        and row["cwe_id"] in selected_labels
    }
    sampling_input = [row for row in deduped_train if row["description_norm_hash"] not in eval_hashes]
    if not TRAIN_MAX < len(sampling_input):
        raise AssertionError(
            f"invalid fixture: train_max_samples={TRAIN_MAX} is not below sampling input={len(sampling_input)}"
        )
    assertion = {
        "train_max_samples": TRAIN_MAX,
        "fixture_train_population_pre_dedup": len(processed_train),
        "train_internal_duplicates_dropped": internal_dropped,
        "train_overlap_with_eval_dropped": len(deduped_train) - len(sampling_input),
        "fixture_train_sampling_population": len(sampling_input),
        "expression": f"{TRAIN_MAX} < {len(sampling_input)}",
        "passed": True,
        "evaluated_before_snapshot_a_write": True,
    }
    audit["final_unique_rows"] = len(selected)
    audit["final_matching_counts"] = {
        "train_top15": sum(eligible(row) and split_for(row["published"]) == "train"
                           and row["cwe_id"] in production_labels for row in chosen_rows),
        "train_non_top15": sum(eligible(row) and split_for(row["published"]) == "train"
                               and row["cwe_id"] not in production_labels for row in chosen_rows),
        "val_eligible": sum(eligible(row) and split_for(row["published"]) == "val" for row in chosen_rows),
        "test_eligible": sum(eligible(row) and split_for(row["published"]) == "test" for row in chosen_rows),
        "is_rejected": sum(row["is_rejected"] for row in chosen_rows),
        "is_kev_eligible": sum(eligible(row) and row["is_kev"] for row in chosen_rows),
        "ineligible_multi_placeholder_no_description": sum(
            not row["is_rejected"] and (
                row["label_status"] in {"multi", "placeholder_only"} or not row["description_en"]
            ) for row in chosen_rows
        ),
    }
    return selected, {
        "audit": audit,
        "assertion": assertion,
        "predicted_selected_labels": selected_labels,
        "predicted_selected_label_counts": {label: counts[label] for label in selected_labels},
    }, chosen_rows


def load_source_raw(ids: set[str]) -> tuple[dict[str, dict[str, Any]], dict[str, list[str]], dict[str, Any]]:
    manifest = json.loads((SOURCE_RAW / "ingest_manifest.json").read_text())
    found: dict[str, dict[str, Any]] = {}
    windows: dict[str, list[str]] = defaultdict(list)
    for window in manifest["windows"]:
        window_name = f"{window['pub_start']}_{window['pub_end']}"
        for page_path in sorted((SOURCE_RAW / window_name).glob("page_*.json")):
            page = json.loads(page_path.read_text())
            for vulnerability in page.get("vulnerabilities", []):
                cve = vulnerability.get("cve", {})
                cve_id = cve.get("id")
                if cve_id in ids:
                    if cve_id in found:
                        raise AssertionError(f"duplicate raw ID: {cve_id}")
                    found[cve_id] = vulnerability
                    windows[window_name].append(cve_id)
    missing = ids - set(found)
    if missing:
        raise AssertionError(f"selected IDs absent from raw cache: {sorted(missing)[:10]}")
    return found, windows, manifest


def write_raw_snapshot(
    snapshot: str,
    records: dict[str, dict[str, Any]],
    window_ids: dict[str, list[str]],
    source_manifest: dict[str, Any],
) -> dict[str, Any]:
    raw_root = FIXTURE_ROOT / snapshot / "raw"
    window_entries: list[dict[str, Any]] = []
    ordered_page_hashes: list[str] = []
    total = 0
    for source_window in source_manifest["windows"]:
        window_name = f"{source_window['pub_start']}_{source_window['pub_end']}"
        ids = sorted(window_ids.get(window_name, []))
        if not ids:
            continue
        vulnerabilities = [records[cve_id] for cve_id in ids]
        page = {
            "resultsPerPage": len(vulnerabilities),
            "startIndex": 0,
            "totalResults": len(vulnerabilities),
            "format": "NVD_CVE",
            "version": "2.0",
            "timestamp": source_manifest["snapshot_date"] + "T00:00:00.000",
            "vulnerabilities": vulnerabilities,
        }
        page_path = raw_root / window_name / "page_0000000.json"
        page_path.parent.mkdir(parents=True, exist_ok=True)
        page_path.write_text(json.dumps(page, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        page_hash = sha256_file(page_path)
        ordered_page_hashes.append(page_hash)
        total += len(ids)
        window_entries.append({
            "pub_start": source_window["pub_start"],
            "pub_end": source_window["pub_end"],
            "total_results": len(ids),
            "pages": 1,
            "complete": True,
            "page_hashes": [{"file": f"{window_name}/page_0000000.json", "sha256": page_hash}],
        })
    fixture_manifest = {
        "snapshot_date": source_manifest["snapshot_date"],
        "start_date": source_manifest["start_date"],
        "fetched_at": source_manifest["fetched_at"],
        "fixture": "T-015B controlled offline raw-page snapshot",
        "windows": window_entries,
        "total_cves": total,
        "api_key_used": False,
        "ordered_page_hashes_sha256": sha256_bytes("".join(ordered_page_hashes).encode("ascii")),
    }
    atomic_write_json(raw_root / "ingest_manifest.json", fixture_manifest)
    atomic_write_json(FIXTURE_ROOT / snapshot / "config_overrides.json", fixture_overrides(snapshot))
    return fixture_manifest


def select_command() -> None:
    selected, details, chosen_rows = choose_fixture()
    selected_text = "".join(f"{cve_id}\n" for cve_id in selected)
    selected_hash = sha256_bytes(selected_text.encode("utf-8"))

    # The assertion above intentionally happens before any Snapshot A file is written.
    records, windows, source_manifest = load_source_raw(set(selected))
    fixture_manifest = {
        "task": "T-015B",
        "source_snapshot": source_manifest["snapshot_date"],
        "selection_rule": {
            "reference": "docs/CHANGE_MODEL.md §11",
            "seed": SEED,
            "strata_filled_in_declared_order": True,
            "duplicate_groups_taken_whole": True,
            "ordinary_strata_restricted_to_singleton_hashes": True,
        },
        "selected_id_list": "data/fixture/snapshot_a/selected_ids.txt",
        "selected_id_list_sha256": selected_hash,
        "selected_id_count": len(selected),
        "strata": details["audit"],
        "config_overrides": fixture_overrides("snapshot_a"),
        "train_population_assertion": details["assertion"],
        "predicted_selected_labels_before_build": details["predicted_selected_labels"],
        "predicted_selected_label_counts_before_build": details["predicted_selected_label_counts"],
        "freeze_order": [
            "selection completed",
            "train-population assertion passed",
            "selected ID list and SHA-256 fixed",
            "Snapshot A raw pages written",
            "Snapshot B not yet declared or written",
        ],
    }
    id_path = FIXTURE_ROOT / "snapshot_a/selected_ids.txt"
    id_path.parent.mkdir(parents=True, exist_ok=True)
    id_path.write_text(selected_text, encoding="utf-8")
    REPORT_ROOT.mkdir(parents=True, exist_ok=True)
    atomic_write_json(REPORT_ROOT / "fixture_manifest.json", fixture_manifest)
    raw_manifest = write_raw_snapshot("snapshot_a", records, windows, source_manifest)
    print(json.dumps({
        "selected": len(selected),
        "selected_id_list_sha256": selected_hash,
        "train_population_assertion": details["assertion"],
        "raw_windows": len(raw_manifest["windows"]),
    }, indent=2))


def english_description(cve: dict[str, Any]) -> tuple[int, str]:
    for index, item in enumerate(cve.get("descriptions", [])):
        if item.get("lang") == "en":
            return index, str(item.get("value", ""))
    raise AssertionError(f"no English description for {cve.get('id')}")


def primary_cwe(cve: dict[str, Any]) -> str:
    values = []
    for weakness in cve.get("weaknesses", []):
        for item in weakness.get("description", []):
            value = str(item.get("value", ""))
            if item.get("lang") == "en" and value.startswith("CWE-") and value[4:].isdigit():
                values.append(value)
    unique = sorted(set(values))
    if len(unique) != 1:
        raise AssertionError(f"expected one CWE for {cve.get('id')}, got {unique}")
    return unique[0]


def set_single_cwe(cve: dict[str, Any], cwe: str) -> None:
    cve["weaknesses"] = [{
        "source": "fixture@t015b",
        "type": "Primary",
        "description": [{"lang": "en", "value": cwe}],
    }]


def raw_records(snapshot: str) -> tuple[dict[str, dict[str, Any]], dict[str, str], dict[str, Any]]:
    root = FIXTURE_ROOT / snapshot / "raw"
    manifest = json.loads((root / "ingest_manifest.json").read_text())
    records: dict[str, dict[str, Any]] = {}
    windows: dict[str, str] = {}
    for window in manifest["windows"]:
        window_name = f"{window['pub_start']}_{window['pub_end']}"
        for page_path in sorted((root / window_name).glob("page_*.json")):
            for vulnerability in json.loads(page_path.read_text())["vulnerabilities"]:
                cve_id = vulnerability["cve"]["id"]
                records[cve_id] = vulnerability
                windows[cve_id] = window_name
    return records, windows, manifest


def declare_command() -> None:
    fixture_report = json.loads((REPORT_ROOT / "fixture_manifest.json").read_text())
    source_manifest = json.loads((SOURCE_RAW / "ingest_manifest.json").read_text())
    id_bytes = (FIXTURE_ROOT / "snapshot_a/selected_ids.txt").read_bytes()
    if sha256_bytes(id_bytes) != fixture_report["selected_id_list_sha256"]:
        raise AssertionError("frozen selected ID list hash changed")

    records_a, windows_a, manifest_a = raw_records("snapshot_a")
    normalized = {row["cve_id"]: row for row in read_jsonl(FIXTURE_ROOT / "snapshot_a/processed/normalized.jsonl")}
    processed = {
        split: {row["cve_id"]: row for row in read_jsonl(FIXTURE_ROOT / f"snapshot_a/processed/{split}.jsonl")}
        for split in ("train", "val", "test")
    }
    sft = {
        split: {row["cve_id"]: row for row in read_jsonl(FIXTURE_ROOT / f"snapshot_a/sft/{split}.jsonl")}
        for split in ("train", "val", "test")
    }
    labels = json.loads((FIXTURE_ROOT / "snapshot_a/labels.json").read_text())["selected"]

    train_rows = list(processed["train"].values())
    by_hash: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in train_rows:
        by_hash[row["description_norm_hash"]].append(row)
    duplicate_groups = [
        sorted(members, key=lambda row: (row["published"], row["cve_id"]))
        for members in by_hash.values() if len(members) > 1
    ]
    duplicate_groups.sort(key=lambda members: (-len(members), members[0]["cve_id"]))
    if not duplicate_groups:
        raise AssertionError("no processed train duplicate group available for description case")
    description_group = duplicate_groups[0]
    description_target = description_group[0]["cve_id"]

    reserved = {description_target}
    train_sft_ids = set(sft["train"])
    train_singletons = [
        row for row in train_rows
        if len(by_hash[row["description_norm_hash"]]) == 1 and row["cve_id"] not in reserved
    ]
    train_singletons.sort(key=lambda row: row["cve_id"])

    def take_train(predicate=lambda row: True, require_sft: bool = False) -> dict[str, Any]:
        for row in train_singletons:
            if row["cve_id"] in reserved:
                continue
            if require_sft and row["cve_id"] not in train_sft_ids:
                continue
            if predicate(row):
                reserved.add(row["cve_id"])
                return row
        raise AssertionError("no train case candidate")

    cwe_target = take_train(lambda row: row["cwe_id"] != labels[0], require_sft=True)
    multi_target = take_train(require_sft=True)
    rejected_target = take_train(require_sft=True)

    test_rows = sorted(processed["test"].values(), key=lambda row: row["cve_id"])
    kev_target = next(row for row in test_rows if not row["is_kev"] and row["cve_id"] not in reserved)
    reserved.add(kev_target["cve_id"])
    cvss_target = next(row for row in test_rows if row["cve_id"] not in reserved)
    reserved.add(cvss_target["cve_id"])
    unchanged_target = next(row for row in test_rows if row["cve_id"] not in reserved)
    reserved.add(unchanged_target["cve_id"])
    val_target = next(
        row for row in sorted(processed["val"].values(), key=lambda row: row["cve_id"])
        if len(by_hash.get(row["description_norm_hash"], [])) <= 1 and row["cve_id"] not in reserved
    )
    reserved.add(val_target["cve_id"])
    missing_target = next(
        row for row in normalized.values()
        if row["is_rejected"] and row["cve_id"] not in reserved
    )

    records_b = copy.deepcopy(records_a)
    cases: list[dict[str, Any]] = []

    def add_case(
        case_id: str, change_type: str, cve_id: str, field: str, old: Any, new: Any,
        local: str, global_effect: str, composition: str, byte: str,
    ) -> None:
        cases.append({
            "case_id": case_id,
            "change_type": change_type,
            "cve_id": cve_id,
            "changed_raw_field": field,
            "old_value": old,
            "new_value": new,
            "expected_local_effect": local,
            "expected_global_effect": global_effect,
            "expected_composition_change": composition,
            "expected_byte_change": byte,
            "declared_before_snapshot_b_write": True,
        })

    # INSERT: clone a valid row but give it a unique ID, date, and description.
    insert_source = records_a[cwe_target["cve_id"]]["cve"]
    insert_cve = copy.deepcopy(insert_source)
    insert_id = "CVE-2024-999999"
    if insert_id in records_a:
        raise AssertionError(f"synthetic insert ID already exists: {insert_id}")
    insert_cve["id"] = insert_id
    insert_cve["published"] = "2024-06-15T12:00:00.000"
    insert_cve["lastModified"] = "2026-09-19T00:00:00.000"
    index, old_description = english_description(insert_cve)
    insert_cve["descriptions"][index]["value"] = old_description + " [T-015B INSERT unique text]"
    records_b[insert_id] = {"cve": insert_cve}
    windows_a[insert_id] = window_for_date(source_manifest, insert_cve["published"])
    add_case(
        "C01_INSERT", "INSERT", insert_id, "entire CVE object", None, insert_cve,
        "normalize, eligibility, and train split add one row",
        "train label count +1; label boundary re-evaluated; sampling globally redrawn",
        "yes: one eligible singleton enters the train population",
        "yes: sampled membership and manifest are expected to change",
    )

    # Description change: move the earliest survivor out of a complete duplicate group.
    target_cve = records_b[description_target]["cve"]
    desc_index, old_description = english_description(target_cve)
    new_description = old_description + " [T-015B survivor moved to a unique hash]"
    target_cve["descriptions"][desc_index]["value"] = new_description
    add_case(
        "C02_DESCRIPTION_UPDATE", "UPDATE", description_target,
        "descriptions[lang=en].value", old_description, new_description,
        "description and description_norm_hash recompute",
        "old and new hash groups recompute; old-group survivor changes; train sampling redraws",
        "yes: the old duplicate group gains a different survivor while the target becomes a singleton",
        "yes: prompt text and globally sampled output change",
    )

    # Single-label CWE change, kept within the selected label set.
    target_cve = records_b[cwe_target["cve_id"]]["cve"]
    old_cwe = primary_cwe(target_cve)
    new_cwe = next(label for label in labels if label != old_cwe)
    set_single_cwe(target_cve, new_cwe)
    add_case(
        "C03_CWE_UPDATE", "UPDATE", cwe_target["cve_id"], "weaknesses", old_cwe, new_cwe,
        "cwe_id changes while eligibility remains single-label",
        "two train class counts move by one; top-label boundary re-evaluated but expected stable",
        "yes: class assignment changes; membership is otherwise unchanged",
        "yes: completion changes if the row remains sampled",
    )

    # Multi-label change removes a train row from eligibility.
    target_cve = records_b[multi_target["cve_id"]]["cve"]
    old_cwe = primary_cwe(target_cve)
    second_cwe = next(label for label in labels if label != old_cwe)
    set_single_cwe(target_cve, old_cwe)
    target_cve["weaknesses"][0]["description"].append({"lang": "en", "value": second_cwe})
    add_case(
        "C04_MULTI_LABEL_UPDATE", "UPDATE", multi_target["cve_id"], "weaknesses",
        [old_cwe], sorted([old_cwe, second_cwe]),
        "label_status becomes multi and the row leaves eligibility",
        "one train class count decreases; label boundary re-evaluated; sampling globally redrawn",
        "yes: one row leaves the train population",
        "yes: sampled membership and manifest are expected to change",
    )

    # Rejection removes another train row from eligibility.
    target_cve = records_b[rejected_target["cve_id"]]["cve"]
    old_status = target_cve.get("vulnStatus")
    target_cve["vulnStatus"] = "Rejected"
    add_case(
        "C05_REJECTED_UPDATE", "UPDATE", rejected_target["cve_id"], "vulnStatus",
        old_status, "Rejected",
        "is_rejected becomes true and the row leaves eligibility",
        "one train class count decreases; label boundary re-evaluated; sampling globally redrawn",
        "yes: one row leaves the train population",
        "yes: sampled membership and manifest are expected to change",
    )

    # KEV byte-only case is placed in unsampled test so it is guaranteed to serialize.
    target_cve = records_b[kev_target["cve_id"]]["cve"]
    old_kev = target_cve.get("cisaExploitAdd")
    new_kev = "2026-09-19"
    target_cve["cisaExploitAdd"] = new_kev
    add_case(
        "C06_KEV_UPDATE", "UPDATE", kev_target["cve_id"], "cisaExploitAdd",
        old_kev, new_kev,
        "is_kev and kev_date_added recompute; eligibility and membership stay unchanged",
        "none: test membership is unsampled and label selection is unaffected",
        "no: all ID sets, labels, splits, and class membership remain unchanged",
        "yes: the serialized test row changes is_kev from false to true",
    )

    # CVSS-only negative control.
    target_cve = records_b[cvss_target["cve_id"]]["cve"]
    metrics = target_cve.setdefault("metrics", {})
    items = metrics.setdefault("cvssMetricV31", [])
    if not items:
        items.append({"cvssData": {"version": "3.1", "baseScore": 5.0, "baseSeverity": "MEDIUM"}})
    cvss_data = items[0].setdefault("cvssData", {})
    old_cvss = copy.deepcopy(cvss_data)
    old_score = float(cvss_data.get("baseScore", 5.0))
    new_score = 9.9 if old_score != 9.9 else 1.1
    cvss_data["baseScore"] = new_score
    cvss_data["baseSeverity"] = "CRITICAL" if new_score >= 9.0 else "LOW"
    add_case(
        "C07_CVSS_NEGATIVE_CONTROL", "UPDATE", cvss_target["cve_id"],
        "metrics.cvssMetricV31[0].cvssData", old_cvss, copy.deepcopy(cvss_data),
        "normalized CVSS fields change, but no dataset-relevant field changes",
        "none",
        "no",
        "no: CVSS is absent from SFT rows and manifest dependencies",
    )

    # Explicit unchanged control.
    unchanged_cve = copy.deepcopy(records_b[unchanged_target["cve_id"]]["cve"])
    add_case(
        "C08_UNCHANGED", "UNCHANGED", unchanged_target["cve_id"], "none",
        unchanged_cve, unchanged_cve,
        "none", "none", "no", "no",
    )

    # Missing is removed from raw B, but the detector must stop before incremental application.
    missing_cve_id = missing_target["cve_id"]
    missing_raw = records_b.pop(missing_cve_id)["cve"]
    windows_a.pop(missing_cve_id)
    add_case(
        "C09_MISSING_REVIEW", "MISSING", missing_cve_id, "entire CVE object",
        missing_raw, None,
        "record and surface the absence; do not apply a deletion",
        "incremental application stops for a human decision",
        "review required; no incremental composition claim is made",
        "review required; no incremental byte claim is made",
    )

    # Added boundary case requested by the handoff: val -> train.
    target_cve = records_b[val_target["cve_id"]]["cve"]
    old_published = target_cve["published"]
    new_published = "2024-12-31T23:59:59.000"
    target_cve["published"] = new_published
    windows_a[val_target["cve_id"]] = window_for_date(source_manifest, new_published)
    add_case(
        "C10_PUBLISHED_BOUNDARY_UPDATE", "UPDATE", val_target["cve_id"], "published",
        old_published, new_published,
        "normalized published date changes and temporal assignment moves val to train",
        "train label count +1; label boundary and train/val sampling globally re-evaluated",
        "yes: split membership changes",
        "yes: train/val membership and serialized published value change",
    )

    case_document = {
        "task": "T-015B",
        "contract": "docs/CHANGE_MODEL.md §8 plus the requested published-boundary extension",
        "canonical_case_count": 9,
        "extension_case_count": 1,
        "total_case_count": len(cases),
        "selected_id_list_sha256_verified_before_declaration": fixture_report["selected_id_list_sha256"],
        "snapshot_b_written_after_this_declaration_was_materialized_in_memory": True,
        "cases": cases,
    }
    # Persist expectations before any B page is written.
    atomic_write_json(REPORT_ROOT / "change_cases.json", case_document)

    window_ids: dict[str, list[str]] = defaultdict(list)
    for cve_id, window in windows_a.items():
        window_ids[window].append(cve_id)
    b_manifest = write_raw_snapshot("snapshot_b", records_b, window_ids, source_manifest)
    (FIXTURE_ROOT / "snapshot_b/selected_ids.txt").write_text(
        "".join(f"{cve_id}\n" for cve_id in sorted(records_b)), encoding="utf-8"
    )
    print(json.dumps({
        "cases": len(cases),
        "snapshot_b_records": len(records_b),
        "snapshot_b_windows": len(b_manifest["windows"]),
        "description_group": [row["cve_id"] for row in description_group],
        "description_survivor_before": description_target,
    }, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("select", "declare-and-build-b"))
    args = parser.parse_args()
    if args.command == "select":
        select_command()
    else:
        declare_command()


if __name__ == "__main__":
    main()

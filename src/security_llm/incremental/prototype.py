"""A deliberately small incremental implementation for the T-015 fixture.

The implementation keeps the reference pipeline's dataset rules.  It reuses
unchanged normalized and processed rows, replaces affected hash groups, and
calls the existing global label-selection and sampling implementations in
full.  It is a prototype, not a service or a persistent state store.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from security_llm.adapters.cwe_instruction import prompt_template_sha256
from security_llm.config import load_config
from security_llm.cwe_names import CWE_NAMES
from security_llm.data.build_sft import (
    CHANGELOG_REASON,
    _git_commit,
    sample_records,
    to_sft_row,
)
from security_llm.data.dedup import drop_internal_duplicates
from security_llm.data.manifest import dataset_hash, v2_fields
from security_llm.data.normalize import normalize_record
from security_llm.data.split import assign_split, select_labels
from security_llm.utils.io import atomic_write_json, read_jsonl, sha256_file, write_jsonl

SPLITS = ("train", "val", "test")
DATASET_FIELDS = (
    "id",
    "published",
    "descriptions[lang=en].value",
    "vulnStatus",
    "weaknesses[].type+description[lang=en].value",
    "cisaExploitAdd",
)
INTERMEDIATE_FIELDS = ("metrics.cvssMetricV31[0].cvssData",)


@dataclass(frozen=True)
class Change:
    cve_id: str
    classification: str
    changed_fields: tuple[str, ...]


def _english(cve: dict[str, Any]) -> str:
    return next(
        (str(item.get("value", "")) for item in cve.get("descriptions", []) if item.get("lang") == "en"),
        "",
    )


def _weaknesses(cve: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for weakness in cve.get("weaknesses", []):
        english = sorted(
            str(item.get("value", ""))
            for item in weakness.get("description", [])
            if item.get("lang") == "en"
        )
        if english:
            result.append({"type": weakness.get("type"), "english": english})
    return sorted(result, key=lambda item: json.dumps(item, sort_keys=True))


def _cvss(cve: dict[str, Any]) -> Any:
    values = cve.get("metrics", {}).get("cvssMetricV31", [])
    return values[0].get("cvssData", {}) if values else None


def _field_view(cve: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": cve.get("id"),
        "published": cve.get("published"),
        "descriptions[lang=en].value": _english(cve),
        "vulnStatus": cve.get("vulnStatus"),
        "weaknesses[].type+description[lang=en].value": _weaknesses(cve),
        "cisaExploitAdd": cve.get("cisaExploitAdd"),
        "metrics.cvssMetricV31[0].cvssData": _cvss(cve),
    }


def load_raw_records(raw_dir: str | Path) -> dict[str, dict[str, Any]]:
    """Load CVE objects from complete windows, matching ``normalize`` semantics."""

    root = Path(raw_dir)
    manifest = json.loads((root / "ingest_manifest.json").read_text(encoding="utf-8"))
    records: dict[str, dict[str, Any]] = {}
    for window in manifest["windows"]:
        if not window.get("complete"):
            continue
        directory = root / f"{window['pub_start']}_{window['pub_end']}"
        for page in sorted(directory.glob("page_*.json")):
            payload = json.loads(page.read_text(encoding="utf-8"))
            for wrapper in payload.get("vulnerabilities", []):
                cve = wrapper.get("cve", {})
                cve_id = str(cve.get("id", ""))
                if cve_id in records:
                    raise ValueError(f"duplicate raw CVE ID: {cve_id}")
                records[cve_id] = cve
    return records


def classify_snapshots(
    before: dict[str, dict[str, Any]], after: dict[str, dict[str, Any]]
) -> list[Change]:
    """Classify changes without using ``lastModified`` as an equality key."""

    result: list[Change] = []
    for cve_id in sorted(set(before) | set(after)):
        if cve_id not in before:
            result.append(Change(cve_id, "INSERT", ("id",)))
            continue
        if cve_id not in after:
            result.append(Change(cve_id, "MISSING_REVIEW", ()))
            continue
        old = _field_view(before[cve_id])
        new = _field_view(after[cve_id])
        changed = tuple(field for field in DATASET_FIELDS + INTERMEDIATE_FIELDS if old[field] != new[field])
        if set(changed).intersection(DATASET_FIELDS):
            classification = "UPDATE_DATASET_RELEVANT"
        elif set(changed).intersection(INTERMEDIATE_FIELDS):
            classification = "UPDATE_INTERMEDIATE_ONLY"
        else:
            classification = "UNCHANGED"
        result.append(Change(cve_id, classification, changed))
    return result


def _eligible_split(row: dict[str, Any], cfg: dict[str, Any], snapshot: str) -> str | None:
    if row["is_rejected"] or not row["description_en"] or row["label_status"] != "single":
        return None
    return assign_split(row["published"], cfg["split"], snapshot)


def _read_splits(root: Path, child: str) -> dict[str, list[dict[str, Any]]]:
    return {name: read_jsonl(root / child / f"{name}.jsonl") for name in SPLITS}


def _effective_populations(
    populations: dict[str, list[dict[str, Any]]], cfg: dict[str, Any]
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, int]]:
    train = populations["train"]
    duplicate_count = 0
    overlap_count = 0
    if cfg["dedup"]["drop_train_exact_duplicates"]:
        train, duplicate_count = drop_internal_duplicates(train)
    if cfg["dedup"]["drop_train_overlap_with_eval"]:
        eval_hashes = {row["description_norm_hash"] for row in populations["val"] + populations["test"]}
        before = len(train)
        train = [row for row in train if row["description_norm_hash"] not in eval_hashes]
        overlap_count = before - len(train)
    val = populations["val"]
    val_overlap_count = 0
    if cfg["dedup"].get("drop_val_overlap_with_test", False):
        eval_hashes = {row["description_norm_hash"] for row in populations["train"] + populations["test"]}
        before = len(val)
        val = [row for row in val if row["description_norm_hash"] not in eval_hashes]
        val_overlap_count = before - len(val)
    return (
        {"train": train, "val": val, "test": populations["test"]},
        {
            "train_exact_duplicates_dropped": duplicate_count,
            "train_overlap_with_eval_dropped": overlap_count,
            "val_overlap_with_eval_dropped": val_overlap_count,
        },
    )


def _incremental_groups(
    previous: dict[str, list[dict[str, Any]]],
    current: dict[str, list[dict[str, Any]]],
    changed_ids: set[str],
    cfg: dict[str, Any],
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, int], dict[str, Any]]:
    """Replace only affected old/new description-hash groups."""

    previous_effective, _ = _effective_populations(previous, cfg)
    old_index = {row["cve_id"]: row for rows in previous.values() for row in rows}
    new_index = {row["cve_id"]: row for rows in current.values() for row in rows}
    affected = {
        row["description_norm_hash"]
        for cve_id in changed_ids
        for row in (old_index.get(cve_id), new_index.get(cve_id))
        if row is not None
    }
    untouched = {
        split: [row for row in rows if row["description_norm_hash"] not in affected]
        for split, rows in previous_effective.items()
    }
    restricted = {
        split: [row for row in rows if row["description_norm_hash"] in affected]
        for split, rows in current.items()
    }
    replacement, _ = _effective_populations(restricted, cfg)
    result = {
        split: sorted(untouched[split] + replacement[split], key=lambda row: (row["published"], row["cve_id"]))
        for split in SPLITS
    }
    # Counts are derived from indexes over the current state; only affected groups
    # are passed through the survivor/overlap transformation above.
    _, counts = _effective_populations(current, cfg)
    group_rows = {
        split: sum(row["description_norm_hash"] in affected for row in current[split])
        for split in SPLITS
    }
    accounting = {
        "affected_hash_groups": len(affected),
        "affected_hashes": sorted(affected),
        "group_recomputed_rows_by_split": group_rows,
        "group_recomputed_rows_total": sum(group_rows.values()),
    }
    return result, counts, accounting


def _serialization_key(row: dict[str, Any], selected: list[str], max_chars: int) -> tuple[Any, ...]:
    return (
        row["cve_id"], row["cwe_id"], row["published"], row["description_en"][:max_chars],
        len(row["description_en"]) > max_chars, row["is_kev"], row["split"], tuple(selected),
    )


def _write_manifest(
    cfg: dict[str, Any], config_path: str | Path, selected: list[str],
    processed: dict[str, list[dict[str, Any]]], effective: dict[str, list[dict[str, Any]]],
    sampled: dict[str, list[dict[str, Any]]],
    output_rows: dict[str, list[dict[str, Any]]], dedup_counts: dict[str, int], snapshot: str,
) -> dict[str, Any]:
    sft_dir = Path(cfg["paths"]["sft_dir"])
    files: dict[str, dict[str, Any]] = {}
    distributions: dict[str, dict[str, int]] = {}
    for name in SPLITS:
        output = sft_dir / f"{name}.jsonl"
        write_jsonl(output, output_rows[name])
        files[name] = {"path": str(output), "rows": len(output_rows[name]), "sha256": sha256_file(output)}
        distributions[name] = dict(Counter(row["cwe_id"] for row in output_rows[name]))
    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "git_commit": _git_commit(),
        "dataset_snapshot": snapshot,
        "data_config_sha256": sha256_file(config_path),
        "prompt_template_sha256": prompt_template_sha256(selected),
        "labels": selected,
        "files": files,
        "counts": {name: len(sampled[name]) for name in SPLITS},
        "population_counts": {
            "train": len(processed["train"]),
            "val": len(effective["val"]),
            "test": len(processed["test"]),
        },
        "class_distribution": distributions,
        "sampling": cfg["sft"],
        "dedup": dedup_counts,
        "dataset_version": "1.1",
        "changelog": [{"version": "1.1", "date": date.today().isoformat(), "reason": CHANGELOG_REASON}],
    }
    manifest.update(v2_fields(cfg, snapshot, selected, files, manifest["counts"]))
    atomic_write_json(cfg["paths"]["manifest"], manifest)
    return manifest


def run_incremental(
    cfg: dict[str, Any], config_path: str | Path, previous_root: str | Path,
    previous_raw_dir: str | Path, current_raw_dir: str | Path,
) -> dict[str, Any]:
    """Apply one snapshot delta, or stop without writes when a row is missing."""

    previous_root = Path(previous_root)
    before = load_raw_records(previous_raw_dir)
    after = load_raw_records(current_raw_dir)
    changes = classify_snapshots(before, after)
    counts = dict(sorted(Counter(change.classification for change in changes).items()))
    missing = [change.cve_id for change in changes if change.classification == "MISSING_REVIEW"]
    base_result: dict[str, Any] = {
        "apply_status": "REVIEW_REQUIRED" if missing else "COMPLETED",
        "classification_counts": counts,
        "changes": [asdict(change) for change in changes if change.classification != "UNCHANGED"],
        "missing_ids": missing,
    }
    if missing:
        base_result["completed"] = False
        base_result["writes_performed"] = False
        return base_result

    manifest = json.loads((Path(current_raw_dir) / "ingest_manifest.json").read_text(encoding="utf-8"))
    snapshot = manifest["snapshot_date"]
    previous_normalized = read_jsonl(previous_root / "processed/normalized.jsonl")
    previous_by_id = {row["cve_id"]: row for row in previous_normalized}
    locally_changed = {
        change.cve_id for change in changes
        if change.classification in {"INSERT", "UPDATE_DATASET_RELEVANT", "UPDATE_INTERMEDIATE_ONLY"}
    }
    for cve_id in locally_changed:
        row = normalize_record(after[cve_id], cfg)
        if row is None:
            previous_by_id.pop(cve_id, None)
        else:
            previous_by_id[cve_id] = row
    normalized = sorted(previous_by_id.values(), key=lambda row: (row["published"], row["cve_id"]))
    write_jsonl(Path(cfg["paths"]["processed_dir"]) / "normalized.jsonl", normalized)

    # Label selection is intentionally GLOBAL_RECOMPUTE.  The eligibility/split
    # values inspected here feed that global reduction; persisted local rows below
    # are patched only for changed IDs when the selected label set is stable.
    eligible_with_split = [
        {**row, "split": split}
        for row in normalized
        if (split := _eligible_split(row, cfg, snapshot)) is not None
    ]
    selected, label_counts = select_labels(
        [row for row in eligible_with_split if row["split"] == "train"],
        int(cfg["labels"]["top_k"]), int(cfg["labels"]["min_train_samples_per_class"]),
    )
    if len(selected) < 2:
        raise AssertionError(f"At least two labels are required; selected {selected}")
    missing_names = [cwe for cwe in selected if cwe not in CWE_NAMES]
    if missing_names:
        raise KeyError(f"Missing CWE names: {missing_names}")
    previous_labels = json.loads((previous_root / "labels.json").read_text(encoding="utf-8"))["selected"]
    previous_processed = _read_splits(previous_root, "processed")
    if selected == previous_labels:
        cached = {row["cve_id"]: row for rows in previous_processed.values() for row in rows}
        for cve_id in locally_changed:
            cached.pop(cve_id, None)
            row = previous_by_id.get(cve_id)
            if row is None:
                continue
            split = _eligible_split(row, cfg, snapshot)
            if split is not None and row["cwe_id"] in selected:
                cached[cve_id] = {**row, "split": split}
        processed = {
            split: sorted(
                [row for row in cached.values() if row["split"] == split],
                key=lambda row: (row["published"], row["cve_id"]),
            )
            for split in SPLITS
        }
        processed_mode = "LOCAL_PATCH"
    else:
        processed = {
            split: [row for row in eligible_with_split if row["split"] == split and row["cwe_id"] in selected]
            for split in SPLITS
        }
        processed_mode = "GLOBAL_INVALIDATION_FROM_LABEL_SET_CHANGE"
    for split in SPLITS:
        write_jsonl(Path(cfg["paths"]["processed_dir"]) / f"{split}.jsonl", processed[split])
    labels = {
        "selected": selected,
        "train_counts": {cwe: label_counts.get(cwe, 0) for cwe in selected},
        "top_k_requested": int(cfg["labels"]["top_k"]),
        "top_k_effective": len(selected),
        "min_train_samples_per_class": int(cfg["labels"]["min_train_samples_per_class"]),
        "train_period": cfg["split"]["train"],
        "names": {cwe: CWE_NAMES[cwe] for cwe in selected},
    }
    atomic_write_json(cfg["paths"]["labels_file"], labels)

    if selected == previous_labels:
        effective, dedup_counts, group_accounting = _incremental_groups(
            previous_processed, processed, locally_changed, cfg
        )
    else:
        effective, dedup_counts = _effective_populations(processed, cfg)
        all_hashes = {row["description_norm_hash"] for rows in processed.values() for row in rows}
        group_accounting = {
            "affected_hash_groups": len(all_hashes),
            "affected_hashes": sorted(all_hashes),
            "group_recomputed_rows_by_split": {split: len(processed[split]) for split in SPLITS},
            "group_recomputed_rows_total": sum(map(len, processed.values())),
        }

    seed = int(cfg["seed"])
    sampled = {
        "train": sample_records(
            effective["train"], cfg["sft"]["train_max_samples"], cfg["sft"]["sampling"],
            random.Random(seed), cfg["sft"].get("balanced_max_per_class"),
        ),
        "val": sample_records(effective["val"], cfg["sft"]["val_max_samples"], "natural", random.Random(seed)),
        "test": sample_records(effective["test"], cfg["sft"]["test_max_samples"], "natural", random.Random(seed)),
    }
    prior_sft = _read_splits(previous_root, "sft")
    prior_sft_by_id = {row["cve_id"]: row for rows in prior_sft.values() for row in rows}
    prior_processed_by_id = {row["cve_id"]: row for rows in previous_processed.values() for row in rows}
    max_chars = int(cfg["sft"]["max_description_chars"])
    output_rows: dict[str, list[dict[str, Any]]] = {}
    reused_serialized = 0
    recomputed_serialized = 0
    source_changed_serialized = 0
    sampling_cache_miss_serialized = 0
    for split in SPLITS:
        values = []
        for row in sampled[split]:
            old_source = prior_processed_by_id.get(row["cve_id"])
            old_output = prior_sft_by_id.get(row["cve_id"])
            if (
                old_source is not None and old_output is not None and selected == previous_labels
                and _serialization_key(old_source, previous_labels, max_chars)
                == _serialization_key(row, selected, max_chars)
            ):
                values.append(old_output)
                reused_serialized += 1
            else:
                values.append(to_sft_row(row, selected, max_chars))
                recomputed_serialized += 1
                if row["cve_id"] in locally_changed:
                    source_changed_serialized += 1
                else:
                    sampling_cache_miss_serialized += 1
        output_rows[split] = values
    built_manifest = _write_manifest(
        cfg, config_path, selected, processed, effective, sampled, output_rows, dedup_counts, snapshot
    )
    base_result.update({
        "completed": True,
        "writes_performed": True,
        "selected_labels_changed": selected != previous_labels,
        "processed_update_mode": processed_mode,
        "global_recomputed_stages": ["label_selection", "sft_sampling"],
        "work_accounting": {
            "input_rows": len(after),
            "normalized_rows_reused": len(normalized) - len(locally_changed),
            "normalized_rows_locally_recomputed": len(locally_changed),
            "processed_rows_reused": sum(
                row["cve_id"] not in locally_changed for rows in processed.values() for row in rows
            ),
            "processed_rows_locally_recomputed": sum(
                row["cve_id"] in locally_changed for rows in processed.values() for row in rows
            ),
            **group_accounting,
            "sft_rows_reused": reused_serialized,
            "sft_rows_serialized": recomputed_serialized,
            "sft_source_changed_rows_locally_recomputed": source_changed_serialized,
            "sft_unchanged_rows_materialized_after_global_sampling": sampling_cache_miss_serialized,
            "global_label_selection_input_rows": len(normalized),
            "global_sampling_input_rows": sum(len(rows) for rows in effective.values()),
            "global_recomputed_stages": 2,
            "global_stage_share": 2 / 2,
        },
        "manifest": built_manifest,
    })
    return base_result


def _overrides(path: Path) -> list[str]:
    values = json.loads(path.read_text(encoding="utf-8"))
    return [f"{key}={json.dumps(value)}" for key, value in values.items()]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--override-file", required=True)
    parser.add_argument("--previous-root", required=True)
    parser.add_argument("--previous-raw", required=True)
    parser.add_argument("--current-raw", required=True)
    parser.add_argument("--result", required=True)
    args = parser.parse_args()
    cfg = load_config(args.config, _overrides(Path(args.override_file)))
    result = run_incremental(
        cfg, args.config, args.previous_root, args.previous_raw, args.current_raw
    )
    atomic_write_json(args.result, result)
    print(json.dumps({key: result[key] for key in ("apply_status", "completed", "classification_counts")}, indent=2))


if __name__ == "__main__":
    main()

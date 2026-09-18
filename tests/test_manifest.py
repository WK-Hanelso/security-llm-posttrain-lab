import hashlib
import json
from pathlib import Path

from security_llm.data.manifest import dataset_hash, v2_fields, verify_files
from security_llm.utils.io import sha256_file


def test_checked_in_manifest_has_v2_keys_and_matches_files():
    manifest = json.loads(Path("manifests/dataset_manifest.json").read_text(encoding="utf-8"))
    required = {
        "schema_version",
        "source",
        "snapshot_time",
        "label_policy",
        "split_policy",
        "dedup_policy",
        "dataset_hash",
        "validation_count",
    }
    assert required <= manifest.keys()
    assert manifest["dataset_hash"] == dataset_hash(manifest["files"])
    verify_files(manifest)


def test_manifest_v2_fields_and_dataset_hash_are_deterministic(tmp_path):
    files = {}
    counts = {"train": 1, "val": 1, "test": 1}
    for split in ("train", "val", "test"):
        path = tmp_path / f"{split}.jsonl"
        path.write_text(f'{{"split":"{split}"}}\n', encoding="utf-8")
        files[split] = {"path": str(path), "rows": 1, "sha256": sha256_file(path)}
    cfg = {
        "filter": {
            "placeholder_cwes": ["NVD-CWE-noinfo", "NVD-CWE-Other"],
            "single_label_only": True,
        },
        "labels": {"top_k": 15, "min_train_samples_per_class": 200},
        "split": {
            "train": ["2020-01-01", "2024-12-31"],
            "val": ["2025-01-01", "2025-12-31"],
            "test": ["2026-01-01", None],
        },
    }

    expected = hashlib.sha256(
        "".join(files[name]["sha256"] for name in ("train", "val", "test")).encode("ascii")
    ).hexdigest()
    assert dataset_hash(files) == expected
    assert dataset_hash(files) == dataset_hash(files)

    additions = v2_fields(cfg, "2026-09-17", ["CWE-79"], files, counts)
    assert {
        "schema_version",
        "source",
        "snapshot_time",
        "label_policy",
        "split_policy",
        "dedup_policy",
        "dataset_hash",
        "validation_count",
    } <= additions.keys()
    assert additions["schema_version"] == "1.0"
    assert additions["source"] == "NVD CVE API 2.0"
    assert additions["snapshot_time"] == "2026-09-17"
    assert additions["dataset_hash"] == expected
    assert additions["validation_count"] == 1
    assert additions["split_policy"]["type"] == "temporal_by_published"
    assert additions["label_policy"]["selected_labels"] == ["CWE-79"]
    assert additions["dedup_policy"] == {
        "train_exact_duplicates": "drop_keep_earliest",
        "train_overlap_with_eval": "drop",
        "eval_overlap": "report_only",
    }

    verify_files({"files": files, "counts": counts})

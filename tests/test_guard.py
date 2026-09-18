import json
from pathlib import Path

import pytest

from security_llm.data.build_sft import build
from security_llm.config import load_config
from security_llm.data.dedup import text_hash
from security_llm.data.guard import check_split_invariants
from security_llm.utils.io import read_jsonl, sha256_file, write_jsonl


def _row(cve_id: str, description: str, split: str) -> dict:
    return {
        "cve_id": cve_id,
        "cwe_id": "CWE-79",
        "published": "2025-01-01",
        "description_en": description,
        "description_norm_hash": text_hash(description),
        "is_kev": False,
        "split": split,
    }


@pytest.mark.parametrize(
    ("left", "right", "pair"),
    [("train", "val", "train_val"), ("train", "test", "train_test"), ("val", "test", "val_test")],
)
def test_guard_detects_each_pair(left, right, pair):
    splits = {name: [_row(f"CVE-2026-{index + 1000}", name, name)] for index, name in enumerate(("train", "val", "test"))}
    splits[right][0]["description_norm_hash"] = splits[left][0]["description_norm_hash"]
    result = check_split_invariants(splits["train"], splits["val"], splits["test"])
    assert result["ok"] is False
    assert result["pairs"][pair]["text_hash"] == 1
    assert len(result["pairs"][pair]["examples"][0][2]) == 12


def test_guard_detects_id_overlap_and_clean_sets_pass():
    clean = {name: [_row(f"CVE-2026-{index + 2000}", name, name)] for index, name in enumerate(("train", "val", "test"))}
    assert check_split_invariants(clean["train"], clean["val"], clean["test"])["ok"] is True
    clean["test"][0]["cve_id"] = clean["train"][0]["cve_id"]
    result = check_split_invariants(clean["train"], clean["val"], clean["test"])
    assert result["pairs"]["train_test"]["cve_id"] == 1


def test_build_refuses_to_write_when_guard_fails(tmp_path):
    processed = tmp_path / "processed"
    output = tmp_path / "sft"
    processed.mkdir()
    train = [_row("CVE-2024-1000", "same description", "train")]
    val = [_row("CVE-2025-1000", "same description", "val")]
    test = [_row("CVE-2026-1000", "different", "test")]
    for name, rows in (("train", train), ("val", val), ("test", test)):
        write_jsonl(processed / f"{name}.jsonl", rows)
    labels = {"selected": ["CWE-79", "CWE-89"]}
    labels_path = processed / "labels.json"
    labels_path.write_text(json.dumps(labels), encoding="utf-8")
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "ingest_manifest.json").write_text(json.dumps({"snapshot_date": "2026-01-01"}), encoding="utf-8")
    cfg = {
        "seed": 42,
        "nvd": {"raw_dir": str(raw)},
        "filter": {"placeholder_cwes": [], "single_label_only": True},
        "labels": {"top_k": 2, "min_train_samples_per_class": 1},
        "split": {"train": ["2024-01-01", "2024-12-31"], "val": ["2025-01-01", "2025-12-31"], "test": ["2026-01-01", None]},
        "dedup": {"drop_train_exact_duplicates": False, "drop_train_overlap_with_eval": False, "drop_val_overlap_with_test": False},
        "sft": {"max_description_chars": 1500, "train_max_samples": None, "val_max_samples": None, "test_max_samples": None, "sampling": "natural", "balanced_max_per_class": 800},
        "paths": {"processed_dir": str(processed), "sft_dir": str(output), "labels_file": str(labels_path), "manifest": str(tmp_path / "manifest.json")},
    }
    with pytest.raises(ValueError, match="split invariant"):
        build(cfg, tmp_path / "data.yaml")
    assert not output.exists()
    assert not Path(cfg["paths"]["manifest"]).exists()


def test_full_rebuild_reproduces_frozen_artifacts_in_temp_dir(tmp_path, monkeypatch):
    monkeypatch.setattr("security_llm.data.build_sft._git_commit", lambda: "test")
    source_cfg = Path("configs/data.yaml")
    cfg = load_config(source_cfg)
    cfg["paths"]["sft_dir"] = str(tmp_path / "sft")
    cfg["paths"]["manifest"] = str(tmp_path / "dataset_manifest.json")
    build(cfg, source_cfg)

    rebuilt = Path(cfg["paths"]["sft_dir"])
    assert sha256_file(rebuilt / "train.jsonl") == sha256_file("data/sft/train.jsonl")
    assert sha256_file(rebuilt / "val.jsonl") == sha256_file("data/sft/val.jsonl")

    key = lambda row: (row["cve_id"], row["cwe_id"], row["prompt"])
    rebuilt_test = {key(row) for row in read_jsonl(rebuilt / "test.jsonl")}
    frozen_test = {key(row) for row in read_jsonl("data/sft/test.jsonl")}
    assert rebuilt_test == frozen_test

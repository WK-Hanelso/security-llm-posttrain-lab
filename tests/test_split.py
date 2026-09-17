from security_llm.data.split import assign_split, select_labels


SPLITS = {
    "train": ["2020-01-01", "2024-12-31"],
    "val": ["2025-01-01", "2025-12-31"],
    "test": ["2026-01-01", None],
}


def test_split_boundaries():
    assert assign_split("2024-12-31", SPLITS, "2026-09-17") == "train"
    assert assign_split("2025-01-01", SPLITS, "2026-09-17") == "val"
    assert assign_split("2026-01-01", SPLITS, "2026-09-17") == "test"
    assert assign_split("2019-12-31", SPLITS, "2026-09-17") is None


def test_select_labels_only_uses_given_train_records_and_minimum():
    train = [{"cwe_id": "CWE-79"}] * 3 + [{"cwe_id": "CWE-89"}] * 2 + [{"cwe_id": "CWE-20"}]
    selected, counts = select_labels(train, top_k=3, min_count=2)
    assert selected == ["CWE-79", "CWE-89"]
    assert counts == {"CWE-79": 3, "CWE-89": 2, "CWE-20": 1}


import json
from pathlib import Path

from security_llm.adapters.cwe_instruction import build_user_prompt, serialize_label


def _read_rows(path: str):
    with Path(path).open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def test_adapter_matches_stored_sft_strings():
    train_rows = _read_rows("data/sft/train.jsonl")
    first = train_rows[0]
    first_cwe_79 = next(row for row in train_rows if row["cwe_id"] == "CWE-79")

    assert serialize_label("CWE-79") == first_cwe_79["completion"]
    assert serialize_label(first["cwe_id"]) == first["completion"]

    labels = json.loads(Path("data/processed/labels.json").read_text(encoding="utf-8"))["selected"]
    sampled = _read_rows("data/sft/val.jsonl")[136]
    assert build_user_prompt(sampled["description"], labels) == sampled["prompt"]

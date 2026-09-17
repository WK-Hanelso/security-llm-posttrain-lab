import json
from pathlib import Path

from security_llm.config import load_config
from security_llm.data.normalize import normalize_record


def fixture_rows():
    page = json.loads(Path("tests/fixtures/nvd_sample.json").read_text(encoding="utf-8"))
    cfg = load_config("configs/data.yaml")
    return [normalize_record(item["cve"], cfg) for item in page["vulnerabilities"]]


def test_normalize_record_schema_cases():
    rows = fixture_rows()
    assert rows[0]["description_en"] == "A reflected script issue."
    assert rows[0]["cwe_id"] == "CWE-79"
    assert rows[0]["cvss_v31_base_score"] == 6.1
    assert rows[1]["label_status"] == "single" and rows[1]["cwe_all"] == ["CWE-89"]
    assert rows[2]["label_status"] == "multi" and rows[2]["cwe_id"] is None
    assert rows[3]["placeholder_only"] and rows[3]["label_status"] == "placeholder_only"
    assert rows[4]["label_status"] == "none"
    assert rows[5]["is_rejected"]
    assert rows[6]["is_kev"] and rows[6]["kev_date_added"] == "2024-07-10"
    assert rows[7]["description_en"] == ""
    assert rows[8] is None


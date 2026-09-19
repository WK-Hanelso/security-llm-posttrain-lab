from security_llm.spark.normalize import _omit_schema_nulls


def test_omit_schema_nulls_restores_missing_json_fields():
    value = {
        "id": "CVE-2024-0001",
        "weaknesses": None,
        "descriptions": [{"lang": "en", "value": "description"}, {"lang": None, "value": None}],
        "metrics": {"cvssMetricV31": None},
    }

    assert _omit_schema_nulls(value) == {
        "id": "CVE-2024-0001",
        "descriptions": [{"lang": "en", "value": "description"}, {}],
        "metrics": {},
    }

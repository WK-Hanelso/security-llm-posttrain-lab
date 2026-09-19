from security_llm.incremental.prototype import classify_snapshots


def _record(cve_id: str = "CVE-2024-1234") -> dict:
    return {
        "id": cve_id,
        "published": "2024-01-01T00:00:00.000",
        "lastModified": "2024-01-01T00:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "example"}],
        "weaknesses": [
            {"type": "Primary", "description": [{"lang": "en", "value": "CWE-79"}]}
        ],
        "metrics": {
            "cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]
        },
    }


def test_classification_ignores_last_modified_alone():
    before = _record()
    after = _record()
    after["lastModified"] = "2026-09-19T00:00:00.000"

    change = classify_snapshots({before["id"]: before}, {after["id"]: after})[0]

    assert change.classification == "UNCHANGED"
    assert change.changed_fields == ()


def test_classification_keeps_cvss_as_intermediate_only():
    before = _record()
    after = _record()
    after["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"] = 9.8

    change = classify_snapshots({before["id"]: before}, {after["id"]: after})[0]

    assert change.classification == "UPDATE_INTERMEDIATE_ONLY"
    assert change.changed_fields == ("metrics.cvssMetricV31[0].cvssData",)


def test_classification_surfaces_missing_without_calling_it_delete():
    before = _record()

    change = classify_snapshots({before["id"]: before}, {})[0]

    assert change.classification == "MISSING_REVIEW"

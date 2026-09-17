import pytest

from security_llm.eval.verifier import verify


ALLOWED = {"CWE-79", "CWE-89"}


@pytest.mark.parametrize(
    ("raw", "pred", "flag"),
    [
        ('{"cwe_id": "CWE-79"}', "CWE-79", None),
        ('```json\n{"cwe_id": "CWE-79"}\n```', "CWE-79", None),
        ('<think>reasoning</think>{"cwe_id": "CWE-79"}', "CWE-79", "think_block_present"),
        ('{"cwe_id": "cwe-79"}', "CWE-79", None),
        ('{"cwe_id": 79}', "CWE-79", None),
        ('{"cwe_id": "CWE-79, CWE-89"}', None, "multiple_cwe"),
        ('{"cwe_id": ["CWE-79"]}', None, "multiple_cwe"),
        ('{"id": "CWE-79"}', None, "missing_key"),
        ("CWE-79", None, "not_json"),
        ('{"cwe_id": "CWE-20"}', "CWE-20", "label_not_allowed"),
        ('{"cwe_id": "CWE-79"} trailing text', "CWE-79", None),
    ],
)
def test_verify_cases(raw, pred, flag):
    result = verify(raw, "CWE-79", ALLOWED)
    assert result["pred"] == pred
    if flag:
        assert flag in result["error_flags"]
    assert result["exact_match"] == (pred == "CWE-79" and pred in ALLOWED)


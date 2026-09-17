from security_llm.data.dedup import drop_internal_duplicates, find_overlap, normalize_text, text_hash


def test_normalize_text_equivalences():
    assert normalize_text("  FOO\nbar\t") == normalize_text("foo bar")
    assert normalize_text("ＡＢＣ") == "abc"


def test_find_overlap_for_id_and_hash():
    a = [{"cve_id": "CVE-A", "description_norm_hash": "h1"}]
    b = [{"cve_id": "CVE-A", "description_norm_hash": "other"}, {"cve_id": "CVE-B", "description_norm_hash": "h1"}]
    assert find_overlap(a, b, "cve_id") == [("CVE-A", "CVE-A")]
    assert find_overlap(a, b, "description_norm_hash") == [("CVE-A", "CVE-B")]


def test_drop_internal_duplicates_keeps_earliest():
    rows = [
        {"cve_id": "CVE-2021-0002", "published": "2021-01-02", "description_norm_hash": text_hash("same")},
        {"cve_id": "CVE-2021-0001", "published": "2021-01-01", "description_norm_hash": text_hash("SAME")},
        {"cve_id": "CVE-2021-0003", "published": "2021-01-03", "description_norm_hash": text_hash("different")},
    ]
    kept, dropped = drop_internal_duplicates(rows)
    assert [row["cve_id"] for row in kept] == ["CVE-2021-0001", "CVE-2021-0003"]
    assert dropped == 1


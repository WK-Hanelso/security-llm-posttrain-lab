from security_llm.eval.generate import _select_rows


def test_select_rows_uses_reproducible_uniform_shuffle_before_limit():
    rows = [{"id": value} for value in range(10)]

    selected = _select_rows(rows, limit=4, subsample_seed=42)

    assert [row["id"] for row in selected] == [7, 3, 2, 8]
    assert [row["id"] for row in rows] == list(range(10))
    assert _select_rows(rows, limit=4, subsample_seed=42) == selected

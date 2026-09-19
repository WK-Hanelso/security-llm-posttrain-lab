import numpy as np

from security_llm.bench.audit_a_exact_truth import _top_k_indices


def test_top_k_indices_uses_reference_order_to_break_boundary_ties():
    scores = np.asarray([0.9, 0.8, 0.8, 0.7, 0.6], dtype=np.float64)

    result = _top_k_indices(scores, 2)

    assert result.tolist() == [0, 1]


def test_top_k_indices_orders_selected_scores_descending():
    scores = np.asarray([0.2, 0.9, 0.4, 0.8], dtype=np.float64)

    result = _top_k_indices(scores, 3)

    assert result.tolist() == [1, 3, 2]

import numpy as np

from security_llm.bench.audit_a_exact_truth import _top_k_indices
from security_llm.bench.blockwise_exact import _merge_top_k


def test_top_k_indices_uses_reference_id_to_break_boundary_ties():
    scores = np.asarray([0.9, 0.8, 0.8, 0.7, 0.6], dtype=np.float64)
    reference_ids = np.asarray(["CVE-Z", "CVE-B", "CVE-A", "CVE-C", "CVE-D"])

    result = _top_k_indices(scores, 2, reference_ids)

    assert result.tolist() == [0, 2]


def test_top_k_indices_orders_selected_scores_descending():
    scores = np.asarray([0.2, 0.9, 0.4, 0.8], dtype=np.float64)
    reference_ids = np.asarray(["CVE-D", "CVE-C", "CVE-B", "CVE-A"])

    result = _top_k_indices(scores, 3, reference_ids)

    assert result.tolist() == [1, 3, 2]


def test_top_k_indices_orders_internal_ties_by_reference_id():
    scores = np.asarray([0.8, 0.9, 0.8, 0.8], dtype=np.float64)
    reference_ids = np.asarray(["CVE-C", "CVE-Z", "CVE-A", "CVE-B"])

    result = _top_k_indices(scores, 4, reference_ids)

    assert result.tolist() == [1, 2, 3, 0]


def test_blockwise_merge_uses_global_reference_ids_across_blocks():
    reference_ids = np.asarray(
        [f"CVE-{number:02d}" for number in range(20, 0, -1)] + ["CVE-00"]
    )
    first_scores = np.asarray(
        [[0.9] * 19 + [0.8]], dtype=np.float64
    )
    empty_scores = np.empty((1, 0), dtype=np.float64)
    empty_indices = np.empty((1, 0), dtype=np.int32)
    top_scores, top_indices = _merge_top_k(
        empty_scores, empty_indices, first_scores, 0, reference_ids
    )

    second_scores = np.asarray([[0.8]], dtype=np.float64)
    merged_scores, merged_indices = _merge_top_k(
        top_scores, top_indices, second_scores, 20, reference_ids
    )

    assert merged_scores.tolist() == [[0.9] * 19 + [0.8]]
    assert merged_indices[0, -1] == 20
    assert 19 not in merged_indices[0]

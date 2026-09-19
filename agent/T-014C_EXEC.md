# T-014B.1 and T-014C execution record

## Preconditions and scope

The checkout was `feat/distributed-pipeline` at `1d420588cf1c696d38121eb3aac4b7d2d017340c`, matching the requested branch and HEAD prefix `1d42058`; it was not `main`. I used `.venv/bin/python`, made no network requests or installs, and did not write, install, or run Ray or Spark.

I read SPEC §§3, 3.1, 6.1, 6.2, and 10 before changing code. Writes stayed in `src/security_llm/bench/`, `tests/`, `reports/distributed/`, and this ignored `agent/` execution record. No v0.1.0 document was edited.

## Part 1 — deterministic truth freeze

The generator now applies raw float64 `(-exact_similarity, reference_cve_id)` during top-20 selection and final retained-row ordering. A boundary tie test deliberately places the lexicographically smaller CVE in the later row and verifies that it is selected.

The superseded Parquet SHA-256 is `c6552a72c60b5643d73121c18991e7bb2f8dd41fb2f58f89c98f86d1641df0d3`. The regenerated artifact contains 362,631 rows and has SHA-256 `929ccdda1432851e7809ce6f4fb8a8513233dc9914ae4039bd25ab536753e657`; its manifest records the current commit and new tie-break rule.

All similarity figures here use the **12,000-reference-only fit; queries transformed**:

| Effect | Expected | Measured |
|---|---:|---:|
| Ordering-changed queries | 4,033 | 4,125 |
| Moved top-20 positions | 14,649 | 14,871 |
| Membership-changed queries | ~588 projected | 533 measured |
| Pairs ≥0.80 | 10,888 | 10,888 |
| Pairs ≥0.90 | 1,735 | 1,735 |

Every one of the 533 membership changes is an equal-score exchange at the rank-20 boundary; zero involve unequal scores. Both threshold pair sets are identical to the superseded artifact.

The ordering discrepancy is explained, not unresolved: re-sorting only the old 20 members produces exactly the expected 4,033/14,649, but that is the forbidden fixed-membership calculation. Correct boundary reselection produces 4,125/14,871. The projected membership count was not an exact acceptance value; the measured full-population value is 533.

The generator was run twice. The complete Parquet hash and ordered top-20-ID hash (`cf4366b8dd6eb3299fb51efac4470bee7210dd1cc44eecefdcfd5eb71f2260c1`) were byte-identical across runs. The second accepted run measured 12.415 s child wall time, 2.174 GiB peak RSS, zero major page faults, and zero swap growth.

The independent 200-query check (seed 20260919) used sparse dot products and a full Python ordering rather than the generator helper. Top-20 IDs and threshold sets/counts all matched. Scores passed absolute tolerance `2e-15`; maximum measured delta was `1.1102230246251565e-15`. The existing 300-query continuity check also passed.

## Part 2 — blockwise exact top-k

`src/security_llm/bench/blockwise_exact.py` streams reference blocks and keeps only the running top 20 plus threshold hits. It never constructs the 18,000 × 12,000 dense matrix. The merge key is the same raw-score/CVE-ID key used by the frozen truth. Each child uses the existing `run_instrumented_subprocess` monitor.

The first measurement was discarded because its cold 256-block child recorded one major page fault. The unchanged warm repeat below passed the zero-major-fault and zero-swap-growth checks.

Every run processes all 216,000,000 pairs. Throughput uses the measured blockwise-exact phase; wall time includes input validation, reference-only vectorizer fit, query transform, truth loading, blockwise work, verification, and staging.

| Block | Wall s | Blockwise s | Peak RSS GiB | Pairs/s |
|---:|---:|---:|---:|---:|
| 256 | 41.692 | 36.636 | 0.571 | 5,895,874 |
| 512 | 28.712 | 23.679 | 0.580 | 9,121,856 |
| 1024 | 20.965 | 15.908 | 0.726 | 13,578,216 |
| 2048 | 16.835 | 11.736 | 0.999 | 18,404,468 |

For all four block sizes, against the frozen truth under the **12,000-reference-only fit; queries transformed**:

- top-20 reference ID ordering is identical;
- top-20 scores are bit-identical, measured maximum delta `0.0`;
- ≥0.80 and ≥0.90 pairs are identical as sets;
- per-query threshold counts are identical;
- tie ordering is identical under the frozen key; and
- results are invariant across all four block sizes, including bit-identical scores.

These are exact-similarity measurements, not contamination findings. The computation remains O(Q × R) and does not reduce pair count. SPEC §6.2's order-of-minutes Audit B estimate remains a projection from measured Audit A, not an Audit B measurement.

## Commands and checks

```text
.venv/bin/python -m pytest tests/test_audit_a_exact_truth.py -q
.venv/bin/python -m py_compile src/security_llm/bench/audit_a_exact_truth.py src/security_llm/bench/blockwise_exact.py
.venv/bin/python -m security_llm.bench.audit_a_exact_truth
.venv/bin/python -m security_llm.bench.blockwise_exact
git diff --check
```

Focused tests passed 4/4 before the measured run. The final non-Spark suite passed **39 tests with 1 skipped** (the three Spark test files were explicitly excluded); the only warning was PyTorch's unavailable NVML notice. `py_compile`, `git diff --check`, and an independent final artifact reload also passed. The reload verified 362,631 rows, 18,000 queries, the raw-score/CVE-ID order in every query group, both threshold counts, the manifest/Parquet hash, zero accepted-run major page faults and swap growth, and every blockwise `all_passed` flag.

## Files

Changed:

- `src/security_llm/bench/audit_a_exact_truth.py`
- `tests/test_audit_a_exact_truth.py`
- `reports/distributed/audit_a_exact_truth.parquet`
- `reports/distributed/audit_a_exact_truth_manifest.json`
- `reports/distributed/audit_a_exact_truth.md`

Added:

- `src/security_llm/bench/blockwise_exact.py`
- `reports/distributed/audit_a_truth_freeze_diff.md`
- `reports/distributed/blockwise_exact.json`
- `reports/distributed/blockwise_exact.md`
- `agent/T-014C_EXEC.md`

A human review decision remains: amend the two measured-ordering rows in SPEC §3.1 to the full-selection values 4,125/14,871, or annotate them as fixed-membership re-sort diagnostics. The implementation should not be changed to force 4,033/14,649, because doing so would violate the same section's selection requirement.

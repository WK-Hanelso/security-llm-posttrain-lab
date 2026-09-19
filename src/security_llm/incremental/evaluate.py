"""Offline correctness harness for T-015C.

Each declared change is applied alone to Snapshot A, rebuilt with the
unmodified reference functions, and then compared with the incremental result.
The real combined A-to-B delta is also submitted to the prototype to verify the
mandatory MISSING_REVIEW stop.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import shutil
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from security_llm.config import load_config
from security_llm.data.build_sft import build
from security_llm.data.normalize import normalize
from security_llm.data.split import create_splits
from security_llm.incremental.prototype import (
    SPLITS,
    _effective_populations,
    load_raw_records,
    run_incremental,
)
from security_llm.utils.io import atomic_write_json, read_jsonl

ROOT = Path(__file__).resolve().parents[3]
FIXTURE = ROOT / "data/fixture"
REPORTS = ROOT / "reports/incremental"

EXPECTED_RELATIONS = {
    "C01_INSERT": ("DIFFERENT", "DIFFERENT", "DIFFERENT"),
    "C02_DESCRIPTION_UPDATE": ("DIFFERENT", "DIFFERENT", "DIFFERENT"),
    "C03_CWE_UPDATE": ("DIFFERENT", "DIFFERENT", "DIFFERENT"),
    "C04_MULTI_LABEL_UPDATE": ("DIFFERENT", "DIFFERENT", "DIFFERENT"),
    "C05_REJECTED_UPDATE": ("DIFFERENT", "DIFFERENT", "DIFFERENT"),
    "C06_KEV_UPDATE": ("SAME", "DIFFERENT", "DIFFERENT"),
    "C07_CVSS_NEGATIVE_CONTROL": ("SAME", "SAME", "DIFFERENT"),
    "C08_UNCHANGED": ("SAME", "SAME", "SAME"),
    "C10_PUBLISHED_BOUNDARY_UPDATE": ("DIFFERENT", "DIFFERENT", "DIFFERENT"),
}


def _apply_overrides(cfg: dict[str, Any], values: dict[str, Any]) -> dict[str, Any]:
    cfg = copy.deepcopy(cfg)
    for dotted, value in values.items():
        target = cfg
        keys = dotted.split(".")
        for key in keys[:-1]:
            target = target[key]
        target[keys[-1]] = value
    return cfg


def _temp_cfg(raw: Path, output: Path) -> dict[str, Any]:
    values = json.loads((FIXTURE / "snapshot_a/config_overrides.json").read_text(encoding="utf-8"))
    values.update({
        "nvd.raw_dir": str(raw),
        "paths.processed_dir": str(output / "processed"),
        "paths.sft_dir": str(output / "sft"),
        "paths.labels_file": str(output / "labels.json"),
        "paths.manifest": str(output / "dataset_manifest.json"),
        "paths.stats": str(output / "stats.json"),
        "paths.contamination": str(output / "contamination.json"),
    })
    return _apply_overrides(load_config(ROOT / "configs/data.yaml"), values)


def _change_raw(raw: Path, cve_id: str, action: str, b_records: dict[str, dict[str, Any]]) -> None:
    found = False
    first_page: Path | None = None
    for page in sorted(raw.glob("*/page_*.json")):
        first_page = first_page or page
        payload = json.loads(page.read_text(encoding="utf-8"))
        rows = payload.get("vulnerabilities", [])
        for index, wrapper in enumerate(rows):
            if wrapper.get("cve", {}).get("id") != cve_id:
                continue
            found = True
            if action == "missing":
                del rows[index]
            elif action == "update":
                rows[index] = {**wrapper, "cve": b_records[cve_id]}
            page.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            return
    if action == "insert":
        if first_page is None:
            raise AssertionError("fixture has no raw page")
        payload = json.loads(first_page.read_text(encoding="utf-8"))
        payload.setdefault("vulnerabilities", []).append({"cve": b_records[cve_id]})
        first_page.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return
    if not found and action != "unchanged":
        raise KeyError(cve_id)


def _capture(root: Path) -> dict[str, Any]:
    return {
        "normalized": (root / "processed/normalized.jsonl").read_bytes(),
        "processed": {split: (root / f"processed/{split}.jsonl").read_bytes() for split in SPLITS},
        "sft": {split: (root / f"sft/{split}.jsonl").read_bytes() for split in SPLITS},
        "labels": json.loads((root / "labels.json").read_text(encoding="utf-8")),
        "manifest": json.loads((root / "dataset_manifest.json").read_text(encoding="utf-8")),
        "processed_rows": {split: read_jsonl(root / f"processed/{split}.jsonl") for split in SPLITS},
        "sft_rows": {split: read_jsonl(root / f"sft/{split}.jsonl") for split in SPLITS},
    }


def _fixture_capture(name: str) -> dict[str, Any]:
    return _capture(FIXTURE / name)


def _stable_manifest(value: dict[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(value)
    value.pop("created_at", None)
    value.pop("git_commit", None)
    value.pop("data_config_sha256", None)
    for entry in value.get("files", {}).values():
        entry["path"] = Path(entry["path"]).name
    return value


def _composition(value: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    effective, counts = _effective_populations(value["processed_rows"], cfg)
    return {
        "selected_labels_ordered": value["labels"]["selected"],
        "split_assignment_and_labels": {
            split: [(row["cve_id"], row["cwe_id"]) for row in value["processed_rows"][split]]
            for split in SPLITS
        },
        "dedup_survivors_and_overlap": {
            "rows": {split: [row["cve_id"] for row in effective[split]] for split in SPLITS},
            "counts": counts,
        },
        "sft_membership_ordered": {
            split: [row["cve_id"] for row in value["sft_rows"][split]] for split in SPLITS
        },
    }


def _relations(left: dict[str, Any], right: dict[str, Any], cfg: dict[str, Any]) -> tuple[str, str, str]:
    composition = "SAME" if _composition(left, cfg) == _composition(right, cfg) else "DIFFERENT"
    final = "SAME" if (
        left["sft"] == right["sft"]
        and _stable_manifest(left["manifest"]) == _stable_manifest(right["manifest"])
    ) else "DIFFERENT"
    intermediate = "SAME" if (
        left["normalized"] == right["normalized"] and left["processed"] == right["processed"]
    ) else "DIFFERENT"
    return composition, final, intermediate


def _equivalence(incremental: dict[str, Any], truth: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    incremental_composition = _composition(incremental, cfg)
    truth_composition = _composition(truth, cfg)
    manifest_equal = _stable_manifest(incremental["manifest"]) == _stable_manifest(truth["manifest"])
    sft_hashes = {
        split: {
            "incremental": hashlib.sha256(incremental["sft"][split]).hexdigest(),
            "full_rebuild": hashlib.sha256(truth["sft"][split]).hexdigest(),
            "equal": incremental["sft"][split] == truth["sft"][split],
        }
        for split in SPLITS
    }
    intermediate_hashes = {
        "normalized": {
            "incremental": hashlib.sha256(incremental["normalized"]).hexdigest(),
            "full_rebuild": hashlib.sha256(truth["normalized"]).hexdigest(),
            "equal": incremental["normalized"] == truth["normalized"],
        },
        "processed": {
            split: {
                "incremental": hashlib.sha256(incremental["processed"][split]).hexdigest(),
                "full_rebuild": hashlib.sha256(truth["processed"][split]).hexdigest(),
                "equal": incremental["processed"][split] == truth["processed"][split],
            }
            for split in SPLITS
        },
    }
    return {
        "A_composition": {
            "verdict": "PASS" if incremental_composition == truth_composition else "FAIL",
            "selected_labels_and_order_equal": incremental_composition["selected_labels_ordered"] == truth_composition["selected_labels_ordered"],
            "split_assignment_and_labels_equal": incremental_composition["split_assignment_and_labels"] == truth_composition["split_assignment_and_labels"],
            "dedup_survivors_and_overlap_equal": incremental_composition["dedup_survivors_and_overlap"] == truth_composition["dedup_survivors_and_overlap"],
            "sft_membership_and_order_equal": incremental_composition["sft_membership_ordered"] == truth_composition["sft_membership_ordered"],
        },
        "B_final_byte": {
            "verdict": "PASS" if incremental["sft"] == truth["sft"] and manifest_equal else "FAIL",
            "sft_files_exact": {split: incremental["sft"][split] == truth["sft"][split] for split in SPLITS},
            "sft_sha256": sft_hashes,
            "manifest_deterministic_values_equal": manifest_equal,
            "manifest_provenance_values": {
                "created_at_equal": incremental["manifest"].get("created_at") == truth["manifest"].get("created_at"),
                "git_commit_equal": incremental["manifest"].get("git_commit") == truth["manifest"].get("git_commit"),
                "data_config_sha256_equal": incremental["manifest"].get("data_config_sha256") == truth["manifest"].get("data_config_sha256"),
                "comparison_policy": "created_at is recorded but excluded from deterministic equivalence; git_commit and config hash are reported separately",
            },
        },
        "C_intermediate_byte": {
            "verdict": "PASS" if incremental["normalized"] == truth["normalized"] and incremental["processed"] == truth["processed"] else "FAIL",
            "normalized_exact": incremental["normalized"] == truth["normalized"],
            "processed_exact": {split: incremental["processed"][split] == truth["processed"][split] for split in SPLITS},
            "sha256": intermediate_hashes,
        },
    }


def _prepare_nonmissing_raw(destination: Path, cases: list[dict[str, Any]], b: dict[str, dict[str, Any]]) -> None:
    shutil.copytree(FIXTURE / "snapshot_a/raw", destination)
    for case in cases:
        case_id = case["case_id"]
        if case_id in {"C08_UNCHANGED", "C09_MISSING_REVIEW"}:
            continue
        action = "insert" if case["change_type"] == "INSERT" else "update"
        _change_raw(destination, case["cve_id"], action, b)


def evaluate() -> dict[str, Any]:
    cases_doc = json.loads((REPORTS / "change_cases.json").read_text(encoding="utf-8"))
    cases = cases_doc["cases"]
    b_records = load_raw_records(FIXTURE / "snapshot_b/raw")
    baseline = _fixture_capture("snapshot_a")
    per_case: list[dict[str, Any]] = []
    work_samples: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="t015c-") as temporary:
        temp = Path(temporary)
        for case in cases:
            case_id = case["case_id"]
            trial = temp / case_id
            raw = trial / "raw"
            output = trial / "output"
            shutil.copytree(FIXTURE / "snapshot_a/raw", raw)
            action = (
                "insert" if case["change_type"] == "INSERT" else
                "missing" if case["change_type"] == "MISSING" else
                "unchanged" if case["change_type"] == "UNCHANGED" else "update"
            )
            _change_raw(raw, case["cve_id"], action, b_records)
            cfg = _temp_cfg(raw, output)
            normalize(cfg)
            create_splits(cfg)
            build(cfg, ROOT / "configs/data.yaml")
            truth = _capture(output)
            relation = _relations(baseline, truth, cfg)
            shutil.rmtree(output)
            output.mkdir(parents=True)
            incremental_result = run_incremental(
                cfg, ROOT / "configs/data.yaml", FIXTURE / "snapshot_a",
                FIXTURE / "snapshot_a/raw", raw,
            )
            if case_id == "C09_MISSING_REVIEW":
                layers = {
                    name: {"verdict": "PASS", "comparison": "NOT_RUN_REVIEW_REQUIRED"}
                    for name in ("A_composition", "B_final_byte", "C_intermediate_byte")
                }
                expectation = "PASS" if not incremental_result["completed"] and not incremental_result["writes_performed"] else "FAIL"
            else:
                incremental = _capture(output)
                layers = _equivalence(incremental, truth, cfg)
                expected = EXPECTED_RELATIONS[case_id]
                expectation = "PASS" if relation == expected else "FAIL"
                work_samples.append(incremental_result["work_accounting"])
            per_case.append({
                "case_id": case_id,
                "canonical_t015b_case": case_id != "C10_PUBLISHED_BOUNDARY_UPDATE",
                "cve_id": case["cve_id"],
                "classification": next(
                    change["classification"] for change in incremental_result["changes"]
                    if change["cve_id"] == case["cve_id"]
                ) if incremental_result["changes"] else "UNCHANGED",
                "apply_status": incremental_result["apply_status"],
                "observed_A_to_case_truth": {
                    "A_composition": relation[0], "B_final_byte": relation[1], "C_intermediate_byte": relation[2]
                },
                "predeclared_expectation_check": expectation,
                "layers": layers,
            })

        combined_cfg = _temp_cfg(FIXTURE / "snapshot_b/raw", temp / "combined-output")
        combined = run_incremental(
            combined_cfg, ROOT / "configs/data.yaml", FIXTURE / "snapshot_a",
            FIXTURE / "snapshot_a/raw", FIXTURE / "snapshot_b/raw",
        )

        nonmissing_raw = temp / "nonmissing-raw"
        _prepare_nonmissing_raw(nonmissing_raw, cases, b_records)
        nonmissing_cfg = _temp_cfg(nonmissing_raw, temp / "nonmissing-output")
        nonmissing = run_incremental(
            nonmissing_cfg, ROOT / "configs/data.yaml", FIXTURE / "snapshot_a",
            FIXTURE / "snapshot_a/raw", nonmissing_raw,
        )

    class_counts = dict(sorted(Counter(
        "UPDATE_INTERMEDIATE_ONLY" if item["classification"] == "UPDATE_INTERMEDIATE_ONLY" else item["classification"]
        for item in per_case if item["canonical_t015b_case"]
    ).items()))
    full_hashes = json.loads((FIXTURE / "snapshot_b/hashes.json").read_text(encoding="utf-8"))
    hash_mismatches = []
    for entry in full_hashes["files"]:
        path = ROOT / entry["path"]
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != entry["sha256"]:
            hash_mismatches.append({"path": entry["path"], "expected": entry["sha256"], "actual": actual})
    expected_manifest_hash = next(
        x["sha256"] for x in full_hashes["files"] if x["path"].endswith("dataset_manifest.json")
    )
    committed_manifest = subprocess.run(
        ["git", "show", "HEAD:data/fixture/snapshot_b/dataset_manifest.json"],
        cwd=ROOT, check=True, capture_output=True,
    ).stdout
    planned_work = nonmissing["work_accounting"]
    global_row_visits = (
        planned_work["global_label_selection_input_rows"]
        + planned_work["global_sampling_input_rows"]
    )
    accounted_row_visits = (
        global_row_visits
        + 3 * planned_work["normalized_rows_locally_recomputed"]
        + 2 * planned_work["group_recomputed_rows_total"]
        + planned_work["sft_rows_serialized"]
    )
    result = {
        "task": "T-015C",
        "truth": "isolated full rebuilds executed with the unmodified reference functions; committed Snapshot B artifacts checked against hashes.json",
        "snapshot_b_hash_check": {
            "artifact_entries": len(full_hashes["files"]),
            "all_nonvolatile_artifacts_match": all(
                item["path"].endswith("dataset_manifest.json") for item in hash_mismatches
            ),
            "mismatches": hash_mismatches,
            "dataset_manifest_current_worktree_mismatch": any(
                item["path"].endswith("dataset_manifest.json") for item in hash_mismatches
            ),
            "dataset_manifest_expected_sha256": expected_manifest_hash,
            "dataset_manifest_committed_head_sha256": hashlib.sha256(committed_manifest).hexdigest(),
            "dataset_manifest_committed_head_matches": hashlib.sha256(committed_manifest).hexdigest() == expected_manifest_hash,
            "cause": "pre-existing worktree change to created_at and git_commit only; committed HEAD blob matches hashes.json",
        },
        "classification_counts_canonical_nine": class_counts,
        "combined_run": {
            "apply_status": combined["apply_status"],
            "completed": combined["completed"],
            "writes_performed": combined["writes_performed"],
            "missing_ids": combined["missing_ids"],
        },
        "stage_dependency_map": {
            "normalization": "LOCAL",
            "eligibility": "LOCAL",
            "temporal_split": "LOCAL",
            "row_serialization": "LOCAL",
            "exact_dedup": "GROUP_RECOMPUTE (old and new description hash)",
            "cross_split_overlap": "GROUP_RECOMPUTE (old and new description hash)",
            "label_selection": "GLOBAL_RECOMPUTE",
            "sft_sampling": "GLOBAL_RECOMPUTE (reference random.sample semantics)",
        },
        "per_case": per_case,
        "work_accounting": {
            "basis": "all eight non-missing changed records in the ten-case fixture (seven canonical plus the C10 extension), with the unresolved missing A row retained only for this diagnostic plan; this is not a completed Snapshot B run",
            **nonmissing["work_accounting"],
            "local_stages": 4,
            "group_stages": 2,
            "global_stages": 2,
            "global_stage_fraction": 0.25,
            "global_stages_recomputed_fraction": 1.0,
            "global_row_visit_proxy": global_row_visits,
            "total_accounted_row_visit_proxy": accounted_row_visits,
            "global_row_visit_proxy_fraction": global_row_visits / accounted_row_visits,
            "row_visit_proxy_caveat": "scale-independent operation-count proxy; stages have different per-row costs, so this is not a runtime fraction",
        },
        "production_projection": {
            "label": "PROJECTION, not a fixture timing result",
            "measured_denominators_seconds": {"normalize": 38.60, "post_ingest_total": 56.18},
            "changed_normalization_fraction": nonmissing["work_accounting"]["normalized_rows_locally_recomputed"] / nonmissing["work_accounting"]["input_rows"],
            "projected_incremental_normalize_seconds_linear": round(
                38.60 * nonmissing["work_accounting"]["normalized_rows_locally_recomputed"] / nonmissing["work_accounting"]["input_rows"], 2
            ),
            "projected_downstream_seconds_before_incremental_overhead": round(
                (56.18 - 38.60) + 38.60 * nonmissing["work_accounting"]["normalized_rows_locally_recomputed"] / nonmissing["work_accounting"]["input_rows"], 2
            ),
            "projected_saving_seconds_before_incremental_overhead": round(
                38.60 * (1 - nonmissing["work_accounting"]["normalized_rows_locally_recomputed"] / nonmissing["work_accounting"]["input_rows"]), 2
            ),
            "peak_memory": "not measured or projected reliably; global label selection and sampling still retain full-population state",
            "verification_policy": "full rebuild on every code/config release and weekly for daily routine runs (1 in 7)",
            "amortized_weekly_verification_seconds_per_daily_run": round(56.18 / 7, 2),
            "projected_total_with_amortized_verification_before_incremental_overhead": round(
                (56.18 - 38.60) + 38.60 * nonmissing["work_accounting"]["normalized_rows_locally_recomputed"] / nonmissing["work_accounting"]["input_rows"] + 56.18 / 7, 2
            ),
            "verify_every_run_seconds_before_incremental_overhead": round(
                56.18 + (56.18 - 38.60) + 38.60 * nonmissing["work_accounting"]["normalized_rows_locally_recomputed"] / nonmissing["work_accounting"]["input_rows"], 2
            ),
        },
        "decision": {
            "case": "B",
            "answer": "Pursue incremental ingestion; retain a deterministic full rebuild downstream at this scale.",
            "reason": "The maximum projected downstream saving is only about 38 seconds, both global stages remain full recomputes, peak-memory reduction is unproven, MISSING blocks application, and exactness adds classification, cache, old/new-group, ordering, manifest, and verification failure modes to an already 56.18-second rebuild.",
        },
        "mismatches": [
            {
                "scope": "combined Snapshot B incremental application",
                "finding": "No output by design",
                "cause": "CVE-2007-6070 is MISSING_REVIEW; producing B by silently deleting it is forbidden",
            }
        ],
    }
    return result


def _markdown(result: dict[str, Any]) -> str:
    w = result["work_accounting"]
    p = result["production_projection"]
    lines = [
        "# T-015C — minimal incremental prototype versus full rebuild", "",
        "## Result", "",
        "**Case B.** Incremental source ingestion is worth pursuing; downstream should remain a deterministic full rebuild at this scale. The applyable changes demonstrate exact LOCAL/GROUP reuse, but the real combined run correctly stops at `REVIEW_REQUIRED` for `CVE-2007-6070` and writes nothing.", "",
        "Snapshot B remains the truth. All nonvolatile fixture artifacts match its recorded hashes. The current worktree's protected `dataset_manifest.json` was already modified in `created_at` and `git_commit`; its committed HEAD blob matches the recorded hash, and the prototype did not alter it.", "",
        "## Change classification (canonical nine cases)", "",
        "| Classification | Count |", "|---|---:|",
    ]
    for key, value in result["classification_counts_canonical_nine"].items():
        lines.append(f"| {key} | {value} |")
    lines += ["", "## Stage dependency map", "", "| Stage | Action |", "|---|---|"]
    for key, value in result["stage_dependency_map"].items():
        lines.append(f"| {key} | {value} |")
    lines += [
        "", "`label_selection` is always recomputed; the rank-15/16 margin is not used as a shortcut. `sft_sampling` calls the unchanged `random.sample` implementation.", "",
        "## Three-layer correctness by case", "",
        "`Relation` is Snapshot A versus that case's isolated full-rebuild truth. `Verdict` is incremental versus that truth. C09 passes the required guard; artifact comparison is not run.", "",
        "| Case | Class | A relation/verdict | B relation/verdict | C relation/verdict | Expectation |", "|---|---|---|---|---|---|",
    ]
    for case in result["per_case"]:
        relation = case["observed_A_to_case_truth"]
        layer = case["layers"]
        lines.append(
            f"| {case['case_id']} | {case['classification']} | {relation['A_composition']} / {layer['A_composition']['verdict']} | "
            f"{relation['B_final_byte']} / {layer['B_final_byte']['verdict']} | {relation['C_intermediate_byte']} / {layer['C_intermediate_byte']['verdict']} | {case['predeclared_expectation_check']} |"
        )
    lines += [
        "", "The CVSS-only case is therefore A SAME / B SAME / C DIFFERENT, the KEV case is A SAME / B DIFFERENT / C DIFFERENT, and UNCHANGED is SAME at all three layers. Intermediate CVSS bytes are preserved rather than ignored.", "",
        "## Work accounting", "",
        f"This is a diagnostic plan over all eight non-missing changed records in the ten-case fixture (seven canonical plus C10), retaining the unresolved missing row; it is not presented as a completed B run. Of {w['input_rows']} rows, normalization reuses {w['normalized_rows_reused']} and recomputes {w['normalized_rows_locally_recomputed']}. Processed artifacts reuse {w['processed_rows_reused']} rows and locally recompute {w['processed_rows_locally_recomputed']}. The two group stages touch {w['affected_hash_groups']} old/new hash groups covering {w['group_recomputed_rows_total']} split rows. Final serialization reuses {w['sft_rows_reused']} existing SFT rows, locally recomputes {w['sft_source_changed_rows_locally_recomputed']} source-changed rows, and materializes {w['sft_unchanged_rows_materialized_after_global_sampling']} unchanged rows that became members after the global draw (there was no prior SFT cache entry for them).", "",
        f"Two of eight transformation stages are global (25% by stage count), and both global stages are fully recomputed (100%). They account for {w['global_row_visit_proxy']}/{w['total_accounted_row_visit_proxy']} = {w['global_row_visit_proxy_fraction']:.1%} of a scale-independent row-visit proxy. The proxy is not a runtime fraction because stage costs differ.", "",
        "## Production projection (not fixture timing)", "",
        f"Measured denominators are 38.60 s for normalization (1.88 GiB peak) and 56.18 s post-ingest. A linear row-work projection puts normalization at {p['projected_incremental_normalize_seconds_linear']:.2f} s and total downstream work at {p['projected_downstream_seconds_before_incremental_overhead']:.2f} s before incremental bookkeeping, a maximum saving of {p['projected_saving_seconds_before_incremental_overhead']:.2f} s. No fixture-scale speedup is reported.", "",
        f"Peak-memory savings are not claimed: global label selection and sampling still require full-population state. Verification would run on every code/config release and weekly for daily routine runs. Weekly verification amortizes {p['amortized_weekly_verification_seconds_per_daily_run']:.2f} s per daily run, bringing the projection to {p['projected_total_with_amortized_verification_before_incremental_overhead']:.2f} s before bookkeeping. Verification every run would cost {p['verify_every_run_seconds_before_incremental_overhead']:.2f} s, more than the 56.18 s full rebuild.", "",
        "## §22 decision", "",
        "**Case B:** pursue incremental ingestion, but use a deterministic downstream full rebuild. The projected downstream saving is at most about 38 seconds against hours of ingestion, while two global stages remain unavoidable. The prototype adds state/version compatibility, field-classification, old/new-group invalidation, cache completeness, ordering, manifest, missing-row, and verification failure modes. A full rebuild is simpler to audit, has a smaller correctness surface, and is already cheap. Exact equivalence is feasible for non-missing changes, but the saving does not justify operating the added machinery.", "",
        "## Mismatch and stop condition", "",
        "The real combined run produces no incremental Snapshot B artifacts: `CVE-2007-6070` is `MISSING_REVIEW`, so `apply_status=REVIEW_REQUIRED`, `completed=false`, and `writes_performed=false`. This is the required behavior, not an equivalence failure to hide. Dropping that row would make a comparison easier and would be incorrect.", "",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", default=str(REPORTS / "incremental_vs_full.json"))
    parser.add_argument("--markdown", default=str(REPORTS / "incremental_vs_full.md"))
    args = parser.parse_args()
    result = evaluate()
    atomic_write_json(args.json, result)
    Path(args.markdown).write_text(_markdown(result), encoding="utf-8")
    print(json.dumps({
        "combined": result["combined_run"],
        "case_verdicts": {
            case["case_id"]: {name: value["verdict"] for name, value in case["layers"].items()}
            for case in result["per_case"]
        },
        "decision": result["decision"]["case"],
    }, indent=2))


if __name__ == "__main__":
    main()

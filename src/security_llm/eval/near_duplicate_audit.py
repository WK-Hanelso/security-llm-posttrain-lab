"""Sampled train/test near-duplicate audit for the frozen evaluation rows."""

from __future__ import annotations

import argparse
import json
import math
import random
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from security_llm.utils.io import atomic_write_json, read_jsonl

SEED = 42
REQUESTED_SAMPLE = {"fixed_by_sft": 200, "both_wrong": 100}
HIGH_THRESHOLD = 0.80
VERY_HIGH_THRESHOLD = 0.90
TRANSITIONS = {
    (True, True): "both_right",
    (False, True): "fixed_by_sft",
    (True, False): "broken_by_sft",
    (False, False): "both_wrong",
}
METRIC = (
    "Cosine similarity on L2-normalized word TF-IDF vectors fitted on the 12,000 "
    "train descriptions plus the 300 sampled test descriptions; ngram_range=(1, 2), "
    "sublinear_tf=True, min_df=2, stop_words=None (English stop words kept)."
)


def transition(base_exact_match: bool, sft_exact_match: bool) -> str:
    """Return the Base-to-SFT outcome transition."""

    return TRANSITIONS[(base_exact_match, sft_exact_match)]


def proportional_allocation(
    class_counts: dict[str, int], requested: int
) -> dict[str, int]:
    """Allocate ``requested`` slots proportionally, with one per available class."""

    available = {label: count for label, count in class_counts.items() if count > 0}
    total = sum(available.values())
    if requested < 0 or requested > total:
        raise ValueError(f"requested={requested} is outside [0, {total}]")
    if requested == 0:
        return {label: 0 for label in sorted(available)}
    if requested < len(available):
        raise ValueError(
            f"requested={requested} cannot give at least one row to "
            f"{len(available)} available classes"
        )

    ideal = {label: requested * count / total for label, count in available.items()}
    allocation = {
        label: min(count, max(1, math.floor(ideal[label])))
        for label, count in available.items()
    }

    while sum(allocation.values()) < requested:
        candidates = [
            label
            for label in sorted(available)
            if allocation[label] < available[label]
        ]
        if not candidates:
            raise AssertionError("allocation exhausted class capacity")
        label = max(candidates, key=lambda item: (ideal[item] - allocation[item], item))
        allocation[label] += 1

    while sum(allocation.values()) > requested:
        candidates = [label for label in sorted(available) if allocation[label] > 1]
        if not candidates:
            raise AssertionError("cannot preserve the one-per-class allocation")
        label = max(
            candidates,
            key=lambda item: (allocation[item] - ideal[item], item),
        )
        allocation[label] -= 1

    return {label: allocation[label] for label in sorted(allocation)}


def stratified_sample(
    rows: Iterable[dict[str, Any]],
    requested: int,
    rng: random.Random,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Sample rows by gold label according to proportional allocation."""

    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[row["gold_cwe"]].append(row)
    allocation = proportional_allocation(
        {label: len(group) for label, group in groups.items()}, requested
    )
    sampled: list[dict[str, Any]] = []
    for label in sorted(allocation):
        sampled.extend(rng.sample(groups[label], allocation[label]))
    if len(sampled) != requested:
        raise AssertionError(f"sampled {len(sampled)} rows, expected {requested}")
    return sampled, allocation


def _load_joined_predictions(
    base_path: str | Path,
    sft_path: str | Path,
    test_path: str | Path,
    manifest_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    base_rows = read_jsonl(base_path)
    sft_rows = read_jsonl(sft_path)
    base_ids = [row["cve_id"] for row in base_rows]
    sft_ids = [row["cve_id"] for row in sft_rows]
    if base_ids != sft_ids:
        raise AssertionError("Base and SFT prediction CVE sequences differ")
    if len(base_ids) != len(set(base_ids)):
        raise AssertionError("Prediction CVE IDs are not unique")

    if manifest_path is not None:
        with Path(manifest_path).open(encoding="utf-8") as handle:
            manifest_ids = json.load(handle)["row_ids"]
        if base_ids != manifest_ids:
            raise AssertionError("Prediction CVE sequence differs from the frozen manifest")

    test_by_id = {row["cve_id"]: row for row in read_jsonl(test_path)}
    missing = set(base_ids) - set(test_by_id)
    if missing:
        raise AssertionError(f"{len(missing)} prediction IDs are missing from test data")

    joined: list[dict[str, Any]] = []
    for base, sft in zip(base_rows, sft_rows, strict=True):
        cve_id = base["cve_id"]
        if base["gold"] != sft["gold"]:
            raise AssertionError(f"Gold mismatch for {cve_id}")
        source = test_by_id[cve_id]
        if source["cwe_id"] != base["gold"]:
            raise AssertionError(f"Test-data gold mismatch for {cve_id}")
        joined.append(
            {
                "test_cve_id": cve_id,
                "gold_cwe": base["gold"],
                "transition": transition(
                    bool(base["exact_match"]), bool(sft["exact_match"])
                ),
                "base_prediction": base.get("pred"),
                "sft_prediction": sft.get("pred"),
                "description": source["description"],
            }
        )
    return joined


def _nearest_train_rows(
    train_rows: list[dict[str, Any]], sampled_rows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    if not train_rows or not sampled_rows:
        raise ValueError("train_rows and sampled_rows must both be non-empty")
    train_text = [row["description"] for row in train_rows]
    sample_text = [row["description"] for row in sampled_rows]
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        sublinear_tf=True,
        min_df=2,
        stop_words=None,
    )
    matrix = vectorizer.fit_transform(train_text + sample_text)
    similarities = cosine_similarity(
        matrix[len(train_rows) :], matrix[: len(train_rows)], dense_output=True
    )
    nearest_indices = np.argmax(similarities, axis=1)

    results: list[dict[str, Any]] = []
    for sample_index, (sample, train_index) in enumerate(
        zip(sampled_rows, nearest_indices, strict=True)
    ):
        nearest = train_rows[int(train_index)]
        results.append(
            {
                "test_cve_id": sample["test_cve_id"],
                "gold_cwe": sample["gold_cwe"],
                "transition": sample["transition"],
                "base_prediction": sample["base_prediction"],
                "sft_prediction": sample["sft_prediction"],
                "nearest_train_cve_id": nearest["cve_id"],
                "nearest_train_cwe": nearest["cwe_id"],
                "similarity": float(similarities[sample_index, train_index]),
                "same_label": sample["gold_cwe"] == nearest["cwe_id"],
                "_test_description": sample["description"],
                "_train_description": nearest["description"],
            }
        )
    return results


def _normalized_characters(text: str) -> str:
    return re.sub(r"\s+", " ", text.casefold()).strip()


def char5_jaccard(left: str, right: str) -> float:
    """Jaccard similarity of lowercased, whitespace-normalized char 5-gram sets."""

    def grams(text: str) -> set[str]:
        normalized = _normalized_characters(text)
        return {
            normalized[index : index + 5]
            for index in range(max(0, len(normalized) - 4))
        }

    left_grams, right_grams = grams(left), grams(right)
    union = left_grams | right_grams
    return len(left_grams & right_grams) / len(union) if union else 1.0


def excerpt(text: str, limit: int = 300) -> str:
    cleaned = re.sub(r"\s+", " ", text).strip()
    return cleaned if len(cleaned) <= limit else cleaned[: limit - 1] + "…"


def _summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    values = np.asarray([row["similarity"] for row in rows], dtype=float)
    if not len(values):
        raise ValueError("cannot summarize an empty audit")
    high = [row for row in rows if row["similarity"] >= HIGH_THRESHOLD]
    return {
        "n_audited": len(rows),
        "similarity_p50": float(np.percentile(values, 50)),
        "similarity_p90": float(np.percentile(values, 90)),
        "similarity_p95": float(np.percentile(values, 95)),
        "similarity_max": float(np.max(values)),
        "ge_0_80_count": len(high),
        "ge_0_90_count": sum(
            row["similarity"] >= VERY_HIGH_THRESHOLD for row in rows
        ),
        "high_sim_same_label": sum(row["same_label"] for row in high),
        "high_sim_different_label": sum(not row["same_label"] for row in high),
    }


def audit(
    train_path: str | Path,
    test_path: str | Path,
    base_path: str | Path,
    sft_path: str | Path,
    manifest_path: str | Path | None = None,
    requested_sample: dict[str, int] | None = None,
    seed: int = SEED,
) -> dict[str, Any]:
    """Run the sampled audit and return its JSON-serializable result."""

    requested_sample = requested_sample or REQUESTED_SAMPLE
    joined = _load_joined_predictions(
        base_path, sft_path, test_path, manifest_path=manifest_path
    )
    rng = random.Random(seed)
    sampled: list[dict[str, Any]] = []
    allocations: dict[str, dict[str, int]] = {}
    for outcome, requested in requested_sample.items():
        candidates = [row for row in joined if row["transition"] == outcome]
        selected, allocation = stratified_sample(candidates, requested, rng)
        sampled.extend(selected)
        allocations[outcome] = allocation

    train_rows = read_jsonl(train_path)
    nearest = _nearest_train_rows(train_rows, sampled)
    ranked = sorted(nearest, key=lambda row: (-row["similarity"], row["test_cve_id"]))
    top20: list[dict[str, Any]] = []
    top_ids = {row["test_cve_id"] for row in ranked[:20]}
    public_rows: list[dict[str, Any]] = []
    for row in nearest:
        public = {key: value for key, value in row.items() if not key.startswith("_")}
        if row["test_cve_id"] in top_ids:
            public["char5_jaccard"] = char5_jaccard(
                row["_test_description"], row["_train_description"]
            )
        public_rows.append(public)
    public_by_id = {row["test_cve_id"]: row for row in public_rows}
    for row in ranked[:20]:
        top20.append(
            {
                **public_by_id[row["test_cve_id"]],
                "test_excerpt": excerpt(row["_test_description"]),
                "train_excerpt": excerpt(row["_train_description"]),
                "manual_category": None,
            }
        )

    overall = _summary(public_rows)
    overall["by_transition"] = {
        outcome: _summary(
            [row for row in public_rows if row["transition"] == outcome]
        )
        for outcome in requested_sample
    }
    return {
        "metric": METRIC,
        "thresholds": {"high": HIGH_THRESHOLD, "very_high": VERY_HIGH_THRESHOLD},
        "sample": {
            **requested_sample,
            "seed": seed,
            "allocation": allocations,
        },
        "summary": overall,
        "rows": public_rows,
        "top20": top20,
    }


def render_markdown(result: dict[str, Any]) -> str:
    """Render the computed portions; manual top-20 judgments are filled afterward."""

    summary = result["summary"]
    lines = [
        "# Sampled train/test near-duplicate audit",
        "",
        "This sampled audit checks for template reuse; it is not a formal semantic-contamination detector.",
        "",
        "## Method",
        "",
        f"- {result['metric']}",
        "- High similarity is cosine similarity >= 0.80; very high similarity is >= 0.90.",
        "- Character 5-gram Jaccard uses lowercased, whitespace-normalized descriptions and is reported only for the top 20 pairs.",
        "",
        "## Summary",
        "",
        "| Slice | n | p50 | p90 | p95 | max | >=0.80 | >=0.90 | >=0.80 same label | >=0.80 different label |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, values in [("all", summary), *summary["by_transition"].items()]:
        lines.append(
            f"| {name} | {values['n_audited']} | {values['similarity_p50']:.6f} | "
            f"{values['similarity_p90']:.6f} | {values['similarity_p95']:.6f} | "
            f"{values['similarity_max']:.6f} | {values['ge_0_80_count']} | "
            f"{values['ge_0_90_count']} | {values['high_sim_same_label']} | "
            f"{values['high_sim_different_label']} |"
        )
    lines.extend(["", "## Stratified allocation", ""])
    for outcome, allocation in result["sample"]["allocation"].items():
        lines.extend(
            [
                f"### {outcome}",
                "",
                "| Gold label | Sampled |",
                "|---|---:|",
                *[f"| {label} | {count} |" for label, count in allocation.items()],
                "",
            ]
        )
    lines.extend(
        [
            "## Manual review of top 20 pairs",
            "",
            "Manual categories and one-line answers are added after inspecting both excerpts.",
            "",
        ]
    )
    for index, row in enumerate(result["top20"], 1):
        lines.extend(
            [
                f"### {index}. {row['test_cve_id']} / {row['nearest_train_cve_id']}",
                "",
                f"- Similarity: {row['similarity']:.6f}; char5 Jaccard: {row['char5_jaccard']:.6f}",
                f"- Labels: gold `{row['gold_cwe']}`; nearest train `{row['nearest_train_cwe']}`; same label: `{str(row['same_label']).lower()}`",
                f"- Transition: `{row['transition']}`; Base: `{row['base_prediction']}`; SFT: `{row['sft_prediction']}`",
                f"- Test excerpt: {row['test_excerpt']}",
                f"- Train excerpt: {row['train_excerpt']}",
                "- Manual category: `PENDING`",
                "- Audit questions: PENDING",
                "",
            ]
        )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--train", default="data/sft/train.jsonl")
    parser.add_argument("--test", default="data/sft/test.jsonl")
    parser.add_argument(
        "--base", default="experiments/exp_001_baseline/predictions.jsonl"
    )
    parser.add_argument(
        "--sft", default="experiments/exp_002_sft_v1/predictions.jsonl"
    )
    parser.add_argument("--manifest", default="reports/eval_subset_manifest.json")
    parser.add_argument("--json-output", default="reports/near_duplicate_audit.json")
    parser.add_argument("--markdown-output", default="reports/near_duplicate_audit.md")
    args = parser.parse_args()

    result = audit(args.train, args.test, args.base, args.sft, args.manifest)
    atomic_write_json(args.json_output, result)
    markdown_path = Path(args.markdown_output)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.write_text(render_markdown(result), encoding="utf-8")


if __name__ == "__main__":
    main()

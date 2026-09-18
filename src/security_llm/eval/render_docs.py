"""Render final result documentation from the frozen JSON artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]


def load_json(path: str) -> dict[str, Any]:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def load_jsonl(path: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in (ROOT / path).read_text(encoding="utf-8").splitlines()]


BASE = load_json("reports/baseline_metrics.json")
SFT = load_json("reports/sft_metrics.json")
FAIL = load_json("reports/failure_summary.json")
MANIFEST = load_json("manifests/dataset_manifest.json")
DATASET = load_json("reports/dataset_report.json")
LABELS = load_json("data/processed/labels.json")
META = load_json("experiments/exp_002_sft_v1/metadata.json")
FAILURES = load_jsonl("reports/failures.jsonl")
TRAIN_LOG = load_jsonl("experiments/exp_002_sft_v1/train_log.jsonl")


def f4(value: float) -> str:
    return f"{value:.4f}"


def d4(value: float) -> str:
    return f"{value:+.4f}"


def integer(value: int) -> str:
    return f"{value:,}"


def excerpt(text: str, limit: int) -> str:
    flat = " ".join(text.split()).replace("|", "\\|")
    if len(flat) <= limit:
        return flat
    return flat[: limit - 1].rstrip() + "…"


def write(path: str, text: str) -> None:
    (ROOT / path).write_text(text.rstrip() + "\n", encoding="utf-8")


def metric_rows(include_weighted: bool = False) -> list[str]:
    rows = [
        ("Accuracy", "accuracy"),
        ("Macro F1", "macro_f1"),
    ]
    if include_weighted:
        rows.append(("Weighted F1", "weighted_f1"))
    rows.append(("Invalid-output rate", "invalid_rate"))
    return [
        f"| {label} | {f4(BASE[key])} | {f4(SFT[key])} | {d4(SFT[key] - BASE[key])} |"
        for label, key in rows
    ]


def support_order() -> list[str]:
    return sorted(BASE["per_class"], key=lambda cwe: (-BASE["per_class"][cwe]["support"], cwe))


def tail_labels() -> set[str]:
    ordered = sorted(LABELS["train_counts"], key=lambda cwe: LABELS["train_counts"][cwe])
    return set(ordered[: len(ordered) // 3])


def per_class_f1_rows(with_name: bool) -> list[str]:
    rows = []
    for cwe in support_order():
        base = BASE["per_class"][cwe]
        sft = SFT["per_class"][cwe]
        name = f" | {LABELS['names'][cwe]}" if with_name else ""
        rows.append(
            f"| {cwe}{name} | {integer(base['support'])} | {f4(base['f1'])} | "
            f"{f4(sft['f1'])} | {d4(sft['f1'] - base['f1'])} |"
        )
    return rows


def selected_failures(transition: str, count: int) -> list[dict[str, Any]]:
    result = []
    seen_gold: set[str] = set()
    for row in FAILURES:
        if row["transition"] != transition or row["gold"] in seen_gold:
            continue
        seen_gold.add(row["gold"])
        result.append(row)
        if len(result) == count:
            break
    return result


def quoted_failure_examples() -> list[dict[str, Any]]:
    """Choose four broken and six both-wrong rows with ten distinct gold labels."""
    broken = selected_failures("broken_by_sft", 4)
    seen_gold = {row["gold"] for row in broken}
    both_wrong = []
    for row in FAILURES:
        if row["transition"] != "both_wrong" or row["gold"] in seen_gold:
            continue
        seen_gold.add(row["gold"])
        both_wrong.append(row)
        if len(both_wrong) == 6:
            break
    return broken + both_wrong


def confusion_count(metrics: dict[str, Any], gold: str, pred: str) -> int:
    labels = metrics["confusion_matrix"]["labels"]
    return metrics["confusion_matrix"]["matrix"][labels.index(gold)][labels.index(pred)]


def render_readme() -> str:
    broken = selected_failures("broken_by_sft", 2)
    residual = next(row for row in FAILURES if row["transition"] == "both_wrong" and row["gold"] == "CWE-79")
    examples = broken + [residual]
    train_end = next(row for row in reversed(TRAIN_LOG) if row.get("event") == "end")

    lines = [
        "# Security-domain LLM Post-training & Evaluation",
        "",
        "*CVE-to-CWE domain SFT with reproducible evaluation*",
        "",
        "The repository cleans public vulnerability data (NVD) into a CWE classification dataset and compares an open-weight LLM's base and LoRA-SFT performance on the same temporal held-out set.",
        "Raw NVD records and model-specific prompt formatting are kept separate so dataset construction and model adaptation are verified independently.",
        "",
        "## Problem",
        "",
        "The task maps one English CVE description to one JSON CWE label in a fixed closed set.",
        "",
        "```text",
        "NVD CVE → Canonical Security Record → CWE Label Policy → Temporal Split + Overlap Check",
        "→ Model Adapter → Qwen3-0.6B Base → LoRA SFT → Same Held-out Test",
        "→ Deterministic Evaluation Verifier → Failure Analysis (→ Data Distribution Ablation, if present)",
        "```",
        "",
        "## Dataset",
        "",
        f"The NVD snapshot date is `{MANIFEST['dataset_snapshot']}`. The source funnel contains {integer(DATASET['raw_records'])} raw records and {integer(DATASET['single_label'])} single-label records.",
        "",
        "Selected CWE IDs: " + ", ".join(f"`{cwe}`" for cwe in MANIFEST["labels"]) + ".",
        "",
        "| Split | Selected-class population | Sampled rows |",
        "|---|---:|---:|",
    ]
    for split, display in (("train", "Train"), ("val", "Validation"), ("test", "Test")):
        lines.append(
            f"| {display} | {integer(MANIFEST['population_counts'][split])} | {integer(MANIFEST['counts'][split])} |"
        )
    lines += [
        "",
        "The training and validation views use seeded natural-distribution samples; the test view retains the full selected-class population. See the [dataset card](DATASET_CARD.md) and [dataset report](reports/dataset_report.md).",
        "",
        "## Temporal split and leakage guard",
        "",
        "| Split | Published-date range |",
        "|---|---|",
        "| Train | 2020-01-01–2024-12-31 |",
        "| Validation | 2025-01-01–2025-12-31 |",
        f"| Test | 2026-01-01–{MANIFEST['dataset_snapshot']} |",
        "",
        "Temporal splits use the NVD `published` timestamp rather than the year embedded in the CVE identifier. An older CVE ID can therefore appear in the 2026 test split when that record was published by NVD during the test period.",
        "",
        "Exact CVE-ID and normalized-description overlap between fine-tuning splits: 0 after build. This is an exact check, not a semantic-similarity claim.",
        "",
        "## Base model",
        "",
        f"The unadapted run uses `{META['model_name']}` at revision `{META['model_revision']}`. It is evaluated with the same prompt, ordered CVE-ID subset, generation settings, and deterministic evaluation verifier as the adapted run.",
        "",
        "## LoRA SFT",
        "",
        "| Setting | Recorded value |",
        "|---|---|",
        f"| Model / revision | `{META['model_name']}` / `{META['model_revision']}` |",
        f"| LoRA rank / alpha / dropout | {META['lora_rank']} / {META['lora_alpha']} / {META['lora_dropout']} |",
        "| Target modules | `q_proj`, `k_proj`, `v_proj`, `o_proj` |",
        f"| Epochs / learning rate | {META['epochs']} / {META['learning_rate']} |",
        f"| Device batch / gradient accumulation / effective batch | {META['batch_size']} / {META['gradient_accumulation']} / {META['batch_size'] * META['gradient_accumulation']} |",
        f"| Maximum sequence length | {integer(META['max_seq_length'])} tokens |",
        f"| Precision / quantization | {META['precision']} / no quantization |",
        f"| GPU | {META['gpu']} |",
        f"| Training wall time | {train_end['train_runtime_s']:.1f} s |",
        f"| Peak allocated VRAM | {train_end['peak_vram_mib']:.1f} MiB |",
        f"| Trainable parameters | {integer(META['trainable_params'])} |",
        "",
        f"The {integer(META['max_seq_length'])}-token limit was used because the recorded rendered prompt-plus-completion maxima are {integer(DATASET['token_length']['train']['max'])} for train, {integer(DATASET['token_length']['val']['max'])} for validation, and {integer(DATASET['token_length']['test']['max'])} for test, with no rows over the configured limit.",
        "",
        "## Base vs SFT",
        "",
        "| Metric | Base | SFT | Delta |",
        "|---|---:|---:|---:|",
        *metric_rows(),
        "",
        f"n = {integer(SFT['n'])}: a seed-{META['seed']} subsample of the {integer(MANIFEST['counts']['test'])}-row 2026 test split.",
        "",
        "### Per-class F1",
        "",
        "Rows are sorted by evaluation support.",
        "",
        "| CWE ID | Name | Test support | Base F1 | SFT F1 | Delta |",
        "|---|---|---:|---:|---:|---:|",
        *per_class_f1_rows(with_name=True),
        "",
        "## Failure analysis",
        "",
        "### Outcome transitions",
        "",
        "| Transition | Count |",
        "|---|---:|",
    ]
    for key in ("both_right", "fixed_by_sft", "broken_by_sft", "both_wrong"):
        lines.append(f"| `{key}` | {integer(FAIL['transitions'][key])} |")
    lines += [
        "",
        "### Error types",
        "",
        "| Outcome or error type | Base | SFT |",
        "|---|---:|---:|",
    ]
    for key in ("correct", "invalid_format", "unknown_cwe", "nearby_cwe_confusion", "semantic_confusion"):
        lines.append(
            f"| `{key}` | {integer(FAIL['error_type_counts']['base'][key])} | {integer(FAIL['error_type_counts']['sft'][key])} |"
        )
    lines += [
        "",
        "### Most frequent SFT confusions",
        "",
        "| Gold → prediction | Count |",
        "|---|---:|",
    ]
    for row in FAIL["top_confusions_sft"][:5]:
        lines.append(f"| {row['gold']} → {row['pred']} | {integer(row['count'])} |")
    lines += [
        "",
        "### Representative residual examples",
        "",
        "The comparison artifact stores residual failures, so the available examples are broken or still wrong rather than fixed cases.",
        "",
        "| Transition | CVE ID | Gold | Base | SFT | Description excerpt |",
        "|---|---|---|---|---|---|",
    ]
    for row in examples:
        lines.append(
            f"| `{row['transition']}` | {row['cve_id']} | {row['gold']} | {row['base_prediction']} | "
            f"{row['prediction']} | {excerpt(row['description'], 160)} |"
        )
    lines += [
        "",
        "See [the full failure analysis](reports/failure_analysis.md) for the top confusions, long-tail results, and quoted records.",
        "",
        "## Reproduction",
        "",
        "Run these commands from the repository root, in order:",
        "",
        "```bash",
        "bash scripts/setup_env.sh       # create the Python environment and install pinned dependencies",
        "bash scripts/prepare_data.sh    # fetch NVD pages and build canonical, split, and SFT views",
        "bash scripts/eval_base.sh       # evaluate the unadapted model on the frozen subset",
        "bash scripts/train_sft.sh       # train and write the LoRA adapter",
        "bash scripts/eval_sft.sh        # evaluate the adapter on the identical frozen subset",
        "bash scripts/build_report.sh    # rebuild comparison and failure-analysis JSON/Markdown artifacts",
        "```",
        "",
        "`NVD_API_KEY` is optional and is never written to a file; setting it increases the NVD API rate limit. Model execution also requires access to the model weights or a populated local cache.",
        "",
        f"Measured on an RTX 2060 6 GB: Base evaluation used batch {BASE['generation']['batch_size']} and took {BASE['throughput']['wall_seconds']:.1f} s; training used device batch {META['batch_size']} with {META['gradient_accumulation']} accumulation steps and took {train_end['train_runtime_s']:.1f} s; SFT evaluation used batch {SFT['generation']['batch_size']} and took {SFT['throughput']['wall_seconds']:.1f} s. Setup, NVD ingestion, and report-rendering time depend on cache and API state and were not recorded in the cited JSON artifacts.",
        "",
        "The mandatory smoke run completed before the full run. Earlier runs next to a GPU co-tenant included two fp16 LoRA OOM probes and an OOM in the quantized fallback; a separate attempt was stopped when the host CUDA driver could not initialize. The successful run started only after the GPU and driver checks passed.",
        "",
        "## Scope and limitations",
        "",
        "See [claim boundaries](docs/claim-boundaries.md) for the fixed wording and complete scope.",
        "",
        "- The dataset includes single-label CVEs only; multi-label CVEs are excluded.",
        "- The output space is a closed set of 15 CWE IDs.",
        "- Results cover one temporal snapshot and one seed.",
        "- Prior exposure of the unadapted model to NVD text cannot be verified.",
        "- KEV is an evaluation slice only.",
        "- No continued-domain adaptation or reinforcement-learning phase was run.",
        "- Exact normalized-description matching does not detect paraphrases.",
        "- Exact CVE-ID and normalized-description overlap between splits is blocked by a fail-fast guard. In addition, a sampled audit of high text-similarity train/test pairs was run to check for template reuse; this is not a formal semantic-contamination detector. Audit (`reports/near_duplicate_audit.md`, word TF-IDF 1–2-gram cosine, 300 evaluated test rows = 200 `fixed_by_sft` + 100 `both_wrong`, class-stratified, seed 42): nearest-train similarity p50 0.27 / p90 0.70 / p95 0.74 / max 1.00; 8 rows ≥ 0.80 (5 same-label, 3 different-label), 3 rows ≥ 0.90; all 8 fall in the `fixed_by_sft` sample (5 same-label = 2.5% of the 200 sampled fixes), 0 in `both_wrong`. Manual review of the top 20: 7 exact-or-near copies, 11 vendor-boilerplate-only, 2 repeated weakness phrases. These sampled counts do not establish template reuse as a material shortcut for the 8,715 `fixed_by_sft` transitions.",
        "- The Natural-vs-Balanced ablation was not run. It is a conditional follow-up if tail recall remains low, predictions remain concentrated, and failures continue to co-occur with class imbalance.",
        "- Future work: Residual errors are concentrated around semantically adjacent or generic CWE boundaries, particularly CWE-862 vs CWE-284 and generic classes such as CWE-20, CWE-120, and CWE-200. A follow-up study could evaluate hierarchical or revised label policies before changing the model architecture.",
        "",
        "## Repository map",
        "",
        "| Directory | Responsibility |",
        "|---|---|",
        "| `src/security_llm/data/` | NVD ingestion, canonical records, validation, statistics, temporal splits, exact deduplication, SFT views, and manifests |",
        "| `src/security_llm/adapters/` | Fixed CWE instruction, closed-set labels, output schema, and model-facing serialization |",
        "| `src/security_llm/eval/` | Generation, deterministic evaluation verifier, metrics, exact overlap checks, failure analysis, and documentation rendering |",
        "| `src/security_llm/train/` | LoRA SFT execution and training-artifact capture |",
        "| `src/security_llm/utils/` | Atomic I/O, metadata, and seed helpers |",
        "| `configs/` | Data, training, and evaluation configuration |",
        "| `data/` | Raw cache, canonical records, split populations, and derived SFT JSONL |",
        "| `manifests/` | Versioned dataset identity, row counts, policies, and file hashes |",
        "| `experiments/` | Run-specific metadata, logs, predictions, metrics, and local adapter output |",
        "| `reports/` | Dataset, Base/SFT evaluation, comparison, and failure-analysis artifacts |",
        "| `docs/` | Specification, data/model boundary, and claim boundaries |",
        "| `scripts/` | End-to-end setup, data preparation, training, evaluation, and report commands |",
        "| `tests/` | Schema, split, verifier, deduplication, metric, and completion-mask checks |",
        "",
        "License: MIT. Vulnerability records are sourced from the [NIST National Vulnerability Database](https://nvd.nist.gov/); CWE identifiers and names are from [MITRE CWE](https://cwe.mitre.org/).",
    ]
    return "\n".join(lines)


def render_model_card() -> str:
    lines = [
        "# Model Card — CVE-to-CWE LoRA adapter",
        "",
        "## Base model",
        "",
        f"`{META['model_name']}` at revision `{META['model_revision']}`. This is the same open-weight chat-model revision used for the unadapted comparison and as the LoRA base.",
        "",
        "## Training method",
        "",
        "LoRA supervised fine-tuning uses completion-only loss over the target JSON. Prompt tokens are masked, the training sample order is seeded, and validation loss is reported once per epoch without checkpoint selection.",
        "",
        "Adapter weights are not committed. A reproduction writes them to `experiments/exp_002_sft_v1/adapter/`.",
        "",
        "## Training dataset",
        "",
        f"The training data is a seed-{META['seed']} natural-distribution sample of {integer(META['train_count'])} rows from a {integer(MANIFEST['population_counts']['train'])}-record selected-class population. The validation view contains {integer(META['val_count'])} rows from a {integer(MANIFEST['population_counts']['val'])}-record population. Labels are the 15 most frequent eligible training-period CWE IDs, and only single-label English CVE records are included.",
        "",
        "Training dates are 2020-01-01–2024-12-31; validation dates are 2025-01-01–2025-12-31. Exact CVE-ID and normalized-description overlap between fine-tuning splits is 0 after build.",
        "",
        "## LoRA configuration",
        "",
        "| Setting | Value |",
        "|---|---|",
        f"| Rank | {META['lora_rank']} |",
        f"| Alpha | {META['lora_alpha']} |",
        f"| Dropout | {META['lora_dropout']} |",
        "| Target modules | `q_proj`, `k_proj`, `v_proj`, `o_proj` |",
        f"| Epochs | {META['epochs']} |",
        f"| Learning rate | {META['learning_rate']} |",
        f"| Device batch / gradient accumulation / effective batch | {META['batch_size']} / {META['gradient_accumulation']} / {META['batch_size'] * META['gradient_accumulation']} |",
        f"| Maximum sequence length | {integer(META['max_seq_length'])} |",
        f"| Precision | {META['precision']} |",
        "| Quantization | None |",
        f"| Trainable parameters | {integer(META['trainable_params'])} |",
        "",
        "## Evaluation dataset",
        "",
        f"The temporal test population contains {integer(MANIFEST['counts']['test'])} rows dated 2026-01-01–{MANIFEST['dataset_snapshot']}. Evaluation uses an ordered seed-{META['seed']} subset of {integer(SFT['n'])} rows; the Base and SFT CVE-ID sequences are identical. Generation is greedy with {SFT['generation']['max_new_tokens']} maximum new tokens and the same fixed prompt and deterministic evaluation verifier.",
        "",
        "KEV is an evaluation slice only.",
        "",
        "## Metrics",
        "",
        "| Metric | Base | SFT | Delta |",
        "|---|---:|---:|---:|",
        *metric_rows(include_weighted=True),
        "",
        "### Per-class F1",
        "",
        "Rows are sorted by evaluation support.",
        "",
        "| CWE ID | Name | Test support | Base F1 | SFT F1 | Delta |",
        "|---|---|---:|---:|---:|---:|",
        *per_class_f1_rows(with_name=True),
        "",
        "## Failure modes",
        "",
        f"Of {integer(FAIL['n_test'])} test rows, {integer(FAIL['transitions']['fixed_by_sft'])} were fixed by SFT, {integer(FAIL['transitions']['broken_by_sft'])} were broken by SFT, {integer(FAIL['transitions']['both_wrong'])} remained wrong, and {integer(FAIL['transitions']['both_right'])} were correct in both runs.",
        "",
        f"Residual SFT errors comprise {integer(FAIL['error_type_counts']['sft']['nearby_cwe_confusion'])} nearby-CWE confusions and {integer(FAIL['error_type_counts']['sft']['semantic_confusion'])} semantic confusions, with {integer(FAIL['error_type_counts']['sft']['unknown_cwe'])} unknown-CWE outputs and {integer(FAIL['error_type_counts']['sft']['invalid_format'])} invalid-format outputs. The most frequent SFT confusion is CWE-862→CWE-284 ({integer(FAIL['top_confusions_sft'][0]['count'])} rows). Long-tail accuracy is {f4(FAIL['long_tail']['sft_accuracy'])} over {integer(FAIL['long_tail']['n'])} rows.",
        "",
        "CWE-200 and CWE-120 F1 improved, but their recall changed by "
        f"{d4(FAIL['largest_changes']['recall']['largest_regressions'][0]['delta'])} and "
        f"{d4(FAIL['largest_changes']['recall']['largest_regressions'][1]['delta'])}, respectively.",
        "",
        "## Limitations",
        "",
        "- Single-label English CVE descriptions and a closed set of 15 CWE IDs only.",
        "- One temporal snapshot and one seed.",
        "- NVD weakness labels can be noisy, incomplete, or ambiguous from description text alone.",
        "- Multi-label records and labels outside the selected set are excluded.",
        "- Exact normalized-description checks do not detect semantic paraphrases.",
        "- Prior exposure of the unadapted model to NVD text cannot be verified.",
        "- KEV is an evaluation slice only, not a separate task or training target.",
        "- No Natural-vs-Balanced ablation, continued-domain adaptation, or reinforcement-learning phase was run.",
        "",
        "## Intended use",
        "",
        "Research reproduction of a domain-SFT experiment and closed-set CWE suggestion from English CVE text. Predictions should be treated as experiment outputs for analysis, not authoritative classifications.",
        "",
        "## Non-intended use",
        "",
        "Production vulnerability triage, security decisions, any use outside the 15-label closed set, or non-English text.",
    ]
    return "\n".join(lines)


def render_sft_eval() -> str:
    lines = [
        "# SFT Model Evaluation",
        "",
        "This report covers `exp_002_sft_v1` and compares it with the unadapted run on the same ordered 18,000-record subset of the 24,975-record test set.",
        "",
        "## Headline metrics",
        "",
        "| Metric | Base | SFT | Base→SFT delta |",
        "|---|---:|---:|---:|",
        f"| Evaluated records | {integer(BASE['n'])} | {integer(SFT['n'])} | {integer(SFT['n'] - BASE['n'])} |",
        *[row.replace("| Delta |", "| Base→SFT delta |") for row in metric_rows(include_weighted=True)],
        f"| Accuracy on valid outputs | {f4(BASE['accuracy_on_valid'])} | {f4(SFT['accuracy_on_valid'])} | {d4(SFT['accuracy_on_valid'] - BASE['accuracy_on_valid'])} |",
        "",
        "## Per-class results",
        "",
        "Tail marks the bottom third of selected labels by training-period count. Rows are sorted by evaluation support.",
        "",
        "| CWE | Tier | Support | Base P | SFT P | ΔP | Base R | SFT R | ΔR | Base F1 | SFT F1 | ΔF1 |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    tails = tail_labels()
    for cwe in support_order():
        b, s = BASE["per_class"][cwe], SFT["per_class"][cwe]
        lines.append(
            f"| {cwe} | {'tail' if cwe in tails else 'head'} | {integer(b['support'])} | "
            f"{f4(b['precision'])} | {f4(s['precision'])} | {d4(s['precision']-b['precision'])} | "
            f"{f4(b['recall'])} | {f4(s['recall'])} | {d4(s['recall']-b['recall'])} | "
            f"{f4(b['f1'])} | {f4(s['f1'])} | {d4(s['f1']-b['f1'])} |"
        )
    lines += [
        "",
        "## Invalid outputs",
        "",
        "| Reason | Base | SFT | Base→SFT delta |",
        "|---|---:|---:|---:|",
    ]
    for key, label in (("not_json", "Not JSON"), ("missing_key", "Missing `cwe_id`"), ("multiple_cwe", "Multiple CWE values"), ("bad_cwe_format", "Bad CWE format"), ("label_not_allowed", "Label outside the allowed set")):
        b, s = BASE["invalid_breakdown"][key], SFT["invalid_breakdown"][key]
        lines.append(f"| {label} | {integer(b)} | {integer(s)} | {s-b:+,} |")
    lines += [
        "",
        "## KEV slice",
        "",
        "| Slice | Records | Base accuracy | SFT accuracy | Base→SFT delta |",
        "|---|---:|---:|---:|---:|",
    ]
    for key, label in (("kev", "KEV"), ("non_kev", "Non-KEV")):
        b, s = BASE["slices"][key], SFT["slices"][key]
        lines.append(f"| {label} | {integer(s['n'])} | {f4(b['accuracy'])} | {f4(s['accuracy'])} | {d4(s['accuracy']-b['accuracy'])} |")
    lines += [
        "",
        "KEV is an evaluation slice only.",
        "",
        "## Generation and throughput",
        "",
        "| Setting | Base | SFT | Base→SFT delta |",
        "|---|---:|---:|---:|",
        f"| Sampling | {str(BASE['generation']['do_sample']).lower()} | {str(SFT['generation']['do_sample']).lower()} | same |",
        "| Temperature | null | null | same |",
        f"| Maximum new tokens | {BASE['generation']['max_new_tokens']} | {SFT['generation']['max_new_tokens']} | {SFT['generation']['max_new_tokens']-BASE['generation']['max_new_tokens']:+d} |",
        f"| Batch size | {BASE['generation']['batch_size']} | {SFT['generation']['batch_size']} | {SFT['generation']['batch_size']-BASE['generation']['batch_size']:+d} |",
        f"| Maximum sequence length | {integer(BASE['generation']['max_seq_length'])} | {integer(SFT['generation']['max_seq_length'])} | {SFT['generation']['max_seq_length']-BASE['generation']['max_seq_length']:+d} |",
        f"| Samples per second | {BASE['throughput']['samples_per_second']:.4f} | {SFT['throughput']['samples_per_second']:.4f} | {SFT['throughput']['samples_per_second']-BASE['throughput']['samples_per_second']:+.4f} |",
        f"| Wall time, seconds | {BASE['throughput']['wall_seconds']:.4f} | {SFT['throughput']['wall_seconds']:.4f} | {SFT['throughput']['wall_seconds']-BASE['throughput']['wall_seconds']:+.4f} |",
        f"| Peak VRAM, MiB | {BASE['throughput']['peak_vram_mib']:.4f} | {SFT['throughput']['peak_vram_mib']:.4f} | {SFT['throughput']['peak_vram_mib']-BASE['throughput']['peak_vram_mib']:+.4f} |",
        "",
        "The decoding configuration matches Base: greedy decoding, null temperature, 32 maximum new tokens, and a 1,536-token sequence limit. Evaluation batch size is an execution setting; it was 2 for Base and 8 for SFT.",
        "",
        "## Identical CVE-ID set check",
        "",
        f"The complete ordered CVE-ID sequence matches exactly: {integer(SFT['n'])} of {integer(BASE['n'])} IDs, including order. Both metric files use subset hash `{SFT['subset_hash']}`.",
        "",
        "## Observations",
        "",
        f"1. Accuracy changed from {f4(BASE['accuracy'])} to {f4(SFT['accuracy'])}, macro F1 from {f4(BASE['macro_f1'])} to {f4(SFT['macro_f1'])}, and invalid-output rate from {f4(BASE['invalid_rate'])} to {f4(SFT['invalid_rate'])}.",
        f"2. All 15 classes gained F1. The largest gain was CWE-416 at {d4(FAIL['per_class_delta']['CWE-416']['delta'])}.",
        f"3. Recall decreased for CWE-200 ({d4(FAIL['per_class']['CWE-200']['delta']['recall'])}) and CWE-120 ({d4(FAIL['per_class']['CWE-120']['delta']['recall'])}); no other class had a recall decrease.",
        f"4. Top-three prediction concentration changed from {f4(FAIL['prediction_distribution_concentration']['base']['top_3_share'])} to {f4(FAIL['prediction_distribution_concentration']['sft']['top_3_share'])}.",
        "",
        "## Failure taxonomy",
        "",
        "### Error types",
        "",
        "| Error type | Base | SFT | Base→SFT delta |",
        "|---|---:|---:|---:|",
    ]
    for key in ("invalid_format", "unknown_cwe", "nearby_cwe_confusion", "semantic_confusion"):
        b, s = FAIL["error_type_counts"]["base"][key], FAIL["error_type_counts"]["sft"][key]
        lines.append(f"| {key.replace('_', ' ')} | {integer(b)} | {integer(s)} | {s-b:+,} |")
    lines += [
        "",
        "### Top SFT confusions",
        "",
        "| Gold | Prediction | Base | SFT | Base→SFT delta |",
        "|---|---|---:|---:|---:|",
    ]
    for row in FAIL["top_confusions_sft"][:10]:
        b = confusion_count(BASE, row["gold"], row["pred"])
        lines.append(f"| {row['gold']} | {row['pred']} | {integer(b)} | {integer(row['count'])} | {row['count']-b:+,} |")
    lines += [
        "",
        "### Head and long-tail accuracy",
        "",
        "| Tier | Records | Base | SFT | Base→SFT delta |",
        "|---|---:|---:|---:|---:|",
        f"| long tail | {integer(FAIL['long_tail']['n'])} | {f4(FAIL['long_tail']['base_accuracy'])} | {f4(FAIL['long_tail']['sft_accuracy'])} | {d4(FAIL['long_tail']['sft_accuracy']-FAIL['long_tail']['base_accuracy'])} |",
    ]
    head_n = FAIL["n_test"] - FAIL["long_tail"]["n"]
    head_base_correct = round(BASE["accuracy"] * BASE["n"] - FAIL["long_tail"]["base_accuracy"] * FAIL["long_tail"]["n"])
    head_sft_correct = round(SFT["accuracy"] * SFT["n"] - FAIL["long_tail"]["sft_accuracy"] * FAIL["long_tail"]["n"])
    head_base = head_base_correct / head_n
    head_sft = head_sft_correct / head_n
    lines.append(f"| head | {integer(head_n)} | {f4(head_base)} | {f4(head_sft)} | {d4(head_sft-head_base)} |")
    for key, title in (("description_length_buckets", "Accuracy by description length"), ("token_length_buckets", "Accuracy by token length")):
        lines += [
            "",
            f"### {title}",
            "",
            "| Bucket | Records | Base | SFT | Base→SFT delta |",
            "|---|---:|---:|---:|---:|",
        ]
        for bucket, b in FAIL["slices"]["base"][key].items():
            s = FAIL["slices"]["sft"][key][bucket]
            lines.append(f"| {bucket} | {integer(b['n'])} | {f4(b['accuracy'])} | {f4(s['accuracy'])} | {d4(s['accuracy']-b['accuracy'])} |")
    lines += [
        "",
        "Lower accuracy was observed together with longer descriptions in the Base buckets; the slice comparison does not establish causation.",
    ]
    return "\n".join(lines)


def render_failure_analysis() -> str:
    tails = tail_labels()
    examples = quoted_failure_examples()
    lines = [
        "# Comparative Failure Analysis",
        "",
        "All counts use the identical ordered 18,000-row Base/SFT evaluation subset.",
        "",
        "## Outcome transitions",
        "",
        "| Transition | Count |",
        "|---|---:|",
    ]
    for key in ("both_right", "fixed_by_sft", "broken_by_sft", "both_wrong"):
        lines.append(f"| `{key}` | {integer(FAIL['transitions'][key])} |")
    lines += [
        "",
        "## Error-type counts",
        "",
        "| Outcome or error type | Base | SFT | Delta |",
        "|---|---:|---:|---:|",
    ]
    for key in ("correct", "invalid_format", "unknown_cwe", "nearby_cwe_confusion", "semantic_confusion"):
        b, s = FAIL["error_type_counts"]["base"][key], FAIL["error_type_counts"]["sft"][key]
        lines.append(f"| `{key}` | {integer(b)} | {integer(s)} | {s-b:+,} |")
    lines += [
        "",
        "## Per-class F1 delta",
        "",
        "Tail is the bottom third of labels by training-period count in `data/processed/labels.json`.",
        "",
        "| CWE | Tier | Train count | Test support | Base F1 | SFT F1 | Delta |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for cwe in support_order():
        values = FAIL["per_class_delta"][cwe]
        lines.append(
            f"| {cwe} | {'tail' if cwe in tails else 'head'} | {integer(LABELS['train_counts'][cwe])} | "
            f"{integer(BASE['per_class'][cwe]['support'])} | {f4(values['base_f1'])} | {f4(values['sft_f1'])} | {d4(values['delta'])} |"
        )
    for model, title in (("base", "Base"), ("sft", "SFT")):
        lines += [
            "",
            f"## Top 10 confusions — {title}",
            "",
            "| Rank | Gold | Prediction | Count |",
            "|---:|---|---|---:|",
        ]
        for rank, row in enumerate(FAIL[f"top_confusions_{model}"][:10], 1):
            lines.append(f"| {rank} | {row['gold']} | {row['pred']} | {integer(row['count'])} |")
    lines += [
        "",
        "## Long-tail slice",
        "",
        "| Records | Base accuracy | SFT accuracy | Delta |",
        "|---:|---:|---:|---:|",
        f"| {integer(FAIL['long_tail']['n'])} | {f4(FAIL['long_tail']['base_accuracy'])} | {f4(FAIL['long_tail']['sft_accuracy'])} | {d4(FAIL['long_tail']['sft_accuracy']-FAIL['long_tail']['base_accuracy'])} |",
        "",
        "## Quoted failure records",
        "",
        "The four broken-by-SFT records and six both-wrong records below have different gold classes. Excerpts are capped at 300 characters.",
    ]
    for index, row in enumerate(examples, 1):
        lines += [
            "",
            f"### {index}. {row['cve_id']}",
            "",
            f"- Transition: `{row['transition']}`",
            f"- Gold: `{row['gold']}`",
            f"- Base: `{row['base_prediction']}`",
            f"- SFT: `{row['prediction']}`",
            f"- Error type: `{row['error_type']}`",
            "",
            f"> {excerpt(row['description'], 300)}",
        ]
    largest = FAIL["largest_changes"]["f1"]["largest_gains"]
    lines += [
        "",
        "## What SFT fixed and what remains",
        "",
        f"- SFT fixed {integer(FAIL['transitions']['fixed_by_sft'])} Base errors and broke {integer(FAIL['transitions']['broken_by_sft'])} Base-correct rows; {integer(FAIL['transitions']['both_wrong'])} rows remained wrong.",
        f"- Unknown-CWE outputs changed from {integer(FAIL['error_type_counts']['base']['unknown_cwe'])} to {integer(FAIL['error_type_counts']['sft']['unknown_cwe'])}; nearby-CWE confusions changed from {integer(FAIL['error_type_counts']['base']['nearby_cwe_confusion'])} to {integer(FAIL['error_type_counts']['sft']['nearby_cwe_confusion'])}; semantic confusions changed from {integer(FAIL['error_type_counts']['base']['semantic_confusion'])} to {integer(FAIL['error_type_counts']['sft']['semantic_confusion'])}.",
        f"- Every class gained F1. The three largest gains were {largest[0]['cwe']} ({d4(largest[0]['delta'])}), {largest[1]['cwe']} ({d4(largest[1]['delta'])}), and {largest[2]['cwe']} ({d4(largest[2]['delta'])}).",
        f"- Long-tail accuracy changed from {f4(FAIL['long_tail']['base_accuracy'])} to {f4(FAIL['long_tail']['sft_accuracy'])}; {integer(FAIL['flag_counts']['sft']['gold_is_long_tail'])} residual SFT failures have a long-tail gold label.",
        f"- The largest remaining confusion is CWE-862→CWE-284 ({integer(FAIL['top_confusions_sft'][0]['count'])}). Recall decreased for CWE-200 ({d4(FAIL['per_class']['CWE-200']['delta']['recall'])}) and CWE-120 ({d4(FAIL['per_class']['CWE-120']['delta']['recall'])}).",
        f"- Top-three prediction concentration changed from {f4(FAIL['prediction_distribution_concentration']['base']['top_3_share'])} to {f4(FAIL['prediction_distribution_concentration']['sft']['top_3_share'])}.",
        "- Lower accuracy was observed together with longer descriptions in the Base buckets; this is a co-occurrence, not a causal result.",
    ]
    return "\n".join(lines)


def main() -> None:
    write("README.md", render_readme())
    write("MODEL_CARD.md", render_model_card())
    write("reports/sft_eval.md", render_sft_eval())
    write("reports/failure_analysis.md", render_failure_analysis())


if __name__ == "__main__":
    main()

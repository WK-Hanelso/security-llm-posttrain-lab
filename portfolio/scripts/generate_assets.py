#!/usr/bin/env python3
"""Generate portfolio figures from frozen report artifacts only."""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch, Rectangle


ROOT = Path(__file__).resolve().parents[2]
REPORTS = ROOT / "reports"
ASSETS = ROOT / "portfolio" / "assets"

BASE_COLOR = "#64748B"
SFT_COLOR = "#03C75A"
NAVY = "#172554"
BLUE = "#2563EB"
PALE_BLUE = "#EFF6FF"
PALE_GREEN = "#ECFDF5"
GRID = "#CBD5E1"
TEXT = "#0F172A"
MUTED = "#475569"


def load_json(name: str) -> dict:
    return json.loads((REPORTS / name).read_text(encoding="utf-8"))


def style() -> None:
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 16,
            "axes.titlesize": 24,
            "axes.labelsize": 17,
            "xtick.labelsize": 15,
            "ytick.labelsize": 16,
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "savefig.facecolor": "white",
            "svg.fonttype": "none",
        }
    )


def save_pair(fig: plt.Figure, stem: str) -> None:
    ASSETS.mkdir(parents=True, exist_ok=True)
    fig.savefig(ASSETS / f"{stem}.png", dpi=180, bbox_inches="tight")
    fig.savefig(ASSETS / f"{stem}.svg", bbox_inches="tight")
    plt.close(fig)


def primary_result(base: dict, sft: dict) -> None:
    assert base["n"] == sft["n"] == 18_000
    assert sft["subset_hash"] == load_json("eval_subset_manifest.json")["subset_hash"]

    labels = ["Accuracy", "Macro F1", "Weighted F1"]
    base_values = [base["accuracy"], base["macro_f1"], base["weighted_f1"]]
    sft_values = [sft["accuracy"], sft["macro_f1"], sft["weighted_f1"]]

    fig = plt.figure(figsize=(16, 9.2))
    grid = fig.add_gridspec(2, 1, height_ratios=[4.7, 1.35], hspace=0.34)
    ax = fig.add_subplot(grid[0])
    x = range(len(labels))
    width = 0.31
    base_bars = ax.bar(
        [i - width / 2 for i in x], base_values, width, color=BASE_COLOR, label="Base"
    )
    sft_bars = ax.bar(
        [i + width / 2 for i in x], sft_values, width, color=SFT_COLOR, label="LoRA SFT"
    )
    ax.set_ylim(0, 1.02)
    ax.set_ylabel("Score")
    ax.set_xticks(list(x), labels)
    ax.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax.grid(axis="y", color=GRID, linewidth=0.8, alpha=0.75)
    ax.set_axisbelow(True)
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(frameon=False, ncol=2, loc="upper left")
    for bars in (base_bars, sft_bars):
        for bar in bars:
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.022,
                f"{bar.get_height():.4f}",
                ha="center",
                va="bottom",
                fontsize=16,
                fontweight="bold",
                color=TEXT,
            )

    fig.suptitle(
        "LoRA SFT lifts classification quality on the same frozen test set",
        x=0.075,
        y=0.98,
        ha="left",
        fontsize=26,
        fontweight="bold",
        color=TEXT,
    )
    fig.text(
        0.075,
        0.925,
        "Same ordered 18,000-ID subset • deterministic verifier • greedy decoding",
        fontsize=16,
        color=MUTED,
    )

    mini = fig.add_subplot(grid[1])
    mini.set_xlim(0, 100)
    mini.set_ylim(0, 1)
    mini.axis("off")
    base_invalid = base["invalid_rate"] * 100
    sft_invalid = sft["invalid_rate"] * 100
    mini.text(0, 0.79, "Invalid-output rate", fontsize=18, fontweight="bold", color=TEXT)
    mini.text(0, 0.32, f"Base  {base_invalid:.2f}%", fontsize=19, color=BASE_COLOR, fontweight="bold")
    mini.add_patch(
        FancyArrowPatch(
            (29, 0.38),
            (62, 0.38),
            arrowstyle="-|>",
            mutation_scale=20,
            linewidth=2.2,
            color=BLUE,
        )
    )
    mini.text(68, 0.32, f"SFT  {sft_invalid:.0f}%", fontsize=19, color=SFT_COLOR, fontweight="bold")
    mini.text(0, 0.02, "Kept separate from the score axis", fontsize=14, color=MUTED)
    save_pair(fig, "01_base_vs_sft_metrics")


def confusion_reduction(summary: dict) -> None:
    pairs = [
        "CWE-862 → CWE-200",
        "CWE-284 → CWE-200",
        "CWE-416 → CWE-434",
        "CWE-787 → CWE-120",
        "CWE-125 → CWE-120",
    ]
    keys = [pair.replace(" → ", "->") for pair in pairs]
    base_values = [summary["tracked_confusions"][key]["base"] for key in keys]
    sft_values = [summary["tracked_confusions"][key]["sft"] for key in keys]

    fig, ax = plt.subplots(figsize=(16, 9))
    y = list(range(len(pairs)))
    height = 0.34
    base_bars = ax.barh(
        [i + height / 2 for i in y], base_values, height, color=BASE_COLOR, label="Base"
    )
    sft_bars = ax.barh(
        [i - height / 2 for i in y], sft_values, height, color=SFT_COLOR, label="LoRA SFT"
    )
    ax.set_yticks(y, pairs)
    ax.invert_yaxis()
    ax.set_xlim(0, 2150)
    ax.set_xlabel("Error count (true label → predicted label)")
    ax.grid(axis="x", color=GRID, linewidth=0.8, alpha=0.75)
    ax.set_axisbelow(True)
    ax.spines[["top", "right", "left"]].set_visible(False)
    ax.legend(frameon=False, ncol=2, loc="lower right")
    for bars in (base_bars, sft_bars):
        for bar in bars:
            ax.text(
                bar.get_width() + 24,
                bar.get_y() + bar.get_height() / 2,
                f"{int(bar.get_width()):,}",
                va="center",
                fontsize=15,
                color=TEXT,
                fontweight="bold",
            )
    ax.set_title(
        "SFT reduces the Base model's semantic prediction sinks",
        loc="left",
        pad=55,
        fontweight="bold",
        color=TEXT,
    )
    ax.text(
        0,
        1.035,
        "The improvement extends beyond output formatting to repeated class confusions.",
        transform=ax.transAxes,
        color=MUTED,
        fontsize=16,
    )
    fig.tight_layout()
    save_pair(fig, "02_confusion_reduction")


def pipeline_diagram() -> None:
    fig, ax = plt.subplots(figsize=(18, 8.4))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.add_patch(Rectangle((0.02, 0.53), 0.96, 0.34, facecolor=PALE_BLUE, edgecolor="none"))
    ax.add_patch(Rectangle((0.02, 0.08), 0.96, 0.34, facecolor=PALE_GREEN, edgecolor="none"))
    ax.text(0.04, 0.82, "DATA LAYER", fontsize=15, fontweight="bold", color=BLUE)
    ax.text(0.04, 0.37, "MODEL + EVALUATION LAYER", fontsize=15, fontweight="bold", color="#047857")

    data_labels = [
        "NVD CVE",
        "Canonical\nSecurity Record",
        "CWE Label\nPolicy",
        "Temporal\nSplit",
        "Exact\nDedup",
        "Fail-fast\nGuard",
    ]
    data_x = [0.045, 0.202, 0.359, 0.516, 0.673, 0.830]
    model_labels = [
        "Model\nAdapter",
        "Base /\nLoRA SFT",
        "Frozen\nSame-test Eval",
        "Failure\nAnalysis",
    ]
    model_x = [0.72, 0.49, 0.26, 0.03]

    def box(x: float, y: float, label: str, number: int, color: str) -> None:
        width, height = 0.13, 0.145
        ax.add_patch(
            FancyBboxPatch(
                (x, y),
                width,
                height,
                boxstyle="round,pad=0.012,rounding_size=0.018",
                facecolor="white",
                edgecolor=color,
                linewidth=2,
            )
        )
        ax.text(x + 0.014, y + height - 0.032, f"{number:02d}", fontsize=12, color=color, fontweight="bold")
        ax.text(
            x + width / 2,
            y + height / 2 - 0.008,
            label,
            ha="center",
            va="center",
            fontsize=14,
            color=TEXT,
            fontweight="bold",
        )

    def arrow(start: tuple[float, float], end: tuple[float, float], color: str = MUTED) -> None:
        ax.add_patch(
            FancyArrowPatch(
                start,
                end,
                arrowstyle="-|>",
                mutation_scale=15,
                linewidth=1.8,
                color=color,
                connectionstyle="arc3,rad=0",
            )
        )

    for index, (x, label) in enumerate(zip(data_x, data_labels), start=1):
        box(x, 0.61, label, index, BLUE)
        if index < len(data_labels):
            arrow((x + 0.13, 0.682), (data_x[index] - 0.008, 0.682))

    for offset, (x, label) in enumerate(zip(model_x, model_labels), start=7):
        box(x, 0.16, label, offset, "#059669")
        if offset < 10:
            next_x = model_x[offset - 6]
            arrow((x, 0.232), (next_x + 0.138, 0.232))

    arrow((0.895, 0.60), (0.785, 0.315), BLUE)
    ax.text(
        0.04,
        0.95,
        "Security data pipeline with explicit leakage guards and frozen evaluation",
        fontsize=25,
        color=TEXT,
        fontweight="bold",
    )
    ax.text(
        0.04,
        0.905,
        "Public NVD records become a controlled 15-label task before model adaptation.",
        fontsize=16,
        color=MUTED,
    )
    save_pair(fig, "03_security_data_pipeline")


def transition_summary(summary: dict) -> None:
    transitions = summary["transitions"]
    order = ["both_right", "fixed_by_sft", "broken_by_sft", "both_wrong"]
    labels = ["Both right", "Fixed by SFT", "Broken by SFT", "Both wrong"]
    colors = ["#2563EB", SFT_COLOR, "#F59E0B", "#94A3B8"]
    values = [transitions[key] for key in order]
    assert sum(values) == summary["n_test"] == 18_000

    fig, ax = plt.subplots(figsize=(16, 6.7))
    left = 0
    centers = []
    for value, color in zip(values, colors):
        ax.barh([0], [value], left=left, height=0.42, color=color, edgecolor="white", linewidth=2)
        centers.append(left + value / 2)
        left += value

    ax.set_xlim(0, summary["n_test"])
    ax.set_ylim(-0.65, 0.8)
    ax.set_yticks([])
    ax.set_xlabel("Evaluation rows")
    ax.set_xticks([0, 3000, 6000, 9000, 12000, 15000, 18000])
    ax.grid(axis="x", color=GRID, linewidth=0.8, alpha=0.65)
    ax.set_axisbelow(True)
    ax.spines[["top", "right", "left"]].set_visible(False)

    for center, label, value, color in zip(centers, labels, values, colors):
        if value >= 1000:
            ax.text(center, 0, f"{label}\n{value:,}", ha="center", va="center", fontsize=15, color="white", fontweight="bold")
        else:
            ax.annotate(
                f"{label}\n{value:,}",
                xy=(center, 0.21),
                xytext=(center, 0.56),
                ha="center",
                va="bottom",
                fontsize=14,
                color=TEXT,
                fontweight="bold",
                arrowprops={"arrowstyle": "-", "color": color, "linewidth": 1.8},
            )

    ax.set_title(
        "Row-level outcome transitions after LoRA SFT",
        loc="left",
        pad=45,
        fontweight="bold",
        color=TEXT,
    )
    ax.text(
        0,
        1.04,
        "Counts sum exactly to the frozen 18,000-row evaluation subset.",
        transform=ax.transAxes,
        color=MUTED,
        fontsize=16,
    )
    fig.tight_layout()
    save_pair(fig, "04_transition_summary")


def main() -> None:
    style()
    base = load_json("baseline_metrics.json")
    sft = load_json("sft_metrics.json")
    summary = load_json("failure_summary.json")
    primary_result(base, sft)
    confusion_reduction(summary)
    pipeline_diagram()
    transition_summary(summary)


if __name__ == "__main__":
    main()

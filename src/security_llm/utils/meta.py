"""Environment and experiment metadata collection."""

from __future__ import annotations

import importlib.metadata
import platform
import subprocess
from datetime import datetime, timezone
from typing import Any


def _version(package: str) -> str | None:
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return None


def _git_commit() -> str:
    result = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def collect_env() -> dict[str, Any]:
    import torch
    return {"git_commit": _git_commit(), "python": platform.python_version(),
        "gpu": torch.cuda.get_device_name(0) if torch.cuda.is_available() else None,
        "cuda": torch.version.cuda, "pytorch": torch.__version__,
        "transformers": _version("transformers"), "trl": _version("trl"), "peft": _version("peft")}


def build_metadata(cfg: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    training, lora, model = cfg.get("training", {}), cfg.get("lora", {}), cfg.get("model", {})
    counts = manifest.get("counts", {})
    return {"experiment_id": cfg["experiment_id"], **collect_env(), "created_at": datetime.now(timezone.utc).isoformat(),
        "model_name": model.get("name"), "model_revision": model.get("revision"),
        "dataset_snapshot": manifest.get("dataset_snapshot"), "dataset_manifest_sha256": None,
        "train_count": counts.get("train"), "val_count": counts.get("val"), "test_count": counts.get("test"),
        "class_distribution": manifest.get("class_distribution"), "seed": cfg.get("seed"),
        "learning_rate": training.get("learning_rate"), "epochs": training.get("epochs"),
        "batch_size": training.get("per_device_train_batch_size"),
        "gradient_accumulation": training.get("gradient_accumulation_steps"),
        "max_seq_length": training.get("max_seq_length"), "lora_rank": lora.get("rank"),
        "lora_alpha": lora.get("alpha"), "lora_dropout": lora.get("dropout"),
        "target_modules": lora.get("target_modules"),
        "precision": "bf16" if training.get("bf16") else "fp16" if training.get("fp16") else model.get("dtype"),
        "quantization": cfg.get("quantization"), "prompt_template_sha256": manifest.get("prompt_template_sha256")}

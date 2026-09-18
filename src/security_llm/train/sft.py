"""LoRA/QLoRA supervised fine-tuning with completion-only loss."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

import torch
import yaml
from datasets import Dataset
from peft import LoraConfig, prepare_model_for_kbit_training
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from trl import SFTConfig, SFTTrainer

from security_llm.config import load_config
from security_llm.prompt import render_chat_prompt
from security_llm.utils.io import atomic_write_json, read_jsonl, sha256_file, write_jsonl
from security_llm.utils.meta import build_metadata
from security_llm.utils.seed import set_seed

LOG = logging.getLogger(__name__)


def make_dataset(path: str | Path, tokenizer: Any) -> Dataset:
    return Dataset.from_list(
        [
            {
                "prompt": render_chat_prompt(tokenizer, row["prompt"]),
                "completion": row["completion"] + "<|im_end|>",
            }
            for row in read_jsonl(path)
        ]
    )


def make_sft_config(
    cfg: dict[str, Any],
    output_dir: Path,
    *,
    use_cpu: bool = False,
    max_steps: int | None = None,
) -> SFTConfig:
    training = cfg["training"]
    resolved_max_steps = training.get("max_steps") if max_steps is None else max_steps
    return SFTConfig(
        output_dir=str(output_dir),
        num_train_epochs=float(training["epochs"]),
        max_steps=-1 if resolved_max_steps is None else int(resolved_max_steps),
        learning_rate=float(training["learning_rate"]),
        lr_scheduler_type=training["lr_scheduler_type"],
        warmup_steps=float(training["warmup_ratio"]),
        per_device_train_batch_size=int(training["per_device_train_batch_size"]),
        gradient_accumulation_steps=int(training["gradient_accumulation_steps"]),
        fp16=False if use_cpu else bool(training["fp16"]),
        bf16=False if use_cpu else bool(training["bf16"]),
        gradient_checkpointing=False if use_cpu else bool(training["gradient_checkpointing"]),
        logging_steps=int(training["logging_steps"]),
        eval_strategy=training["eval_strategy"],
        save_strategy=training["save_strategy"],
        weight_decay=float(training["weight_decay"]),
        max_grad_norm=float(training["max_grad_norm"]),
        seed=int(cfg["seed"]),
        max_length=int(training["max_seq_length"]),
        completion_only_loss=True,
        report_to=[],
        dataloader_num_workers=0 if use_cpu else 2,
        dataloader_pin_memory=not use_cpu,
        remove_unused_columns=True,
        use_cpu=use_cpu,
    )


def assert_completion_mask(batch: dict[str, torch.Tensor], im_end_id: int) -> tuple[int, int]:
    labels = batch["labels"]
    masked = int((labels == -100).sum().item())
    supervised = int((labels != -100).sum().item())
    if masked == 0 or supervised == 0:
        raise AssertionError(f"Invalid completion mask: masked={masked}, supervised={supervised}")
    for row in labels:
        nonmasked = torch.nonzero(row != -100, as_tuple=False).flatten()
        if not len(nonmasked):
            raise AssertionError("Batch row has no completion labels")
        first, last = int(nonmasked[0]), int(nonmasked[-1])
        if not bool(torch.all(row[:first] == -100)):
            raise AssertionError("A prompt token is not masked")
        if not bool(torch.all(row[first : last + 1] != -100)):
            raise AssertionError("A completion token is masked")
        if int(row[last]) != im_end_id:
            raise AssertionError("Last supervised token is not <|im_end|>")
    return masked, supervised


def assert_dataset_completion_masks(
    dataset: Dataset, im_end_id: int, expected_rows: int
) -> None:
    """Verify every trainer-tokenized row retains a complete supervised completion."""
    if len(dataset) != expected_rows:
        raise AssertionError(
            "Trainer dropped rows with no supervised labels: "
            f"expected={expected_rows} actual={len(dataset)}"
        )
    for index, row in enumerate(dataset):
        labels = row["labels"]
        supervised = [label for label in labels if label != -100]
        if not supervised:
            raise AssertionError(f"Train row {index} has no supervised labels")
        if supervised[-1] != im_end_id:
            raise AssertionError(
                f"Train row {index} completion was truncated before <|im_end|>"
            )
    LOG.info("mask check: rows=%d truncated_completions=0", expected_rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--override", action="append", default=[])
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)
    cfg = load_config(args.config, args.override)
    set_seed(int(cfg["seed"]))
    if torch.cuda.is_available():
        torch.cuda.reset_peak_memory_stats()
    out_dir = Path(cfg["output"]["root"]) / cfg["experiment_id"]
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "config_resolved.yaml").write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    model_cfg = cfg["model"]
    tokenizer = AutoTokenizer.from_pretrained(model_cfg["name"], revision=model_cfg.get("revision"))
    tokenizer.padding_side = "right"
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token
    quantized = bool(cfg["quantization"]["load_in_4bit"])
    if quantized:
        bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4", bnb_4bit_use_double_quant=True, bnb_4bit_compute_dtype=torch.float16)
        model = AutoModelForCausalLM.from_pretrained(model_cfg["name"], revision=model_cfg.get("revision"), quantization_config=bnb, device_map={"": 0})
        model = prepare_model_for_kbit_training(model)
    else:
        model = AutoModelForCausalLM.from_pretrained(model_cfg["name"], revision=model_cfg.get("revision"), torch_dtype=torch.float16, device_map={"": 0})
    model.config.use_cache = False
    lora_cfg = cfg["lora"]
    lora = LoraConfig(r=int(lora_cfg["rank"]), lora_alpha=int(lora_cfg["alpha"]), lora_dropout=float(lora_cfg["dropout"]), target_modules=lora_cfg["target_modules"], bias=lora_cfg["bias"], task_type="CAUSAL_LM")
    train_ds = make_dataset(cfg["data"]["train_file"], tokenizer)
    val_ds = make_dataset(cfg["data"]["val_file"], tokenizer)
    trainer = SFTTrainer(
        model=model,
        args=make_sft_config(cfg, out_dir / "trainer"),
        train_dataset=train_ds,
        eval_dataset=val_ds,
        processing_class=tokenizer,
        peft_config=lora,
    )
    for parameter in trainer.model.parameters():
        if parameter.requires_grad and parameter.dtype == torch.float16:
            parameter.data = parameter.data.float()
    trainer.model.print_trainable_parameters()
    trainable_params = sum(parameter.numel() for parameter in trainer.model.parameters() if parameter.requires_grad)
    assert_dataset_completion_masks(
        trainer.train_dataset,
        tokenizer.convert_tokens_to_ids("<|im_end|>"),
        expected_rows=len(train_ds),
    )
    started = time.monotonic()
    result = trainer.train()
    trainer.model.save_pretrained(out_dir / "adapter")
    tokenizer.save_pretrained(out_dir / "adapter")
    log_rows = list(trainer.state.log_history)
    log_rows.append({"event": "end", "train_runtime_s": time.monotonic() - started,
        "train_samples_per_second": result.metrics.get("train_samples_per_second"),
        "peak_vram_mib": torch.cuda.max_memory_allocated() / 1024**2, "total_steps": trainer.state.global_step})
    write_jsonl(out_dir / "train_log.jsonl", log_rows)
    with Path("manifests/dataset_manifest.json").open(encoding="utf-8") as handle:
        manifest = json.load(handle)
    metadata = build_metadata(cfg, manifest)
    metadata["dataset_hash"] = manifest.get("dataset_hash")
    metadata["dataset_manifest_sha256"] = sha256_file("manifests/dataset_manifest.json")
    metadata["model_revision"] = getattr(model.config, "_commit_hash", None) or model_cfg.get("revision")
    metadata["trainable_params"] = trainable_params
    metadata["training_config"] = cfg
    metadata["subset_hash"] = "N/A"
    atomic_write_json(out_dir / "metadata.json", metadata)


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        if torch.cuda.is_available():
            LOG.error("CUDA peak allocated before failure: %.1f MiB", torch.cuda.max_memory_allocated() / 1024**2)
        raise

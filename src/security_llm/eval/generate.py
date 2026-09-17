"""Batched greedy generation and deterministic evaluation."""

from __future__ import annotations

import argparse
import json
import shutil
import time
from pathlib import Path
from typing import Any, Iterator

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

from security_llm.config import load_config
from security_llm.eval.metrics import compute
from security_llm.eval.verifier import verify
from security_llm.prompt import render_chat_prompt
from security_llm.utils.io import atomic_write_json, read_jsonl, sha256_file, write_jsonl
from security_llm.utils.meta import build_metadata
from security_llm.utils.seed import set_seed


def _chunks(rows: list[dict[str, Any]], size: int) -> Iterator[list[dict[str, Any]]]:
    for offset in range(0, len(rows), size):
        yield rows[offset : offset + size]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--override", action="append", default=[])
    parser.add_argument("--report-name", default=None)
    args = parser.parse_args()
    cfg = load_config(args.config, args.override)
    set_seed(int(cfg["seed"]))
    model_cfg, generation_cfg = cfg["model"], cfg["generation"]
    tokenizer = AutoTokenizer.from_pretrained(model_cfg["name"], revision=model_cfg.get("revision"))
    tokenizer.padding_side = "left"
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token
    dtype = getattr(torch, model_cfg["dtype"])
    model = AutoModelForCausalLM.from_pretrained(model_cfg["name"], revision=model_cfg.get("revision"), torch_dtype=dtype, device_map={"": 0})
    merged = False
    if model_cfg.get("adapter_path"):
        model = PeftModel.from_pretrained(model, model_cfg["adapter_path"]).merge_and_unload()
        merged = True
    model.eval()
    rows = read_jsonl(cfg["data"]["file"])
    limit = cfg["data"].get("limit")
    if limit is not None:
        rows = rows[: int(limit)]
    with Path(cfg["data"]["labels_file"]).open(encoding="utf-8") as handle:
        labels = json.load(handle)
    allowed = set(labels["selected"])
    max_length = int(generation_cfg.get("max_seq_length", 512))
    max_new_tokens = int(generation_cfg["max_new_tokens"])
    rendered = [render_chat_prompt(tokenizer, row["prompt"]) for row in rows]
    for row, prompt in zip(rows, rendered):
        length = len(tokenizer(prompt, add_special_tokens=False)["input_ids"])
        if length > max_length - max_new_tokens:
            raise ValueError(f"Prompt exceeds token budget for {row['cve_id']}: {length}")
    eos_ids = list(dict.fromkeys([tokenizer.convert_tokens_to_ids("<|im_end|>"), tokenizer.eos_token_id]))
    eos_ids = [token_id for token_id in eos_ids if token_id is not None]
    torch.cuda.reset_peak_memory_stats()
    started = time.monotonic()
    predictions: list[dict[str, Any]] = []
    batch_size = int(generation_cfg["batch_size"])
    for start, batch in enumerate(_chunks(rows, batch_size)):
        prompts = rendered[start * batch_size : start * batch_size + len(batch)]
        encoded = tokenizer(prompts, return_tensors="pt", padding=True, add_special_tokens=False).to("cuda")
        with torch.no_grad():
            output = model.generate(**encoded, do_sample=False, max_new_tokens=max_new_tokens, eos_token_id=eos_ids, pad_token_id=tokenizer.pad_token_id)
        generated = output[:, encoded.input_ids.shape[1] :]
        for row, token_ids in zip(batch, generated):
            raw_output = tokenizer.decode(token_ids, skip_special_tokens=True)
            checked = verify(raw_output, row["cwe_id"], allowed)
            n_new = int((token_ids != tokenizer.pad_token_id).sum().item())
            if n_new >= max_new_tokens and not checked["valid_json"]:
                checked["error_flags"].append("truncated_generation")
            predictions.append({"cve_id": row["cve_id"], "gold": row["cwe_id"], "raw_output": raw_output,
                **checked, "is_kev": row["is_kev"], "n_new_tokens": n_new})
    wall_seconds = time.monotonic() - started
    out_dir = Path(cfg["output"]["root"]) / cfg["experiment_id"]
    out_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(out_dir / "predictions.jsonl", predictions)
    metrics = {"experiment_id": cfg["experiment_id"], "limit": limit, **compute(predictions, labels["selected"]),
        "generation": generation_cfg, "throughput": {"samples_per_second": len(rows) / wall_seconds if wall_seconds else 0.0,
            "wall_seconds": wall_seconds, "peak_vram_mib": torch.cuda.max_memory_allocated() / 1024**2}}
    atomic_write_json(out_dir / "metrics.json", metrics)
    with Path("manifests/dataset_manifest.json").open(encoding="utf-8") as handle:
        manifest = json.load(handle)
    metadata = build_metadata(cfg, manifest)
    metadata["dataset_manifest_sha256"] = sha256_file("manifests/dataset_manifest.json")
    metadata["model_revision"] = getattr(model.config, "_commit_hash", None) or model_cfg.get("revision")
    metadata["merged"] = merged
    atomic_write_json(out_dir / "metadata.json", metadata)
    report_name = args.report_name or ("sft_metrics.json" if "sft" in cfg["experiment_id"] else "baseline_metrics.json")
    Path("reports").mkdir(exist_ok=True)
    shutil.copy2(out_dir / "metrics.json", Path("reports") / report_name)


if __name__ == "__main__":
    main()

import copy

import pytest
import torch
from datasets import Dataset
from peft import LoraConfig
from transformers import AutoModelForCausalLM, AutoTokenizer
from trl import SFTTrainer

from security_llm.config import load_config
from security_llm.prompt import build_user_prompt, render_chat_prompt
from security_llm.train.sft import assert_completion_mask, make_sft_config


def test_completion_only_mask_with_qwen_tokenizer_and_model(tmp_path):
    model_name = "Qwen/Qwen3-0.6B"
    try:
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModelForCausalLM.from_pretrained(model_name, torch_dtype=torch.float32)
    except (OSError, ConnectionError) as exc:
        pytest.skip(f"Qwen model unavailable offline: {exc}")
    tokenizer.padding_side = "right"
    selected = ["CWE-79", "CWE-89"]
    rows = []
    for index in range(4):
        user = build_user_prompt(f"Synthetic vulnerability description {index}.", selected)
        rows.append({"prompt": render_chat_prompt(tokenizer, user), "completion": '{"cwe_id": "CWE-79"}<|im_end|>'})
    dataset = Dataset.from_list(rows)
    cfg = copy.deepcopy(load_config("configs/sft.yaml"))
    cfg["training"].update({"eval_strategy": "no", "save_strategy": "no", "per_device_train_batch_size": 2,
        "gradient_accumulation_steps": 1, "max_seq_length": 512, "logging_steps": 1})
    trainer = SFTTrainer(
        model=model,
        args=make_sft_config(cfg, tmp_path / "trainer", use_cpu=True, max_steps=1),
        train_dataset=dataset,
        processing_class=tokenizer,
        peft_config=LoraConfig(r=2, lora_alpha=4, target_modules=["q_proj"], lora_dropout=0.0, bias="none", task_type="CAUSAL_LM"),
    )
    batch = next(iter(trainer.get_train_dataloader()))
    im_end_id = tokenizer.convert_tokens_to_ids("<|im_end|>")
    expected_completion = tokenizer(rows[0]["completion"], add_special_tokens=False)["input_ids"]
    masked, supervised = assert_completion_mask(batch, im_end_id)
    assert masked > 0 and supervised > 0
    for labels in batch["labels"]:
        first_completion = int(torch.nonzero(labels != -100, as_tuple=False)[0])
        assert torch.all(labels[:first_completion] == -100)
        supervised_labels = labels[labels != -100].tolist()
        assert supervised_labels == expected_completion
        assert all(label != -100 for label in supervised_labels)
        assert supervised_labels[-1] == im_end_id

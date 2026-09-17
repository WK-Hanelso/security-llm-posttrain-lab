"""The fixed classification prompt and chat rendering helpers."""

from __future__ import annotations

import hashlib

from security_llm.cwe_names import CWE_NAMES

PROMPT_TEMPLATE = (
    "Classify the vulnerability description into the most appropriate CWE ID.\n"
    "Choose exactly one CWE ID from this list:\n"
    "{label_lines}\n\n"
    "Return only JSON with key `cwe_id`, for example {{\"cwe_id\": \"CWE-79\"}}.\n\n"
    "Description: {description}"
)


def build_user_prompt(description: str, selected: list[str]) -> str:
    label_lines = "\n".join(f"- {cwe}: {CWE_NAMES[cwe]}" for cwe in selected)
    return PROMPT_TEMPLATE.format(label_lines=label_lines, description=description)


def render_chat_prompt(tokenizer: object, user_text: str) -> str:
    return tokenizer.apply_chat_template(  # type: ignore[attr-defined,no-any-return]
        [{"role": "user", "content": user_text}],
        tokenize=False,
        add_generation_prompt=True,
        enable_thinking=False,
    )


def prompt_template_sha256(selected: list[str]) -> str:
    value = PROMPT_TEMPLATE + "\n" + "\n".join(selected)
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

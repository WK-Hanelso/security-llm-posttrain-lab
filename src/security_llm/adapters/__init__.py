"""Model-adapter entry points."""

from security_llm.adapters.cwe_instruction import (
    OUTPUT_SCHEMA,
    PROMPT_TEMPLATE,
    build_user_prompt,
    prompt_template_sha256,
    render_chat_prompt,
    serialize_label,
)

__all__ = [
    "OUTPUT_SCHEMA",
    "PROMPT_TEMPLATE",
    "build_user_prompt",
    "prompt_template_sha256",
    "render_chat_prompt",
    "serialize_label",
]

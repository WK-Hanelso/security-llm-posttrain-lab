"""CWE closed-set instruction adapter."""

from __future__ import annotations

import json

from security_llm.prompt import (
    PROMPT_TEMPLATE,
    build_user_prompt,
    prompt_template_sha256,
    render_chat_prompt,
)

OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {"cwe_id": {"type": "string", "pattern": r"^CWE-\d+$"}},
    "required": ["cwe_id"],
    "additionalProperties": False,
}


def serialize_label(cwe_id: str) -> str:
    """Serialize a label exactly as stored in the SFT completion field."""

    return json.dumps({"cwe_id": cwe_id}, separators=(",", ": "))


__all__ = [
    "OUTPUT_SCHEMA",
    "PROMPT_TEMPLATE",
    "build_user_prompt",
    "prompt_template_sha256",
    "render_chat_prompt",
    "serialize_label",
]

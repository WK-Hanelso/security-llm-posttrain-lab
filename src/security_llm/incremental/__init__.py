"""Minimal, auditable incremental dataset prototype."""

from security_llm.incremental.prototype import (
    Change,
    classify_snapshots,
    run_incremental,
)

__all__ = ["Change", "classify_snapshots", "run_incremental"]

"""Pinned-hash verification for system prompt files."""

from __future__ import annotations

import hashlib


class PromptIntegrityError(RuntimeError):
    """Raised when a system prompt file does not match its pinned digest."""


def sha256_of(file_path: str) -> str:
    with open(file_path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def verify_prompt_hash(file_path: str, expected_hash: str) -> str:
    """Return the prompt text if its digest matches expected_hash, else raise."""
    with open(file_path, "rb") as handle:
        raw = handle.read()
    actual = hashlib.sha256(raw).hexdigest()
    if not expected_hash:
        raise PromptIntegrityError(
            f"No pinned hash supplied for {file_path}; refusing to load an unverified prompt."
        )
    if actual != expected_hash:
        raise PromptIntegrityError(
            f"{file_path} digest {actual} does not match pinned {expected_hash}."
        )
    return raw.decode("utf-8")

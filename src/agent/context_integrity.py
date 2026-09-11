"""HMAC protection for the context dict handed between orchestrator and sub-agent."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

_SIGNATURE_FIELD = "_signature"


class ContextIntegrityError(ValueError):
    """Raised when a context dict fails signature verification."""


def _signing_key() -> bytes:
    key = os.environ.get("CONTEXT_SIGNING_KEY")
    if not key:
        raise ContextIntegrityError(
            "CONTEXT_SIGNING_KEY environment variable is required to sign agent context."
        )
    return key.encode()


def _digest(payload: dict[str, Any]) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hmac.new(_signing_key(), body.encode(), hashlib.sha256).hexdigest()


def sign_context(context: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of context carrying an HMAC over its contents."""
    payload = {k: v for k, v in context.items() if k != _SIGNATURE_FIELD}
    return {**payload, _SIGNATURE_FIELD: _digest(payload)}


def verify_context(context: dict[str, Any]) -> dict[str, Any]:
    """Return the context's payload, or raise if the signature does not match."""
    signature = context.get(_SIGNATURE_FIELD)
    if not signature:
        raise ContextIntegrityError("Agent context carries no signature.")
    payload = {k: v for k, v in context.items() if k != _SIGNATURE_FIELD}
    if not hmac.compare_digest(signature, _digest(payload)):
        raise ContextIntegrityError("Agent context signature does not match its contents.")
    return payload

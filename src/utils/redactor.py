"""Redaction helpers for PII and secret material leaving the service."""

from __future__ import annotations

import re
from typing import Any

_PII_FIELDS = ("email", "address", "card_last4", "phone", "full_name")

_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY_ID]"),
    (re.compile(r"(?i)\baws_secret_access_key\b\s*[=:]\s*\S+"), "[REDACTED_AWS_SECRET]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb)(?:\+\w+)?://[^\s\"']+"), "[REDACTED_DSN]"),
    (re.compile(r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "[REDACTED_JWT]"),
    (re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password)\b\s*[=:]\s*\S+"), "[REDACTED_SECRET]"),
)


def redact_secrets_text(text: str) -> str:
    """Mask credential-shaped substrings in free text."""
    if not isinstance(text, str):
        return text
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def mask_email(value: str) -> str:
    local, _, domain = value.partition("@")
    if not domain:
        return "[REDACTED]"
    return f"{local[:1]}***@{domain}"


def redact_pii_dict(data: Any) -> Any:
    """Mask PII fields in a record, recursing through nested containers."""
    if isinstance(data, list):
        return [redact_pii_dict(item) for item in data]
    if not isinstance(data, dict):
        return data

    redacted: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, (dict, list)):
            redacted[key] = redact_pii_dict(value)
        elif key in _PII_FIELDS and value is not None:
            redacted[key] = mask_email(str(value)) if key == "email" else "[REDACTED]"
        else:
            redacted[key] = value
    return redacted

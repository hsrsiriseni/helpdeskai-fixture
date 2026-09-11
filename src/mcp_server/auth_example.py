"""
API key authentication for MCP tool calls.

Wired into server.py: every exposed tool carries @require_api_key, so a caller
must present the key whose SHA-256 digest is in MCP_API_KEY_HASH.
"""

import hashlib
import hmac
import os
from functools import wraps
from typing import Callable


class ApiKeyAuthMiddleware:
    """Validates a per-client API key on every MCP tool invocation.

    Configuration:
      MCP_API_KEY_HASH (env var): SHA-256 hex digest of the valid API key.
        Set this instead of the raw key so the key is never in the environment.

    Each tool function is wrapped with require_api_key(); the key travels in the
    tool call's arguments and is compared against the stored digest.
    """

    def __init__(self) -> None:
        self._key_hash = os.environ.get("MCP_API_KEY_HASH", "")
        if not self._key_hash:
            raise RuntimeError(
                "MCP_API_KEY_HASH environment variable is required. "
                "Set it to the SHA-256 hex digest of the MCP API key."
            )

    def validate(self, provided_key: str) -> bool:
        """Constant-time comparison against the stored key hash."""
        provided_hash = hashlib.sha256(provided_key.encode()).hexdigest()
        return hmac.compare_digest(provided_hash, self._key_hash)


def require_api_key(tool_func: Callable) -> Callable:
    """Decorator: reject tool calls that do not carry a valid API key."""

    @wraps(tool_func)
    def wrapper(*args, api_key: str = "", **kwargs):
        if not ApiKeyAuthMiddleware().validate(api_key):
            raise PermissionError("Invalid or missing API key for MCP tool call.")
        return tool_func(*args, **kwargs)

    return wrapper

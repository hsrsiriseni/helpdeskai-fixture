"""Tool authorization that does not depend on model output.

Each agent role carries a fixed capability set. A tool checks the role recorded
in the run context before it does any work, so a model that is talked into
calling a tool it was never granted is refused at the tool boundary.
"""

from __future__ import annotations

import contextvars
from functools import wraps
from typing import Callable

ORCHESTRATOR = "orchestrator"
SUB_AGENT = "sub_agent"

_CAPABILITIES: dict[str, frozenset[str]] = {
    ORCHESTRATOR: frozenset(
        {
            "read_file",
            "fetch_url",
            "lookup_order",
            "issue_refund",
            "search_kb",
            "create_ticket",
            "delegate_to_sub_agent",
        }
    ),
    SUB_AGENT: frozenset({"read_file", "fetch_url", "lookup_order", "search_kb"}),
}

_active_role: contextvars.ContextVar[str] = contextvars.ContextVar(
    "agent_role", default=ORCHESTRATOR
)


class ToolNotAuthorized(PermissionError):
    """Raised when the active agent role may not invoke the requested tool."""


def capabilities_for(role: str) -> frozenset[str]:
    return _CAPABILITIES.get(role, frozenset())


def set_active_role(role: str) -> contextvars.Token:
    return _active_role.set(role)


def reset_active_role(token: contextvars.Token) -> None:
    _active_role.reset(token)


def require_tool_authorization(capability: str) -> Callable:
    """Refuse the call unless the active role holds the named capability."""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            role = _active_role.get()
            if capability not in capabilities_for(role):
                raise ToolNotAuthorized(
                    f"Role {role!r} is not authorized to invoke {capability!r}."
                )
            return func(*args, **kwargs)

        return wrapper

    return decorator

"""
Agent tool definitions.

The ops tools (read_file, fetch_url) are constrained: reads are confined to an
allowlist of directories, and fetches are confined to an allowlist of hosts with
private address ranges refused. Shell execution is not exposed to the agent.

The HelpDeskAI domain tools wire the support agent into the tenant data layer
(src/data/*); each one passes the caller's tenant_id down, and the data layer
scopes every query by it.
"""

import ipaddress
import os
import socket
import subprocess
import urllib.parse
import urllib.request
from pathlib import Path

from langchain_core.tools import tool

from src.agent.authz import require_tool_authorization
from src.data.rds_client import RDSClient
from src.data.s3_client import S3Client
from src.data.dynamodb_client import DynamoDBClient
from src.utils.redactor import redact_pii_dict, redact_secrets_text

_MAX_FETCH_BYTES = 1_000_000
_FETCH_TIMEOUT_SECONDS = 5


def _allowed_read_roots() -> list[Path]:
    configured = os.environ.get("READ_FILE_PATHS", "")
    return [Path(p).resolve() for p in configured.split(",") if p.strip()]


def _allowed_fetch_hosts() -> set[str]:
    configured = os.environ.get("ALLOWED_FETCH_DOMAINS", "")
    return {h.strip().lower() for h in configured.split(",") if h.strip()}


def _allowed_shell_commands() -> set[str]:
    configured = os.environ.get("ALLOWED_SHELL_COMMANDS", "")
    return {c.strip() for c in configured.split(",") if c.strip()}


def _resolve_within_allowlist(path: str) -> Path:
    roots = _allowed_read_roots()
    if not roots:
        raise PermissionError(
            "READ_FILE_PATHS is not configured; no filesystem path may be read."
        )
    candidate = Path(path).resolve()
    if candidate.is_symlink():
        raise PermissionError(f"Refusing to read symlink {path!r}.")
    for root in roots:
        if candidate == root or root in candidate.parents:
            return candidate
    raise PermissionError(f"Path {path!r} is outside the configured read allowlist.")


def _assert_public_host(hostname: str) -> None:
    for info in socket.getaddrinfo(hostname, None):
        address = ipaddress.ip_address(info[4][0])
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
        ):
            raise PermissionError(
                f"Host {hostname!r} resolves to non-public address {address}."
            )


class _SingleRedirectHandler(urllib.request.HTTPRedirectHandler):
    max_redirections = 1


@tool
@require_tool_authorization("read_file")
def read_file(path: str) -> str:
    """Read the contents of a file at the given path and return them as a string.

    Args:
        path: Filesystem path to read. Must resolve inside READ_FILE_PATHS.
    """
    resolved = _resolve_within_allowlist(path)
    return redact_secrets_text(resolved.read_text())


def run_allowlisted_command(command: str, *args: str) -> str:
    """Run one allowlisted binary without a shell and return its output.

    Not registered as an agent tool: it is available to operators only, and the
    binary must be named in ALLOWED_SHELL_COMMANDS.
    """
    allowed = _allowed_shell_commands()
    if command not in allowed:
        raise PermissionError(f"Command {command!r} is not in ALLOWED_SHELL_COMMANDS.")
    result = subprocess.run(
        [command, *args],
        shell=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return redact_secrets_text(result.stdout + result.stderr)


@tool
@require_tool_authorization("fetch_url")
def fetch_url(url: str) -> str:
    """Fetch the contents of an allowlisted URL and return the response body.

    Args:
        url: The URL to fetch. Host must be named in ALLOWED_FETCH_DOMAINS.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise PermissionError(f"Scheme {parsed.scheme!r} is not permitted.")
    hostname = (parsed.hostname or "").lower()
    if hostname not in _allowed_fetch_hosts():
        raise PermissionError(f"Host {hostname!r} is not in ALLOWED_FETCH_DOMAINS.")
    _assert_public_host(hostname)

    opener = urllib.request.build_opener(_SingleRedirectHandler)
    with opener.open(url, timeout=_FETCH_TIMEOUT_SECONDS) as response:
        body = response.read(_MAX_FETCH_BYTES).decode("utf-8", errors="replace")
    return f"[EXTERNAL_DATA]{redact_secrets_text(body)}[/EXTERNAL_DATA]"


# ── HelpDeskAI domain tools (operate on tenant data) ─────────────────────────

@tool
@require_tool_authorization("lookup_order")
def lookup_order(order_id: str, tenant_id: str) -> dict:
    """Look up a customer order by its ID for the current tenant.

    Args:
        order_id: The order identifier to look up.
        tenant_id: The current tenant context.
    """
    order = RDSClient().lookup_order(order_id=order_id, tenant_id=tenant_id)
    return redact_pii_dict(order)


@tool
@require_tool_authorization("issue_refund")
def issue_refund(order_id: str, amount: float, tenant_id: str) -> bool:
    """Issue a refund of `amount` against `order_id` for the current tenant.

    Args:
        order_id: The order to refund.
        amount: Refund amount.
        tenant_id: The current tenant context.
    """
    return RDSClient().issue_refund(order_id=order_id, amount=amount, tenant_id=tenant_id)


@tool
@require_tool_authorization("search_kb")
def search_kb(query_prefix: str, tenant_id: str) -> list:
    """Search the tenant knowledge base for documents matching a prefix.

    Args:
        query_prefix: Document key prefix to search, relative to the tenant prefix.
        tenant_id: The current tenant context.
    """
    return S3Client().search_kb(tenant_id, query_prefix)


@tool
@require_tool_authorization("create_ticket")
def create_ticket(subject: str, body: str, customer_email: str, tenant_id: str) -> dict:
    """Create a support ticket for the current tenant.

    Args:
        subject: Ticket subject.
        body: Ticket body.
        customer_email: Customer's email.
        tenant_id: The current tenant context.
    """
    ticket = DynamoDBClient().create_ticket(tenant_id, subject, body, customer_email)
    return redact_pii_dict(ticket)


@tool
@require_tool_authorization("delegate_to_sub_agent")
def delegate_to_sub_agent(task: str) -> str:
    """Delegate a focused, self-contained sub-task to the task-executor sub-agent.

    Use this for multi-step research or escalation work that should run as its own
    ReAct loop (e.g. "investigate why order X keeps failing and summarize").

    Args:
        task: A self-contained description of the sub-task to execute.
    """
    return "delegated"


ALL_TOOLS = [
    read_file,
    fetch_url,
    lookup_order,
    issue_refund,
    search_kb,
    create_ticket,
    delegate_to_sub_agent,
]

SUB_AGENT_TOOLS = [read_file, fetch_url, lookup_order, search_kb]

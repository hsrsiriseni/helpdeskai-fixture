"""
MCP server — exposes tools to any MCP-compatible host agent (e.g., the orchestrator).

Every tool requires the caller to present the API key whose SHA-256 digest is in
MCP_API_KEY_HASH (see auth_example.ApiKeyAuthMiddleware). Database access is
restricted to allowlisted tables and columns with the filter value bound as a
query parameter.

Server name: fixture-mcp
Transport: stdio (for local use) or SSE (for network use)

To start:
  python -m src.mcp_server.server

The MCP client configuration is in server_config.json.
"""

import os
import sqlite3

from mcp.server.fastmcp import FastMCP

from src.mcp_server.auth_example import require_api_key

ALLOWED_TABLES = {"orders", "customers", "tickets"}
ALLOWED_COLUMNS = {"order_id", "customer_id", "ticket_id", "tenant_id", "status"}
MAX_FILTER_VALUE_LENGTH = 255

_DB_PATH = os.environ.get("MCP_DB_PATH", "data.db")

mcp = FastMCP("fixture-mcp")


@mcp.tool()
@require_api_key
def query_database(
    table: str,
    filter_column: str,
    filter_value: str,
    api_key: str = "",
) -> list[dict]:
    """Query a record from an allowlisted table by filtering on an allowlisted column.

    Requires an `api_key` matching the digest in MCP_API_KEY_HASH.

    Args:
        table: Name of the table to query. Must be in ALLOWED_TABLES.
        filter_column: Name of the column to filter on. Must be in ALLOWED_COLUMNS.
        filter_value: Value to match in the filter column.
        api_key: Caller credential.

    Returns:
        List of matching rows as dicts.
    """
    if table not in ALLOWED_TABLES:
        raise ValueError(f"Table {table!r} is not queryable.")
    if filter_column not in ALLOWED_COLUMNS:
        raise ValueError(f"Column {filter_column!r} is not filterable.")
    if len(filter_value) > MAX_FILTER_VALUE_LENGTH:
        raise ValueError("filter_value exceeds the maximum permitted length.")

    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    sql = f"SELECT * FROM {table} WHERE {filter_column} = ?"  # noqa: S608
    cursor.execute(sql, (filter_value,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


if __name__ == "__main__":
    mcp.run()

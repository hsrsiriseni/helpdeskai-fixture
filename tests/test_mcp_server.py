"""
Unit tests for the MCP server tools.

These verify the tool function behaviour without an MCP runtime, and assert the
security contract each tool now carries: authentication on every call, and
allowlisted table/column names with the filter value bound as a parameter.
"""

import hashlib
import os
import sqlite3
import tempfile

import pytest

API_KEY = "test-api-key-12345"


@pytest.fixture()
def api_key(monkeypatch):
    monkeypatch.setenv(
        "MCP_API_KEY_HASH", hashlib.sha256(API_KEY.encode()).hexdigest()
    )
    return API_KEY


@pytest.fixture()
def seeded_db(monkeypatch):
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE orders (order_id TEXT, status TEXT)")
    conn.execute("INSERT INTO orders VALUES ('ord-1', 'shipped')")
    conn.commit()
    conn.close()

    monkeypatch.setattr("src.mcp_server.server._DB_PATH", db_path)
    yield db_path
    os.unlink(db_path)


def test_execute_code_tool_is_not_exposed():
    """The arbitrary-code-execution tool is no longer part of the server."""
    from src.mcp_server import server

    assert not hasattr(server, "execute_code")


def test_query_database_returns_rows_for_authenticated_caller(api_key, seeded_db):
    from src.mcp_server.server import query_database

    rows = query_database(
        table="orders",
        filter_column="order_id",
        filter_value="ord-1",
        api_key=api_key,
    )
    assert len(rows) == 1
    assert rows[0]["status"] == "shipped"


def test_query_database_rejects_missing_api_key(api_key, seeded_db):
    from src.mcp_server.server import query_database

    with pytest.raises(PermissionError):
        query_database(
            table="orders", filter_column="order_id", filter_value="ord-1"
        )


def test_query_database_rejects_unlisted_table(api_key, seeded_db):
    from src.mcp_server.server import query_database

    with pytest.raises(ValueError):
        query_database(
            table="sqlite_master",
            filter_column="order_id",
            filter_value="ord-1",
            api_key=api_key,
        )


def test_query_database_rejects_unlisted_column(api_key, seeded_db):
    from src.mcp_server.server import query_database

    with pytest.raises(ValueError):
        query_database(
            table="orders",
            filter_column="status) OR (1=1",
            filter_value="x",
            api_key=api_key,
        )


def test_query_database_binds_filter_value(api_key, seeded_db):
    """A classic injection payload is matched literally, not interpreted."""
    from src.mcp_server.server import query_database

    rows = query_database(
        table="orders",
        filter_column="order_id",
        filter_value="' OR '1'='1",
        api_key=api_key,
    )
    assert rows == []


def test_auth_example_validates_key(monkeypatch):
    """Verify the auth middleware correctly validates API keys."""
    from src.mcp_server.auth_example import ApiKeyAuthMiddleware

    monkeypatch.setenv("MCP_API_KEY_HASH", hashlib.sha256(API_KEY.encode()).hexdigest())

    middleware = ApiKeyAuthMiddleware()
    assert middleware.validate(API_KEY) is True
    assert middleware.validate("wrong-key") is False

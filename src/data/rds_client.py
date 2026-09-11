"""PostgreSQL (RDS) client for HelpDeskAI orders and customer records.

Uses psycopg (v3) with a connection pool. Every query is parameterised and
carries a tenant_id predicate, so a caller cannot reach another tenant's rows
and cannot inject SQL through a value.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import psycopg
from psycopg_pool import ConnectionPool

logger = logging.getLogger(__name__)

_ORDER_FIELDS = "order_id, status, total_amount, created_at"

_pool: ConnectionPool | None = None


def _resolve_dsn() -> str:
    dsn = os.environ.get("DATABASE_URL")
    if dsn:
        return dsn
    secret_id = os.environ.get("DATABASE_SECRET_ID")
    if secret_id:
        return _fetch_dsn_from_secrets_manager(secret_id)
    raise RuntimeError(
        "Set DATABASE_URL, or DATABASE_SECRET_ID naming an AWS Secrets Manager "
        "secret whose payload holds the connection string."
    )


def _fetch_dsn_from_secrets_manager(secret_id: str) -> str:
    import json

    import boto3

    client = boto3.client("secretsmanager", region_name=os.environ.get("AWS_REGION", "us-east-1"))
    payload = client.get_secret_value(SecretId=secret_id)["SecretString"]
    try:
        return json.loads(payload)["dsn"]
    except (ValueError, KeyError) as exc:
        raise RuntimeError(f"Secret {secret_id} does not carry a 'dsn' field.") from exc


def _get_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        _pool = ConnectionPool(conninfo=_resolve_dsn(), min_size=2, max_size=10)
    return _pool


class RDSClient:
    """Thin psycopg-based client for the HelpDeskAI orders database."""

    def __init__(self) -> None:
        self._pool = _get_pool()

    def lookup_order(self, order_id: str, tenant_id: str) -> dict[str, Any]:
        """Fetch one order belonging to tenant_id."""
        sql = (
            f"SELECT {_ORDER_FIELDS} "
            "FROM orders "
            "WHERE tenant_id = %s AND order_id = %s"
        )
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
                cur.execute(sql, (tenant_id, order_id))
                row = cur.fetchone()
        return dict(row) if row else {}

    def get_customer(self, customer_id: str, tenant_id: str) -> dict[str, Any]:
        """Fetch one customer record belonging to tenant_id."""
        sql = (
            "SELECT customer_id, email, full_name, address, card_last4 "
            "FROM customers "
            "WHERE customer_id = %s AND tenant_id = %s"
        )
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
                cur.execute(sql, (customer_id, tenant_id))
                row = cur.fetchone()

        customer = dict(row) if row else {}

        logger.info(
            "Customer lookup",
            extra={
                "tenant_id": tenant_id,
                "customer_id": customer.get("customer_id"),
                "outcome": "found" if customer else "not_found",
            },
        )

        return customer

    def issue_refund(self, order_id: str, amount: float, tenant_id: str) -> bool:
        """Apply a refund to an order belonging to tenant_id."""
        sql = (
            "UPDATE orders "
            "SET refund_amount = %s, status = 'refunded' "
            "WHERE order_id = %s AND tenant_id = %s"
        )
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (amount, order_id, tenant_id))
                affected = cur.rowcount
            conn.commit()

        logger.info(
            "Refund issued",
            extra={
                "tenant_id": tenant_id,
                "order_id": order_id,
                "amount": amount,
                "rows_affected": affected,
            },
        )
        return affected > 0

    def list_orders_for_tenant(
        self,
        tenant_id: str,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Return recent orders scoped to a specific tenant."""
        sql = (
            f"SELECT {_ORDER_FIELDS} "
            "FROM orders "
            "WHERE tenant_id = %s "
            "ORDER BY created_at DESC "
            "LIMIT %s"
        )
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
                cur.execute(sql, (tenant_id, limit))
                rows = cur.fetchall()
        return [dict(r) for r in rows]

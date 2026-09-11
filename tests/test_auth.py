"""Tenant-isolation tests for the /v1/chat authentication path.

Each case asserts that the request is rejected before the orchestrator runs,
so no AWS or LLM credentials are needed.
"""

import jwt
import pytest
from fastapi.testclient import TestClient

from src.auth import jwt_validator

CHAT_BODY = {"message": "where is my order?"}


@pytest.fixture()
def client():
    from src.api.app import create_app

    return TestClient(create_app())


def _token(claims, secret=jwt_validator.JWT_SECRET, algorithm="HS256"):
    return jwt.encode(claims, secret, algorithm=algorithm)


def test_chat_rejects_spoofed_tenant_header(client):
    resp = client.post("/v1/chat", json=CHAT_BODY, headers={"X-Tenant-Id": "victim-tenant"})
    assert resp.status_code == 401


def test_chat_rejects_missing_token(client):
    assert client.post("/v1/chat", json=CHAT_BODY).status_code == 401


def test_chat_rejects_token_signed_with_wrong_key(client):
    forged = _token({"tenant_id": "victim-tenant", "sub": "attacker"}, secret="attacker-key")
    resp = client.post("/v1/chat", json=CHAT_BODY, headers={"Authorization": f"Bearer {forged}"})
    assert resp.status_code == 401


def test_chat_rejects_token_without_tenant_claim(client):
    resp = client.post(
        "/v1/chat",
        json=CHAT_BODY,
        headers={"Authorization": f"Bearer {_token({'sub': 'user-1'})}"},
    )
    assert resp.status_code == 401


def test_header_tenant_dependency_is_gone():
    assert not hasattr(jwt_validator, "get_tenant_from_header")


def test_verified_token_yields_tenant_from_claim():
    payload = jwt_validator._validator.validate(
        _token({"tenant_id": "tenant-a", "sub": "user-1", "email": "u@example.com"})
    )
    assert payload.tenant_id == "tenant-a"

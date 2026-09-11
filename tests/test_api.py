"""Smoke tests for the FastAPI app wiring.

These import the full application (which transitively imports the agent, MCP, and
data layers) and exercise the health endpoint via TestClient — proving the service
actually wires together without real AWS/LLM credentials.
"""

from fastapi.testclient import TestClient


def test_app_imports_and_health_ok():
    from src.api.app import create_app

    app = create_app()
    client = TestClient(app)
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_routes_registered():
    from src.api.app import create_app

    app = create_app()
    paths = {getattr(route, "path", None) for route in app.routes}
    assert "/v1/chat" in paths
    assert "/v1/kb/documents" in paths
    assert "/v1/admin/tenants" in paths


def test_orchestrator_factory_returns_invokable(monkeypatch):
    """create_orchestrator returns an Orchestrator exposing invoke(message, tenant_id, thread_id).

    We assert the surface without calling it (calling would require live Anthropic creds).
    """
    import hashlib

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-used")
    with open("prompts/orchestrator_system.md", "rb") as handle:
        monkeypatch.setenv(
            "AGENT_SYSTEM_PROMPT_HASH", hashlib.sha256(handle.read()).hexdigest()
        )
    with open("prompts/sub_agent_system.md", "rb") as handle:
        monkeypatch.setenv(
            "SUB_AGENT_SYSTEM_PROMPT_HASH", hashlib.sha256(handle.read()).hexdigest()
        )

    from src.agent.orchestrator import create_orchestrator, Orchestrator

    orch = create_orchestrator()
    assert isinstance(orch, Orchestrator)
    assert hasattr(orch, "invoke")


def test_orchestrator_factory_refuses_unpinned_prompt(monkeypatch):
    """A system prompt with no pinned digest fails loudly rather than loading."""
    import pytest

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-used")
    monkeypatch.delenv("AGENT_SYSTEM_PROMPT_HASH", raising=False)

    from src.agent.orchestrator import create_orchestrator
    from src.agent.prompt_integrity import PromptIntegrityError

    with pytest.raises(PromptIntegrityError):
        create_orchestrator()

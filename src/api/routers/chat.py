"""Chat route handlers for HelpDeskAI.

POST /v1/chat — accepts a customer message and returns the agent reply.

The tenant whose data the agent may act on is taken from the verified JWT
bearer token, so a caller cannot direct the request at another tenant. Requests
are rate limited per tenant and the reply is scrubbed of credential material
before it leaves the service.
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from collections import defaultdict, deque

from fastapi import APIRouter, Depends, HTTPException, status

from src.agent.orchestrator import PromptInjectionDetected, create_orchestrator
from src.auth.jwt_validator import TokenPayload, get_current_tenant
from src.utils.redactor import redact_secrets_text

from ..models import ChatRequest, ChatResponse

logger = logging.getLogger(__name__)

router = APIRouter()

RATE_LIMIT_REQUESTS = 10
RATE_LIMIT_WINDOW_SECONDS = 60

_request_times: dict[str, deque[float]] = defaultdict(deque)


def _enforce_rate_limit(tenant_id: str) -> None:
    now = time.monotonic()
    seen = _request_times[tenant_id]
    while seen and now - seen[0] > RATE_LIMIT_WINDOW_SECONDS:
        seen.popleft()
    if len(seen) >= RATE_LIMIT_REQUESTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Try again shortly.",
        )
    seen.append(now)


@router.post("/chat", response_model=ChatResponse, status_code=status.HTTP_200_OK)
async def chat(
    body: ChatRequest,
    tenant: TokenPayload = Depends(get_current_tenant),
) -> ChatResponse:
    """Process a customer chat message and return the agent reply.

    Requires an Authorization bearer token whose signature verifies; the
    tenant_id claim from that verified token scopes every tool the agent runs.
    """
    _enforce_rate_limit(tenant.tenant_id)

    thread_id = body.thread_id or str(uuid.uuid4())

    orchestrator = create_orchestrator()
    try:
        reply = orchestrator.invoke(
            message=body.message,
            tenant_id=tenant.tenant_id,
            thread_id=thread_id,
        )
    except PromptInjectionDetected:
        logger.warning(
            "Rejected suspicious chat input",
            extra={
                "tenant_id": tenant.tenant_id,
                "thread_id": thread_id,
                "message_sha256": hashlib.sha256(body.message.encode()).hexdigest(),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed or suspicious input detected.",
        ) from None

    return ChatResponse(
        reply=redact_secrets_text(reply),
        thread_id=thread_id,
        tenant_id=tenant.tenant_id,
    )

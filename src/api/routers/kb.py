"""Knowledge base document management routes for HelpDeskAI.

POST /v1/kb/documents — upload a document to the caller's tenant KB.

Tenant identity comes from get_current_tenant(), which verifies the JWT
signature and extracts tenant_id from the verified payload.
"""

from __future__ import annotations

import base64
import logging

from fastapi import APIRouter, Depends, HTTPException, status

from src.auth.jwt_validator import TokenPayload, get_current_tenant
from src.data.s3_client import S3Client

from ..models import KBUploadRequest, KBUploadResponse

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/kb/documents",
    response_model=KBUploadResponse,
    status_code=status.HTTP_201_CREATED,
)
async def upload_kb_document(
    body: KBUploadRequest,
    tenant: TokenPayload = Depends(get_current_tenant),
) -> KBUploadResponse:
    """Upload a document to the authenticated tenant's knowledge base.

    The document is stored under the tenant's own S3 prefix, enforced server-side.
    The tenant_id is sourced from the verified JWT (not from a client header).
    """
    try:
        content = base64.b64decode(body.content_base64)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="content_base64 must be valid base64-encoded data.",
        ) from exc

    if len(content) > 10 * 1024 * 1024:  # 10 MB limit
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Document exceeds the 10 MB size limit.",
        )

    client = S3Client()
    stored_key = client.upload_kb_document(
        tenant_id=tenant.tenant_id,
        document_key=body.document_key,
        content=content,
    )

    logger.info(
        "KB document uploaded via API",
        extra={"tenant_id": tenant.tenant_id, "document_key": stored_key},
    )

    return KBUploadResponse(
        document_key=stored_key,
        tenant_id=tenant.tenant_id,
        uploaded=True,
    )


@router.get("/kb/documents/{document_key:path}", status_code=status.HTTP_200_OK)
async def get_kb_document_url(
    document_key: str,
    tenant: TokenPayload = Depends(get_current_tenant),
) -> dict:
    """Generate a short-lived presigned URL for one of the tenant's KB documents."""
    client = S3Client()
    try:
        url = client.get_document_url(
            tenant_id=tenant.tenant_id, document_key=document_key
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Document key is outside the caller's tenant scope.",
        ) from exc
    return {"url": url, "document_key": document_key}

"""S3 client for HelpDeskAI knowledge base documents and customer attachments.

Two logical buckets:
  {tenant_id}-kb-docs        — per-tenant KB documents
  helpdeskAI-attachments     — shared attachments bucket

Both enforce SSE-KMS at rest and block public access (see infra/main.tf). Every
key this client builds is prefixed with the caller's tenant_id, and reads
validate that prefix before they are served.
"""

from __future__ import annotations

import logging
import os
import posixpath
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

_AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
_ATTACHMENTS_BUCKET = os.environ.get("ATTACHMENTS_BUCKET", "helpdeskAI-attachments")
_PRESIGNED_URL_EXPIRY = 900
_KB_BUCKET = os.environ.get("KB_BUCKET", "helpdeskai-kb-docs")


class S3Client:
    """S3 client wrapper for KB documents and file attachments."""

    def __init__(self, region: str = _AWS_REGION) -> None:
        self._s3 = boto3.client("s3", region_name=region)

    @staticmethod
    def _scoped_key(tenant_id: str, key: str) -> str:
        """Build a tenant-prefixed key, rejecting anything that escapes the prefix."""
        prefix = f"{tenant_id}/"
        candidate = key if key.startswith(prefix) else f"{prefix}{key}"
        if not posixpath.normpath(candidate).startswith(prefix):
            raise ValueError(f"Key {key!r} escapes the tenant prefix {prefix!r}.")
        return candidate

    def search_kb(self, tenant_id: str, document_prefix: str) -> list[dict[str, Any]]:
        """List KB documents under the tenant's own prefix."""
        kb_bucket = f"{tenant_id}-kb-docs"
        scoped_prefix = self._scoped_key(tenant_id, document_prefix)

        paginator = self._s3.get_paginator("list_objects_v2")
        results: list[dict[str, Any]] = []

        for page in paginator.paginate(Bucket=kb_bucket, Prefix=scoped_prefix):
            for obj in page.get("Contents", []):
                results.append(
                    {
                        "key": obj["Key"],
                        "size": obj["Size"],
                        "last_modified": obj["LastModified"].isoformat(),
                    }
                )

        return results

    def upload_kb_document(
        self,
        tenant_id: str,
        document_key: str,
        content: bytes,
    ) -> str:
        """Upload a document to the tenant's KB bucket with a namespaced key.

        The key is prefixed with tenant_id so documents are stored under the
        tenant's own path (correct pattern for write operations).
        """
        kb_bucket = f"{tenant_id}-kb-docs"
        scoped_key = self._scoped_key(tenant_id, document_key)
        self._s3.put_object(
            Bucket=kb_bucket,
            Key=scoped_key,
            Body=content,
            ServerSideEncryption="aws:kms",
        )
        logger.info(
            "KB document uploaded",
            extra={"tenant_id": tenant_id, "key": scoped_key},
        )
        return scoped_key

    def get_document_url(self, tenant_id: str, document_key: str) -> str:
        """Generate a short-lived presigned URL for one of the tenant's KB documents."""
        scoped_key = self._scoped_key(tenant_id, document_key)
        return self._s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": _KB_BUCKET, "Key": scoped_key},
            ExpiresIn=_PRESIGNED_URL_EXPIRY,
        )

    def upload_attachment(
        self,
        tenant_id: str,
        filename: str,
        content: bytes,
    ) -> str:
        """Upload a customer attachment to the SSE-KMS-protected attachments bucket."""
        scoped_key = f"attachments/{tenant_id}/{filename}"

        self._s3.put_object(
            Bucket=_ATTACHMENTS_BUCKET,
            Key=scoped_key,
            Body=content,
            ServerSideEncryption="aws:kms",
        )
        logger.info(
            "Attachment uploaded",
            extra={"tenant_id": tenant_id, "key": scoped_key},
        )
        return scoped_key

    def get_attachment(self, tenant_id: str, filename: str) -> bytes:
        """Fetch an attachment from the secure attachments bucket.

        Key is constructed with the tenant prefix to prevent cross-tenant reads.
        """
        scoped_key = f"attachments/{tenant_id}/{filename}"
        try:
            response = self._s3.get_object(Bucket=_ATTACHMENTS_BUCKET, Key=scoped_key)
            return response["Body"].read()
        except ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            if error_code == "NoSuchKey":
                raise FileNotFoundError(f"Attachment not found: {filename}") from exc
            raise

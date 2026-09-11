"""JWT validation and tenant context extraction for HelpDeskAI.

Tenant identity is only ever derived from a signature-verified JWT claim.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/v1/auth/token")

JWT_SECRET = os.environ.get("JWT_SECRET", "changeme-replace-in-production")
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")


@dataclass
class TokenPayload:
    """Verified JWT claims extracted from a validated bearer token."""

    tenant_id: str
    sub: str
    email: str
    exp: int


class JWTValidator:
    """Validates JWT bearer tokens and extracts structured claims.

    Uses PyJWT with signature verification enabled (the correct pattern).
    Algorithm is pinned to prevent the 'none' algorithm attack.
    """

    def __init__(self, secret: str, algorithm: str = "HS256") -> None:
        self.secret = secret
        self.algorithm = algorithm

    def validate(self, token: str) -> TokenPayload:
        """Decode and verify a JWT, returning the structured payload.

        Signature verification is enabled and the accepted algorithm is explicit,
        so a tampered, forged, expired or malformed token raises HTTP 401.
        """
        try:
            payload = jwt.decode(
                token,
                self.secret,
                algorithms=[self.algorithm],
            )
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except jwt.InvalidTokenError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials.",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc

        tenant_id = payload.get("tenant_id")
        if not tenant_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token is missing required tenant_id claim.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return TokenPayload(
            tenant_id=tenant_id,
            sub=payload.get("sub", ""),
            email=payload.get("email", ""),
            exp=payload.get("exp", 0),
        )


_validator = JWTValidator(secret=JWT_SECRET, algorithm=JWT_ALGORITHM)


async def get_current_tenant(token: str = Depends(oauth2_scheme)) -> TokenPayload:
    """FastAPI dependency: extract the tenant from a verified JWT bearer token.

    This is the only supported way to resolve tenant identity. Tenant IDs are
    never read from a client-supplied header, which carries no cryptographic
    binding to the authenticated caller.
    """
    return _validator.validate(token)

"""JWT authentication utilities for v6.0 RBAC (T142).

Provides:
  - password hashing / verification
  - JWT creation and decoding
  - FastAPI dependency `require_auth` — injects the current User
  - Role-guard dependency factory `require_role`
  - `audit` helper — writes one row to audit_log
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext

try:
    import jwt as pyjwt
except ImportError:
    pyjwt = None  # type: ignore[assignment]

from app.models.user import AuditLog, User, UserRole

_JWT_SECRET_DEFAULT = "genesis-dev-secret-change-in-production"
_SECRET = os.getenv("JWT_SECRET", _JWT_SECRET_DEFAULT)
if _SECRET == _JWT_SECRET_DEFAULT:
    import warnings
    warnings.warn(
        "JWT_SECRET is not set — using the insecure hardcoded default. "
        "Set JWT_SECRET in your .env file before deploying.",
        stacklevel=1,
    )
_ALGORITHM = "HS256"
_EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", "24"))

_pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
_bearer = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------

def hash_password(plain: str) -> str:
    return _pwd_ctx.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd_ctx.verify(plain, hashed)


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def create_access_token(user_id: str, email: str, role: str, tenant_id: Optional[str] = None) -> str:
    if pyjwt is None:
        raise RuntimeError("PyJWT not installed — add 'PyJWT' to requirements.txt")
    expire = datetime.now(timezone.utc) + timedelta(hours=_EXPIRE_HOURS)
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "tenant_id": tenant_id,
        "exp": expire,
    }
    return pyjwt.encode(payload, _SECRET, algorithm=_ALGORITHM)


def decode_access_token(token: str) -> dict:
    if pyjwt is None:
        raise RuntimeError("PyJWT not installed")
    try:
        return pyjwt.decode(token, _SECRET, algorithms=[_ALGORITHM])
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {exc}",
        )


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------

async def get_current_user_optional(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> Optional[dict]:
    """Returns decoded JWT payload or None if no token present (used by mixed-auth paths)."""
    if credentials is None:
        return None
    return decode_access_token(credentials.credentials)


async def require_auth(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> dict:
    """Raises 401 if no valid JWT. Returns decoded payload."""
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return decode_access_token(credentials.credentials)


def require_role(*roles: UserRole):
    """Dependency factory — raises 403 if the authenticated user doesn't have one of the given roles."""
    async def _check(payload: dict = Depends(require_auth)) -> dict:
        if payload.get("role") not in {r.value for r in roles}:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {[r.value for r in roles]}",
            )
        return payload
    return _check


# ---------------------------------------------------------------------------
# Audit helper
# ---------------------------------------------------------------------------

async def audit(
    action: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    extra: Optional[dict] = None,
    user_payload: Optional[dict] = None,
    request: Optional[Request] = None,
) -> None:
    """Write one immutable row to audit_log. Never raises — failures are logged only."""
    try:
        from app.database.postgres import AsyncSessionLocal
        user_id = user_payload.get("sub") if user_payload else None
        tenant_id = user_payload.get("tenant_id") if user_payload else None
        ip_address = None
        if request:
            forwarded = request.headers.get("X-Forwarded-For")
            ip_address = forwarded.split(",")[0].strip() if forwarded else str(request.client.host) if request.client else None

        async with AsyncSessionLocal() as db:
            row = AuditLog(
                id=uuid.uuid4(),
                tenant_id=uuid.UUID(tenant_id) if tenant_id else None,
                user_id=uuid.UUID(user_id) if user_id else None,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                ip_address=ip_address,
                extra=extra or {},
            )
            db.add(row)
            await db.commit()
    except Exception:
        import logging
        logging.getLogger(__name__).debug("audit write failed", exc_info=True)

"""Authentication endpoints — v6.0 RBAC (T142).

POST /api/v1/auth/register  — create a new user account
POST /api/v1/auth/login     — exchange email+password for JWT
GET  /api/v1/auth/me        — return current user info
"""
from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr

from app.middleware.auth import (
    audit,
    create_access_token,
    hash_password,
    require_auth,
    require_role,
    verify_password,
)
from app.models.user import UserRole

router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    role: UserRole = UserRole.operator
    tenant_id: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    email: str
    tenant_id: Optional[str]


class UserResponse(BaseModel):
    id: str
    email: str
    role: str
    tenant_id: Optional[str]
    is_active: bool


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest, request: Request):
    """Register a new user. First registered user auto-gets admin role."""
    from app.database.postgres import AsyncSessionLocal
    from app.models.user import User
    from sqlalchemy import select, func

    async with AsyncSessionLocal() as db:
        # Check uniqueness
        result = await db.execute(select(User).where(User.email == body.email))
        if result.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Email already registered")

        # First user ever becomes admin
        count_result = await db.execute(select(func.count()).select_from(User))
        total = count_result.scalar() or 0
        role = UserRole.admin if total == 0 else body.role

        user = User(
            id=uuid.uuid4(),
            email=body.email,
            hashed_password=hash_password(body.password),
            role=role,
            tenant_id=uuid.UUID(body.tenant_id) if body.tenant_id else None,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)

    token = create_access_token(
        str(user.id), user.email, user.role.value if hasattr(user.role, "value") else user.role,
        str(user.tenant_id) if user.tenant_id else None,
    )
    await audit("user.register", "user", str(user.id), request=request)
    return TokenResponse(
        access_token=token,
        role=user.role.value if hasattr(user.role, "value") else user.role,
        email=user.email,
        tenant_id=str(user.tenant_id) if user.tenant_id else None,
    )


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, request: Request):
    from app.database.postgres import AsyncSessionLocal
    from app.models.user import User
    from sqlalchemy import select
    from datetime import datetime, timezone

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.email == body.email))
        user = result.scalar_one_or_none()
        if not user or not verify_password(body.password, user.hashed_password):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        if not user.is_active:
            raise HTTPException(status_code=403, detail="Account deactivated")

        user.last_login_at = datetime.now(timezone.utc)
        await db.commit()

    role_str = user.role.value if hasattr(user.role, "value") else user.role
    token = create_access_token(
        str(user.id), user.email, role_str,
        str(user.tenant_id) if user.tenant_id else None,
    )
    await audit("user.login", "user", str(user.id), request=request)
    return TokenResponse(
        access_token=token, role=role_str, email=user.email,
        tenant_id=str(user.tenant_id) if user.tenant_id else None,
    )


@router.get("/me", response_model=UserResponse)
async def me(payload: dict = Depends(require_auth)):
    return UserResponse(
        id=payload["sub"],
        email=payload["email"],
        role=payload["role"],
        tenant_id=payload.get("tenant_id"),
        is_active=True,
    )


# ---------------------------------------------------------------------------
# Tenant management (admin-only)
# ---------------------------------------------------------------------------

class TenantCreate(BaseModel):
    name: str
    slug: str
    token_budget: int = 1_000_000


@router.post("/tenants", status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_role(UserRole.admin))])
async def create_tenant(body: TenantCreate, request: Request,
                        payload: dict = Depends(require_auth)):
    from app.database.postgres import AsyncSessionLocal
    from app.models.user import Tenant
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        r = await db.execute(select(Tenant).where(Tenant.slug == body.slug))
        if r.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Slug already taken")
        tenant = Tenant(
            id=uuid.uuid4(),
            name=body.name,
            slug=body.slug,
            neo4j_namespace=body.slug,
            token_budget=body.token_budget,
        )
        db.add(tenant)
        await db.commit()
        await db.refresh(tenant)

    await audit("tenant.create", "tenant", str(tenant.id), user_payload=payload, request=request)
    return {"id": str(tenant.id), "name": tenant.name, "slug": tenant.slug}


@router.get("/tenants", dependencies=[Depends(require_role(UserRole.admin))])
async def list_tenants():
    from app.database.postgres import AsyncSessionLocal
    from app.models.user import Tenant
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Tenant).order_by(Tenant.created_at))
        tenants = result.scalars().all()
    return [{"id": str(t.id), "name": t.name, "slug": t.slug, "token_budget": t.token_budget}
            for t in tenants]


# ---------------------------------------------------------------------------
# Audit log (admin-only)
# ---------------------------------------------------------------------------

@router.get("/audit", dependencies=[Depends(require_role(UserRole.admin))])
async def get_audit_log(limit: int = 100, offset: int = 0):
    from app.database.postgres import AsyncSessionLocal
    from app.models.user import AuditLog
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(AuditLog).order_by(AuditLog.ts.desc()).offset(offset).limit(limit)
        )
        rows = result.scalars().all()
    return [
        {
            "id": str(r.id),
            "action": r.action,
            "resource_type": r.resource_type,
            "resource_id": r.resource_id,
            "ip_address": r.ip_address,
            "ts": r.ts.isoformat(),
            "extra": r.extra,
        }
        for r in rows
    ]

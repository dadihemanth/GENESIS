"""Audit log endpoint — v6.0 (T142).

GET /api/v1/audit  — paginated audit log, admin-only
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, Query

from app.middleware.auth import require_auth, require_role
from app.models.user import UserRole

router = APIRouter()


@router.get("")
async def get_audit_log(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    action: Optional[str] = Query(None),
    user_payload: dict = Depends(require_role(UserRole.admin)),
) -> dict:
    """Return paginated audit log rows. Admin only."""
    try:
        from app.database.postgres import AsyncSessionLocal
        from app.models.user import AuditLog
        from sqlalchemy import select, desc

        offset = (page - 1) * page_size
        async with AsyncSessionLocal() as db:
            stmt = select(AuditLog).order_by(desc(AuditLog.ts)).offset(offset).limit(page_size)
            if action:
                stmt = stmt.where(AuditLog.action == action)
            result = await db.execute(stmt)
            rows = result.scalars().all()

        entries = [
            {
                "id": str(row.id),
                "action": row.action,
                "resource_type": row.resource_type,
                "resource_id": row.resource_id,
                "user_id": str(row.user_id) if row.user_id else None,
                "tenant_id": str(row.tenant_id) if row.tenant_id else None,
                "ip_address": row.ip_address,
                "extra": row.extra,
                "ts": row.ts.isoformat() if row.ts else None,
            }
            for row in rows
        ]
        return {"entries": entries, "page": page, "page_size": page_size}
    except Exception as exc:
        return {"entries": [], "page": page, "page_size": page_size, "error": str(exc)}

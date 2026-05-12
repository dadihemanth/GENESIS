"""T145 — Budget Controls API routes."""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.middleware.auth import require_auth

router = APIRouter()


class BudgetControlCreate(BaseModel):
    target_ip: str
    monthly_usd_cap: Optional[float] = None
    token_budget: Optional[int] = None
    sandbox_cpu_cap: Optional[int] = None
    tool_call_cap: Optional[int] = None


@router.post("")
async def create_budget_control(
    body: BudgetControlCreate,
    user: Dict[str, Any] = Depends(require_auth),
) -> Dict[str, Any]:
    """Create or update a budget control rule for a target."""
    from app.database.postgres import AsyncSessionLocal
    from app.models.user import BudgetControl
    from sqlalchemy import select
    import uuid

    tenant_id = user.get("tenant_id") or str(uuid.UUID(int=0))
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(BudgetControl).where(
                BudgetControl.tenant_id == tenant_id,
                BudgetControl.target_ip == body.target_ip,
            )
        )
        existing = result.scalar_one_or_none()
        if existing:
            if body.monthly_usd_cap is not None:
                existing.monthly_usd_cap = body.monthly_usd_cap
            if body.token_budget is not None:
                existing.token_budget = body.token_budget
            if body.sandbox_cpu_cap is not None:
                existing.sandbox_cpu_cap = body.sandbox_cpu_cap
            if body.tool_call_cap is not None:
                existing.tool_call_cap = body.tool_call_cap
            await db.commit()
            return {"action": "updated", "target_ip": body.target_ip}
        else:
            ctrl = BudgetControl(
                tenant_id=tenant_id,
                target_ip=body.target_ip,
                monthly_usd_cap=body.monthly_usd_cap,
                token_budget=body.token_budget,
                sandbox_cpu_cap=body.sandbox_cpu_cap,
                tool_call_cap=body.tool_call_cap,
            )
            db.add(ctrl)
            await db.commit()
            return {"action": "created", "target_ip": body.target_ip}


@router.get("/{target_ip}")
async def get_budget_status(
    target_ip: str,
    session_id: Optional[str] = None,
    user: Dict[str, Any] = Depends(require_auth),
) -> Dict[str, Any]:
    """Return current budget consumption vs cap for a target."""
    from app.services.budget_tracker import get_budget_control, get_session_spend, estimate_usd
    import uuid

    tenant_id = user.get("tenant_id") or str(uuid.UUID(int=0))
    control = await get_budget_control(tenant_id, target_ip)
    spend = await get_session_spend(session_id or "global") if session_id else {}
    usd = await estimate_usd(spend.get("tokens", 0)) if spend else 0.0

    return {
        "target_ip": target_ip,
        "control": control,
        "spend": {**spend, "estimated_usd": round(usd, 4)},
    }


@router.get("/{target_ip}/check")
async def check_budget(
    target_ip: str,
    session_id: str,
    user: Dict[str, Any] = Depends(require_auth),
) -> Dict[str, Any]:
    """Check if a session is within budget for a target."""
    from app.services.budget_tracker import check_budget as _check
    import uuid

    tenant_id = user.get("tenant_id") or str(uuid.UUID(int=0))
    return await _check(session_id, tenant_id, target_ip)

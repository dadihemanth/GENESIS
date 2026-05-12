"""T144 — Compliance Reporter API routes."""
from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException

from app.middleware.auth import get_current_user_optional

router = APIRouter()

SUPPORTED_FRAMEWORKS = ["pci_dss", "hipaa", "soc2", "iso27001", "nist_csf", "owasp_asvs"]


@router.get("/sessions/{session_id}/{framework}")
async def get_compliance_report(
    session_id: str,
    framework: str,
    _user: Dict[str, Any] | None = Depends(get_current_user_optional),
) -> Dict[str, Any]:
    """Generate a compliance report for a session against the specified framework."""
    if framework not in SUPPORTED_FRAMEWORKS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown framework '{framework}'. Supported: {SUPPORTED_FRAMEWORKS}",
        )
    from app.services.compliance_reporter import generate_report
    report = await generate_report(session_id, framework)
    return report.to_dict()


@router.get("/frameworks")
async def list_frameworks() -> Dict[str, Any]:
    return {"frameworks": SUPPORTED_FRAMEWORKS}

"""SOC integration configuration endpoints — v6.0 T143.

POST /api/v1/integrations           — save integration config
GET  /api/v1/integrations           — list configured integrations
POST /api/v1/integrations/{id}/test — test webhook
DELETE /api/v1/integrations/{id}    — remove integration
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.middleware.auth import get_current_user_optional

router = APIRouter()

# In-memory store for integration configs (backed by app_settings in prod)
# Key: integration id, value: config dict
_INTEGRATIONS: Dict[str, dict] = {}


class IntegrationConfig(BaseModel):
    type: str  # slack | jira | pagerduty | servicenow | splunk | teams | msteams
    name: str
    webhook_url: Optional[str] = None
    token: Optional[str] = None
    project_key: Optional[str] = None
    extra: Dict[str, Any] = {}
    enabled: bool = True


class IntegrationResponse(BaseModel):
    id: str
    type: str
    name: str
    enabled: bool


@router.post("", response_model=IntegrationResponse, status_code=201)
async def create_integration(
    body: IntegrationConfig,
    user: Optional[dict] = Depends(get_current_user_optional),
):
    integration_id = str(uuid.uuid4())
    _INTEGRATIONS[integration_id] = {
        "id": integration_id,
        **body.model_dump(),
    }
    return IntegrationResponse(id=integration_id, type=body.type, name=body.name, enabled=body.enabled)


@router.get("", response_model=List[IntegrationResponse])
async def list_integrations():
    return [
        IntegrationResponse(id=v["id"], type=v["type"], name=v["name"], enabled=v["enabled"])
        for v in _INTEGRATIONS.values()
    ]


@router.post("/{integration_id}/test")
async def test_integration(integration_id: str):
    cfg = _INTEGRATIONS.get(integration_id)
    if not cfg:
        raise HTTPException(status_code=404, detail="Integration not found")
    from app.services.integrations.dispatcher import test_integration as _test
    result = await _test(cfg)
    return {"ok": result}


@router.delete("/{integration_id}", status_code=204)
async def delete_integration(integration_id: str):
    if integration_id not in _INTEGRATIONS:
        raise HTTPException(status_code=404, detail="Integration not found")
    del _INTEGRATIONS[integration_id]

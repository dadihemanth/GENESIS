from __future__ import annotations

from typing import Any, Dict, List

import httpx
from fastapi import APIRouter, HTTPException

from app.config import settings

router = APIRouter()


def _get_mcp_url() -> str:
    return settings.mcp_base_url


def _mcp_headers() -> Dict[str, str]:
    headers: Dict[str, str] = {}
    if settings.mcp_api_key:
        headers["X-API-Key"] = settings.mcp_api_key
    return headers


@router.get("")
async def list_tools() -> Any:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{_get_mcp_url()}/tools", headers=_mcp_headers())
            if resp.status_code == 200:
                return resp.json()
            raise HTTPException(
                status_code=resp.status_code,
                detail=f"MCP server error: {resp.text[:500]}",
            )
    except httpx.RequestError as exc:
        raise HTTPException(status_code=503, detail=f"MCP server unreachable: {str(exc)}")


@router.post("/test-all")
async def test_all_tools() -> Any:
    """Run test-all on MCP server, then return the refreshed ToolInfo[] list."""
    try:
        async with httpx.AsyncClient(timeout=300.0) as client:
            # Trigger the test run (updates in-memory status for every tool)
            await client.post(
                f"{_get_mcp_url()}/tools/test-all",
                headers=_mcp_headers(),
                timeout=300.0,
            )
            # Always return the refreshed tool list so the frontend can setTools(result)
            tools_resp = await client.get(f"{_get_mcp_url()}/tools", headers=_mcp_headers())
            if tools_resp.status_code == 200:
                return tools_resp.json()
            raise HTTPException(
                status_code=tools_resp.status_code,
                detail=f"MCP server error fetching updated tools: {tools_resp.text[:300]}",
            )
    except httpx.RequestError as exc:
        raise HTTPException(status_code=503, detail=f"MCP server unreachable: {str(exc)}")

from __future__ import annotations

from typing import Any, Dict, Optional

import httpx
from fastapi import APIRouter, Body, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.postgres import get_db
from app.models.session import AppSettings
from app.schemas.settings import TestConnectionResult

router = APIRouter()

# Keys whose values must never be returned in plaintext by GET /settings.
# The test-llm endpoint and the orchestrator still read the real value via
# _load_all_settings(), which remains un-redacted.
_SENSITIVE_KEYS = frozenset(
    {
        "llm_api_key",
        # T13 · keep cloud/research secrets out of GET /settings responses
        "aws_access_key",
        "aws_secret_key",
        "aws_session_token",
        "custom_headers",
    }
)

# Prefix we emit for redacted values. The frontend displays this verbatim in
# the input field; if the user hits Save without editing, the PUT handler
# recognises the prefix and skips the update instead of overwriting the real
# stored secret with the redacted placeholder.
_REDACT_PREFIX = "••••"


def _redact_value(value: str) -> str:
    """Mask a sensitive value, preserving the last 4 chars when long enough.

    Short values (<8 chars) are fully masked — revealing the last 4 of a
    6-char value would leak two-thirds of it.
    """
    if not value:
        return ""
    if len(value) >= 8:
        return f"{_REDACT_PREFIX}{value[-4:]}"
    return _REDACT_PREFIX


def _redact_for_response(data: Dict[str, str]) -> Dict[str, str]:
    """Return a copy of `data` with _SENSITIVE_KEYS redacted for client display."""
    out = dict(data)
    for key in _SENSITIVE_KEYS:
        if key in out and out[key]:
            out[key] = _redact_value(out[key])
    return out


def _is_redacted_sentinel(value: str) -> bool:
    """True when the value is an unchanged redacted placeholder from GET /settings."""
    return isinstance(value, str) and value.startswith(_REDACT_PREFIX)


async def _load_all_settings(db: AsyncSession) -> Dict[str, str]:
    """Read raw settings from the DB. Never redact here — internal callers
    (test-llm, orchestrator) need the real values."""
    result = await db.execute(select(AppSettings))
    rows = result.scalars().all()
    return {row.key: row.value for row in rows}


def _normalize_azure_endpoint(endpoint: str) -> str:
    """Strip /v1/messages or /v1 suffix — the SDK appends /v1/messages itself."""
    url = endpoint.rstrip("/")
    if url.endswith("/v1/messages"):
        url = url[: -len("/v1/messages")]
    elif url.endswith("/v1"):
        url = url[: -len("/v1")]
    return url


@router.get("", response_model=Dict[str, str])
async def get_settings(db: AsyncSession = Depends(get_db)) -> Dict[str, str]:
    return _redact_for_response(await _load_all_settings(db))


@router.put("", response_model=Dict[str, str])
async def update_settings(
    body: Dict[str, str] = Body(...),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, str]:
    for key, value in body.items():
        # Skip any sensitive field that arrived still bearing the redacted
        # sentinel — the user didn't actually edit it, so the stored secret
        # must be preserved.
        if key in _SENSITIVE_KEYS and _is_redacted_sentinel(value):
            continue
        result = await db.execute(select(AppSettings).where(AppSettings.key == key))
        existing = result.scalar_one_or_none()
        if existing is not None:
            existing.value = value
        else:
            db.add(AppSettings(key=key, value=value, value_type="string"))
    await db.commit()
    return _redact_for_response(await _load_all_settings(db))


@router.post("/test-llm", response_model=TestConnectionResult)
async def test_llm_connection(
    body: Optional[Dict[str, str]] = Body(None),
    db: AsyncSession = Depends(get_db),
) -> TestConnectionResult:
    # Prefer body (unsaved UI values) over DB-persisted settings. If the body's
    # llm_api_key is still the redacted sentinel, the user clicked Test without
    # editing the key — swap in the real stored value so we actually test it.
    db_settings = await _load_all_settings(db)
    if body:
        app_settings = dict(body)
        if _is_redacted_sentinel(app_settings.get("llm_api_key", "")):
            app_settings["llm_api_key"] = db_settings.get("llm_api_key", "")
    else:
        app_settings = db_settings

    api_key = app_settings.get("llm_api_key", "")
    model = app_settings.get("llm_model", "claude-sonnet-4-6")
    provider = app_settings.get("llm_provider", "anthropic")

    if not api_key:
        return TestConnectionResult(
            success=False,
            message="LLM API key is not configured",
        )

    try:
        # T13 · route every test through the same provider adapter as the
        # orchestrator so "Test Connection" reflects real runtime behaviour
        # for bedrock / custom endpoints too, not just anthropic + azure.
        from app.services.llm_providers import build_llm_client, describe_provider
        client = build_llm_client(app_settings)
        _, desc = describe_provider(app_settings)

        response = await client.messages.create(
            model=model,
            max_tokens=10,
            timeout=30.0,
            messages=[{"role": "user", "content": "Say: OK"}],
        )
        return TestConnectionResult(
            success=True,
            message=f"LLM connection successful ({desc})",
            details={
                "model": model,
                "provider": provider,
                "stop_reason": response.stop_reason,
            },
        )
    except Exception as exc:
        return TestConnectionResult(
            success=False,
            message=f"LLM connection failed: {str(exc)}",
            details={"error": str(exc)},
        )


@router.post("/test-mcp", response_model=TestConnectionResult)
async def test_mcp_connection(
    body: Optional[Dict[str, str]] = Body(None),
    db: AsyncSession = Depends(get_db),
) -> TestConnectionResult:
    if body:
        mcp_host = body.get("host") or body.get("mcp_host", "localhost")
        mcp_port = body.get("port") or body.get("mcp_port", "3001")
    else:
        app_settings = await _load_all_settings(db)
        mcp_host = app_settings.get("mcp_host", "localhost")
        mcp_port = app_settings.get("mcp_port", "3001")

    mcp_url = f"http://{mcp_host}:{mcp_port}"
    try:
        async with httpx.AsyncClient(timeout=10.0) as http:
            resp = await http.get(f"{mcp_url}/health")
            if resp.status_code == 200:
                return TestConnectionResult(
                    success=True,
                    message="MCP server connection successful",
                    details=resp.json(),
                )
            return TestConnectionResult(
                success=False,
                message=f"MCP server returned HTTP {resp.status_code}",
                details={"status_code": resp.status_code, "body": resp.text[:500]},
            )
    except Exception as exc:
        return TestConnectionResult(
            success=False,
            message=f"MCP server connection failed: {str(exc)}",
            details={"error": str(exc), "url": mcp_url},
        )

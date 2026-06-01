"""
T13 · Tier-3 model-swap hook.

Centralises LLM-client construction so the orchestrator, critic, test-connection
route, and multi-agent sub-agents all reach for the same provider matrix.

Supported providers:
  - "anthropic" (default)  → AsyncAnthropic, api.anthropic.com
  - "azure"                → AsyncAnthropic with Azure-hosted Anthropic endpoint
  - "bedrock"              → AsyncAnthropicBedrock (AWS signed)
  - "custom"               → AsyncAnthropic with a pluggable base_url + optional
                             extra auth header.
  - "azure_openai"         → AzureOpenAIAdapter (AsyncAzureOpenAI) for GPT models
                             on Azure AI Foundry. Presents an Anthropic-compatible
                             .messages.create() interface so the orchestrator needs
                             zero changes.

All variants expose `.messages.create(**kwargs)` with identical signatures.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from anthropic import AsyncAnthropic

logger = logging.getLogger(__name__)

_CACHE_CAPABLE = frozenset({"anthropic"})

# Global semaphore limiting concurrent Azure OpenAI API calls across ALL
# sub-agents in the process.  Without this, up to 11 Phase-2 agents fire
# simultaneously, collectively saturating the per-minute RPM/TPM quota and
# producing cascading 429s that exhaust retries and kill sub-agents entirely.
# Default is 2 concurrent calls — conservative enough for S0/S1 deployments.
# Operators with higher quota can raise this via AZURE_OAI_CONCURRENCY env var
# (e.g. AZURE_OAI_CONCURRENCY=4) without code changes.
_AZURE_OAI_SEMAPHORE: Optional[asyncio.Semaphore] = None
_AZURE_OAI_CONCURRENCY = int(os.getenv("AZURE_OAI_CONCURRENCY", "2"))


def _get_azure_semaphore() -> asyncio.Semaphore:
    global _AZURE_OAI_SEMAPHORE
    if _AZURE_OAI_SEMAPHORE is None:
        _AZURE_OAI_SEMAPHORE = asyncio.Semaphore(_AZURE_OAI_CONCURRENCY)
    return _AZURE_OAI_SEMAPHORE


def anthropic_thinking_kwargs(model: str, budget_tokens: Optional[int] = None) -> Dict[str, Any]:
    """Return thinking kwargs compatible with the configured Claude model.

    Older Claude extended-thinking models accepted:
      {"thinking": {"type": "enabled", "budget_tokens": N}}

    Newer Claude 4.6/4.7 models reject that shape and require adaptive
    thinking controlled through output_config.effort. anthropic==0.49.0 does
    not expose output_config as a top-level create() parameter, so we pass it
    through extra_body.
    """
    m = (model or "").lower()
    if "opus" not in m and "sonnet" not in m:
        return {}

    # Current demo profiles use claude-opus-4-7 and claude-sonnet-4-6. These
    # models expect adaptive thinking, not the legacy enabled/budget shape.
    adaptive_markers = (
        "opus-4-7",
        "opus-4-6",
        "sonnet-4-6",
        "sonnet-4-5",
    )
    if any(marker in m for marker in adaptive_markers):
        effort = "high" if (budget_tokens or 0) >= 5000 else "medium"
        return {
            "thinking": {"type": "adaptive"},
            "extra_body": {"output_config": {"effort": effort}},
        }

    budget = max(1024, int(budget_tokens or 3000))
    return {"thinking": {"type": "enabled", "budget_tokens": budget}}


def apply_anthropic_thinking(
    create_kwargs: Dict[str, Any],
    model: str,
    budget_tokens: Optional[int] = None,
) -> None:
    """Mutate create_kwargs with model-compatible Claude thinking settings."""
    thinking_kwargs = anthropic_thinking_kwargs(model, budget_tokens)
    if not thinking_kwargs:
        return

    extra_body = thinking_kwargs.pop("extra_body", None)
    create_kwargs.update(thinking_kwargs)
    if extra_body:
        merged = dict(create_kwargs.get("extra_body") or {})
        for key, value in extra_body.items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = {**merged[key], **value}
            else:
                merged[key] = value
        create_kwargs["extra_body"] = merged


# ---------------------------------------------------------------------------
# Fake Anthropic-compatible response objects used by AzureOpenAIAdapter
# ---------------------------------------------------------------------------

class _FakeUsage:
    def __init__(self, input_tokens: int, output_tokens: int) -> None:
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.cache_read_input_tokens: int = 0
        self.cache_creation_input_tokens: int = 0


class _FakeTextBlock:
    type: str = "text"

    def __init__(self, text: str) -> None:
        self.text = text


class _FakeToolUseBlock:
    type: str = "tool_use"

    def __init__(self, id: str, name: str, input: dict) -> None:
        self.id = id
        self.name = name
        self.input = input


class _FakeMessage:
    def __init__(self, content: list, stop_reason: str, usage: _FakeUsage) -> None:
        self.content = content
        self.stop_reason = stop_reason
        self.usage = usage
        self.type = "message"
        self.role = "assistant"
        self.model = ""
        self.id = ""


# ---------------------------------------------------------------------------
# Conversion helpers
# ---------------------------------------------------------------------------

def _flatten_to_str(content: Any) -> str:
    """Collapse Anthropic-style content (str | list of blocks) to a plain string."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: List[str] = []
        for b in content:
            if isinstance(b, dict):
                btype = b.get("type", "")
                if btype == "text":
                    parts.append(b.get("text", ""))
                elif btype == "tool_result":
                    parts.append(_flatten_to_str(b.get("content", "")))
            elif hasattr(b, "text"):
                parts.append(b.text or "")
        return "\n".join(p for p in parts if p)
    if isinstance(content, dict):
        return content.get("text", str(content))
    return str(content)


def _to_oai_messages(messages: list, system: Any) -> list:
    """Convert Anthropic-format messages + system param to OpenAI messages list."""
    import json as _j
    oai: list = []

    if system:
        sys_text = _flatten_to_str(system) if isinstance(system, list) else str(system)
        oai.append({"role": "system", "content": sys_text})

    for msg in messages:
        role = msg.get("role", "user")
        content = msg.get("content", "")

        if role == "assistant":
            if isinstance(content, list):
                text_parts: List[str] = []
                tool_calls: list = []
                for b in content:
                    btype = b.get("type") if isinstance(b, dict) else getattr(b, "type", "")
                    if btype == "tool_use":
                        name = b.get("name") if isinstance(b, dict) else getattr(b, "name", "")
                        inp  = b.get("input") if isinstance(b, dict) else getattr(b, "input", {})
                        bid  = b.get("id")    if isinstance(b, dict) else getattr(b, "id", "")
                        tool_calls.append({
                            "id": bid, "type": "function",
                            "function": {"name": name, "arguments": _j.dumps(inp or {})},
                        })
                    elif btype == "thinking":
                        pass  # drop extended-thinking blocks
                    else:
                        t = b.get("text") if isinstance(b, dict) else getattr(b, "text", "")
                        if t:
                            text_parts.append(t)
                if tool_calls:
                    oai.append({
                        "role": "assistant",
                        "content": " ".join(text_parts) or None,
                        "tool_calls": tool_calls,
                    })
                else:
                    oai.append({"role": "assistant", "content": "\n".join(text_parts)})
            else:
                oai.append({"role": "assistant", "content": _flatten_to_str(content)})

        else:  # user
            if isinstance(content, list):
                tool_results: list = []
                text_parts_u: List[str] = []
                for b in content:
                    if isinstance(b, dict):
                        if b.get("type") == "tool_result":
                            tool_results.append({
                                "role": "tool",
                                "tool_call_id": b.get("tool_use_id", ""),
                                "content": _flatten_to_str(b.get("content", "")),
                            })
                        elif b.get("type") == "text":
                            text_parts_u.append(b.get("text", ""))
                        else:
                            text_parts_u.append(_flatten_to_str(b))
                    else:
                        text_parts_u.append(_flatten_to_str(b))
                oai.extend(tool_results)
                if text_parts_u:
                    oai.append({"role": "user", "content": "\n".join(p for p in text_parts_u if p)})
            else:
                oai.append({"role": "user", "content": _flatten_to_str(content)})

    return oai


def _translate_oai_response(r: Any) -> _FakeMessage:
    """Convert an OpenAI ChatCompletion to a _FakeMessage (Anthropic shape)."""
    import json as _j
    choice = r.choices[0]
    stop_map = {
        "stop": "end_turn",
        "tool_calls": "tool_use",
        "length": "max_tokens",
        "content_filter": "end_turn",
    }
    stop_reason = stop_map.get(choice.finish_reason or "stop", "end_turn")

    blocks: list = []
    if choice.message.content:
        blocks.append(_FakeTextBlock(choice.message.content))
    for tc in (choice.message.tool_calls or []):
        try:
            args = _j.loads(tc.function.arguments or "{}")
        except Exception:
            args = {}
        blocks.append(_FakeToolUseBlock(tc.id, tc.function.name, args))

    usage = r.usage
    return _FakeMessage(
        content=blocks,
        stop_reason=stop_reason,
        usage=_FakeUsage(
            getattr(usage, "prompt_tokens", 0),
            getattr(usage, "completion_tokens", 0),
        ),
    )


# ---------------------------------------------------------------------------
# Azure OpenAI adapter
# ---------------------------------------------------------------------------

class _AzureOAIMessages:
    """The .messages sub-object — holds the create() coroutine."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    async def create(
        self,
        *,
        model: str,
        messages: list,
        max_tokens: int = 4096,
        system: Any = None,
        temperature: Optional[float] = None,
        tools: Optional[list] = None,
        thinking: Any = None,         # Anthropic-only — accepted and dropped
        extra_headers: Any = None,    # Anthropic-only — accepted and dropped
        timeout: Optional[float] = None,
        **_ignored: Any,
    ) -> _FakeMessage:
        oai_messages = _to_oai_messages(messages, system)
        kwargs: Dict[str, Any] = {
            "model": model,
            "messages": oai_messages,
            "max_completion_tokens": max_tokens,
        }
        if temperature is not None:
            kwargs["temperature"] = temperature
        if timeout is not None:
            kwargs["timeout"] = timeout
        if tools:
            kwargs["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t["name"],
                        "description": t.get("description", ""),
                        "parameters": t.get("input_schema", {"type": "object", "properties": {}}),
                    },
                }
                for t in tools
            ]
            kwargs["tool_choice"] = "auto"

        # Retry on transient 429s and connection errors. Multi-agent mode runs
        # up to 11 sub-agents in parallel; without a semaphore + retry they
        # collectively saturate Azure OpenAI's per-minute RPM/TPM quota.
        # The global semaphore (_get_azure_semaphore) limits concurrent calls
        # to 4 so we never fan out faster than the quota allows; the retry
        # loop handles any 429s that still slip through (e.g. during warmup).
        import asyncio as _asyncio
        import random as _random
        try:
            from openai import (
                APIConnectionError as _ConnErr,
                APITimeoutError as _TimeoutErr,
                InternalServerError as _SrvErr,
                RateLimitError as _RateErr,
            )
        except Exception:  # openai not installed in some test contexts
            _RateErr = _ConnErr = _TimeoutErr = _SrvErr = Exception  # type: ignore

        MAX_RETRIES = 8
        for attempt in range(MAX_RETRIES + 1):
            try:
                async with _get_azure_semaphore():
                    oai_resp = await self._inner.chat.completions.create(**kwargs)
                return _translate_oai_response(oai_resp)
            except _RateErr as exc:
                if attempt >= MAX_RETRIES:
                    raise
                # Honour Retry-After / x-ms-retry-after-ms headers when
                # present — Azure returns the latter (milliseconds) more often
                # than the standard seconds-based Retry-After.
                retry_after = 0.0
                try:
                    hdr = getattr(exc, "response", None)
                    if hdr is not None and hasattr(hdr, "headers"):
                        ra_ms = hdr.headers.get("x-ms-retry-after-ms")
                        if ra_ms:
                            retry_after = float(ra_ms) / 1000.0
                        else:
                            ra = hdr.headers.get("retry-after")
                            if ra:
                                retry_after = float(ra)
                except Exception:
                    retry_after = 0.0
                # Exponential backoff: 4 s, 8 s, 16 s, 32 s, 60 s, 90 s,
                # 120 s, 120 s — ceiling raised to 120 s for severe throttles.
                base = retry_after if retry_after > 0 else min(120.0, 2 ** (attempt + 2))
                wait = base + _random.uniform(0, 3)
                logger.warning(
                    "[AZURE_OAI] 429 RateLimit on attempt %d/%d — sleeping %.1fs",
                    attempt + 1, MAX_RETRIES + 1, wait,
                )
                await _asyncio.sleep(wait)
            except (_ConnErr, _TimeoutErr, _SrvErr) as exc:
                if attempt >= MAX_RETRIES:
                    raise
                wait = min(30.0, 2 ** (attempt + 1)) + _random.uniform(0, 2)
                logger.warning(
                    "[AZURE_OAI] %s on attempt %d/%d — sleeping %.1fs",
                    type(exc).__name__, attempt + 1, MAX_RETRIES + 1, wait,
                )
                await _asyncio.sleep(wait)
        # Unreachable — the loop either returns or raises.
        raise RuntimeError("azure_openai retry loop exited without result")


class AzureOpenAIAdapter:
    """Anthropic-compatible facade over AsyncAzureOpenAI.

    The orchestrator calls client.messages.create(**kwargs) — this adapter
    translates arguments and response shapes so zero orchestrator changes
    are needed when azure_openai is the selected provider.
    """

    def __init__(self, inner: Any) -> None:
        self.messages = _AzureOAIMessages(inner)


# ---------------------------------------------------------------------------
# Existing helpers (unchanged)
# ---------------------------------------------------------------------------

def _normalize_azure_endpoint(endpoint: str) -> str:
    url = endpoint.rstrip("/")
    if url.endswith("/v1/messages"):
        url = url[: -len("/v1/messages")]
    elif url.endswith("/v1"):
        url = url[: -len("/v1")]
    return url


def _parse_extra_headers(raw: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not raw:
        return out
    for piece in raw.split(","):
        piece = piece.strip()
        if not piece or ":" not in piece:
            continue
        k, v = piece.split(":", 1)
        k = k.strip()
        v = v.strip()
        if k and v:
            out[k] = v
    return out


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_llm_client(app_settings: Dict[str, str]) -> Any:
    """Return an async Anthropic-compatible client for the configured provider."""
    provider = (app_settings.get("llm_provider") or "anthropic").strip().lower()
    api_key = app_settings.get("llm_api_key", "")

    if provider == "azure_openai":
        try:
            from openai import AsyncAzureOpenAI
        except ImportError as exc:
            raise RuntimeError(
                "llm_provider=azure_openai requires the `openai` package "
                "(pip install openai>=1.54.0)."
            ) from exc
        endpoint = (app_settings.get("azure_endpoint") or "").rstrip("/")
        if not endpoint:
            raise RuntimeError(
                "llm_provider=azure_openai requires azure_endpoint to be set "
                "(e.g. https://my-resource.cognitiveservices.azure.com/)"
            )
        api_version = app_settings.get("azure_oai_api_version") or "2024-12-01-preview"
        # max_retries=4 lets the SDK absorb a few transient 429s before our
        # explicit retry loop in _AzureOAIMessages.create kicks in. Combined
        # they smooth out multi-agent fan-out where 4–9 sub-agents fire
        # simultaneously and trip Azure's per-minute TPM/RPM quotas.
        inner = AsyncAzureOpenAI(
            api_key=api_key,
            azure_endpoint=endpoint,
            api_version=api_version,
            max_retries=4,
        )
        return AzureOpenAIAdapter(inner)

    if provider == "foundry_serverless":
        # Azure AI Foundry serverless inference exposes an OpenAI-compatible
        # /chat/completions endpoint for non-OpenAI models (Llama 4, DeepSeek-R1,
        # Qwen2.5-Coder, Mistral Large). The /openai/v1/ subpath is the OpenAI-
        # compatible surface; our existing AzureOpenAIAdapter wraps it with zero
        # new translation code because it only requires chat.completions.create.
        try:
            from openai import AsyncOpenAI
        except ImportError as exc:
            raise RuntimeError(
                "llm_provider=foundry_serverless requires the `openai` package "
                "(pip install openai>=1.54.0)."
            ) from exc
        base_url = (app_settings.get("foundry_endpoint") or "").rstrip("/")
        if not base_url:
            raise RuntimeError(
                "llm_provider=foundry_serverless requires foundry_endpoint to be set "
                "(e.g. https://your-resource.services.ai.azure.com/openai/v1/)"
            )
        # Foundry serverless honours both Authorization: Bearer and api-key headers.
        # Sending api-key avoids a redirect on some deployments.
        inner = AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
            default_headers={"api-key": api_key} if api_key else None,
            max_retries=4,
        )
        return AzureOpenAIAdapter(inner)

    if provider == "azure":
        base_url = _normalize_azure_endpoint(app_settings.get("azure_endpoint", ""))
        if not base_url:
            raise RuntimeError("llm_provider=azure requires azure_endpoint to be set")
        return AsyncAnthropic(api_key=api_key, base_url=base_url)

    if provider == "bedrock":
        try:
            from anthropic import AsyncAnthropicBedrock
        except ImportError as exc:
            raise RuntimeError(
                "llm_provider=bedrock requires the `anthropic[bedrock]` extra "
                "(pip install 'anthropic[bedrock]') to be installed."
            ) from exc
        return AsyncAnthropicBedrock(
            aws_region=app_settings.get("aws_region") or "us-east-1",
            aws_access_key=app_settings.get("aws_access_key") or None,
            aws_secret_key=app_settings.get("aws_secret_key") or None,
            aws_session_token=app_settings.get("aws_session_token") or None,
        )

    if provider == "custom":
        base_url = (app_settings.get("custom_endpoint") or "").rstrip("/")
        if not base_url:
            raise RuntimeError("llm_provider=custom requires custom_endpoint to be set")
        extra_headers = _parse_extra_headers(app_settings.get("custom_headers", ""))
        effective_key = api_key or "unused-via-custom-header"
        return AsyncAnthropic(
            api_key=effective_key,
            base_url=base_url,
            default_headers=extra_headers or None,
        )

    # Default anthropic branch — optionally accept a custom base URL for
    # operator-controlled Anthropic-compatible endpoints (proxies, regional
    # gateways). Empty/missing => SDK default (api.anthropic.com).
    anthropic_endpoint = (
        app_settings.get("anthropic_endpoint")
        or app_settings.get("custom_endpoint")
        or ""
    ).strip().rstrip("/")
    if anthropic_endpoint:
        return AsyncAnthropic(api_key=api_key, base_url=anthropic_endpoint)
    return AsyncAnthropic(api_key=api_key)


def provider_supports_caching(app_settings: Dict[str, str]) -> bool:
    """True when Anthropic-style prompt caching (cache_control) is safe to emit."""
    provider = (app_settings.get("llm_provider") or "anthropic").strip().lower()
    return provider in _CACHE_CAPABLE


def describe_provider(app_settings: Dict[str, str]) -> Tuple[str, str]:
    """Return (provider, human_description) for logs and error messages."""
    provider = (app_settings.get("llm_provider") or "anthropic").strip().lower()
    model = app_settings.get("llm_model", "claude-opus-4-7")
    if provider == "azure_openai":
        return provider, (
            f"Azure OpenAI · endpoint={app_settings.get('azure_endpoint', '?')} "
            f"· deployment={model} "
            f"· api_version={app_settings.get('azure_oai_api_version', '2024-12-01-preview')}"
        )
    if provider == "foundry_serverless":
        return provider, (
            f"Foundry serverless · endpoint={app_settings.get('foundry_endpoint', '?')} "
            f"· model={model}"
        )
    if provider == "azure":
        return provider, f"Azure · endpoint={app_settings.get('azure_endpoint', '?')} · model={model}"
    if provider == "bedrock":
        return provider, f"Bedrock · region={app_settings.get('aws_region', '?')} · model={model}"
    if provider == "custom":
        return provider, f"Custom · endpoint={app_settings.get('custom_endpoint', '?')} · model={model}"
    return provider, f"Anthropic API · model={model}"

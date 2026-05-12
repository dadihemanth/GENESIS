"""v7.x — session cost summary derived from llm_usage rows.

Pricing model:
  - Operator-configured per-model rates live in AppSettings under the key
    `model_pricing`, stored as JSON. Shape:
        {"<model>": {"input": <usd_per_1m>, "output": <usd_per_1m>}, ...}
  - Cache rates are auto-derived per Anthropic's published ratios:
        cache_create = 1.25 × input rate
        cache_read   = 0.1  × input rate
  - If a session used a model that has no entry in `model_pricing`, the API
    falls back to `_DEFAULT_RATES` (best-effort published prices); zero
    rates are NEVER assumed silently — they're flagged in `unknown_models`.

Endpoint:
  GET /sessions/{session_id}/costs
    -> {
         "session_id": "...",
         "total_usd": 1.234,
         "totals": {"input": ..., "output": ..., "cache_create": ..., "cache_read": ...},
         "tokens": {"input": ..., "output": ..., "cache_create": ..., "cache_read": ...},
         "by_iteration": [{"iteration": N, "cost_usd": ..., "cumulative_usd": ...}, ...],
         "by_source": {"orchestrator": 0.45, "critic": 0.02, ...},
         "by_model":  {"claude-opus-4-7": 0.61, "gpt-5.5": 0.03, ...},
         "rates_used": {"claude-opus-4-7": {"input": 15, "output": 75}, ...},
         "unknown_models": []
       }
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.mongodb import get_llm_usage_collection
from app.database.postgres import AsyncSessionLocal
from app.models.session import AppSettings

router = APIRouter()


# Best-effort published list prices (USD per 1M tokens) used when the operator
# hasn't configured a rate for the model. Edit in Settings to override.
_DEFAULT_RATES: Dict[str, Dict[str, float]] = {
    # Anthropic
    "claude-opus-4-7": {"input": 15.0, "output": 75.0},
    "claude-opus-4-7[1m]": {"input": 15.0, "output": 75.0},
    "claude-sonnet-4-6": {"input": 3.0, "output": 15.0},
    "claude-haiku-4-5": {"input": 0.8, "output": 4.0},
    "claude-haiku-4-5-20251001": {"input": 0.8, "output": 4.0},
    # Azure OpenAI / OpenAI
    "gpt-5.5": {"input": 1.25, "output": 10.0},
    "gpt-5": {"input": 1.25, "output": 10.0},
    "gpt-4o": {"input": 2.5, "output": 10.0},
    "gpt-4o-mini": {"input": 0.15, "output": 0.6},
    "gpt-4.1": {"input": 2.0, "output": 8.0},
    "o3": {"input": 15.0, "output": 60.0},
    "o4-mini": {"input": 3.0, "output": 12.0},
}

_CACHE_CREATE_MULT = 1.25
_CACHE_READ_MULT = 0.1


async def _load_model_pricing() -> Dict[str, Dict[str, float]]:
    """Load operator-configured per-model rates from AppSettings.

    v7.x — prefers `model_profiles` (the multi-model role-routing config) when
    present: each profile's `rates` dict is keyed by its `model` field. Falls
    back to the legacy `model_pricing` JSON for installs that haven't migrated.
    """
    async with AsyncSessionLocal() as db:  # type: AsyncSession
        result = await db.execute(
            select(AppSettings).where(
                AppSettings.key.in_(["model_profiles", "model_pricing"])
            )
        )
        rows = {row.key: row.value for row in result.scalars().all()}

    out: Dict[str, Dict[str, float]] = {}

    # First-priority — read rates from each profile in model_profiles.
    raw_profiles = rows.get("model_profiles") or ""
    if raw_profiles:
        try:
            profiles = json.loads(raw_profiles)
            if isinstance(profiles, list):
                for p in profiles:
                    if not isinstance(p, dict):
                        continue
                    model = str(p.get("model") or "")
                    rates = p.get("rates") or {}
                    if not model or not isinstance(rates, dict):
                        continue
                    try:
                        i = float(rates.get("input", 0) or 0)
                        o = float(rates.get("output", 0) or 0)
                    except (TypeError, ValueError):
                        continue
                    if i > 0 or o > 0:
                        out[model] = {"input": i, "output": o}
        except Exception:
            pass

    # Second-priority — legacy `model_pricing` JSON (filling gaps only).
    raw_legacy = rows.get("model_pricing") or ""
    if raw_legacy:
        try:
            parsed = json.loads(raw_legacy)
            if isinstance(parsed, dict):
                for k, v in parsed.items():
                    if not isinstance(v, dict) or k in out:
                        continue
                    try:
                        out[str(k)] = {
                            "input": float(v.get("input", 0) or 0),
                            "output": float(v.get("output", 0) or 0),
                        }
                    except (TypeError, ValueError):
                        continue
        except Exception:
            pass

    return out


def _resolve_rate(
    model: str,
    operator_rates: Dict[str, Dict[str, float]],
) -> Optional[Dict[str, float]]:
    """Operator rate wins; fall back to defaults; None when nothing matches."""
    if model in operator_rates:
        return operator_rates[model]
    if model in _DEFAULT_RATES:
        return _DEFAULT_RATES[model]
    # Loose match — strip provider/path prefixes and trailing variant tags.
    base = model.split("/")[-1].split(":")[0].strip()
    if base in operator_rates:
        return operator_rates[base]
    if base in _DEFAULT_RATES:
        return _DEFAULT_RATES[base]
    return None


def _cost_for_doc(
    doc: Dict[str, Any],
    operator_rates: Dict[str, Dict[str, float]],
    unknown_models: set,
) -> float:
    """Compute USD for a single llm_usage document. Cache deltas use the
    derived 1.25× / 0.1× ratios from the input rate."""
    model = str(doc.get("model", ""))
    rate = _resolve_rate(model, operator_rates)
    if rate is None:
        unknown_models.add(model or "(unknown)")
        return 0.0
    in_per = float(rate.get("input", 0))
    out_per = float(rate.get("output", 0))
    if in_per <= 0 and out_per <= 0:
        unknown_models.add(model or "(unknown)")
        return 0.0
    inp = int(doc.get("input_tokens", 0) or 0)
    out = int(doc.get("output_tokens", 0) or 0)
    cc = int(doc.get("cache_create_tokens", 0) or 0)
    cr = int(doc.get("cache_read_tokens", 0) or 0)
    return (
        (inp / 1_000_000.0) * in_per
        + (out / 1_000_000.0) * out_per
        + (cc / 1_000_000.0) * (in_per * _CACHE_CREATE_MULT)
        + (cr / 1_000_000.0) * (in_per * _CACHE_READ_MULT)
    )


@router.get("/{session_id}/costs")
async def get_session_costs(session_id: str) -> Dict[str, Any]:
    """Aggregate cost across every LLM call recorded for the session."""
    operator_rates = await _load_model_pricing()
    col = get_llm_usage_collection()
    cursor = col.find({"session_id": str(session_id)}).sort([("ts", 1)])

    totals = {"input": 0.0, "output": 0.0, "cache_create": 0.0, "cache_read": 0.0}
    tokens = {"input": 0, "output": 0, "cache_create": 0, "cache_read": 0}
    by_iter_map: Dict[int, float] = {}
    by_source: Dict[str, float] = {}
    by_model: Dict[str, float] = {}
    rates_used: Dict[str, Dict[str, float]] = {}
    unknown_models: set = set()

    total_usd = 0.0

    async for doc in cursor:
        cost = _cost_for_doc(doc, operator_rates, unknown_models)
        total_usd += cost

        # split contribution by token class for the totals breakdown
        model = str(doc.get("model", ""))
        rate = _resolve_rate(model, operator_rates) or {}
        in_per = float(rate.get("input", 0))
        out_per = float(rate.get("output", 0))
        if rate and (in_per > 0 or out_per > 0):
            rates_used[model] = {"input": in_per, "output": out_per}
        inp = int(doc.get("input_tokens", 0) or 0)
        out = int(doc.get("output_tokens", 0) or 0)
        cc = int(doc.get("cache_create_tokens", 0) or 0)
        cr = int(doc.get("cache_read_tokens", 0) or 0)
        tokens["input"] += inp
        tokens["output"] += out
        tokens["cache_create"] += cc
        tokens["cache_read"] += cr
        totals["input"] += (inp / 1_000_000.0) * in_per
        totals["output"] += (out / 1_000_000.0) * out_per
        totals["cache_create"] += (cc / 1_000_000.0) * (in_per * _CACHE_CREATE_MULT)
        totals["cache_read"] += (cr / 1_000_000.0) * (in_per * _CACHE_READ_MULT)

        # per-iteration accumulator (cost-only — cumulative computed below)
        it = int(doc.get("iteration", 0) or 0)
        by_iter_map[it] = by_iter_map.get(it, 0.0) + cost

        src = str(doc.get("source", "orchestrator") or "orchestrator")
        by_source[src] = by_source.get(src, 0.0) + cost

        if model:
            by_model[model] = by_model.get(model, 0.0) + cost

    by_iteration: List[Dict[str, Any]] = []
    cumulative = 0.0
    for it in sorted(by_iter_map.keys()):
        cost = by_iter_map[it]
        cumulative += cost
        by_iteration.append({
            "iteration": it,
            "cost_usd": round(cost, 6),
            "cumulative_usd": round(cumulative, 6),
        })

    # v7.x — surface all configured profiles in the by_model breakdown so
    # the operator sees every model they wired up, with $0 if it never ran.
    # That makes it obvious which profiles are dormant vs active.
    try:
        async with AsyncSessionLocal() as db2:
            r2 = await db2.execute(
                select(AppSettings).where(AppSettings.key == "model_profiles")
            )
            row = r2.scalar_one_or_none()
        if row and row.value:
            for p in (json.loads(row.value) or []):
                if not isinstance(p, dict):
                    continue
                m = str(p.get("model") or "")
                if m and m not in by_model:
                    by_model[m] = 0.0
                rates = p.get("rates") or {}
                if m and m not in rates_used and isinstance(rates, dict):
                    try:
                        rates_used[m] = {
                            "input": float(rates.get("input", 0) or 0),
                            "output": float(rates.get("output", 0) or 0),
                        }
                    except (TypeError, ValueError):
                        pass
    except Exception:
        pass

    return {
        "session_id": str(session_id),
        "total_usd": round(total_usd, 6),
        "totals": {k: round(v, 6) for k, v in totals.items()},
        "tokens": tokens,
        "by_iteration": by_iteration,
        "by_source": {k: round(v, 6) for k, v in by_source.items()},
        "by_model": {k: round(v, 6) for k, v in by_model.items()},
        "rates_used": rates_used,
        "default_rates": _DEFAULT_RATES,
        "unknown_models": sorted(unknown_models),
    }



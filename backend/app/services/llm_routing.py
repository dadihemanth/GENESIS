"""v7.x — multi-model role-based routing.

Each call site in the orchestrator carries a fixed role label
(`primary`, `critic`, `compress`, `brief`, `reasoning`, `payload`,
`red_blue`, `philosopher`, `subagent`). The operator stores N model
profiles in AppSettings and assigns each role to a profile. This module
resolves role -> (client, model, rates) on demand.

Settings shape (both stored as JSON strings in the AppSettings k/v table):

  model_profiles  -> [{"id", "name", "provider", "model", "api_key",
                        "endpoint", "api_version", "custom_endpoint",
                        "custom_headers", "rates": {"input", "output"},
                        "supports_tools": bool}, ...]
  role_assignments -> {"primary": "<profile-id>", "critic": "<profile-id>", ...}

Backward compatibility: when `model_profiles` is empty/missing, every role
routes to a synthetic "legacy" profile derived from the existing single-
model settings (`llm_provider`, `llm_model`, `llm_api_key`, `azure_endpoint`,
`azure_oai_api_version`). Existing installs work unchanged.

Cache: clients are cached by profile signature (sha256 of profile JSON) so
operator edits invalidate transparently. The cache is process-level — each
Celery worker holds its own.
"""
from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Role registry
# ---------------------------------------------------------------------------

# All roles the orchestrator routes through. The labels must match the
# `source=` argument passed to record_llm_usage so the Costs tab attributes
# spend correctly.
KNOWN_ROLES = (
    "primary",       # main orchestrator loop
    "critic",        # _adversarial_critique
    "compress",      # _compress_history
    "brief",         # _generate_target_brief
    "reasoning",     # _make_llm_call_adapter (deliberate loops + backstop)
    "payload",       # multi-agent payload SubAgent
    "red_blue",      # adversarial RedBlueDialectic — Red (auditor) agent
    "debate",        # adversarial RedBlueDialectic — Blue (debater) agent; assign a DIFFERENT provider/model than red_blue for cross-model signal
    "philosopher",   # adversarial PhilosopherAgent
    "subagent",      # multi-agent generic SubAgent
    "judge",         # v8 SessionJudge — per-round coverage + goal evaluator
    "validator",     # validated_dynamic candidate reachability/evidence review
    "endpoint_validator",  # validated_dynamic live endpoint reachability reviewer
    "source_validator",    # validated_dynamic source/taint/cross-file reviewer
    "counter_validator",   # validated_dynamic refutation/missing-proof reviewer
    "proof_planner",       # optional validation-lab concrete proof-action planner
)

# Per-role human-readable description + which sources fire under that role.
# The Routing tab uses these to explain to the operator what each role is for
# and why a given model would be a good (or bad) fit.
ROLE_DETAILS: Dict[str, Dict[str, Any]] = {
    "primary": {
        "fires_in": "solo agent_mode only",
        "purpose": (
            "Drives the main orchestrator loop in solo mode — every turn that "
            "isn't critic/compress/brief/reasoning. In multi_agent mode the "
            "primary role does NOT fire; sub-agents take over via the "
            "`subagent` role."
        ),
        "good_models": "Opus 4.7, Sonnet 4.6, GPT-5.5 — high context + tool use",
        "sources": ("orchestrator",),
    },
    "subagent": {
        "fires_in": "multi_agent mode only",
        "purpose": (
            "Used by EVERY multi-agent sub-agent (recon, analyst, exploit, "
            "code, crypto, auth, reveng, exploitdev, network, iot, mobile, "
            "ot, embedded). In multi-agent mode this is the role that does "
            "the bulk of the work — set this if you want a model to drive "
            "the actual scanning."
        ),
        "good_models": "Opus 4.7 for deep, Llama 4 / DeepSeek-R1 for less-restrictive payload work",
        "sources": ("subagent:recon", "subagent:analyst", "subagent:exploit",
                    "subagent:code", "subagent:crypto", "subagent:auth",
                    "subagent:reveng", "subagent:exploitdev", "subagent:network",
                    "subagent:iot", "subagent:mobile", "subagent:ot",
                    "subagent:embedded", "subagent:source_analyst",
                    "subagent:invariant_engineer"),
    },
    "critic": {
        "fires_in": "both modes",
        "purpose": (
            "Adversarial critic that confirms/disputes each finding's "
            "evidence. High-volume, short prompts — cheaper models excel."
        ),
        "good_models": "Haiku 4.5, gpt-4o-mini, GPT-5.5",
        "sources": ("critic",),
    },
    "compress": {
        "fires_in": "solo agent_mode only",
        "purpose": (
            "Compresses old conversation history every 15 iterations to "
            "control input-token growth. Pure summarisation work."
        ),
        "good_models": "Haiku 4.5, gpt-4o-mini",
        "sources": ("history_compress",),
    },
    "brief": {
        "fires_in": "both modes (once per session)",
        "purpose": (
            "Pre-scan target intent brief. Reads recon hints + intelligence "
            "from past sessions and emits a structured hypothesis list."
        ),
        "good_models": "Sonnet 4.6, GPT-5.5",
        "sources": ("brief",),
    },
    "reasoning": {
        "fires_in": "both modes",
        "purpose": (
            "v7 deliberate loops + the orchestrator-side backstop. Multi-step "
            "structured reasoning — counterfactual, hypothesis_decomp, "
            "chain_composer, code_intent."
        ),
        "good_models": "Opus 4.7, o3, DeepSeek-R1 (reasoning models excel)",
        "sources": ("reasoning_loop", "backstop_loop"),
    },
    "payload": {
        "fires_in": "multi_agent mode (Phase 2)",
        "purpose": (
            "Dedicated payload SubAgent that joins exploit + code in every "
            "Phase-2 round. Generation-only — emits "
            "SHARED_FINDING(kind='payload_candidate') blocks the exploit "
            "agent then runs via forge_runner / payload_swarm. Picks aggressive "
            "non-obvious payloads (WAF-bypass encodings, parser-differential, "
            "polyglots, second-order, content-type confusion) that stock "
            "scanners miss."
        ),
        "good_models": "Llama 4 Maverick, DeepSeek-R1 (less restrictive guardrails for offensive payloads)",
        "sources": ("subagent:payload",),
    },
    "red_blue": {
        "fires_in": "both modes",
        "purpose": (
            "Adversarial dialectic — Red (auditor) proposes attacks. "
            "Assign a capable model here. For maximum signal, assign `debate` "
            "to a DIFFERENT provider/model family so cross-model disagreement "
            "becomes a confidence boost (validated scanner cross_model_confirmed pattern)."
        ),
        "good_models": "Opus 4.7, Sonnet 4.6",
        "sources": ("red_agent",),
    },
    "debate": {
        "fires_in": "both modes",
        "purpose": (
            "Adversarial dialectic — Blue (debater) challenges Red's hypotheses. "
            "When assigned to a DIFFERENT model family than `red_blue`, surviving "
            "hypotheses are tagged `cross_model_confirmed` and receive a +0.2 "
            "confidence stake boost — cross-model agreement is a stronger signal "
            "than same-model agreement (validation milestone 1). Falls back to red_blue "
            "profile when not explicitly assigned."
        ),
        "good_models": "GPT-4o via azure_openai (if red_blue uses Claude), or vice versa",
        "sources": ("blue_agent",),
    },
    "philosopher": {
        "fires_in": "both modes (once per session)",
        "purpose": (
            "First-principles bug-class generator. Reads anomaly history "
            "and proposes novel hypotheses. Same role drives the new "
            "insider-threat and nation-state APT personas."
        ),
        "good_models": "Opus 4.7, Sonnet 4.6 (reasoning quality matters)",
        "sources": ("philosopher", "insider", "nation_state"),
    },
    "judge": {
        "fires_in": "both modes (after each Phase-2 round; every 25 iterations in solo)",
        "purpose": (
            "v8 SessionJudge evaluator. Receives the full session state — "
            "kill-chain coverage matrix, goal-tree progress, hypothesis "
            "resolution rate, finding quality — and produces a structured "
            "verdict with a ranked gap list. The SessionSupervisor then "
            "dispatches targeted directives to subagents for each gap. "
            "Use a fast, cheap model — Claude Haiku strongly preferred. "
            "Guarded by a per-round counter so it fires at most once per round."
        ),
        "good_models": "Haiku 4.5 (fast + cheap; quality sufficient for structured eval)",
        "sources": ("judge",),
    },
    "validator": {
        "fires_in": "validated_dynamic mode",
        "purpose": (
            "Independent multi-stage candidate reviewer. Reads candidate "
            "findings before promotion and decides support/refute/needs-proof "
            "based on reachability, exploitability, evidence quality, and the "
            "proposed deterministic proof action."
        ),
        "good_models": "Sonnet 4.6, GPT-5.5, Opus 4.7 for high-impact candidates",
        "sources": ("validator",),
    },
    "endpoint_validator": {
        "fires_in": "validated_dynamic mode",
        "purpose": (
            "Reviews live reachability for candidate findings: endpoint mapping, "
            "HTTP method, auth/session assumptions, exploitability evidence, and "
            "whether an endpoint proof tool should be run."
        ),
        "good_models": "Sonnet 4.6 or GPT-5.5 for high-impact endpoint candidates",
        "sources": ("endpoint_validator",),
    },
    "source_validator": {
        "fires_in": "validated_dynamic mode when source/artifacts exist",
        "purpose": (
            "Reviews source-grounded candidates: taint path plausibility, sink/input "
            "mapping, invariants, cross-file consistency, and whether live replay is required."
        ),
        "good_models": "Opus 4.7, Sonnet 4.6, GPT-5.5",
        "sources": ("source_validator",),
    },
    "counter_validator": {
        "fires_in": "validated_dynamic mode",
        "purpose": (
            "Independent refutation role. Looks for missing reachability, weak evidence, "
            "unmapped source-only bugs, and proof gaps before promotion."
        ),
        "good_models": "Cheap critic model for volume; stronger counter-model for critical candidates",
        "sources": ("counter_validator",),
    },
    "proof_planner": {
        "fires_in": "Validation Lab / Complete Validation when candidates need concrete proof parameters",
        "purpose": (
            "Turns a candidate's hypothesis and evidence into one safe deterministic "
            "proof-tool call. It should produce JSON parameters for ai_request_forge, "
            "forge_runner, browser_session, oob_check, payload_swarm, fuzz_binary, "
            "symbolic_exec, instrument_trace, semgrep_scan, ast_walker, or taint_engine."
        ),
        "good_models": "Sonnet 4.6 or GPT-5.5 for precise tool params; Haiku for low-cost simple HTTP proofs",
        "sources": ("proof_planner",),
    },
}


# ---------------------------------------------------------------------------
# Profile parsing
# ---------------------------------------------------------------------------

def _parse_profiles(raw: str) -> list:
    """Parse the `model_profiles` JSON. Returns [] on any failure."""
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
        if not isinstance(parsed, list):
            return []
        # Filter out malformed entries — every profile needs at least an id
        # and a model. Missing fields elsewhere fall back to defaults.
        return [p for p in parsed if isinstance(p, dict) and p.get("id") and p.get("model")]
    except Exception as exc:
        logger.warning("[ROUTING] failed to parse model_profiles: %s", exc)
        return []


def _parse_assignments(raw: str) -> Dict[str, str]:
    """Parse `role_assignments` JSON. Returns {} on any failure."""
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            return {}
        return {str(k): str(v) for k, v in parsed.items() if isinstance(v, str)}
    except Exception as exc:
        logger.warning("[ROUTING] failed to parse role_assignments: %s", exc)
        return {}


def _legacy_fallback_profile(app_settings: Dict[str, str]) -> Dict[str, Any]:
    """Synthesise a single profile from the existing single-model settings.

    Used when no `model_profiles` are configured. Routes ALL roles through
    this profile, preserving pre-routing behaviour bit-for-bit.
    """
    return {
        "id": "legacy",
        "name": "Legacy single-model",
        "provider": app_settings.get("llm_provider") or "anthropic",
        "model": app_settings.get("llm_model") or "claude-opus-4-7",
        "api_key": app_settings.get("llm_api_key", ""),
        "endpoint": app_settings.get("azure_endpoint", ""),
        "api_version": app_settings.get("azure_oai_api_version", "2024-12-01-preview"),
        "foundry_endpoint": app_settings.get("foundry_endpoint", ""),
        "foundry_api_version": app_settings.get("foundry_api_version", "2024-05-01-preview"),
        "custom_endpoint": app_settings.get("custom_endpoint", ""),
        "custom_headers": app_settings.get("custom_headers", ""),
        "rates": {},
        "supports_tools": True,
    }


def _resolve_profile(
    role: str,
    profiles: list,
    assignments: Dict[str, str],
) -> Optional[Dict[str, Any]]:
    """Find the profile assigned to `role`.

    Cascade: explicit assignment for role -> profile id; falls back to the
    `primary` assignment; falls back to the first profile in the list.
    Returns None if `profiles` is empty.
    """
    if not profiles:
        return None
    profiles_by_id = {p["id"]: p for p in profiles}
    assigned_id = assignments.get(role) or assignments.get("primary")
    if assigned_id and assigned_id in profiles_by_id:
        return profiles_by_id[assigned_id]
    if assigned_id:
        # Stale id (operator deleted that profile after assigning it).
        # Fall through; warn once-ish.
        logger.warning(
            "[ROUTING] role=%s assigned to unknown profile_id=%s — using first profile",
            role, assigned_id,
        )
    return profiles[0]


def _profile_to_settings(profile: Dict[str, Any]) -> Dict[str, str]:
    """Build a per-profile app_settings dict that build_llm_client understands."""
    return {
        "llm_provider": str(profile.get("provider") or "anthropic"),
        "llm_model": str(profile.get("model") or ""),
        "llm_api_key": str(profile.get("api_key") or ""),
        "azure_endpoint": str(profile.get("endpoint") or ""),
        "azure_oai_api_version": str(profile.get("api_version") or "2024-12-01-preview"),
        "foundry_endpoint": str(profile.get("foundry_endpoint") or profile.get("endpoint") or ""),
        "foundry_api_version": str(profile.get("foundry_api_version") or profile.get("api_version") or "2024-05-01-preview"),
        # v7.x — optional base-URL override for the Anthropic provider. Empty
        # means use the SDK default (api.anthropic.com); set for proxies,
        # regional gateways, or on-prem Anthropic-compatible deployments.
        "anthropic_endpoint": str(profile.get("endpoint") or ""),
        "custom_endpoint": str(profile.get("custom_endpoint") or ""),
        "custom_headers": str(profile.get("custom_headers") or ""),
    }


def _profile_signature(profile: Dict[str, Any]) -> str:
    """Stable hash over the fields that affect client construction."""
    blob = json.dumps({
        k: profile.get(k) for k in (
            "id", "provider", "model", "api_key",
            "endpoint", "api_version",
            "foundry_endpoint", "foundry_api_version",
            "custom_endpoint", "custom_headers",
            "supports_tools",
        )
    }, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Client cache
# ---------------------------------------------------------------------------
# profile_id -> (client, signature). Mismatched signature triggers rebuild.
_PROFILE_CLIENT_CACHE: Dict[str, Tuple[Any, str]] = {}


def reset_routing_cache() -> None:
    """Drop every cached client. Called from celery_tasks at session start to
    avoid sharing event-loop-bound httpx clients across Celery tasks."""
    _PROFILE_CLIENT_CACHE.clear()


def _build_client_for_profile(profile: Dict[str, Any]) -> Any:
    from app.services.llm_providers import build_llm_client
    return build_llm_client(_profile_to_settings(profile))


def _get_or_build(profile: Dict[str, Any]) -> Any:
    sig = _profile_signature(profile)
    cached = _PROFILE_CLIENT_CACHE.get(profile["id"])
    if cached and cached[1] == sig:
        return cached[0]
    client = _build_client_for_profile(profile)
    _PROFILE_CLIENT_CACHE[profile["id"]] = (client, sig)
    return client


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def get_client_and_model_for_role(
    role: str,
    app_settings: Dict[str, str],
) -> Tuple[Any, str, Dict[str, float]]:
    """Resolve role -> (client, model, rates).

    `rates` is `{"input": float, "output": float}` (USD per 1M tokens).
    Empty dict when the profile has no rates set — the Costs tab falls back
    to legacy `model_pricing` JSON or hardcoded defaults.

    Never raises for missing config: always returns a usable client via the
    legacy fallback so existing installs work unchanged.
    """
    # v7.x — explicit mode toggle ("single" forces legacy regardless of profiles).
    mode = (app_settings.get("llm_mode") or "").strip().lower()
    profiles = _parse_profiles(app_settings.get("model_profiles", ""))
    assignments = _parse_assignments(app_settings.get("role_assignments", ""))

    if mode == "single" or not profiles:
        # Single-model path — synthesise one profile from the existing
        # legacy settings and route every role to it.
        profile = _legacy_fallback_profile(app_settings)
    else:
        profile = _resolve_profile(role, profiles, assignments)
        if profile is None:
            profile = _legacy_fallback_profile(app_settings)

    client = _get_or_build(profile)
    model = str(profile.get("model") or "")
    rates_raw = profile.get("rates") or {}
    rates: Dict[str, float] = {}
    try:
        if isinstance(rates_raw, dict):
            if rates_raw.get("input") is not None:
                rates["input"] = float(rates_raw["input"])
            if rates_raw.get("output") is not None:
                rates["output"] = float(rates_raw["output"])
    except (TypeError, ValueError):
        rates = {}

    # v8 — judge role always defaults to Haiku when no explicit assignment is
    # configured. This prevents the judge from accidentally inheriting Opus via
    # the `primary` fallback cascade, which would make per-round evaluation
    # expensive. The client (provider/endpoint) is kept as-is.
    if role == "judge" and not assignments.get("judge"):
        model = model or "claude-haiku-4-5-20251001"
        if not model.startswith("claude-haiku") and "haiku" not in model.lower():
            model = "claude-haiku-4-5-20251001"

    return client, model, rates

"""T125/T127 — Curiosity Scorer & Surprise Budget.

Scores hypotheses by predicted likelihood of leading to a confirmed bug.
Uses Claude Haiku for fast/cheap scoring with Redis caching (10-minute TTL).
Allocates sandbox iteration budget proportionally to curiosity scores.
"""
from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_SCORE_TTL = 600  # 10-minute Redis TTL
_MIN_SCORE_THRESHOLD = 0.2  # Block hypotheses below this score

_SYSTEM_PROMPT = """You are a senior security researcher scoring hypotheses for their exploitability potential.
Given a security hypothesis and session context, return a JSON object:
{"score": 0.0-1.0, "reasoning": "one sentence", "attack_class": "SSRF|XSS|SQLi|RCE|LFI|AuthBypass|..."}

Score interpretation:
- 0.0-0.2: Unlikely to yield a bug (no evidence, speculative)
- 0.2-0.5: Low confidence, worth quick validation
- 0.5-0.8: Moderate confidence, supported by partial evidence
- 0.8-1.0: High confidence, strong indicators present

Return ONLY valid JSON, no markdown."""


def _cache_key(hypothesis_text: str, context_fingerprint: str) -> str:
    digest = hashlib.sha256(f"{hypothesis_text}:{context_fingerprint}".encode()).hexdigest()[:16]
    return f"curiosity_score:{digest}"


def _context_fingerprint(session_context: Dict[str, Any]) -> str:
    """Stable short identifier for caching — based on target + tech stack."""
    target = str(session_context.get("target", ""))
    stack = str(session_context.get("stack_pin", ""))
    return hashlib.sha256(f"{target}:{stack}".encode()).hexdigest()[:12]


async def score_hypothesis(hypothesis: Dict[str, Any], session_context: Dict[str, Any]) -> float:
    """Score a single hypothesis. Returns 0.0–1.0. Uses Redis cache."""
    from app.database.redis_client import get_redis_client

    hyp_text = hypothesis.get("hypothesis", hypothesis.get("text", str(hypothesis)))
    ctx_fp = _context_fingerprint(session_context)
    cache_key = _cache_key(hyp_text, ctx_fp)

    try:
        redis = await get_redis_client()
        cached = await redis.get(cache_key)
        if cached:
            return float(cached)
    except Exception:
        pass

    score = await _llm_score(hyp_text, session_context)

    try:
        redis = await get_redis_client()
        await redis.setex(cache_key, _SCORE_TTL, str(score))
    except Exception:
        pass

    return score


async def _llm_score(hyp_text: str, session_context: Dict[str, Any]) -> float:
    """Call Claude Haiku to score the hypothesis."""
    import os
    import anthropic

    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        return 0.5  # neutral fallback when no key

    context_summary = {
        "target": session_context.get("target", "unknown"),
        "stack_pin": session_context.get("stack_pin", "unknown"),
        "phase": session_context.get("phase", "unknown"),
        "confirmed_findings": session_context.get("confirmed_findings", [])[:3],
    }

    user_msg = f"""Session context:
{json.dumps(context_summary, indent=2)}

Hypothesis to score:
{hyp_text}"""

    try:
        client = anthropic.AsyncAnthropic(api_key=api_key)
        response = await client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=150,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_msg}],
        )
        raw = response.content[0].text.strip()
        data = json.loads(raw)
        return float(max(0.0, min(1.0, data.get("score", 0.5))))
    except Exception as exc:
        logger.debug("curiosity scorer LLM call failed: %s", exc)
        return 0.5


async def score_batch(
    hypotheses: List[Dict[str, Any]],
    session_context: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Score a list of hypotheses and return them sorted by score descending."""
    import asyncio

    scored = []
    scores = await asyncio.gather(*[score_hypothesis(h, session_context) for h in hypotheses])
    for hyp, score in zip(hypotheses, scores):
        scored.append({**hyp, "curiosity_score": score})
    return sorted(scored, key=lambda x: x.get("curiosity_score", 0), reverse=True)


async def allocate_budget(
    hypotheses: List[Dict[str, Any]],
    total_iterations: int,
) -> Dict[str, int]:
    """Proportionally allocate sandbox iterations to hypotheses by curiosity score.
    Hypotheses below _MIN_SCORE_THRESHOLD receive 0 iterations.
    """
    eligible = [h for h in hypotheses if h.get("curiosity_score", 0) >= _MIN_SCORE_THRESHOLD]
    if not eligible:
        return {}

    total_score = sum(h.get("curiosity_score", 0) for h in eligible)
    allocation: Dict[str, int] = {}

    remaining = total_iterations
    for i, hyp in enumerate(eligible):
        hyp_id = hyp.get("id", hyp.get("hypothesis", str(i))[:40])
        if i == len(eligible) - 1:
            allocation[hyp_id] = remaining
        else:
            share = h.get("curiosity_score", 0) / total_score if total_score else 0
            iterations = max(1, round(total_iterations * share))
            iterations = min(iterations, remaining)
            allocation[hyp_id] = iterations
            remaining -= iterations

    return allocation


def get_top_hypotheses(hypotheses: List[Dict[str, Any]], n: int = 3) -> List[Dict[str, Any]]:
    """Return top N hypotheses by curiosity_score for injection into next iteration."""
    scored = [h for h in hypotheses if "curiosity_score" in h]
    return sorted(scored, key=lambda x: x.get("curiosity_score", 0), reverse=True)[:n]

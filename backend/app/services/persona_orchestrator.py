"""T135/T136 — Multi-Persona Adversarial Orchestrator.

Five adversary personas run parallel Claude API calls each iteration,
generating diverse hypotheses that are pooled into the hypothesis market.
T136 collaborative_refinement synthesises top hypotheses across personas.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

PERSONAS: Dict[str, str] = {
    "paranoid_pentester": (
        "You are an extremely cautious pentester. You only act on confirmed evidence. "
        "Every hypothesis must cite specific observed behavior. Never speculate. "
        "Generate 2–3 hypotheses grounded in concrete indicators found so far."
    ),
    "ransomware_operator": (
        "You are a ransomware operator focused on maximum business impact. "
        "Prioritize: data exfiltration paths, privilege escalation, lateral movement, "
        "backup destruction vectors. Generate 2–3 hypotheses for highest-impact access."
    ),
    "nation_state_apt": (
        "You are a nation-state APT operator. Long-horizon, low-noise. "
        "Blend into normal traffic patterns. Prefer persistence mechanisms over immediate exploitation. "
        "Generate 2–3 hypotheses for stealthy, durable access."
    ),
    "insider_threat": (
        "You are a malicious insider with legitimate credentials. "
        "Focus on privilege escalation, accessing data beyond your role, and covering tracks. "
        "Generate 2–3 hypotheses exploiting authorized access pathways."
    ),
    "opportunistic": (
        "You are an opportunistic attacker. Take the easiest path. "
        "What can be exploited with zero customization and public tools in under 5 minutes? "
        "Generate 2–3 hypotheses for the lowest-effort, highest-yield attacks."
    ),
}


async def _generate_persona_hypotheses(
    persona_name: str,
    persona_prompt: str,
    session_context: Dict[str, Any],
    findings_summary: str,
) -> List[Dict[str, Any]]:
    """Run a single persona's hypothesis generation call."""
    import os
    import anthropic

    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        return []

    system = (
        f"{persona_prompt}\n\n"
        "Respond with a JSON array of hypothesis objects:\n"
        '[{"hypothesis": "...", "attack_class": "...", "evidence": "...", "next_probe": "..."}]\n'
        "Return ONLY valid JSON."
    )

    context_str = json.dumps({
        "target": session_context.get("target", "unknown"),
        "stack_pin": session_context.get("stack_pin", "unknown"),
        "phase": session_context.get("phase", "recon"),
        "findings": findings_summary[:1000],
    }, indent=2)

    try:
        client = anthropic.AsyncAnthropic(api_key=api_key)
        response = await client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=600,
            system=system,
            messages=[{"role": "user", "content": f"Session context:\n{context_str}\n\nGenerate hypotheses now."}],
        )
        raw = response.content[0].text.strip()
        hypotheses = json.loads(raw)
        if not isinstance(hypotheses, list):
            hypotheses = [hypotheses]
        for h in hypotheses:
            h["persona"] = persona_name
        return hypotheses
    except Exception as exc:
        logger.debug("persona %s hypothesis generation failed: %s", persona_name, exc)
        return []


async def _collaborative_refinement(
    top_hypotheses: List[Dict[str, Any]],
    session_context: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """T136 — Synthesise top hypothesis from each persona into a refined combined hypothesis."""
    import os
    import anthropic

    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key or not top_hypotheses:
        return None

    system = (
        "You are a synthesis analyst. Given hypotheses from multiple adversary personas, "
        "produce one refined hypothesis that combines the strongest evidence and most actionable next step.\n"
        'Return JSON: {"hypothesis": "...", "attack_class": "...", "evidence": "...", "next_probe": "...", "persona": "synthesis"}'
    )

    hyp_str = json.dumps(top_hypotheses, indent=2)[:2000]
    try:
        client = anthropic.AsyncAnthropic(api_key=api_key)
        response = await client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=300,
            system=system,
            messages=[{"role": "user", "content": f"Hypotheses to synthesize:\n{hyp_str}"}],
        )
        raw = response.content[0].text.strip()
        return json.loads(raw)
    except Exception as exc:
        logger.debug("collaborative_refinement failed: %s", exc)
        return None


async def run_persona_round(
    session_context: Dict[str, Any],
    findings_summary: str = "",
    enabled_personas: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Run all persona hypothesis generators in parallel and synthesise results.

    Returns a dict with per-persona hypotheses and a synthesised top hypothesis.
    """
    personas_to_run = {
        k: v for k, v in PERSONAS.items()
        if enabled_personas is None or k in enabled_personas
    }

    tasks = [
        _generate_persona_hypotheses(name, prompt, session_context, findings_summary)
        for name, prompt in personas_to_run.items()
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_hypotheses: List[Dict[str, Any]] = []
    per_persona: Dict[str, List[Dict[str, Any]]] = {}

    for persona_name, result in zip(personas_to_run.keys(), results):
        if isinstance(result, Exception):
            logger.debug("persona %s error: %s", persona_name, result)
            per_persona[persona_name] = []
        else:
            per_persona[persona_name] = result
            all_hypotheses.extend(result)

    # Pick top hypothesis per persona for synthesis
    top_per_persona = [hyps[0] for hyps in per_persona.values() if hyps]
    synthesis = await _collaborative_refinement(top_per_persona, session_context)
    if synthesis:
        all_hypotheses.append(synthesis)

    return {
        "per_persona": per_persona,
        "all_hypotheses": all_hypotheses,
        "synthesis": synthesis,
        "total_hypotheses": len(all_hypotheses),
    }

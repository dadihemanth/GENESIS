"""Goal compiler — T132.

Translates a free-text operator goal into a structured attack tree JSON.
The tree is injected into the system prompt at session start so the
orchestrator works toward a concrete objective instead of a generic scan.

Tree schema:
{
  "root": "compromise admin@target.example",
  "phases": [
    {
      "name": "reconnaissance",
      "sub_goals": [
        {"description": "enumerate all admin-accessible endpoints", "probe_hints": ["idor_probe", "gobuster_scan"]},
        ...
      ]
    },
    ...
  ],
  "open_questions": ["Is admin auth JWT-based or session-cookie-based?"]
}
"""
from __future__ import annotations

import json
import logging

logger = logging.getLogger(__name__)

_SYSTEM = """You are a senior penetration tester. Your task is to translate an operator's
natural-language goal into a structured attack tree in JSON format.

The JSON must follow exactly this schema (no extra keys):
{
  "root": "<the goal, verbatim>",
  "phases": [
    {
      "name": "<phase name: reconnaissance|service_analysis|vulnerability_scan|exploitation|reporting>",
      "sub_goals": [
        {
          "description": "<concrete action>",
          "probe_hints": ["<tool_name_1>", "<tool_name_2>"]
        }
      ]
    }
  ],
  "open_questions": ["<question about the target needed to progress>"]
}

Keep it concise: 2–4 phases, 2–4 sub_goals per phase, 1–3 open_questions.
Respond with ONLY the JSON object, no markdown fences, no prose."""


async def compile_goal(session_id: str, goal_text: str) -> dict:
    """Call Claude to compile a goal text into an attack tree dict.

    Falls back to a minimal default tree on any error so the session
    can proceed even if the LLM call fails.
    """
    try:
        from app.services.llm_providers import build_llm_client
        from app.database.postgres import AsyncSessionLocal
        from sqlalchemy import select as _select
        from app.models.session import AppSettings as _AppSettingsRow
        async with AsyncSessionLocal() as _db:
            _rows = await _db.execute(_select(_AppSettingsRow))
            _app_settings = {r.key: r.value for r in _rows.scalars().all()}
        client = build_llm_client(_app_settings)
        model_name = _app_settings.get("llm_model") or "claude-haiku-4-5-20251001"
        response = await client.messages.create(
            model=model_name,
            max_tokens=1024,
            system=_SYSTEM,
            messages=[{"role": "user", "content": f"Goal: {goal_text}"}],
        )
        raw = response.content[0].text.strip()
        # Strip accidental markdown fences
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        tree = json.loads(raw)
        logger.info("goal_compiler: compiled tree for session %s", session_id)
        return tree
    except Exception as exc:
        logger.warning("goal_compiler: LLM call failed (%s), using default tree", exc)
        return _default_tree(goal_text)


def _default_tree(goal_text: str) -> dict:
    return {
        "root": goal_text,
        "phases": [
            {
                "name": "reconnaissance",
                "sub_goals": [
                    {"description": "Enumerate open ports and services", "probe_hints": ["nmap_scan", "httpx_probe"]},
                    {"description": "Identify technology stack", "probe_hints": ["whatweb_identify", "behavioral_fingerprint"]},
                ],
            },
            {
                "name": "vulnerability_scan",
                "sub_goals": [
                    {"description": "Run automated vulnerability scan", "probe_hints": ["nuclei_scan", "nikto_scan"]},
                    {"description": "Test authentication endpoints", "probe_hints": ["idor_probe", "jwt_probe"]},
                ],
            },
            {
                "name": "exploitation",
                "sub_goals": [
                    {"description": "Attempt to achieve goal via discovered vulnerabilities", "probe_hints": ["ai_request_forge", "forge_runner"]},
                ],
            },
        ],
        "open_questions": [
            "What authentication mechanism protects the target?",
            "Are there any known CVEs for the detected stack version?",
        ],
    }

"""Inventory of GENESIS agents + the tool sets they have access to.

Read-only. Drives the Settings → Agents tab so an operator can see at a
glance how the multi-agent layout is composed and which tools each
agent is allowed to call. The single-agent (GENESIS) orchestrator is
also reported with its full union of tool access.
"""
from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter

from app.services.multi_agent_orchestrator import (
    _AGENT_TOOL_SETS,
    _GENERALIST_AGENTS,
    _SPECIALIST_AGENTS,
)

router = APIRouter()


_AGENT_DESCRIPTIONS: Dict[str, str] = {
    "recon":      "Maps the attack surface — port discovery, DNS, subdomains, OSINT.",
    "analyst":    "Identifies tech stack, WAF, TLS posture, framework signatures.",
    "exploit":    "Drives PoC verification — sqlmap, nuclei, JWT/IDOR/CORS probes.",
    "code":       "Static analysis on pulled artifacts — semgrep, bandit, decompile.",
    "crypto":     "T22 specialist — padding/RSA/ECDSA/JWT confusion attacks.",
    "auth":       "T22 specialist — OAuth/SAML/session-handling weaknesses.",
    "reveng":     "T22 specialist — binary decompile, fuzz, instrument, symbolic exec.",
    "exploitdev": "T22 specialist — chain crashes into PoCs, custom payload forging.",
    "network":    "T22 specialist — multi-host pivoting, AD/Kerberos enumeration.",
}

_AGENT_PHASE: Dict[str, str] = {
    "recon":      "phase-1",
    "analyst":    "phase-1",
    "exploit":    "phase-2",
    "code":       "phase-2",
    "crypto":     "phase-2 (conditional)",
    "auth":       "phase-2 (conditional)",
    "reveng":     "phase-2 (conditional)",
    "exploitdev": "phase-2 (conditional)",
    "network":    "phase-2 (conditional)",
}


@router.get("")
async def list_agents() -> Dict[str, Any]:
    """Return the agent roster + their tool sets."""
    agents: List[Dict[str, Any]] = []
    for name, tools in _AGENT_TOOL_SETS.items():
        kind = (
            "generalist" if name in _GENERALIST_AGENTS
            else "specialist" if name in _SPECIALIST_AGENTS
            else "other"
        )
        agents.append({
            "name": name,
            "kind": kind,
            "phase": _AGENT_PHASE.get(name, "unknown"),
            "description": _AGENT_DESCRIPTIONS.get(name, ""),
            "tool_count": len(tools),
            "tools": list(tools),
        })

    # Single-agent ("solo GENESIS") is reported separately so the UI can show
    # it alongside the multi-agent roster. It has access to the union.
    solo_tools = sorted({t for ts in _AGENT_TOOL_SETS.values() for t in ts})
    solo = {
        "name": "genesis",
        "kind": "solo",
        "phase": "all",
        "description": "Single-agent mode — one Opus instance with the full tool union.",
        "tool_count": len(solo_tools),
        "tools": solo_tools,
    }

    return {
        "agents": agents,
        "solo": solo,
        "totals": {
            "generalists": sum(1 for a in agents if a["kind"] == "generalist"),
            "specialists": sum(1 for a in agents if a["kind"] == "specialist"),
            "agents_total": len(agents),
            "tools_total": len(solo_tools),
        },
    }

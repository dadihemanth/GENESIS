"""v8 — SessionSupervisor: dispatches agent directives from judge gap list.

Reads the gap_list from a SessionJudge verdict and pushes targeted Redis
directives to specific subagents. SubAgents poll Redis each iteration via
_build_directive_injection() (consumed-once LPOP semantics).

Redis key pattern:
  genesis:session:{session_id}:supervisor_directives:{agent_type}
  → Redis List  (RPUSH to write, LPOP to consume)
  → TTL = 3600s (session-scoped; resets on each RPUSH)
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Awaitable, Dict, List, Optional

logger = logging.getLogger(__name__)

PublishFn = Callable[[str, Dict[str, Any]], Awaitable[None]]

_DIRECTIVE_KEY_TMPL = "genesis:session:{session_id}:supervisor_directives:{agent_type}"
_DIRECTIVE_TTL = 3600  # 1 hour, same scope as shared_findings

# Fallback: attack class → best-fit agent types when the judge omits target_agents
_CLASS_TO_AGENT: Dict[str, List[str]] = {
    "recon_port_scan":          ["recon"],
    "recon_web_enum":           ["recon", "exploit"],
    "recon_subdomain":          ["recon"],
    "recon_fingerprint":        ["analyst"],
    "recon_osint":              ["recon"],
    "static_analysis":          ["code"],
    "binary_analysis":          ["reveng", "code"],
    "payload_construction":     ["exploit", "payload"],
    "crypto_analysis":          ["crypto"],
    "deserialization":          ["exploit"],
    "http_delivery":            ["exploit"],
    "browser_delivery":         ["analyst"],
    "protocol_delivery":        ["analyst", "exploit"],
    "upload_delivery":          ["exploit"],
    "ssrf_delivery":            ["exploit"],
    "injection":                ["exploit"],
    "xss":                      ["exploit"],
    "auth_bypass":              ["auth"],
    "idor_access_control":      ["exploit"],
    "ssti_rce":                 ["exploit"],
    "deserialization_exec":     ["exploit", "reveng"],
    "smuggling":                ["analyst", "exploit"],
    "ad_exploitation":          ["network"],
    "persistence_hypothesis":   ["exploit"],
    "privilege_escalation":     ["exploit"],
    "c2_simulation":            ["exploit"],
    "exfil_channel":            ["network"],
    "data_exfil":               ["network"],
    "lateral_movement":         ["network"],
    "crown_jewel_access":       ["network"],
    "killchain_exec":           ["network"],
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SessionSupervisor:
    """Stateless class — all methods are static."""

    @staticmethod
    async def dispatch_from_verdict(
        session_id: str,
        verdict: Dict[str, Any],
        publish_fn: Optional[PublishFn] = None,
        max_directives: int = 5,
    ) -> List[Dict[str, Any]]:
        """Push directives for the top-N gaps in a judge verdict.

        Returns the list of directive payloads actually dispatched.
        Silently no-ops on any Redis failure so the orchestrator is never blocked.
        """
        gap_list: List[Dict[str, Any]] = verdict.get("gap_list") or []
        if not gap_list:
            return []

        verdict_id = verdict.get("_id", "")
        round_triggered_by = verdict.get("round_idx", -1)
        dispatched: List[Dict[str, Any]] = []

        for gap in gap_list[:max_directives]:
            attack_class = gap.get("class", "")
            phase = gap.get("phase", "")
            directive_text = gap.get("directive", "")
            rank = gap.get("rank", len(dispatched) + 1)

            # Judge provides target_agents; fall back to class map
            target_agents: List[str] = gap.get("target_agents") or []
            if not target_agents:
                target_agents = _CLASS_TO_AGENT.get(attack_class, ["exploit"])

            for agent_type in target_agents:
                directive_id = f"dir-{uuid.uuid4().hex[:12]}"
                payload: Dict[str, Any] = {
                    "directive_id": directive_id,
                    "session_id": session_id,
                    "agent_type": agent_type,
                    "phase": phase,
                    "attack_class": attack_class,
                    "instruction": directive_text,
                    "priority": rank,
                    "created_at": _now_iso(),
                }

                await SessionSupervisor.push_directive(session_id, agent_type, payload)
                dispatched.append(payload)

                if publish_fn:
                    try:
                        await publish_fn(session_id, {
                            "type": "supervisor_directive_dispatched",
                            "data": {
                                "agent_type": agent_type,
                                "phase": phase,
                                "attack_class": attack_class,
                                "directive_id": directive_id,
                                "priority": rank,
                            },
                            "timestamp": _now_iso(),
                        })
                    except Exception as pub_exc:
                        logger.debug("[SUPERVISOR] publish failed (non-fatal): %s", pub_exc)

        if dispatched:
            await SessionSupervisor._persist_to_mongo(
                session_id=session_id,
                verdict_id=verdict_id,
                round_triggered_by=round_triggered_by,
                directives=dispatched,
            )
            logger.info(
                "[SUPERVISOR] session=%s dispatched %d directives from verdict=%s",
                session_id, len(dispatched), verdict_id,
            )

        return dispatched

    @staticmethod
    async def push_directive(
        session_id: str,
        agent_type: str,
        directive: Dict[str, Any],
    ) -> None:
        """RPUSH one directive JSON onto the agent's Redis list; refresh TTL."""
        try:
            from app.database.redis_client import get_redis
            redis = await get_redis()
            key = _DIRECTIVE_KEY_TMPL.format(
                session_id=session_id, agent_type=agent_type
            )
            await redis.rpush(key, json.dumps(directive, default=str))
            await redis.expire(key, _DIRECTIVE_TTL)
        except Exception as exc:
            logger.debug("[SUPERVISOR] push_directive failed (non-fatal): %s", exc)

    @staticmethod
    async def pop_directive(
        session_id: str,
        agent_type: str,
    ) -> Optional[Dict[str, Any]]:
        """LPOP one directive for this agent. Consumed-once; returns None if empty."""
        try:
            from app.database.redis_client import get_redis
            redis = await get_redis()
            key = _DIRECTIVE_KEY_TMPL.format(
                session_id=session_id, agent_type=agent_type
            )
            raw = await redis.lpop(key)
            if not raw:
                return None
            directive = json.loads(raw)
            # Best-effort: mark consumed_at in MongoDB
            try:
                from app.database.mongodb import get_supervisor_directives_collection
                col = get_supervisor_directives_collection()
                await col.update_one(
                    {"_id": directive.get("directive_id")},
                    {"$set": {"consumed_at": datetime.now(timezone.utc)}},
                )
            except Exception:
                pass
            return directive
        except Exception as exc:
            logger.debug("[SUPERVISOR] pop_directive failed (non-fatal): %s", exc)
            return None

    @staticmethod
    async def _persist_to_mongo(
        session_id: str,
        verdict_id: str,
        round_triggered_by: int,
        directives: List[Dict[str, Any]],
    ) -> None:
        """Persist dispatched directives to the supervisor_directives collection."""
        try:
            from app.database.mongodb import get_supervisor_directives_collection
            col = get_supervisor_directives_collection()
            docs = [
                {
                    "_id": d["directive_id"],
                    "session_id": session_id,
                    "round_triggered_by": round_triggered_by,
                    "verdict_id": verdict_id,
                    "agent_type": d["agent_type"],
                    "phase": d["phase"],
                    "attack_class": d["attack_class"],
                    "instruction": d["instruction"],
                    "priority": d["priority"],
                    "created_at": datetime.now(timezone.utc),
                    "consumed_at": None,
                    "consumed_by_iteration": None,
                }
                for d in directives
            ]
            if docs:
                await col.insert_many(docs, ordered=False)
        except Exception as exc:
            logger.debug("[SUPERVISOR] persist failed (non-fatal): %s", exc)

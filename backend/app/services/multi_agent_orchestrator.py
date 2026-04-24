from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional

from app.services.mcp_client import MCPClient

logger = logging.getLogger(__name__)

_SHARED_FINDINGS_KEY_TMPL = "genesis:session:{session_id}:shared_findings"
_SHARED_FINDINGS_MAX = 200  # cap list length to bound memory
_SHARED_FINDINGS_TTL = 7200  # 2 hours — matches typical session budget

# Tool subsets assigned to each specialized agent
_AGENT_TOOL_SETS: Dict[str, List[str]] = {
    "recon": [
        "nmap_scan", "masscan_scan", "amass_enum", "subfinder_discover",
        "dnsrecon_enumerate", "harvester_gather", "httpx_probe",
    ],
    "analyst": [
        "whatweb_identify", "wafw00f_detect", "sslscan_check",
        "curl_probe", "openssl_check", "wpscan_scan",
        "cache_probe", "http_smuggling_probe",
    ],
    "exploit": [
        "nuclei_scan", "nikto_scan", "sqlmap_test", "xsstrike_test",
        "commix_test", "gobuster_scan", "ffuf_fuzz", "feroxbuster_scan",
        "arjun_discover", "payload_crafter",
        "idor_probe", "cors_probe", "jwt_probe", "graphql_probe",
        "ssti_detect", "nosql_probe", "prototype_pollution_probe", "oauth_probe",
    ],
    "code": [
        "semgrep_scan", "bandit_scan", "binary_analyzer", "code_pattern_search",
    ],
}

_SHARED_USAGE_HINT = (
    "\nYou share a Redis list with the other GENESIS agents for runtime coordination. "
    "When you discover something another agent can use (open port + service, live URL/endpoint, "
    "detected framework/CMS, WAF verdict, leaked credential, auth endpoint, interesting header), "
    "emit a JSON block of the form "
    "{{\"SHARED_FINDING\": {{\"kind\": \"endpoint|port|tech|waf|cred|header|path|other\", "
    "\"value\": \"...\", \"context\": \"short note\"}}}} "
    "so the platform can broadcast it. Consume PRIOR_PHASE_FINDINGS and any SHARED_FINDINGS already "
    "in your initial context before planning your own tool calls — reuse, do not re-enumerate."
)

_AGENT_PROMPTS: Dict[str, str] = {
    "recon": (
        "You are the GENESIS Recon Agent. Your sole focus is network and DNS reconnaissance. "
        "Enumerate hosts, ports, subdomains, and services for target {target}. "
        "Use: nmap_scan (all ports), masscan_scan (fast sweep), subfinder_discover, amass_enum, "
        "dnsrecon_enumerate, harvester_gather (passive OSINT), httpx_probe (web service fingerprint). "
        "Emit TOPOLOGY_UPDATE JSON blocks whenever you discover a new host or service. "
        "When done, emit a JSON block: {{\"RECON_COMPLETE\": true, \"findings\": <summary>}}"
        + _SHARED_USAGE_HINT
    ),
    "analyst": (
        "You are the GENESIS Analyst Agent. You perform deep service analysis on target {target}. "
        "Use: whatweb_identify, wafw00f_detect, sslscan_check, openssl_check, curl_probe, wpscan_scan. "
        "Identify: web frameworks, CMS, WAF presence, TLS weaknesses, interesting headers. "
        "When done, emit: {{\"ANALYST_COMPLETE\": true, \"findings\": <summary>}}"
        + _SHARED_USAGE_HINT
    ),
    "exploit": (
        "You are the GENESIS Exploit Agent. You test for vulnerabilities on target {target}. "
        "Use: nuclei_scan (templates), nikto_scan, sqlmap_test, xsstrike_test, commix_test, "
        "gobuster_scan / feroxbuster_scan / ffuf_fuzz (directory/parameter discovery), payload_crafter. "
        "For each confirmed vulnerability, emit a VULNERABILITY JSON block with all required fields "
        "including attack_chain_id, chain_position, mitre_techniques, exploit_code, patch_code, "
        "and evidence_for. Prefer endpoints surfaced via PRIOR_PHASE_FINDINGS or SHARED_FINDINGS "
        "over re-discovering them yourself. "
        "When done, emit: {{\"EXPLOIT_COMPLETE\": true, \"vuln_count\": <n>}}"
        + _SHARED_USAGE_HINT
    ),
    "code": (
        "You are the GENESIS Code Analysis Agent. You perform static analysis on downloadable "
        "source code or binaries from target {target}. "
        "Use: semgrep_scan, bandit_scan, binary_analyzer, code_pattern_search. "
        "Look for: hardcoded secrets, injection sinks, weak crypto, unsafe deserialization. "
        "When done, emit: {{\"CODE_COMPLETE\": true, \"findings\": <summary>}}"
        + _SHARED_USAGE_HINT
    ),
}


def _extract_shared_findings(text: str) -> List[Dict[str, Any]]:
    """Parse all {"SHARED_FINDING": {...}} blocks from an assistant text output."""
    out: List[Dict[str, Any]] = []
    marker = '"SHARED_FINDING"'
    pos = 0
    while True:
        idx = text.find(marker, pos)
        if idx == -1:
            break
        start = text.rfind("{", 0, idx)
        if start == -1:
            pos = idx + len(marker)
            continue
        depth = 0
        i = start
        in_string = False
        escape_next = False
        while i < len(text):
            ch = text[i]
            if escape_next:
                escape_next = False
            elif ch == "\\" and in_string:
                escape_next = True
            elif ch == '"':
                in_string = not in_string
            elif not in_string:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            outer = json.loads(text[start : i + 1])
                            data = outer.get("SHARED_FINDING", {})
                            if isinstance(data, dict) and data.get("value"):
                                out.append(data)
                        except Exception:
                            pass
                        pos = i + 1
                        break
            i += 1
        else:
            pos = idx + len(marker)
    return out


async def _publish_shared_finding(
    session_id: str, agent_type: str, finding: Dict[str, Any]
) -> None:
    """Push a SHARED_FINDING into the per-session Redis list (capped + TTL)."""
    try:
        from app.database.redis_client import get_redis
        redis = await get_redis()
        key = _SHARED_FINDINGS_KEY_TMPL.format(session_id=session_id)
        payload = json.dumps({
            "from_agent": agent_type,
            "kind": str(finding.get("kind", "other"))[:20],
            "value": str(finding.get("value", ""))[:500],
            "context": str(finding.get("context", ""))[:500],
        })
        await redis.rpush(key, payload)
        await redis.ltrim(key, -_SHARED_FINDINGS_MAX, -1)
        await redis.expire(key, _SHARED_FINDINGS_TTL)
    except Exception as exc:
        logger.debug("Shared finding publish failed: %s", exc)


async def _read_shared_findings(session_id: str) -> List[Dict[str, Any]]:
    """Read the current shared-findings list for a session."""
    try:
        from app.database.redis_client import get_redis
        redis = await get_redis()
        key = _SHARED_FINDINGS_KEY_TMPL.format(session_id=session_id)
        raw_list = await redis.lrange(key, 0, -1)
        out: List[Dict[str, Any]] = []
        for raw in raw_list:
            try:
                out.append(json.loads(raw))
            except Exception:
                continue
        return out
    except Exception as exc:
        logger.debug("Shared findings read failed: %s", exc)
        return []


def _format_prior_findings_block(prior: Optional[Dict[str, Any]]) -> str:
    """Render a compact PRIOR_PHASE_FINDINGS JSON block for a Phase 2 agent seed."""
    if not prior:
        return ""
    try:
        compact = json.dumps(prior, default=str)[:4000]
    except Exception:
        compact = str(prior)[:4000]
    return (
        "PRIOR_PHASE_FINDINGS (from recon + analyst agents — reuse these, do NOT re-enumerate):\n"
        f"{compact}"
    )


class SubAgent:
    def __init__(
        self,
        agent_type: str,
        session_id: str,
        target: str,
        publish_fn: Any,
        save_vuln_fn: Any,
        store_thought_fn: Any,
        store_deep_thought_fn: Any,
        prior_findings: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.agent_type = agent_type
        self.session_id = session_id
        self.target = target
        self._publish = publish_fn
        self._save_vuln = save_vuln_fn
        self._store_thought = store_thought_fn
        self._store_deep_thought = store_deep_thought_fn
        self._tool_names = _AGENT_TOOL_SETS[agent_type]
        self._mcp = MCPClient(timeout=300.0)
        self._prior_findings = prior_findings
        self._result_summary: Dict[str, Any] = {}
        # Track already-seen shared-findings signatures so we don't
        # re-inject the same item on every iteration of the inner loop.
        self._consumed_shared_sigs: set = set()

    def _system_prompt(self) -> str:
        return _AGENT_PROMPTS[self.agent_type].format(target=self.target)

    @property
    def result_summary(self) -> Dict[str, Any]:
        return self._result_summary

    def _tool_schemas(self) -> List[Dict[str, Any]]:
        # Import from the main orchestrator's schema list
        from app.services.ai_orchestrator import TOOL_SCHEMAS
        return [s for s in TOOL_SCHEMAS if s["name"] in self._tool_names]

    async def _build_shared_findings_refresh(self) -> Optional[str]:
        """Produce a refresh text block with any new shared findings this agent hasn't yet seen."""
        current = await _read_shared_findings(self.session_id)
        if not current:
            return None
        fresh: List[Dict[str, Any]] = []
        for item in current:
            # Ignore findings the current agent itself published.
            if item.get("from_agent") == self.agent_type:
                continue
            sig = f"{item.get('from_agent')}::{item.get('kind')}::{item.get('value')}"
            if sig in self._consumed_shared_sigs:
                continue
            self._consumed_shared_sigs.add(sig)
            fresh.append(item)
        if not fresh:
            return None
        try:
            payload = json.dumps(fresh, default=str)[:3000]
        except Exception:
            payload = str(fresh)[:3000]
        return (
            "SHARED_FINDINGS (new since last turn — reuse these, do NOT re-enumerate):\n"
            f"{payload}"
        )

    async def run(self) -> Dict[str, Any]:
        import anthropic
        from app.config import settings
        from app.services.ai_orchestrator import (
            _now_iso,
            _extract_vulnerability_blocks,
            _max_tokens_for_model,
            _ANTHROPIC_TIMEOUT_SECONDS,
        )

        client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
        messages: List[Dict[str, Any]] = []
        iteration = 0
        max_iter = 20
        result_summary: Dict[str, Any] = {}
        # Derive max_tokens from the model family so it always exceeds the
        # extended-thinking budget (Anthropic rejects the call otherwise) and
        # stays below the Anthropic SDK's non-streaming timeout threshold.
        agent_max_tokens = _max_tokens_for_model(settings.claude_model)
        # Budget must be strictly < max_tokens; leave >=2048 for actual output.
        agent_thinking_budget = min(5000, max(1024, agent_max_tokens - 2048))

        # Seed Phase 2 agents with structured prior-phase findings.
        seed_text_parts: List[str] = []
        prior_block = _format_prior_findings_block(self._prior_findings)
        if prior_block:
            seed_text_parts.append(prior_block)
        initial_shared = await self._build_shared_findings_refresh()
        if initial_shared:
            seed_text_parts.append(initial_shared)
        if seed_text_parts:
            messages.append({
                "role": "user",
                "content": "\n\n".join(seed_text_parts),
            })

        await self._publish(self.session_id, {
            "type": "agent_start",
            "data": {
                "agent_type": self.agent_type,
                "target": self.target,
                "seeded_with_prior": bool(prior_block),
            },
            "timestamp": _now_iso(),
        })

        while iteration < max_iter:
            iteration += 1
            try:
                response = await client.messages.create(
                    model=settings.claude_model,
                    max_tokens=agent_max_tokens,
                    thinking={"type": "enabled", "budget_tokens": agent_thinking_budget},
                    system=self._system_prompt(),
                    tools=self._tool_schemas(),
                    messages=messages,
                    timeout=_ANTHROPIC_TIMEOUT_SECONDS,
                )
            except Exception as exc:
                logger.error("SubAgent[%s] API error: %s", self.agent_type, exc)
                try:
                    from app.services.ai_orchestrator import AIOrchestrator
                    await AIOrchestrator()._record_error(
                        self.session_id,
                        "subagent_api",
                        exc,
                        iteration=iteration,
                        context={
                            "agent_type": self.agent_type,
                            "model": settings.claude_model,
                        },
                    )
                except Exception as inner:
                    logger.debug("subagent error record failed: %s", inner)
                break

            # Collect content
            text_parts: List[str] = []
            tool_calls: List[Dict[str, Any]] = []
            done = False

            for block in response.content:
                btype = getattr(block, "type", None)
                if btype == "thinking":
                    await self._store_deep_thought(
                        self.session_id,
                        f"[{self.agent_type}] {block.thinking}",
                        iteration,
                    )
                elif btype == "text":
                    text = block.text
                    text_parts.append(text)
                    # Extract vulnerabilities
                    for vuln_data in _extract_vulnerability_blocks(text):
                        await self._save_vuln(self.session_id, vuln_data)
                    # Publish any SHARED_FINDING blocks this agent emitted
                    for finding in _extract_shared_findings(text):
                        await _publish_shared_finding(self.session_id, self.agent_type, finding)
                        await self._publish(self.session_id, {
                            "type": "shared_finding",
                            "data": {
                                "agent": self.agent_type,
                                "kind": finding.get("kind", "other"),
                                "value": str(finding.get("value", ""))[:300],
                                "context": str(finding.get("context", ""))[:300],
                            },
                            "timestamp": _now_iso(),
                        })
                    # Check completion signal
                    completion_key = f"{self.agent_type.upper()}_COMPLETE"
                    if completion_key in text:
                        try:
                            for chunk in text.split("{"):
                                if completion_key in chunk:
                                    obj = json.loads("{" + chunk.split("}")[0] + "}")
                                    result_summary = obj
                                    done = True
                                    break
                        except Exception:
                            done = True
                elif btype == "tool_use":
                    tool_calls.append({"name": block.name, "id": block.id, "input": block.input})

            # Store thought
            full_text = "\n".join(text_parts)
            if full_text.strip():
                await self._store_thought(self.session_id, full_text, self.agent_type, iteration)

            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "end_turn" or done:
                break

            # Execute tool calls, then attach any fresh shared findings.
            if tool_calls:
                tool_results: List[Dict[str, Any]] = []
                for tc in tool_calls:
                    tool_result = await self._mcp.execute_tool(tc["name"], tc["input"])
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tc["id"],
                        "content": tool_result.get("output", ""),
                    })
                    await self._publish(self.session_id, {
                        "type": "tool_output",
                        "data": {
                            "agent": self.agent_type,
                            "tool_name": tc["name"],
                            "output": tool_result.get("output", "")[:2000],
                        },
                        "timestamp": _now_iso(),
                    })
                content_blocks: List[Dict[str, Any]] = list(tool_results)
                refresh = await self._build_shared_findings_refresh()
                if refresh:
                    content_blocks.append({"type": "text", "text": refresh})
                messages.append({"role": "user", "content": content_blocks})
            else:
                break

        await self._publish(self.session_id, {
            "type": "agent_complete",
            "data": {"agent_type": self.agent_type, "summary": result_summary},
            "timestamp": _now_iso(),
        })

        self._result_summary = result_summary
        return result_summary


class MultiAgentOrchestrator:
    """
    Runs parallel specialized sub-agents (Recon, Analyst, Exploit, Code) for a session.
    Called by AIOrchestrator when session.agent_mode == "multi_agent".
    """

    def __init__(
        self,
        session_id: str,
        target: str,
        publish_fn: Any,
        save_vuln_fn: Any,
        store_thought_fn: Any,
        store_deep_thought_fn: Any,
    ) -> None:
        self.session_id = session_id
        self.target = target
        self._publish = publish_fn
        self._save_vuln = save_vuln_fn
        self._store_thought = store_thought_fn
        self._store_deep_thought = store_deep_thought_fn

    async def run(self) -> None:
        from app.services.ai_orchestrator import _now_iso

        await self._publish(self.session_id, {
            "type": "multi_agent_start",
            "data": {"agents": list(_AGENT_TOOL_SETS.keys()), "target": self.target},
            "timestamp": _now_iso(),
        })

        def _make_agent(
            agent_type: str, prior: Optional[Dict[str, Any]] = None
        ) -> SubAgent:
            return SubAgent(
                agent_type=agent_type,
                session_id=self.session_id,
                target=self.target,
                publish_fn=self._publish,
                save_vuln_fn=self._save_vuln,
                store_thought_fn=self._store_thought,
                store_deep_thought_fn=self._store_deep_thought,
                prior_findings=prior,
            )

        # Phase 1: Recon + Analyst run in parallel (no prior context)
        recon_agent = _make_agent("recon")
        analyst_agent = _make_agent("analyst")
        recon_result, analyst_result = await asyncio.gather(
            recon_agent.run(), analyst_agent.run(), return_exceptions=True
        )
        logger.info("Phase 1 complete — recon=%s analyst=%s", recon_result, analyst_result)

        # Compile prior-phase findings for Phase 2 agents.
        prior_findings = await self._compile_prior_findings(recon_agent, analyst_agent)
        await self._publish(self.session_id, {
            "type": "phase_transition",
            "data": {
                "from_phase": "phase1_recon_analyst",
                "to_phase": "phase2_exploit_code",
                "prior_findings": prior_findings,
            },
            "timestamp": _now_iso(),
        })

        # Phase 2: Exploit + Code run in parallel, seeded with structured prior context.
        exploit_agent = _make_agent("exploit", prior=prior_findings)
        code_agent = _make_agent("code", prior=prior_findings)
        exploit_result, code_result = await asyncio.gather(
            exploit_agent.run(), code_agent.run(), return_exceptions=True
        )
        logger.info("Phase 2 complete — exploit=%s code=%s", exploit_result, code_result)

        await self._publish(self.session_id, {
            "type": "multi_agent_complete",
            "data": {
                "recon": str(recon_result),
                "analyst": str(analyst_result),
                "exploit": str(exploit_result),
                "code": str(code_result),
            },
            "timestamp": _now_iso(),
        })

    async def _compile_prior_findings(
        self,
        recon_agent: "SubAgent",
        analyst_agent: "SubAgent",
    ) -> Dict[str, Any]:
        """Build a compact structured findings dict for Phase 2 agents.

        Sources, in order of preference:
          (1) the agents' own completion summaries (RECON_COMPLETE / ANALYST_COMPLETE blocks)
          (2) shared-findings list accumulated in Redis during Phase 1
        """
        compiled: Dict[str, Any] = {
            "recon_summary": recon_agent.result_summary or {},
            "analyst_summary": analyst_agent.result_summary or {},
        }
        shared = await _read_shared_findings(self.session_id)
        if shared:
            by_kind: Dict[str, List[str]] = {}
            for item in shared:
                kind = str(item.get("kind", "other"))[:20]
                value = str(item.get("value", ""))[:300]
                if not value:
                    continue
                by_kind.setdefault(kind, [])
                if value not in by_kind[kind]:
                    by_kind[kind].append(value)
            compiled["shared_findings_by_kind"] = by_kind
        return compiled

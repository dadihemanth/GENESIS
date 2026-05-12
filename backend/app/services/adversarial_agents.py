"""T87 + T88 — adversarial agent pair and philosopher agent.

RedBlueDialectic (T87):
  Red proposes an attack hypothesis; blue counters it; red must defend or the
  hypothesis stake is reduced.  Two sequential LLM calls using the configured
  model.  Feeds results into hypothesis_market.

PhilosopherAgent (T88):
  Reads the session's anomaly log and asks "what bug class would explain all
  these anomalies?" — generates novel hypotheses from first principles rather
  than from known vulnerability patterns.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional

from app.database.mongodb import (
    get_adversarial_reasoning_collection,
    get_agent_thoughts_collection,
)
from app.services.hypothesis_market import submit_hypothesis

logger = logging.getLogger(__name__)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now_utc().isoformat()


# Type alias for the publish_session_message-compatible callable.
PublishFn = Callable[[str, Dict[str, Any]], Awaitable[None]]

_RED_SYSTEM = (
    "You are the RED AGENT in GENESIS v5 adversarial hypothesis synthesis. "
    "Your role is to propose a specific, testable attack hypothesis for the "
    "target described. Be concrete: name the attack class, the entry point, "
    "and why this target is likely vulnerable. "
    "Respond with JSON: {\"hypothesis\": \"...\", \"attack_class\": \"...\", "
    "\"entry_point\": \"...\", \"confidence\": 0.0–1.0}"
)

_BLUE_SYSTEM = (
    "You are the BLUE AGENT in GENESIS v5 adversarial hypothesis synthesis. "
    "Your role is to challenge the red agent's attack hypothesis. "
    "Find weaknesses in the reasoning, missing mitigations, or why the target "
    "is unlikely to be vulnerable. Be specific and technical. "
    "Respond with JSON: {\"challenge\": \"...\", \"mitigations_found\": [...], "
    "\"kills_hypothesis\": true|false}"
)

_PHILOSOPHER_SYSTEM = (
    "You are the PHILOSOPHER AGENT in GENESIS v5. "
    "You read a list of anomalies observed during a security scan and reason "
    "from first principles about what *underlying bug class* could explain them. "
    "Do NOT reference known CVEs — reason about the architecture and behavior. "
    "Respond with JSON: {\"bug_class\": \"...\", \"explanation\": \"...\", "
    "\"novel_hypotheses\": [{\"text\": \"...\", \"confidence\": 0.0–1.0}]}"
)

_INSIDER_SYSTEM = (
    "You are the INSIDER-THREAT AGENT in GENESIS v7. "
    "Role-play an authenticated user (employee, contractor, low-privilege "
    "service account) who already has legitimate access. Propose attacks "
    "that abuse that access — privilege escalation, data exfiltration via "
    "permitted channels, lateral movement using already-issued tokens, "
    "audit-log tampering, and credential reuse across internal services. "
    "Focus on attacks that DO NOT require breaking into the perimeter. "
    "Respond with JSON: {\"persona\": \"insider\", \"attack_class\": \"...\", "
    "\"trust_level_required\": \"any-employee|specific-role|service-account\", "
    "\"explanation\": \"...\", "
    "\"novel_hypotheses\": [{\"text\": \"...\", \"confidence\": 0.0–1.0}]}"
)

_NATION_STATE_SYSTEM = (
    "You are the NATION-STATE / APT AGENT in GENESIS v7. "
    "Role-play a well-resourced advanced-persistent-threat actor with months "
    "of patience, supply-chain access, zero-day inventory, and strict "
    "stealth requirements. Propose attacks the agent would otherwise miss "
    "because the cost-to-detect is high or the timeline is long: dormant "
    "implants, BIOS / firmware persistence, golden-ticket-grade credential "
    "harvesting, supply-chain compromise of build pipelines, vendored "
    "library typo-squatting, multi-step low-and-slow lateral movement that "
    "stays under DLP / EDR thresholds, identity-provider abuse. "
    "Respond with JSON: {\"persona\": \"nation_state\", \"attack_class\": \"...\", "
    "\"timeline\": \"days|weeks|months\", \"stealth_priority\": \"high|medium|low\", "
    "\"explanation\": \"...\", "
    "\"novel_hypotheses\": [{\"text\": \"...\", \"confidence\": 0.0–1.0}]}"
)


class RedBlueDialectic:
    """T87 — two-agent adversarial hypothesis synthesis."""

    def __init__(self, client: Any, model: str) -> None:
        self._client = client
        self._model = model

    async def synthesize(
        self,
        session_id: str,
        target_context: str,
        max_pairs: int = 3,
        *,
        trigger: str = "seed",
        trigger_hypothesis_id: Optional[str] = None,
        publish_fn: Optional[PublishFn] = None,
    ) -> List[Dict[str, Any]]:
        """Run up to *max_pairs* red-blue exchanges for the target context.

        Persists the full red+blue transcript (raw + parsed) to the
        `adversarial_reasoning` Mongo collection per round, regardless of
        whether the hypothesis survives. Optionally publishes a WS event for
        each round so the frontend Adversarial tab can update live.

        Returns a list of accepted hypotheses (those that survived blue's
        challenge) — same shape as before for backward compatibility.
        """
        if self._client is None:
            return []

        accepted: List[Dict[str, Any]] = []
        col = get_adversarial_reasoning_collection()

        for round_idx in range(max_pairs):
            try:
                # --- Red agent proposes ---
                red_user = (
                    f"Round {round_idx + 1}. Target context:\n{target_context[:3000]}\n\n"
                    f"Previous accepted hypotheses: {[h['hypothesis'] for h in accepted]}\n"
                    "Propose a NEW, untested attack hypothesis."
                )
                red_resp = await self._client.messages.create(
                    model=self._model,
                    # 2048 lets reasoning-heavy models (GPT-5/o-series) keep
                    # ~1500 tokens for visible JSON after their internal
                    # reasoning consumes the front of the budget. 512 was
                    # producing empty content rounds for non-Claude models.
                    max_tokens=2048,
                    timeout=90.0,
                    system=_RED_SYSTEM,
                    messages=[{"role": "user", "content": red_user}],
                )
                try:
                    from app.services.llm_usage import record_llm_usage
                    await record_llm_usage(
                        session_id=session_id, iteration=0, source="red_agent",
                        model=self._model, response=red_resp,
                        publish_fn=publish_fn,
                    )
                except Exception:
                    pass
                red_text = _extract_text(red_resp)
                red_json = _parse_json(red_text)
                if not red_json or "hypothesis" not in red_json:
                    # Distinguish "model returned nothing" from "model returned
                    # text we couldn't parse" — they have different fixes
                    # (bump tokens vs adjust prompt).
                    red_verdict = "red_no_response" if not red_text else "parse_failed"
                    logger.warning(
                        "red_blue: red %s in round %d (text_len=%d)",
                        red_verdict, round_idx + 1, len(red_text),
                    )
                    doc = {
                        "_id": f"advrnd-{uuid.uuid4().hex[:12]}",
                        "session_id": str(session_id),
                        "kind": "red_blue",
                        "round": round_idx + 1,
                        "trigger": trigger,
                        "trigger_hypothesis_id": trigger_hypothesis_id,
                        "red": {"raw": red_text, "parsed": red_json or {}},
                        "blue": None,
                        "verdict": red_verdict,
                        "linked_hypothesis_id": None,
                        "created_at": _now_utc(),
                    }
                    try:
                        await col.insert_one(doc)
                    except Exception as exc:
                        logger.debug("adversarial_reasoning insert failed: %s", exc)
                    await _publish_round(publish_fn, session_id, doc)
                    continue

                hypothesis_text = red_json["hypothesis"]
                confidence = float(red_json.get("confidence", 0.5))

                # --- Blue agent challenges ---
                blue_user = (
                    f"Red agent's hypothesis:\n{hypothesis_text}\n\n"
                    f"Target context:\n{target_context[:1500]}"
                )
                # v7.x — isolate blue's API call so a content-filter 4xx
                # (Azure OpenAI's cyber_policy is the common culprit) doesn't
                # discard red's transcript. We persist the red half with
                # verdict="blue_blocked" so the operator sees what was
                # proposed even when blue couldn't engage.
                try:
                    blue_resp = await self._client.messages.create(
                        model=self._model,
                        max_tokens=2048,
                        timeout=90.0,
                        system=_BLUE_SYSTEM,
                        messages=[{"role": "user", "content": blue_user}],
                    )
                except Exception as blue_exc:
                    logger.warning(
                        "red_blue: blue agent failed in round %d (%s) — "
                        "persisting red half only",
                        round_idx + 1, blue_exc,
                    )
                    doc = {
                        "_id": f"advrnd-{uuid.uuid4().hex[:12]}",
                        "session_id": str(session_id),
                        "kind": "red_blue",
                        "round": round_idx + 1,
                        "trigger": trigger,
                        "trigger_hypothesis_id": trigger_hypothesis_id,
                        "red": {"raw": red_text, "parsed": red_json},
                        "blue": {
                            "raw": "",
                            "parsed": {},
                            "error": str(blue_exc)[:500],
                        },
                        "verdict": "blue_blocked",
                        "linked_hypothesis_id": None,
                        "confidence": confidence,
                        "created_at": _now_utc(),
                    }
                    try:
                        await col.insert_one(doc)
                    except Exception as exc:
                        logger.debug("adversarial_reasoning insert failed: %s", exc)
                    await _publish_round(publish_fn, session_id, doc)
                    continue
                try:
                    from app.services.llm_usage import record_llm_usage
                    await record_llm_usage(
                        session_id=session_id, iteration=0, source="blue_agent",
                        model=self._model, response=blue_resp,
                        publish_fn=publish_fn,
                    )
                except Exception:
                    pass
                blue_text = _extract_text(blue_resp)
                blue_json = _parse_json(blue_text)

                # 3-way verdict — empty/unparseable blue is NOT approval.
                # Previously a None blue_json defaulted to verdict='survives',
                # which let any unresponsive blue rubber-stamp red's hypothesis
                # straight into the market. Now we persist the round but
                # refuse to submit unverified hypotheses.
                linked_hypothesis_id: Optional[str] = None
                if not blue_text or not blue_json:
                    logger.warning(
                        "red_blue: blue response empty/unparseable in round %d "
                        "(text_len=%d, parsed=%s) — NOT submitting to market",
                        round_idx + 1, len(blue_text), bool(blue_json),
                    )
                    verdict = "no_response"
                elif bool(blue_json.get("kills_hypothesis", False)):
                    verdict = "killed"
                    confidence = max(0.05, confidence - 0.3)
                    logger.debug(
                        "red_blue: hypothesis killed by blue in round %d",
                        round_idx + 1,
                    )
                else:
                    verdict = "survives"
                    hyp = await submit_hypothesis(
                        session_id=session_id,
                        text=hypothesis_text,
                        proposer_agent="red_blue_dialectic",
                        hypothesis_type=red_json.get("attack_class", "generic"),
                        confidence_stake=confidence,
                    )
                    linked_hypothesis_id = hyp.get("hypothesis_id", "") or None
                    accepted.append({
                        **red_json,
                        "hypothesis_id": linked_hypothesis_id or "",
                        "round": round_idx + 1,
                    })

                # Persist the FULL round (red + blue raw + parsed + verdict)
                doc = {
                    "_id": f"advrnd-{uuid.uuid4().hex[:12]}",
                    "session_id": str(session_id),
                    "kind": "red_blue",
                    "round": round_idx + 1,
                    "trigger": trigger,
                    "trigger_hypothesis_id": trigger_hypothesis_id,
                    "red": {"raw": red_text, "parsed": red_json},
                    "blue": {"raw": blue_text, "parsed": blue_json or {}},
                    "verdict": verdict,
                    "linked_hypothesis_id": linked_hypothesis_id,
                    "confidence": confidence,
                    "created_at": _now_utc(),
                }
                try:
                    await col.insert_one(doc)
                except Exception as exc:
                    logger.debug("adversarial_reasoning insert failed: %s", exc)
                await _publish_round(publish_fn, session_id, doc)

            except Exception as exc:
                logger.debug("red_blue round %d failed: %s", round_idx + 1, exc)

        logger.info(
            "red_blue_dialectic: session=%s accepted=%d/%d",
            session_id, len(accepted), max_pairs,
        )
        return accepted


class PhilosopherAgent:
    """T88 — first-principles hypothesis generation from anomaly patterns."""

    def __init__(self, client: Any, model: str) -> None:
        self._client = client
        self._model = model

    async def generate(
        self,
        session_id: str,
        limit_anomalies: int = 20,
        *,
        publish_fn: Optional[PublishFn] = None,
    ) -> List[Dict[str, Any]]:
        """Read session anomalies and generate novel bug-class hypotheses.

        Persists the full philosopher transcript (anomalies fed in + raw LLM
        response + parsed bug_class + linked hypothesis IDs) to
        `adversarial_reasoning` so the operator can read the reasoning. Returns
        the list of submitted hypotheses (same shape as before).
        """
        if self._client is None:
            return []

        anomalies = await self._fetch_anomaly_summary(session_id, limit_anomalies)
        if not anomalies:
            return []

        col = get_adversarial_reasoning_collection()

        try:
            user_msg = (
                f"Session ID: {session_id}\n\n"
                f"Observed anomalies:\n{anomalies}\n\n"
                "What underlying bug class explains the pattern of these anomalies? "
                "Generate novel, first-principles hypotheses."
            )
            resp = await self._client.messages.create(
                model=self._model,
                max_tokens=2048,
                timeout=120.0,
                system=_PHILOSOPHER_SYSTEM,
                messages=[{"role": "user", "content": user_msg}],
            )
            try:
                from app.services.llm_usage import record_llm_usage
                await record_llm_usage(
                    session_id=session_id, iteration=0, source="philosopher",
                    model=self._model, response=resp,
                    publish_fn=publish_fn,
                )
            except Exception:
                pass
            text = _extract_text(resp)
            parsed = _parse_json(text)
            if not parsed:
                # Persist the failed-parse so the operator can see what came
                # back even when JSON extraction fell over.
                doc = {
                    "_id": f"advphil-{uuid.uuid4().hex[:12]}",
                    "session_id": str(session_id),
                    "kind": "philosopher",
                    "trigger": "anomaly_threshold",
                    "anomalies_summary": anomalies[:1500],
                    "raw": text,
                    "parsed": {},
                    "linked_hypothesis_ids": [],
                    "created_at": _now_utc(),
                }
                try:
                    await col.insert_one(doc)
                except Exception as exc:
                    logger.debug("adversarial_reasoning insert failed: %s", exc)
                await _publish_round(publish_fn, session_id, doc)
                return []

            novel = parsed.get("novel_hypotheses", [])
            stored: List[Dict[str, Any]] = []
            linked_ids: List[str] = []
            for item in novel[:5]:
                if not isinstance(item, dict) or "text" not in item:
                    continue
                hyp = await submit_hypothesis(
                    session_id=session_id,
                    text=item["text"],
                    proposer_agent="philosopher_agent",
                    hypothesis_type=parsed.get("bug_class", "novel"),
                    confidence_stake=float(item.get("confidence", 0.4)),
                )
                stored.append(hyp)
                hid = hyp.get("hypothesis_id")
                if hid:
                    linked_ids.append(str(hid))

            doc = {
                "_id": f"advphil-{uuid.uuid4().hex[:12]}",
                "session_id": str(session_id),
                "kind": "philosopher",
                "trigger": "anomaly_threshold",
                "anomalies_summary": anomalies[:1500],
                "raw": text,
                "parsed": parsed,
                "linked_hypothesis_ids": linked_ids,
                "created_at": _now_utc(),
            }
            try:
                await col.insert_one(doc)
            except Exception as exc:
                logger.debug("adversarial_reasoning insert failed: %s", exc)
            await _publish_round(publish_fn, session_id, doc)

            logger.info(
                "philosopher_agent: session=%s bug_class=%s hypotheses=%d",
                session_id, parsed.get("bug_class", "?"), len(stored),
            )
            return stored

        except Exception as exc:
            logger.warning("philosopher_agent failed: %s", exc)
            return []

    async def _fetch_anomaly_summary(self, session_id: str, limit: int) -> str:
        lines: List[str] = []
        try:
            coll = get_agent_thoughts_collection()
            cursor = coll.find({"session_id": session_id}).sort("timestamp", -1).limit(limit * 3)
            count = 0
            async for doc in cursor:
                content = str(doc.get("content", ""))[:200]
                if any(kw in content.lower() for kw in ["unexpected", "anomaly", "error", "differ", "mismatch"]):
                    lines.append(f"- {content}")
                    count += 1
                if count >= limit:
                    break
        except Exception as exc:
            logger.debug("anomaly fetch failed: %s", exc)
        return "\n".join(lines[:limit])


# ---------------------------------------------------------------------------
# v7.x — single-shot persona agents (insider, nation-state)
# ---------------------------------------------------------------------------

class _SinglePersonaAgent:
    """Shared base for the philosopher-pattern personas (insider, APT).

    Each generates ONE structured set of novel hypotheses per call, persists
    the full transcript to `adversarial_reasoning`, and submits the spawned
    hypotheses to the market. Subclasses override `_kind`, `_system_prompt`,
    `_user_prompt`, and `_proposer_agent`.
    """
    _kind: str = ""               # adversarial_reasoning.kind value
    _proposer_agent: str = ""     # hypothesis_market.proposer_agent value
    _system_prompt: str = ""

    def __init__(self, client: Any, model: str) -> None:
        self._client = client
        self._model = model

    def _user_prompt(self, *, session_id: str, target_context: str) -> str:
        raise NotImplementedError

    async def generate(
        self,
        session_id: str,
        target_context: str,
        *,
        publish_fn: Optional[PublishFn] = None,
    ) -> List[Dict[str, Any]]:
        if self._client is None:
            return []
        col = get_adversarial_reasoning_collection()
        try:
            user_msg = self._user_prompt(
                session_id=session_id, target_context=target_context,
            )
            resp = await self._client.messages.create(
                model=self._model,
                max_tokens=2048,
                timeout=120.0,
                system=self._system_prompt,
                messages=[{"role": "user", "content": user_msg}],
            )
            try:
                from app.services.llm_usage import record_llm_usage
                await record_llm_usage(
                    session_id=session_id, iteration=0,
                    source=self._kind, model=self._model, response=resp,
                    publish_fn=publish_fn,
                )
            except Exception:
                pass
            text = _extract_text(resp)
            parsed = _parse_json(text)
            if not parsed:
                doc = {
                    "_id": f"adv{self._kind[:3]}-{uuid.uuid4().hex[:12]}",
                    "session_id": str(session_id),
                    "kind": self._kind,
                    "trigger": "post_phase1",
                    "target_context": target_context[:1500],
                    "raw": text,
                    "parsed": {},
                    "linked_hypothesis_ids": [],
                    "created_at": _now_utc(),
                }
                try:
                    await col.insert_one(doc)
                except Exception:
                    pass
                await _publish_round(publish_fn, session_id, doc)
                return []
            novel = parsed.get("novel_hypotheses", [])
            stored: List[Dict[str, Any]] = []
            linked_ids: List[str] = []
            for item in (novel or [])[:5]:
                if not isinstance(item, dict) or "text" not in item:
                    continue
                hyp = await submit_hypothesis(
                    session_id=session_id,
                    text=item["text"],
                    proposer_agent=self._proposer_agent,
                    hypothesis_type=parsed.get("attack_class") or self._kind,
                    confidence_stake=float(item.get("confidence", 0.4)),
                )
                stored.append(hyp)
                hid = hyp.get("hypothesis_id")
                if hid:
                    linked_ids.append(str(hid))
            doc = {
                "_id": f"adv{self._kind[:3]}-{uuid.uuid4().hex[:12]}",
                "session_id": str(session_id),
                "kind": self._kind,
                "trigger": "post_phase1",
                "target_context": target_context[:1500],
                "raw": text,
                "parsed": parsed,
                "linked_hypothesis_ids": linked_ids,
                "created_at": _now_utc(),
            }
            try:
                await col.insert_one(doc)
            except Exception:
                pass
            await _publish_round(publish_fn, session_id, doc)
            logger.info(
                "%s: session=%s hypotheses=%d",
                self._kind, session_id, len(stored),
            )
            return stored
        except Exception as exc:
            logger.warning("%s failed: %s", self._kind, exc)
            return []


class InsiderThreatAgent(_SinglePersonaAgent):
    _kind = "insider"
    _proposer_agent = "insider_threat_agent"
    _system_prompt = _INSIDER_SYSTEM

    def _user_prompt(self, *, session_id: str, target_context: str) -> str:
        return (
            f"Session: {session_id}\n\n"
            f"Target context (recon + service inventory):\n{target_context[:2500]}\n\n"
            "From the perspective of an authenticated insider, propose 3–5 "
            "novel hypotheses about how the target could be abused without "
            "needing to break in from outside."
        )


class NationStateAgent(_SinglePersonaAgent):
    _kind = "nation_state"
    _proposer_agent = "nation_state_agent"
    _system_prompt = _NATION_STATE_SYSTEM

    def _user_prompt(self, *, session_id: str, target_context: str) -> str:
        return (
            f"Session: {session_id}\n\n"
            f"Target context (recon + observed defences):\n{target_context[:2500]}\n\n"
            "From the perspective of a patient, well-resourced APT actor, "
            "propose 3–5 novel hypotheses that exploit timeline, "
            "stealth, and supply-chain leverage. Avoid noisy short-horizon "
            "exploits — those are the orchestrator's job."
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_text(resp: Any) -> str:
    text = ""
    for block in (resp.content or []):
        if hasattr(block, "text") and block.text:
            text += block.text
    return text.strip()


def _parse_json(text: str) -> Optional[Dict[str, Any]]:
    text = text.strip()
    if text.startswith("```"):
        parts = text.split("```", 2)
        text = parts[1] if len(parts) > 1 else text
        if text.lower().startswith("json"):
            text = text[4:]
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        return json.loads(text[start:end + 1])
    except Exception:
        return None


async def _publish_round(
    publish_fn: Optional[PublishFn],
    session_id: str,
    doc: Dict[str, Any],
) -> None:
    """Broadcast a compact summary of the round to the session WS channel.

    The full document is fetchable via the GET endpoint; the WS payload is
    intentionally trimmed so the SessionViewer doesn't have to redraw on
    multi-kilobyte messages.
    """
    if publish_fn is None:
        return
    summary: Dict[str, Any] = {
        "_id": doc.get("_id"),
        "session_id": doc.get("session_id"),
        "kind": doc.get("kind"),
        "trigger": doc.get("trigger"),
        "round": doc.get("round"),
        "verdict": doc.get("verdict"),
        "linked_hypothesis_id": doc.get("linked_hypothesis_id"),
        "linked_hypothesis_ids": doc.get("linked_hypothesis_ids", []),
        "bug_class": (doc.get("parsed") or {}).get("bug_class"),
        "created_at": (
            doc["created_at"].isoformat() if hasattr(doc.get("created_at"), "isoformat")
            else doc.get("created_at")
        ),
    }
    try:
        await publish_fn(str(session_id), {
            "type": "adversarial_round_complete",
            "data": summary,
            "timestamp": _now_iso(),
        })
    except Exception as exc:
        logger.debug("adversarial publish failed (non-fatal): %s", exc)

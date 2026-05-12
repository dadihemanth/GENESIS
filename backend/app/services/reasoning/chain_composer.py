"""T157 — chain_composer_loop.

Given the set of confirmed primitive vulnerabilities for a session, plan a
valid composition ordering. Tracks pre-/post-conditions of each primitive
(e.g. an info-leak must precede an ASLR-defeated write) and persists the
chosen order onto the existing `Vulnerability.attack_chain_id` and
`Vulnerability.chain_position` columns.

Algorithm:
  T1: load confirmed vulns for the session (PostgreSQL)
  T2: model annotates each vuln with pre/post-conditions
  T3: topological sort over the dependency graph
        - LLM picks a tie-breaker when multiple valid orderings exist
  T4: persist chain ids onto the vuln rows
  T5: emit chain summary

Inputs:
  {
    "chain_id": str,                          # optional — generated if absent
    "include_unconfirmed": bool,              # default false
    "context": str,                           # optional rationale
  }

Result:
  {
    "status":     "success|skipped|aborted",
    "chain_id":   str,
    "ordered":    [{"vuln_id":..., "title":..., "position":...}],
    "discarded":  [{"vuln_id":..., "reason":"cycle|missing_precondition|..."}],
    "rationale":  str,
  }

Reuse:
  - `app.services.attack_chain.AttackChainService.get_chains` (read existing chains)
  - `app.models.vulnerability.Vulnerability` (the `attack_chain_id` columns)
  - `AsyncSessionLocal` for PostgreSQL writes
"""
from __future__ import annotations

import json
import logging
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select, update

from app.services.reasoning.framework import DeliberationLoop, TickOutcome

logger = logging.getLogger(__name__)


_ANNOTATE_SYSTEM = (
    "You are an EXPLOIT CHAIN ANNOTATOR (GENESIS v7 T157). "
    "For each primitive vulnerability, list the PRE-conditions (what the "
    "attacker must already have) and POST-conditions (what the primitive "
    "produces). Use a small canonical vocabulary: 'unauthenticated_access', "
    "'auth_credentials', 'session_token', 'session_fixation', "
    "'info_leak_address', 'aslr_bypassed', 'arbitrary_read', "
    "'arbitrary_write', 'rce_user', 'rce_root', 'persistence', "
    "'data_exfil'. Return STRICT JSON: "
    '{"annotations": [{"vuln_id": "...", "pre": ["..."], "post": ["..."]}]}'
)

_TIEBREAK_SYSTEM = (
    "You are an EXPLOIT CHAIN ORDERING ARBITER (GENESIS v7 T157). "
    "Multiple valid topological orderings exist; pick the ONE that maximises "
    "blast radius and minimises noise (fewer reqs, lower detectable "
    "footprint). Return STRICT JSON: "
    '{"chosen_order": ["vuln_id1", "vuln_id2", ...], "rationale": "..."}'
)


class ChainComposerLoop(DeliberationLoop):
    loop_type = "chain_composer"

    async def setup(self) -> None:
        self.state["chain_id"] = (
            str(self.inputs.get("chain_id") or f"chain-{uuid.uuid4().hex[:10]}")
        )
        self.state["include_unconfirmed"] = bool(self.inputs.get("include_unconfirmed", False))
        self.state["context"] = str(self.inputs.get("context", "") or "")[:1500]
        self.state["phase"] = "load"
        self.state["vulns"] = []
        self.state["annotations"] = {}
        self.state["ordered"] = []
        self.state["discarded"] = []

    async def tick(self) -> TickOutcome:
        phase = self.state["phase"]
        if phase == "load":
            return await self._tick_load()
        if phase == "annotate":
            return await self._tick_annotate()
        if phase == "topo_sort":
            return await self._tick_topo_sort()
        if phase == "persist":
            return await self._tick_persist()
        return TickOutcome(done=True, reasoning=f"unknown phase {phase}",
                           result={"status": "aborted", "error": f"unknown phase {phase}"})

    # ------------------------------------------------------------------

    async def _tick_load(self) -> TickOutcome:
        from app.database.postgres import AsyncSessionLocal
        from app.models.vulnerability import Vulnerability

        try:
            sess_uuid = uuid.UUID(self.session_id)
        except Exception as exc:
            return TickOutcome(done=True, reasoning=f"invalid session_id: {exc}",
                               result={"status": "aborted", "error": "invalid session_id"})

        try:
            async with AsyncSessionLocal() as db:
                stmt = select(Vulnerability).where(Vulnerability.session_id == sess_uuid)
                if not self.state["include_unconfirmed"]:
                    stmt = stmt.where(Vulnerability.verification_status.in_(("confirmed", "exploited")))
                result = await db.execute(stmt)
                rows = result.scalars().all()
        except Exception as exc:
            logger.warning("chain_composer load failed: %s", exc)
            return TickOutcome(done=True, reasoning=f"db read failed: {exc}",
                               result={"status": "aborted", "error": f"db read failed: {exc}"})

        vulns: List[Dict[str, Any]] = []
        for v in rows:
            vulns.append({
                "vuln_id": str(v.id),
                "title": v.title or "",
                "severity": v.severity or "info",
                "description": (v.description or "")[:400],
                "mitre_techniques": list(v.mitre_techniques or []),
                "exploit_available": bool(v.exploit_available),
                "verification_status": v.verification_status,
                "cvss_score": float(v.cvss_score) if v.cvss_score is not None else None,
            })

        if not vulns:
            return TickOutcome(done=True, reasoning="no eligible vulnerabilities for this session",
                               result={
                                   "status": "skipped",
                                   "chain_id": self.state["chain_id"],
                                   "ordered": [],
                                   "discarded": [],
                                   "rationale": "no confirmed primitives — nothing to chain",
                               })

        self.state["vulns"] = vulns
        self.state["phase"] = "annotate"
        return TickOutcome(
            state_delta={"vulns": vulns, "phase": "annotate"},
            chosen="load",
            reasoning=f"loaded {len(vulns)} vulnerabilities",
            tokens=20,
        )

    async def _tick_annotate(self) -> TickOutcome:
        if self._llm_call is None:
            # Fallback heuristic: derive pre/post from severity + title keywords.
            for v in self.state["vulns"]:
                pre, post = _heuristic_pre_post(v)
                self.state["annotations"][v["vuln_id"]] = {"pre": pre, "post": post}
            self.state["phase"] = "topo_sort"
            return TickOutcome(
                state_delta={"annotations": self.state["annotations"], "phase": "topo_sort"},
                reasoning="no llm_call → heuristic pre/post conditions",
                tokens=0,
            )

        vuln_block = "\n".join(
            f"  {v['vuln_id']}: [{v['severity']}] {v['title']} — {v['description'][:120]}"
            for v in self.state["vulns"]
        )
        user = (
            f"Session vulns:\n{vuln_block}\n\n"
            f"Context: {self.state['context']}\n\n"
            f"Return JSON only."
        )
        try:
            result = await self._llm_call(system=_ANNOTATE_SYSTEM, user=user, max_tokens=900)
            parsed = _extract_json(result.get("text", ""))
        except Exception as exc:
            logger.warning("chain_composer annotate llm failed: %s", exc)
            parsed = {}

        anns = parsed.get("annotations", []) or []
        self.state["annotations"] = {}
        for a in anns:
            vid = a.get("vuln_id")
            if vid is None:
                continue
            self.state["annotations"][str(vid)] = {
                "pre": [str(p) for p in (a.get("pre") or [])][:6],
                "post": [str(p) for p in (a.get("post") or [])][:6],
            }
        # Fill in any vuln the model skipped with heuristic defaults.
        for v in self.state["vulns"]:
            if v["vuln_id"] not in self.state["annotations"]:
                pre, post = _heuristic_pre_post(v)
                self.state["annotations"][v["vuln_id"]] = {"pre": pre, "post": post}

        self.state["phase"] = "topo_sort"
        return TickOutcome(
            state_delta={"annotations": self.state["annotations"], "phase": "topo_sort"},
            chosen="annotate",
            reasoning=f"annotated {len(self.state['annotations'])} vulns with pre/post conditions",
            tokens=850,
        )

    async def _tick_topo_sort(self) -> TickOutcome:
        ordered, discarded = _topo_sort(self.state["vulns"], self.state["annotations"])
        # If there's exactly one feasible chain, no tie-break needed.
        if len(ordered) <= 1 or self._llm_call is None:
            self.state["ordered"] = ordered
            self.state["discarded"] = discarded
            self.state["rationale"] = "deterministic topo sort" if ordered else "no feasible ordering"
            self.state["phase"] = "persist"
            return TickOutcome(
                state_delta={"ordered": ordered, "discarded": discarded, "phase": "persist"},
                chosen="topo_sort",
                reasoning=f"ordered {len(ordered)} vulns, discarded {len(discarded)}",
                tokens=0,
            )

        # Ask the model to pick the best ordering among the produced chain.
        ordered_block = "\n".join(
            f"  {i}. {v['vuln_id']} — {v['title']}" for i, v in enumerate(ordered)
        )
        user = (
            f"A topo sort produced this ordering. Confirm it or propose a "
            f"better permutation that respects all pre/post conditions:\n\n"
            f"{ordered_block}\n\n"
            f"Annotations: {json.dumps(self.state['annotations'])[:1500]}\n\n"
            f"Return JSON only."
        )
        try:
            result = await self._llm_call(system=_TIEBREAK_SYSTEM, user=user, max_tokens=500)
            parsed = _extract_json(result.get("text", ""))
        except Exception as exc:
            logger.warning("chain_composer tiebreak llm failed: %s", exc)
            parsed = {}

        chosen_order = parsed.get("chosen_order") or []
        rationale = str(parsed.get("rationale", ""))[:400]
        if chosen_order:
            id_to_v = {v["vuln_id"]: v for v in ordered}
            reordered: List[Dict[str, Any]] = []
            for vid in chosen_order:
                v = id_to_v.get(str(vid))
                if v:
                    reordered.append(v)
            # Keep any ids the model omitted.
            seen = {v["vuln_id"] for v in reordered}
            for v in ordered:
                if v["vuln_id"] not in seen:
                    reordered.append(v)
            ordered = reordered

        self.state["ordered"] = ordered
        self.state["discarded"] = discarded
        self.state["rationale"] = rationale or "topological sort with model tie-break"
        self.state["phase"] = "persist"
        return TickOutcome(
            state_delta={"ordered": ordered, "discarded": discarded,
                         "rationale": self.state["rationale"], "phase": "persist"},
            chosen="topo_sort",
            reasoning=f"final ordering: {len(ordered)} steps",
            tokens=450,
        )

    async def _tick_persist(self) -> TickOutcome:
        from app.database.postgres import AsyncSessionLocal
        from app.models.vulnerability import Vulnerability

        ordered = self.state["ordered"]
        chain_id = self.state["chain_id"]
        if not ordered:
            return TickOutcome(
                done=True, reasoning="nothing to persist (no ordering)",
                result={
                    "status": "skipped",
                    "chain_id": chain_id,
                    "ordered": [],
                    "discarded": self.state["discarded"],
                    "rationale": self.state.get("rationale", ""),
                },
            )

        try:
            async with AsyncSessionLocal() as db:
                for pos, v in enumerate(ordered):
                    try:
                        vid = uuid.UUID(v["vuln_id"])
                    except Exception:
                        continue
                    await db.execute(
                        update(Vulnerability)
                        .where(Vulnerability.id == vid)
                        .values(attack_chain_id=chain_id, chain_position=pos)
                    )
                await db.commit()
        except Exception as exc:
            logger.warning("chain_composer persist failed: %s", exc)
            return TickOutcome(
                done=True, reasoning=f"persist failed: {exc}",
                result={
                    "status": "aborted",
                    "error": f"persist failed: {exc}",
                    "chain_id": chain_id,
                    "ordered": [{"vuln_id": v["vuln_id"], "title": v["title"], "position": i}
                                for i, v in enumerate(ordered)],
                    "discarded": self.state["discarded"],
                },
            )

        return TickOutcome(
            done=True,
            tokens=20,
            reasoning=f"persisted {len(ordered)}-step chain {chain_id}",
            result={
                "status": "success",
                "chain_id": chain_id,
                "ordered": [
                    {"vuln_id": v["vuln_id"], "title": v["title"], "severity": v["severity"], "position": i}
                    for i, v in enumerate(ordered)
                ],
                "discarded": self.state["discarded"],
                "rationale": self.state.get("rationale", ""),
            },
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _heuristic_pre_post(v: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """Default annotations when no LLM is available. Crude but never empty."""
    title = (v.get("title", "") + " " + v.get("description", "")).lower()
    pre: List[str] = ["unauthenticated_access"]
    post: List[str] = []
    if "rce" in title or "command injection" in title or "code execution" in title:
        post.append("rce_user")
    if "auth" in title and "bypass" in title:
        post.append("auth_credentials")
    if "info" in title and ("leak" in title or "disclosure" in title):
        post.append("info_leak_address")
    if "ssrf" in title:
        post.append("info_leak_address")
    if "sql" in title or "nosql" in title:
        post.append("arbitrary_read")
    if "write" in title or "upload" in title:
        post.append("arbitrary_write")
    if "session" in title and "fixation" in title:
        post.append("session_fixation")
    if not post:
        post.append("info_leak_address")
    return pre, post


def _topo_sort(
    vulns: List[Dict[str, Any]],
    annotations: Dict[str, Dict[str, List[str]]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Greedy topological order respecting pre/post conditions.

    State accumulates as `available` capabilities. At each step pick the
    highest-severity vuln whose pre-conditions are satisfied; add its
    post-conditions to `available`. Discard any cycle remainder.
    """
    severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    remaining = list(vulns)
    available = {"unauthenticated_access"}
    ordered: List[Dict[str, Any]] = []
    discarded: List[Dict[str, Any]] = []

    while remaining:
        eligible: List[Dict[str, Any]] = []
        for v in remaining:
            ann = annotations.get(v["vuln_id"], {})
            pre = set(ann.get("pre", []) or [])
            if pre.issubset(available):
                eligible.append(v)
        if not eligible:
            for v in remaining:
                ann = annotations.get(v["vuln_id"], {})
                missing = sorted(set(ann.get("pre", []) or []) - available)
                discarded.append({
                    "vuln_id": v["vuln_id"],
                    "title": v["title"],
                    "reason": "missing_precondition",
                    "missing": missing,
                })
            break
        # Pick the highest-severity eligible vuln.
        best = max(eligible, key=lambda v: severity_rank.get(v["severity"].lower(), 0))
        ordered.append(best)
        remaining.remove(best)
        for cap in annotations.get(best["vuln_id"], {}).get("post", []) or []:
            available.add(cap)
    return ordered, discarded


def _extract_json(text: str) -> Dict[str, Any]:
    if not text:
        return {}
    match = re.search(r"\{[\s\S]*\}", text)
    if not match:
        return {}
    try:
        return json.loads(match.group(0))
    except Exception:
        return {}

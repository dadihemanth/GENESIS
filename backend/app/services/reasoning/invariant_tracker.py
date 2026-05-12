"""T163 — cross_component_invariant_tracker.

Tracks invariants that span multiple files / services / processes. Maintains
the invariants as a graph; validates them at every code change; flags
inconsistencies as bug candidates.

Worked example (from the manual):
  Service A returns role: "user"|"admin".
  Service B uses role.toLowerCase() to authorize.
  Implicit invariant: "role values from A are always lowercase".
  A is later modified to allow capitalised role names; B is not updated.
  → Tracker flags privesc candidate.

Inputs:
  {
    "invariants":  [
      {"id": "inv-1", "name": "role_lowercase",
       "description": "role values from Service A are always lowercase",
       "producers": ["service_a/auth.py"],
       "consumers": ["service_b/check.py"],
       "kind": "format|range|ordering|trust|null|type"},
      ...
    ],
    "code_changes": [
      {"path": "service_a/auth.py", "summary": "added support for capitalised roles"},
      ...
    ],
    "evidence": [
      {"path": "service_b/check.py", "snippet": "if role.toLowerCase() == 'admin':"},
      ...
    ]
  }

Result:
  {
    "violations": [
      {"invariant_id": "inv-1", "severity": "high",
       "explanation": "...", "vuln_candidate": true},
      ...
    ],
    "graph_size": 3,
  }
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

from app.services.reasoning.framework import DeliberationLoop, TickOutcome
from app.services.hypothesis_market import submit_hypothesis

logger = logging.getLogger(__name__)


_INVARIANT_VALIDATION_SYSTEM = (
    "You are an INVARIANT VALIDATOR (GENESIS v7 T163). "
    "Given an invariant and a relevant code change or evidence snippet, "
    "decide whether the invariant still HOLDS or has been VIOLATED. "
    "Return STRICT JSON: "
    '{"holds": true|false, "severity": "low|medium|high|critical", '
    '"explanation": "...", "vuln_candidate": true|false}'
)


class InvariantTrackerLoop(DeliberationLoop):
    loop_type = "invariant_tracker"

    async def setup(self) -> None:
        invariants: List[Dict[str, Any]] = list(self.inputs.get("invariants", []) or [])
        # If the caller didn't pass any invariants, infer them heuristically
        # from `evidence` snippets so the loop is still useful in zero-config
        # mode.
        if not invariants:
            invariants = _infer_invariants_from_evidence(
                list(self.inputs.get("evidence", []) or [])
            )
        self.state["invariants"] = invariants
        self.state["pending_idx"] = 0
        self.state["violations"] = []
        self.state["code_changes"] = list(self.inputs.get("code_changes", []) or [])
        self.state["evidence_by_path"] = _index_by_path(
            list(self.inputs.get("evidence", []) or [])
        )

    async def tick(self) -> TickOutcome:
        if self._llm_call is None:
            return TickOutcome(done=True, reasoning="no llm_call provided",
                               result={"violations": [], "error": "missing llm_call"})

        invariants: List[Dict[str, Any]] = self.state["invariants"]
        idx: int = self.state["pending_idx"]
        if idx >= len(invariants):
            return self._finalize()

        inv = invariants[idx]
        self.state["pending_idx"] = idx + 1

        relevant_changes = [
            c for c in self.state["code_changes"]
            if c.get("path") in (inv.get("producers", []) + inv.get("consumers", []))
        ]
        relevant_evidence: List[Dict[str, Any]] = []
        for path in (inv.get("producers", []) + inv.get("consumers", [])):
            relevant_evidence.extend(self.state["evidence_by_path"].get(path, []))

        if not relevant_changes and not relevant_evidence:
            return TickOutcome(
                state_delta={"pending_idx": idx + 1},
                chosen=inv.get("id", f"inv-{idx}"),
                reasoning=f"invariant '{inv.get('name')}': no relevant changes/evidence — assumed holding",
                tokens=0,
            )

        verdict = await self._validate_invariant(inv, relevant_changes, relevant_evidence)
        if verdict and not verdict.get("holds", True):
            violation = {
                "invariant_id": inv.get("id", f"inv-{idx}"),
                "invariant_name": inv.get("name", ""),
                "severity": verdict.get("severity", "medium"),
                "explanation": verdict.get("explanation", "")[:500],
                "vuln_candidate": bool(verdict.get("vuln_candidate", False)),
                "producers": inv.get("producers", []),
                "consumers": inv.get("consumers", []),
            }
            self.state["violations"].append(violation)
            if violation["vuln_candidate"]:
                try:
                    import asyncio
                    asyncio.create_task(submit_hypothesis(
                        session_id=self.session_id,
                        text=(
                            f"Cross-component invariant '{violation['invariant_name']}' violated "
                            f"between {violation['producers']} and {violation['consumers']}: "
                            f"{violation['explanation']}"
                        ),
                        proposer_agent="invariant_tracker_t163",
                        hypothesis_type="invariant_violation",
                        confidence_stake=0.55 if violation["severity"] == "high" else 0.4,
                    ))
                except Exception:
                    pass

        if self.state["pending_idx"] >= len(invariants):
            return self._finalize()

        return TickOutcome(
            state_delta={"pending_idx": self.state["pending_idx"]},
            chosen=inv.get("id", f"inv-{idx}"),
            reasoning=(
                f"invariant '{inv.get('name')}' "
                f"{'HOLDS' if (verdict or {}).get('holds', True) else 'VIOLATED'}"
            ),
            tokens=300,
        )

    async def _validate_invariant(
        self,
        inv: Dict[str, Any],
        changes: List[Dict[str, Any]],
        evidence: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        change_lines = "\n".join(f"- {c.get('path')}: {c.get('summary','')[:200]}" for c in changes[:5])
        evidence_lines = "\n".join(
            f"- {e.get('path')}: {e.get('snippet','')[:300]}" for e in evidence[:5]
        )
        user = (
            f"Invariant: {inv.get('name')} ({inv.get('kind','unknown')})\n"
            f"Description: {inv.get('description','')}\n"
            f"Producers: {inv.get('producers', [])}\n"
            f"Consumers: {inv.get('consumers', [])}\n\n"
            f"Recent changes (relevant files):\n{change_lines or '(none)'}\n\n"
            f"Code evidence:\n{evidence_lines or '(none)'}\n\n"
            f"Return JSON only."
        )
        try:
            result = await self._llm_call(system=_INVARIANT_VALIDATION_SYSTEM, user=user, max_tokens=400)
            return _extract_json(result.get("text", ""))
        except Exception as exc:
            logger.debug("invariant validation llm failed: %s", exc)
            return None

    def _finalize(self) -> TickOutcome:
        violations = self.state.get("violations", [])
        return TickOutcome(
            done=True,
            reasoning=f"validated {len(self.state['invariants'])} invariants, {len(violations)} violations",
            tokens=200,
            result={
                "violations": violations,
                "graph_size": len(self.state["invariants"]),
                "vuln_candidate_count": sum(1 for v in violations if v.get("vuln_candidate")),
            },
        )


# ---------------------------------------------------------------------------
# Heuristics
# ---------------------------------------------------------------------------

_HINT_PATTERNS = [
    (re.compile(r"\.toLowerCase\(\)|\.toUpperCase\(\)", re.I), "format", "case-sensitivity"),
    (re.compile(r"==\s*['\"](?:admin|root|superuser)['\"]"), "trust", "privileged-role-comparison"),
    (re.compile(r"strcmp|strncmp|memcmp"), "format", "byte-comparison"),
    (re.compile(r"==\s*null|=== null|!= null|!== null"), "null", "null-check-pair"),
    (re.compile(r"\b(?:assert|invariant|require)\b", re.I), "ordering", "explicit-assertion"),
]


def _infer_invariants_from_evidence(evidence: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Pull invariants from evidence snippets when caller didn't pass any."""
    inferred: List[Dict[str, Any]] = []
    for i, e in enumerate(evidence):
        snippet = e.get("snippet", "") or ""
        path = e.get("path", "<unknown>")
        for pattern, kind, name_suffix in _HINT_PATTERNS:
            if pattern.search(snippet):
                inferred.append({
                    "id": f"inv-auto-{i}",
                    "name": f"{name_suffix}_at_{path}",
                    "description": f"Inferred from snippet at {path}",
                    "producers": [],
                    "consumers": [path],
                    "kind": kind,
                })
                break
    return inferred


def _index_by_path(evidence: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    for e in evidence:
        out.setdefault(e.get("path", ""), []).append(e)
    return out


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

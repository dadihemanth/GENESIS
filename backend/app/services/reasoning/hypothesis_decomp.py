"""T166 — hypothesis_decomposition_framework: break complex hypotheses into atomic claims.

"There's a privesc bug here" decomposes into a tree of atomic claims:
  1. X is reachable from unauthenticated context
  2. X writes to Y
  3. Y is a privileged resource
  4. The write doesn't sanitise the privilege check

Each atomic claim becomes its own market hypothesis (with parent_hypothesis_id
pointing back to the root) so existing tools — semantic dedup, evidence
tracking, resolution status, resource allocation — work on every node of the
tree without changes.

Public API:
  - decompose_hypothesis(session_id, text, parent_id=None, llm_call=...) -> list[str]
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Awaitable, Callable, Dict, List, Optional

from app.database.mongodb import get_db
from app.services.hypothesis_market import submit_hypothesis

logger = logging.getLogger(__name__)

_MARKET_COLLECTION = "hypothesis_market"

_DECOMP_SYSTEM = (
    "You are HYPOTHESIS DECOMPOSER (GENESIS v7 T166). "
    "Break a complex security hypothesis into 2-5 ATOMIC claims. "
    "Each atomic claim must be (a) independently testable, (b) a necessary "
    "precondition for the parent, and (c) more concrete than the parent. "
    "Return STRICT JSON only:\n"
    '{"atoms": [{"claim": "X is reachable without auth", "test": "send unauth GET /admin"}, ...]}'
)


async def decompose_hypothesis(
    session_id: str,
    text: str,
    parent_id: Optional[str] = None,
    llm_call: Optional[Callable[..., Awaitable[Dict[str, Any]]]] = None,
    max_atoms: int = 5,
) -> List[str]:
    """Decompose a hypothesis into atomic claims, persisting each as a child
    in `hypothesis_market`. Returns the list of new child hypothesis_ids.

    Falls back to a simple heuristic split if no `llm_call` is provided or
    the LLM call fails — the framework guarantees forward progress.
    """
    atoms = await _generate_atoms_via_llm(text, llm_call, max_atoms) if llm_call else []
    if not atoms:
        atoms = _heuristic_atoms(text, max_atoms)
    if not atoms:
        return []

    child_ids: List[str] = []
    for atom in atoms:
        claim = atom.get("claim") or atom.get("text") or ""
        if not claim:
            continue
        try:
            hyp = await submit_hypothesis(
                session_id=session_id,
                text=claim[:500],
                proposer_agent="hypothesis_decomp_t166",
                hypothesis_type="atomic_claim",
                # Atoms inherit half their parent's confidence; market evidence will adjust.
                confidence_stake=0.4,
            )
            child_id = hyp.get("hypothesis_id") if hyp else None
            if not child_id:
                continue
            child_ids.append(child_id)

            # Tag the parent linkage. submit_hypothesis stores in MongoDB
            # already; we patch in parent_id and any test hint as a follow-up
            # update so existing schema evolves without a migration.
            try:
                db = await get_db()
                update: Dict[str, Any] = {}
                if parent_id:
                    update["parent_hypothesis_id"] = parent_id
                if atom.get("test"):
                    update["suggested_test"] = atom["test"][:300]
                if update:
                    await db[_MARKET_COLLECTION].update_one(
                        {"hypothesis_id": child_id},
                        {"$set": update},
                    )
            except Exception as exc:
                logger.debug("hypothesis_decomp parent-link update failed: %s", exc)
        except Exception as exc:
            logger.warning("hypothesis_decomp submit failed: %s", exc)

    return child_ids


async def get_decomposition_tree(
    session_id: str,
    root_hypothesis_id: str,
    max_depth: int = 4,
) -> Dict[str, Any]:
    """Walk the parent_hypothesis_id chain and return a tree."""
    try:
        db = await get_db()
        root = await db[_MARKET_COLLECTION].find_one({"hypothesis_id": root_hypothesis_id})
        if not root:
            return {}
        root.pop("_id", None)

        async def _children(parent_id: str, depth: int) -> List[Dict[str, Any]]:
            if depth >= max_depth:
                return []
            cursor = db[_MARKET_COLLECTION].find({
                "session_id": session_id,
                "parent_hypothesis_id": parent_id,
            })
            kids: List[Dict[str, Any]] = []
            async for doc in cursor:
                doc.pop("_id", None)
                doc["children"] = await _children(doc["hypothesis_id"], depth + 1)
                kids.append(doc)
            return kids

        root["children"] = await _children(root_hypothesis_id, 0)
        return root
    except Exception as exc:
        logger.warning("get_decomposition_tree failed: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------

async def _generate_atoms_via_llm(
    text: str,
    llm_call: Callable[..., Awaitable[Dict[str, Any]]],
    max_atoms: int,
) -> List[Dict[str, str]]:
    try:
        result = await llm_call(
            system=_DECOMP_SYSTEM,
            user=f"Parent hypothesis:\n{text}\n\nReturn JSON only.",
            max_tokens=600,
        )
        raw = (result or {}).get("text", "")
        match = re.search(r"\{[\s\S]*\}", raw)
        if not match:
            return []
        parsed = json.loads(match.group(0))
        atoms = parsed.get("atoms", [])
        if isinstance(atoms, list):
            return atoms[:max_atoms]
    except Exception as exc:
        logger.debug("decomp llm failed (falling back to heuristic): %s", exc)
    return []


def _heuristic_atoms(text: str, max_atoms: int) -> List[Dict[str, str]]:
    """Simple sentence/clause split — last-resort, used only when no LLM is
    available or the LLM returned junk. Better than failing the loop."""
    chunks = re.split(r"(?:[.;]|\band\b|\bbecause\b|\bsuch that\b)", text, flags=re.IGNORECASE)
    atoms: List[Dict[str, str]] = []
    for c in chunks:
        s = c.strip()
        if len(s) >= 12:
            atoms.append({"claim": s, "test": ""})
        if len(atoms) >= max_atoms:
            break
    return atoms


# ---------------------------------------------------------------------------
# DeliberationLoop wrapper — used when the orchestrator calls deliberate(loop_type=hypothesis_decomp)
# ---------------------------------------------------------------------------

from app.services.reasoning.framework import DeliberationLoop, TickOutcome  # noqa: E402


class HypothesisDecompLoop(DeliberationLoop):
    """One-tick wrapper around `decompose_hypothesis` so the deliberate tool
    can invoke it like any other v7 loop. Decomposition itself is naturally
    a single round-trip; the loop framing exists for replay/audit and for
    consistency with the rest of v7."""

    loop_type = "hypothesis_decomp"

    async def tick(self) -> TickOutcome:
        text = str(self.inputs.get("text", "")).strip()
        parent_id = self.inputs.get("parent_hypothesis_id")
        max_atoms = int(self.inputs.get("max_atoms", 5))

        if not text:
            return TickOutcome(done=True, reasoning="empty hypothesis text",
                               result={"child_hypothesis_ids": [], "error": "missing text"})

        child_ids = await decompose_hypothesis(
            session_id=self.session_id,
            text=text,
            parent_id=parent_id,
            llm_call=self._llm_call,
            max_atoms=max_atoms,
        )
        return TickOutcome(
            done=True,
            state_delta={"child_ids": child_ids},
            chosen=parent_id or "",
            reasoning=f"decomposed into {len(child_ids)} atomic claims",
            tokens=400,  # rough fixed cost; actual tokens depend on llm_call internals
            result={
                "child_hypothesis_ids": child_ids,
                "parent_hypothesis_id": parent_id,
                "atom_count": len(child_ids),
            },
        )

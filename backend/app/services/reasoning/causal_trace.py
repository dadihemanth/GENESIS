"""T164 — causal_exploit_trace_builder.

For every confirmed exploit, build a causal graph:
  input bytes  →  side effects  →  downstream primitives.

The graph is the foundation for:
  - T159 self_correcting_exploit_loop (explains *why* an attempt failed)
  - Operator-facing explanation of what each byte of payload does
  - v8 corpus ingestion (T167) — annotated chains become training data

Inputs:
  {
    "exploit_payload": str | bytes-hex,        # the raw input
    "stages": [
      {"label": "send_request", "observed": "..."},
      {"label": "log_buffer_overflow", "observed": "..."},
      {"label": "rip_overwrite", "observed": "..."},
    ],
    "primitives": ["arbitrary_write", "leak_libc"],   # optional
    "context": str,                                    # optional free-form
  }

Result:
  {
    "nodes": [{"id": "...", "kind": "input|side_effect|primitive", "label": "..."}],
    "edges": [{"from": "...", "to": "...", "rationale": "..."}],
    "root_id": "input-0",
    "neo4j_synced": bool,
  }

The graph is also serialised to Neo4j via app.services.attack_graph if that
module is available (best-effort; failure non-fatal).
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

from app.services.reasoning.framework import DeliberationLoop, TickOutcome

logger = logging.getLogger(__name__)


_CAUSAL_SYSTEM = (
    "You are a CAUSAL TRACE BUILDER (GENESIS v7 T164). "
    "Given an exploit payload and an ordered list of observed stages, "
    "explain how each stage CAUSES the next. For each transition return a "
    "short rationale: which bytes of the payload (or which side effect) "
    "trigger the next observation. Return STRICT JSON: "
    '{"transitions": [{"from_label": "...", "to_label": "...", '
    '"rationale": "...", "byte_range": "0-7|null"}], '
    '"primitives_enabled": [{"primitive": "...", "via": "..."}]}'
)


class CausalTraceLoop(DeliberationLoop):
    loop_type = "causal_trace"

    async def setup(self) -> None:
        self.state["payload"] = str(self.inputs.get("exploit_payload", "") or "")
        self.state["stages"] = list(self.inputs.get("stages", []) or [])
        self.state["primitives"] = list(self.inputs.get("primitives", []) or [])
        self.state["context"] = str(self.inputs.get("context", "") or "")
        self.state["graph"] = {"nodes": [], "edges": []}
        self.state["llm_done"] = False

    async def tick(self) -> TickOutcome:
        graph = self.state["graph"]

        # Tick 1 — assemble nodes (deterministic, no LLM)
        if not graph["nodes"]:
            self._assemble_nodes()
            return TickOutcome(
                state_delta={"graph": self.state["graph"]},
                reasoning=f"assembled {len(self.state['graph']['nodes'])} nodes",
                tokens=0,
            )

        # Tick 2 — LLM fills in causal rationales for edges
        if not self.state["llm_done"]:
            if self._llm_call is None:
                # No LLM: link consecutive stages with empty rationales (still useful).
                self._link_consecutive_stages()
                self.state["llm_done"] = True
                return TickOutcome(
                    state_delta={"graph": self.state["graph"], "llm_done": True},
                    reasoning="no llm_call → linked consecutive stages without rationales",
                    tokens=0,
                )
            await self._llm_link_stages()
            self.state["llm_done"] = True
            return TickOutcome(
                state_delta={"graph": self.state["graph"], "llm_done": True},
                reasoning=f"LLM produced {len(self.state['graph']['edges'])} causal edges",
                tokens=600,
            )

        # Tick 3 — sync to Neo4j (best-effort) and finalize
        synced = await self._maybe_sync_neo4j()
        return TickOutcome(
            done=True,
            reasoning=f"causal trace complete; neo4j_synced={synced}",
            tokens=50,
            result={
                "nodes": self.state["graph"]["nodes"],
                "edges": self.state["graph"]["edges"],
                "root_id": self.state["graph"]["nodes"][0]["id"] if self.state["graph"]["nodes"] else None,
                "neo4j_synced": synced,
            },
        )

    # ------------------------------------------------------------------

    def _assemble_nodes(self) -> None:
        nodes: List[Dict[str, Any]] = []
        # input node
        payload = self.state["payload"]
        nodes.append({
            "id": "input-0",
            "kind": "input",
            "label": payload[:80] + ("..." if len(payload) > 80 else ""),
            "size": len(payload),
        })
        # stage nodes (side effects)
        for i, st in enumerate(self.state["stages"]):
            nodes.append({
                "id": f"stage-{i}",
                "kind": "side_effect",
                "label": str(st.get("label", f"stage_{i}"))[:80],
                "observed": str(st.get("observed", ""))[:300],
            })
        # primitive nodes
        for i, p in enumerate(self.state["primitives"]):
            nodes.append({
                "id": f"prim-{i}",
                "kind": "primitive",
                "label": str(p)[:80],
            })
        self.state["graph"]["nodes"] = nodes

    def _link_consecutive_stages(self) -> None:
        nodes = self.state["graph"]["nodes"]
        edges = []
        prev = "input-0"
        for n in nodes[1:]:
            if n["kind"] == "side_effect":
                edges.append({"from": prev, "to": n["id"], "rationale": "", "byte_range": None})
                prev = n["id"]
        # primitives connect from the last side-effect
        last_side_effect = prev
        for n in nodes:
            if n["kind"] == "primitive":
                edges.append({"from": last_side_effect, "to": n["id"], "rationale": "", "byte_range": None})
        self.state["graph"]["edges"] = edges

    async def _llm_link_stages(self) -> None:
        stages = self.state["stages"]
        if len(stages) < 1:
            self._link_consecutive_stages()
            return
        stage_block = "\n".join(
            f"  {i}. {s.get('label')}: {str(s.get('observed',''))[:200]}"
            for i, s in enumerate(stages)
        )
        primitives_block = ", ".join(self.state["primitives"]) or "(none)"
        user = (
            f"Payload (hex/string, first 400 chars):\n{self.state['payload'][:400]}\n\n"
            f"Stages observed (in order):\n{stage_block}\n\n"
            f"Primitives that were enabled: {primitives_block}\n\n"
            f"Context: {self.state['context'][:500]}\n\n"
            f"Return JSON only."
        )
        try:
            result = await self._llm_call(system=_CAUSAL_SYSTEM, user=user, max_tokens=900)
            parsed = _extract_json(result.get("text", ""))
        except Exception as exc:
            logger.warning("causal_trace llm failed: %s", exc)
            parsed = {}

        edges: List[Dict[str, Any]] = []
        # Map stage labels back to node ids
        label_to_id = {n["label"]: n["id"] for n in self.state["graph"]["nodes"]}
        # input is the first transition source by convention
        # transitions
        for t in parsed.get("transitions", []) or []:
            from_label = t.get("from_label", "")
            to_label = t.get("to_label", "")
            from_id = label_to_id.get(from_label[:80]) or "input-0"
            to_id = label_to_id.get(to_label[:80])
            if not to_id:
                continue
            edges.append({
                "from": from_id,
                "to": to_id,
                "rationale": str(t.get("rationale", ""))[:300],
                "byte_range": t.get("byte_range"),
            })
        # primitives_enabled
        for p in parsed.get("primitives_enabled", []) or []:
            prim_label = p.get("primitive", "")
            via_label = p.get("via", "")
            prim_id = label_to_id.get(prim_label[:80])
            via_id = label_to_id.get(via_label[:80])
            if prim_id and via_id:
                edges.append({"from": via_id, "to": prim_id, "rationale": f"enables {prim_label}", "byte_range": None})

        if not edges:
            # fall back so the graph isn't empty
            self._link_consecutive_stages()
            return

        self.state["graph"]["edges"] = edges

    async def _maybe_sync_neo4j(self) -> bool:
        try:
            from app.services import attack_graph as _ag  # type: ignore
            sync_fn = getattr(_ag, "sync_causal_trace", None)
            if sync_fn is None:
                return False
            await sync_fn(
                session_id=self.session_id,
                loop_id=self.loop_id,
                nodes=self.state["graph"]["nodes"],
                edges=self.state["graph"]["edges"],
            )
            return True
        except Exception as exc:
            logger.debug("causal_trace neo4j sync skipped: %s", exc)
            return False


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

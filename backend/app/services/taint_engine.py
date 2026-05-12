"""T82 — taint_engine: source-to-sink taint analysis.

Layers on top of ast_walker to produce ranked taint paths.  High-confidence
paths are stored in the `hypotheses` ChromaDB collection so T89 (hypothesis
market) can assign them confidence stakes.

Supported languages: Python, PHP, Java, Node.js (JavaScript/TypeScript), Go.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.database.chroma_client import get_hypotheses_collection
from app.services.ast_walker import find_sinks, find_user_inputs, trace_dataflow

logger = logging.getLogger(__name__)

# Minimum similarity score to surface a taint path
_MIN_CONFIDENCE = 0.35

# Known high-severity sink→CWE mappings for enrichment
_SINK_TO_CWE: Dict[str, str] = {
    "cursor.execute": "CWE-89",
    "db.query(": "CWE-89",
    "mysqli_query(": "CWE-89",
    "PDO::query": "CWE-89",
    "Statement.execute(": "CWE-89",
    "eval(": "CWE-95",
    "exec(": "CWE-78",
    "os.system": "CWE-78",
    "subprocess.run": "CWE-78",
    "child_process.exec": "CWE-78",
    "Runtime.exec(": "CWE-78",
    "innerHTML": "CWE-79",
    "dangerouslySetInnerHTML": "CWE-79",
    "document.write": "CWE-79",
    "pickle.loads": "CWE-502",
    "ObjectInputStream": "CWE-502",
    "unserialize(": "CWE-502",
    "yaml.load(": "CWE-502",
    "template.render": "CWE-94",
    "template.HTML(": "CWE-94",
    "open(": "CWE-73",
    "fs.writeFile": "CWE-73",
    "include(": "CWE-98",
    "require(": "CWE-98",
}


def _score_path(source_present: bool, sink_present: bool, similarity: float) -> float:
    base = similarity
    if source_present:
        base += 0.25
    if sink_present:
        base += 0.25
    return min(base, 1.0)


async def analyze_taint_paths(
    session_id: str,
    language: Optional[str] = None,
    n_paths: int = 20,
) -> List[Dict[str, Any]]:
    """Run full taint analysis: enumerate inputs × sinks, rank paths.

    Returns a list of taint path dicts sorted by confidence, each containing:
      source, sink, file_path, snippet, confidence, cwe, language.
    """
    inputs = await find_user_inputs(session_id, language=language, n_results=15)
    sinks = await find_sinks(session_id, language=language, n_results=15)

    if not inputs and not sinks:
        return []

    # Collect unique source/sink pattern pairs to trace
    source_patterns = list({
        p for entry in inputs
        for p in entry.get("input_sources", [])
    })[:8]
    sink_patterns = list({
        s for entry in sinks
        for s in entry.get("sinks_found", [])
    })[:8]

    all_paths: List[Dict[str, Any]] = []
    seen_files: set = set()

    for source in source_patterns:
        for sink in sink_patterns:
            paths = await trace_dataflow(
                session_id,
                source_pattern=source,
                sink_pattern=sink,
                language=language,
                n_results=5,
            )
            for path in paths:
                score = _score_path(
                    path["source_present"],
                    path["sink_present"],
                    path["similarity"],
                )
                if score < _MIN_CONFIDENCE:
                    continue
                file_key = (path["file_path"], source, sink)
                if file_key in seen_files:
                    continue
                seen_files.add(file_key)
                cwe = next(
                    (_SINK_TO_CWE[k] for k in _SINK_TO_CWE if k in sink),
                    "CWE-unknown",
                )
                all_paths.append({
                    "source": source,
                    "sink": sink,
                    "file_path": path["file_path"],
                    "language": path.get("language", language or ""),
                    "snippet": path["snippet"],
                    "confidence": round(score, 3),
                    "cwe": cwe,
                    "session_id": session_id,
                })

    all_paths.sort(key=lambda x: x["confidence"], reverse=True)
    top_paths = all_paths[:n_paths]

    # Persist high-confidence paths as hypotheses in ChromaDB
    if top_paths:
        await _store_taint_hypotheses(session_id, top_paths)

    logger.info(
        "taint_engine: session=%s language=%s paths=%d",
        session_id, language, len(top_paths),
    )
    return top_paths


async def _store_taint_hypotheses(
    session_id: str,
    paths: List[Dict[str, Any]],
) -> None:
    """Persist high-confidence taint paths into the hypotheses ChromaDB collection."""
    try:
        collection = await get_hypotheses_collection()
        ids: List[str] = []
        docs: List[str] = []
        metas: List[Dict[str, Any]] = []

        for path in paths:
            if path["confidence"] < 0.6:
                continue
            hyp_id = f"taint-{session_id}-{uuid.uuid4().hex[:8]}"
            doc = (
                f"Taint path: {path['source']} → {path['sink']}\n"
                f"File: {path['file_path']}\n"
                f"CWE: {path['cwe']}\n"
                f"Confidence: {path['confidence']}\n"
                f"Snippet: {path['snippet'][:400]}"
            )
            ids.append(hyp_id)
            docs.append(doc)
            metas.append({
                "session_id": session_id,
                "hypothesis_type": "taint_path",
                "confidence_stake": path["confidence"],
                "status": "open",
                "source": path["source"],
                "sink": path["sink"],
                "cwe": path["cwe"],
                "file_path": path["file_path"],
                "created_at": datetime.now(timezone.utc).isoformat(),
            })

        if ids:
            await collection.add(ids=ids, documents=docs, metadatas=metas)
            logger.debug("taint_engine: stored %d hypotheses in ChromaDB", len(ids))
    except Exception as exc:
        logger.warning("_store_taint_hypotheses failed: %s", exc)


async def get_taint_hypotheses(
    session_id: str,
    n_results: int = 10,
) -> List[Dict[str, Any]]:
    """Recall stored taint-derived hypotheses for a session."""
    try:
        collection = await get_hypotheses_collection()
        results = await collection.query(
            query_texts=[f"taint path vulnerability session {session_id}"],
            where={"session_id": session_id},
            n_results=n_results,
            include=["documents", "metadatas", "distances"],
        )
        items: List[Dict[str, Any]] = []
        if results and results.get("ids"):
            for i, doc_id in enumerate(results["ids"][0]):
                items.append({
                    "id": doc_id,
                    "document": results["documents"][0][i],
                    "metadata": results["metadatas"][0][i],
                })
        return items
    except Exception as exc:
        logger.warning("get_taint_hypotheses failed: %s", exc)
        return []

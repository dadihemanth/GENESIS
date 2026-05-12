"""T81 — ast_walker: AST/CFG query layer over ingested source corpus.

Provides three query operations used by taint_engine (T82) and
invariant_inferer (T83):
  - find_sinks()       — locate dangerous sink patterns in source
  - find_user_inputs() — locate all user-controlled input entry points
  - trace_dataflow()   — follow data from a source node to a sink

All operations first do semantic recall from the `source_corpus` ChromaDB
collection to narrow the search before applying semgrep rule patterns.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from app.services.repo_ingest import search_source_corpus

logger = logging.getLogger(__name__)

# Semgrep-compatible sink patterns per language.  These are descriptions we
# embed as query strings so ChromaDB finds relevant code before we invoke
# the semgrep MCP tool on the retrieved snippets.
_SINK_PATTERNS: Dict[str, List[str]] = {
    "python": [
        "subprocess.run", "os.system", "eval(", "exec(",
        "cursor.execute", "db.query", "open(", "pickle.loads",
        "yaml.load(", "template.render",
    ],
    "javascript": [
        "eval(", "innerHTML", "document.write", "dangerouslySetInnerHTML",
        "child_process.exec", "fs.writeFile", "res.send(", "db.query(",
    ],
    "php": [
        "system(", "exec(", "eval(", "mysqli_query(", "PDO::query",
        "include(", "require(", "file_get_contents(", "unserialize(",
    ],
    "java": [
        "Runtime.exec(", "ProcessBuilder", "Statement.execute(",
        "ObjectInputStream", "ScriptEngine.eval(", "ClassLoader.loadClass(",
    ],
    "go": [
        "exec.Command(", "os.OpenFile(", "sql.DB.Exec(", "template.HTML(",
    ],
}

_INPUT_PATTERNS: Dict[str, List[str]] = {
    "python": ["request.GET", "request.POST", "request.json()", "request.form",
               "sys.argv", "input(", "os.environ"],
    "javascript": ["req.body", "req.query", "req.params", "process.env",
                   "location.search", "location.hash", "document.cookie"],
    "php": ["$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER"],
    "java": ["request.getParameter(", "request.getHeader(", "getenv("],
    "go": ["r.URL.Query()", "r.FormValue(", "r.Header.Get(", "os.Getenv("],
}


def _build_sink_query(language: str) -> str:
    sinks = _SINK_PATTERNS.get(language, []) + _SINK_PATTERNS.get("python", [])
    return "dangerous sink function call: " + " OR ".join(sinks[:6])


def _build_input_query(language: str) -> str:
    inputs = _INPUT_PATTERNS.get(language, []) + _INPUT_PATTERNS.get("python", [])
    return "user controlled input source: " + " OR ".join(inputs[:6])


async def find_sinks(
    session_id: str,
    language: Optional[str] = None,
    n_results: int = 15,
) -> List[Dict[str, Any]]:
    """Return code snippets from the corpus that contain dangerous sink calls."""
    query = _build_sink_query(language or "python")
    hits = await search_source_corpus(session_id, query, n_results=n_results, language=language)
    results = []
    for hit in hits:
        doc = hit.get("document", "")
        meta = hit.get("metadata", {})
        # Annotate which sink patterns are present in the snippet
        found_sinks = [
            s for patterns in _SINK_PATTERNS.values()
            for s in patterns if s in doc
        ]
        if found_sinks:
            results.append({
                "file_path": meta.get("file_path", ""),
                "language": meta.get("language", language or ""),
                "snippet": doc[:800],
                "sinks_found": list(set(found_sinks))[:5],
                "similarity": hit.get("similarity", 0.0),
            })
    logger.debug("find_sinks: session=%s hits=%d", session_id, len(results))
    return results


async def find_user_inputs(
    session_id: str,
    language: Optional[str] = None,
    n_results: int = 15,
) -> List[Dict[str, Any]]:
    """Return code snippets that receive user-controlled input."""
    query = _build_input_query(language or "python")
    hits = await search_source_corpus(session_id, query, n_results=n_results, language=language)
    results = []
    for hit in hits:
        doc = hit.get("document", "")
        meta = hit.get("metadata", {})
        found_inputs = [
            p for patterns in _INPUT_PATTERNS.values()
            for p in patterns if p in doc
        ]
        if found_inputs:
            results.append({
                "file_path": meta.get("file_path", ""),
                "language": meta.get("language", language or ""),
                "snippet": doc[:800],
                "input_sources": list(set(found_inputs))[:5],
                "similarity": hit.get("similarity", 0.0),
            })
    logger.debug("find_user_inputs: session=%s hits=%d", session_id, len(results))
    return results


async def trace_dataflow(
    session_id: str,
    source_pattern: str,
    sink_pattern: str,
    language: Optional[str] = None,
    n_results: int = 10,
) -> List[Dict[str, Any]]:
    """Find code paths where *source_pattern* data reaches *sink_pattern*.

    Does a combined semantic query to surface snippets that contain both the
    source and the sink in proximity. Taint scoring is heuristic: presence
    of both patterns in the same ~512-token chunk is a strong signal.
    """
    combined_query = (
        f"data flows from {source_pattern} to {sink_pattern} "
        f"user input reaches dangerous sink taint path"
    )
    hits = await search_source_corpus(session_id, combined_query, n_results=n_results, language=language)
    results = []
    for hit in hits:
        doc = hit.get("document", "")
        meta = hit.get("metadata", {})
        source_present = source_pattern.lower() in doc.lower()
        sink_present = sink_pattern.lower() in doc.lower()
        if source_present or sink_present:
            confidence = 0.9 if (source_present and sink_present) else 0.4
            results.append({
                "file_path": meta.get("file_path", ""),
                "language": meta.get("language", language or ""),
                "snippet": doc[:800],
                "source_present": source_present,
                "sink_present": sink_present,
                "confidence": confidence,
                "similarity": hit.get("similarity", 0.0),
            })
    results.sort(key=lambda x: x["confidence"], reverse=True)
    logger.debug("trace_dataflow: session=%s paths=%d", session_id, len(results))
    return results


async def query_symbol(
    session_id: str,
    symbol: str,
    n_results: int = 8,
) -> List[Dict[str, Any]]:
    """Find all corpus entries that reference a specific function or class name."""
    hits = await search_source_corpus(session_id, f"definition or usage of {symbol}", n_results=n_results)
    return [
        {
            "file_path": h.get("metadata", {}).get("file_path", ""),
            "snippet": h.get("document", "")[:600],
            "similarity": h.get("similarity", 0.0),
        }
        for h in hits
        if symbol in h.get("document", "")
    ]

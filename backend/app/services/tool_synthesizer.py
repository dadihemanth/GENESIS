"""T97 — tool_synthesizer: LLM-driven synthesis and registration of new tools.

Workflow:
  1. Receive a description of a missing capability + example input/output.
  2. Use the LLM to generate a Python forge_runner-compatible script.
  3. Validate the script by running it in the existing forge_sandbox pool.
  4. On success: store in `synthesized_tools` ChromaDB collection and MinIO.
  5. Register metadata in MongoDB `synthesized_tools` collection.

The synthesized script is a standalone Python file that reads JSON from stdin
and writes JSON to stdout — identical to existing forge_runner scripts.
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.database.chroma_client import get_synthesized_tools_collection
from app.database.mongodb import get_db
from app.services.mcp_client import call_mcp_tool

logger = logging.getLogger(__name__)

_SYNTH_SYSTEM = (
    "You are a security tool developer for GENESIS v5. "
    "Your job is to write a standalone Python script that implements a requested "
    "security testing capability. The script MUST:\n"
    "1. Read a JSON object from stdin (json.loads(sys.stdin.read()))\n"
    "2. Write a JSON result to stdout (print(json.dumps(result)))\n"
    "3. Never exit with code != 0 on handled errors — return {\"error\": \"...\"}\n"
    "4. Be self-contained — only use stdlib + requests + common security libs\n"
    "5. Include a brief docstring explaining what it does\n\n"
    "Respond with ONLY the Python script. No prose, no markdown fences."
)

_MONGO_COLLECTION = "synthesized_tools"


async def synthesize_tool(
    description: str,
    example_input: Optional[Dict[str, Any]] = None,
    example_output: Optional[Dict[str, Any]] = None,
    capability_tag: str = "custom",
    session_id: str = "",
    client: Any = None,
    model: str = "claude-opus-4-7",
) -> Dict[str, Any]:
    """Generate, validate, and register a new tool from a natural-language description.

    Returns a result dict with `tool_name`, `status`, and `script_hash`.
    """
    if client is None:
        return {"error": "LLM client not available"}

    user_msg = f"Description: {description}\n"
    if example_input:
        user_msg += f"Example input (stdin JSON): {json.dumps(example_input, indent=2)}\n"
    if example_output:
        user_msg += f"Example output (stdout JSON): {json.dumps(example_output, indent=2)}\n"

    # --- LLM generation ---
    try:
        resp = await client.messages.create(
            model=model,
            max_tokens=2000,
            timeout=120.0,
            system=_SYNTH_SYSTEM,
            messages=[{"role": "user", "content": user_msg}],
        )
        script = ""
        for block in (resp.content or []):
            if hasattr(block, "text"):
                script += block.text
        script = script.strip()
        if script.startswith("```"):
            parts = script.split("```", 2)
            script = parts[1] if len(parts) > 1 else script
            if script.lower().startswith("python"):
                script = script[6:]
            script = script.strip()
    except Exception as exc:
        logger.warning("tool_synthesizer LLM call failed: %s", exc)
        return {"error": str(exc)}

    if not script or "def " not in script:
        return {"error": "LLM did not return a valid Python script"}

    # --- Validation via forge_runner sandbox ---
    test_input = json.dumps(example_input or {})
    validation_result = await _validate_script(script, test_input, session_id)
    if not validation_result.get("valid"):
        return {
            "status": "validation_failed",
            "reason": validation_result.get("error", "unknown"),
            "script_preview": script[:300],
        }

    # --- Registration ---
    script_hash = hashlib.sha256(script.encode()).hexdigest()[:16]
    tool_name = f"synth_{capability_tag}_{script_hash}"
    minio_path = f"synthesized_tools/{tool_name}.py"

    # Store script in MinIO
    minio_ok = await _store_script_minio(minio_path, script)

    # Register in MongoDB
    await _register_mongo(
        tool_name=tool_name,
        description=description,
        capability_tag=capability_tag,
        script_hash=script_hash,
        minio_path=minio_path if minio_ok else "",
        session_id=session_id,
        language="python",
    )

    # Register in ChromaDB synthesized_tools collection
    await _register_chroma(
        tool_name=tool_name,
        description=description,
        capability_tag=capability_tag,
        script_hash=script_hash,
        session_id=session_id,
    )

    logger.info("tool_synthesizer: registered %s (hash=%s)", tool_name, script_hash)
    return {
        "status": "registered",
        "tool_name": tool_name,
        "script_hash": script_hash,
        "minio_path": minio_path if minio_ok else None,
        "capability_tag": capability_tag,
    }


async def _validate_script(script: str, test_input: str, session_id: str) -> Dict[str, Any]:
    """Run the script in the forge_sandbox to check for basic errors."""
    try:
        # Wrap script in a forge_runner-compatible harness
        harness = (
            "import sys, json, io\n"
            "sys.stdin = io.StringIO(" + repr(test_input) + ")\n"
            "_captured = []\n"
            "_orig_print = print\n"
            "def print(*a, **k): _captured.append(' '.join(str(x) for x in a))\n"
            + script + "\n"
            "_orig_print(json.dumps({'output': _captured, 'valid': True}))\n"
        )
        result = await call_mcp_tool(
            "forge_runner",
            {"session_id": session_id or "synth-validation", "script": harness, "timeout": 20},
        )
        if result and not result.get("error"):
            return {"valid": True}
        return {"valid": False, "error": str(result.get("error", "forge_runner error"))}
    except Exception as exc:
        logger.debug("script validation failed: %s", exc)
        return {"valid": False, "error": str(exc)}


async def _store_script_minio(minio_path: str, script: str) -> bool:
    """Store the synthesized script in MinIO artifact store."""
    try:
        from app.services.artifact_resolver import ArtifactResolver
        resolver = ArtifactResolver()
        await resolver.store_text(minio_path, script)
        return True
    except Exception as exc:
        logger.debug("minio store failed: %s", exc)
        return False


async def _register_mongo(
    tool_name: str,
    description: str,
    capability_tag: str,
    script_hash: str,
    minio_path: str,
    session_id: str,
    language: str = "python",
) -> None:
    try:
        db = await get_db()
        await db[_MONGO_COLLECTION].update_one(
            {"script_hash": script_hash},
            {"$set": {
                "tool_name": tool_name,
                "description": description,
                "capability_tag": capability_tag,
                "script_hash": script_hash,
                "minio_path": minio_path,
                "session_created": session_id,
                "language": language,
                "created_at": datetime.now(timezone.utc),
            }},
            upsert=True,
        )
    except Exception as exc:
        logger.debug("mongo register failed: %s", exc)


async def _register_chroma(
    tool_name: str,
    description: str,
    capability_tag: str,
    script_hash: str,
    session_id: str,
) -> None:
    try:
        collection = await get_synthesized_tools_collection()
        await collection.add(
            ids=[f"tool-{script_hash}"],
            documents=[f"{tool_name}: {description}"],
            metadatas=[{
                "tool_name": tool_name,
                "language": "python",
                "capability_tag": capability_tag,
                "session_created": session_id,
                "script_hash": script_hash,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }],
        )
    except Exception as exc:
        logger.debug("chroma register failed: %s", exc)


async def search_synthesized_tools(query: str, n_results: int = 5) -> List[Dict[str, Any]]:
    """Semantic search over registered synthesized tools."""
    try:
        collection = await get_synthesized_tools_collection()
        results = await collection.query(
            query_texts=[query],
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
                    "similarity": 1.0 - results["distances"][0][i],
                })
        return items
    except Exception as exc:
        logger.warning("search_synthesized_tools failed: %s", exc)
        return []

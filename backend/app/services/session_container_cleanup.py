from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Set

from app.database.mongodb import (
    get_agent_thoughts_collection,
    get_replay_sessions_collection,
    get_tool_outputs_collection,
)

logger = logging.getLogger(__name__)

_REPLICA_ID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)


def _unique(values: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for value in values:
        value = str(value or "").strip()
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


async def _docker(*args: str, timeout: float = 30.0) -> str:
    """Run a docker CLI command and return stdout, or empty string on failure."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker",
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            logger.debug("[CLEANUP] docker %s timed out", args)
            return ""
        if proc.returncode not in (0, None):
            logger.debug(
                "[CLEANUP] docker %s exited rc=%s stderr=%s",
                args,
                proc.returncode,
                err.decode(errors="ignore")[:500],
            )
        return out.decode(errors="ignore")
    except FileNotFoundError:
        logger.debug("[CLEANUP] docker CLI not found; skipping docker cleanup")
        return ""
    except Exception as exc:  # noqa: BLE001
        logger.debug("[CLEANUP] docker %s failed: %s", args, exc)
        return ""


def _collect_replica_ids(value: Any, found: Set[str]) -> None:
    """Recursively extract replica UUIDs from Mongo documents and raw output."""
    if value is None:
        return
    if isinstance(value, str):
        for match in _REPLICA_ID_RE.findall(value):
            found.add(match)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"replica_id", "replicaId"} and isinstance(item, str):
                for match in _REPLICA_ID_RE.findall(item):
                    found.add(match)
            else:
                _collect_replica_ids(item, found)
        return
    if isinstance(value, list):
        for item in value:
            _collect_replica_ids(item, found)


async def _discover_replica_ids(session_id: str) -> List[str]:
    replica_ids: Set[str] = set()

    try:
        thoughts = get_agent_thoughts_collection()
        cursor = thoughts.find(
            {
                "session_id": session_id,
                "$or": [
                    {"_type": "replica_info"},
                    {"replica_id": {"$exists": True}},
                    {"replicas": {"$exists": True}},
                ],
            }
        )
        async for doc in cursor:
            _collect_replica_ids(doc, replica_ids)
    except Exception as exc:  # noqa: BLE001
        logger.debug("[CLEANUP] replica id discovery from thoughts failed: %s", exc)

    try:
        outputs = get_tool_outputs_collection()
        cursor = outputs.find(
            {
                "session_id": session_id,
                "tool_name": {"$in": ["spawn_replica", "spawn_asan_replica"]},
            },
            {"parsed_output": 1, "raw_output": 1, "params": 1},
        )
        async for doc in cursor:
            _collect_replica_ids(doc.get("parsed_output"), replica_ids)
            raw_output = doc.get("raw_output")
            if isinstance(raw_output, str) and raw_output.strip().startswith(("{", "[")):
                try:
                    _collect_replica_ids(json.loads(raw_output), replica_ids)
                except Exception:
                    _collect_replica_ids(raw_output, replica_ids)
            else:
                _collect_replica_ids(raw_output, replica_ids)
    except Exception as exc:  # noqa: BLE001
        logger.debug("[CLEANUP] replica id discovery from tool outputs failed: %s", exc)

    try:
        cursor = get_replay_sessions_collection().find(
            {"session_id": session_id, "replica_id": {"$exists": True}},
            {"replica_id": 1},
        )
        async for doc in cursor:
            _collect_replica_ids(doc, replica_ids)
    except Exception as exc:  # noqa: BLE001
        logger.debug("[CLEANUP] replica id discovery from replay sessions failed: %s", exc)

    return sorted(replica_ids)


async def _ids_for(kind: str, label_filter: str) -> List[str]:
    stdout = await _docker(kind, "ls", "-q", "--filter", label_filter)
    return [line.strip() for line in stdout.splitlines() if line.strip()]


async def _container_ids_for(label_filter: str) -> List[str]:
    stdout = await _docker("ps", "-aq", "--filter", label_filter)
    return [line.strip() for line in stdout.splitlines() if line.strip()]


async def _mark_replica_cleanup(
    session_id: str,
    replica_ids: List[str],
    reason: str,
    result: Dict[str, Any],
) -> None:
    if not replica_ids:
        return
    try:
        await get_agent_thoughts_collection().update_many(
            {"session_id": session_id, "replica_id": {"$in": replica_ids}},
            {
                "$set": {
                    "replica_cleanup": {
                        "reason": reason,
                        "cleaned_up_at": datetime.now(timezone.utc),
                        "result": result,
                    }
                }
            },
        )
        await get_agent_thoughts_collection().update_one(
            {"session_id": session_id, "_type": "container_cleanup"},
            {
                "$set": {
                    "session_id": session_id,
                    "_type": "container_cleanup",
                    "reason": reason,
                    "replica_ids": replica_ids,
                    "result": result,
                    "timestamp": datetime.now(timezone.utc),
                }
            },
            upsert=True,
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("[CLEANUP] replica cleanup marker failed: %s", exc)


async def cleanup_session_containers(
    session_id: str,
    *,
    reason: str = "session_lifecycle",
) -> Dict[str, Any]:
    """Best-effort cleanup for Docker resources created by one GENESIS session.

    The cleanup intentionally targets only exact session labels and exact
    Compose project labels derived from the session id or replica ids recorded
    in that session. It does not touch shared GENESIS services.
    """
    session_id = str(session_id).strip()
    result: Dict[str, Any] = {
        "session_id": session_id,
        "reason": reason,
        "replica_ids": [],
        "replicas_teardown_requested": 0,
        "containers_removed": 0,
        "networks_removed": 0,
        "volumes_removed": 0,
        "errors": [],
    }
    if not session_id:
        result["errors"].append("empty session id")
        return result

    replica_ids = await _discover_replica_ids(session_id)
    result["replica_ids"] = replica_ids

    if replica_ids:
        try:
            from app.services.replica_manager_client import teardown_replica

            for replica_id in replica_ids:
                ok = await teardown_replica(replica_id)
                result["replicas_teardown_requested"] += 1
                if not ok:
                    result["errors"].append(
                        f"replica-manager teardown failed or not found for {replica_id}; docker label fallback attempted"
                    )
        except Exception as exc:  # noqa: BLE001
            result["errors"].append(f"replica-manager teardown error: {exc}")

    compose_projects = [f"compose_{session_id}"] + [f"compose_{rid}" for rid in replica_ids]
    container_filters = [
        f"label=genesis.session_id={session_id}",
        *[f"label=com.docker.compose.project={project}" for project in compose_projects],
        *[f"label=genesis.replica_id={rid}" for rid in replica_ids],
    ]
    network_volume_filters = [
        f"label=genesis.session_id={session_id}",
        *[f"label=com.docker.compose.project={project}" for project in compose_projects],
    ]

    container_ids: List[str] = []
    for label_filter in container_filters:
        container_ids.extend(await _container_ids_for(label_filter))
    container_ids = _unique(container_ids)
    if container_ids:
        logger.info(
            "[CLEANUP] removing %d containers for session=%s reason=%s",
            len(container_ids),
            session_id,
            reason,
        )
        await _docker("rm", "-f", *container_ids, timeout=60.0)
        result["containers_removed"] = len(container_ids)

    network_ids: List[str] = []
    for label_filter in network_volume_filters:
        network_ids.extend(await _ids_for("network", label_filter))
    network_ids = _unique(network_ids)
    if network_ids:
        logger.info(
            "[CLEANUP] removing %d networks for session=%s reason=%s",
            len(network_ids),
            session_id,
            reason,
        )
        await _docker("network", "rm", *network_ids, timeout=30.0)
        result["networks_removed"] = len(network_ids)

    volume_ids: List[str] = []
    for label_filter in network_volume_filters:
        volume_ids.extend(await _ids_for("volume", label_filter))
    volume_ids = _unique(volume_ids)
    if volume_ids:
        logger.info(
            "[CLEANUP] removing %d volumes for session=%s reason=%s",
            len(volume_ids),
            session_id,
            reason,
        )
        await _docker("volume", "rm", *volume_ids, timeout=30.0)
        result["volumes_removed"] = len(volume_ids)

    await _mark_replica_cleanup(session_id, replica_ids, reason, result)
    if not any(
        result[key]
        for key in ("replicas_teardown_requested", "containers_removed", "networks_removed", "volumes_removed")
    ):
        logger.debug("[CLEANUP] no per-session docker resources found for %s", session_id)
    return result

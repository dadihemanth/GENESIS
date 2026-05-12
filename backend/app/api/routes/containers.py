"""Inventory of GENESIS containers + the MCP service surface.

Powers Settings → Containers. Reads the local Docker engine over the
unix-socket (mounted into this container by docker-compose). Filters to
containers that belong to the GENESIS compose project so a host running
unrelated workloads doesn't leak into the UI.
"""
from __future__ import annotations

import datetime as _dt
import logging
import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException

logger = logging.getLogger(__name__)
router = APIRouter()

# Compose stamps every container it manages with this label. Filtering by it
# keeps the inventory bounded to GENESIS even when other projects share the
# host's Docker daemon.
COMPOSE_PROJECT_LABEL = "com.docker.compose.project"
COMPOSE_SERVICE_LABEL = "com.docker.compose.service"

# Subset of services we surface as the "MCP service surface" — the MCP server
# itself plus every sibling container the MCP tools dispatch to.
_MCP_SERVICES = {
    "mcp_server", "forge_sandbox", "forge_sandbox_2", "forge_sandbox_3",
    "forge_sandbox_4", "ghidra_headless", "chromium_renderer", "fuzzer",
    "symbex", "instrumentation",
}


def _docker_client():
    try:
        import docker  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise HTTPException(
            status_code=503,
            detail="docker SDK not installed in backend image",
        ) from exc
    try:
        # The default base_url honours DOCKER_HOST; in compose we mount the
        # unix socket so the client picks it up automatically.
        return docker.from_env()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=503,
            detail=f"docker engine unreachable: {exc}",
        ) from exc


def _project_name() -> str:
    """The compose project this backend is part of (defaults to 'genesis')."""
    # The MCP host name is set by compose to <project>-mcp_server-1; we don't
    # actually need to derive the project here, but we read the env in case
    # an operator runs with COMPOSE_PROJECT_NAME=foo.
    return os.environ.get("COMPOSE_PROJECT_NAME", "genesis")


def _started_iso(state: Dict[str, Any]) -> Optional[str]:
    started = state.get("StartedAt") or ""
    return started if started and not started.startswith("0001-") else None


def _uptime_seconds(state: Dict[str, Any]) -> Optional[int]:
    started = _started_iso(state)
    if not started:
        return None
    try:
        started_dt = _dt.datetime.fromisoformat(started.replace("Z", "+00:00"))
    except ValueError:
        return None
    delta = _dt.datetime.now(tz=_dt.timezone.utc) - started_dt
    return max(0, int(delta.total_seconds()))


def _summarise_container(c: Any) -> Dict[str, Any]:
    attrs = c.attrs or {}
    state = attrs.get("State", {}) or {}
    config = attrs.get("Config", {}) or {}
    labels = config.get("Labels") or {}
    network_settings = attrs.get("NetworkSettings", {}) or {}
    networks = network_settings.get("Networks") or {}

    # Port summary — keep it short. Each entry is "host_port→container_port/proto"
    # if exposed; bare "container_port/proto" if not host-bound.
    ports: List[str] = []
    raw_ports = network_settings.get("Ports") or {}
    for cport, hosts in raw_ports.items():
        if hosts:
            for h in hosts:
                ports.append(f"{h.get('HostPort')}→{cport}")
        else:
            ports.append(cport)
    ports = sorted(set(ports))[:8]

    # Health is optional — only present when the image declared a HEALTHCHECK.
    health_obj = state.get("Health") or {}
    health_status = health_obj.get("Status")  # "starting" | "healthy" | "unhealthy"

    service = labels.get(COMPOSE_SERVICE_LABEL) or c.name
    return {
        "id": (c.id or "")[:12],
        "name": c.name,
        "service": service,
        "is_mcp_service": service in _MCP_SERVICES,
        "image": (c.image.tags[0] if c.image and c.image.tags else (config.get("Image") or "")),
        "status": c.status,                   # running | exited | created | restarting
        "state": state.get("Status"),         # similar; sometimes more granular
        "exit_code": state.get("ExitCode") if c.status != "running" else None,
        "health": health_status,
        "started_at": _started_iso(state),
        "uptime_seconds": _uptime_seconds(state),
        "restart_count": attrs.get("RestartCount", 0),
        "networks": sorted(networks.keys()),
        "ports": ports,
    }


@router.get("")
async def list_containers() -> Dict[str, Any]:
    """Return every GENESIS container (running and stopped) with status."""
    client = _docker_client()
    project = _project_name()

    try:
        # all=True so we see exited / created containers too — the user
        # explicitly asked for non-running ones.
        containers = client.containers.list(
            all=True,
            filters={"label": f"{COMPOSE_PROJECT_LABEL}={project}"},
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=f"docker list failed: {exc}") from exc

    summaries = [_summarise_container(c) for c in containers]

    # Sort: MCP-surface first, then running, then by service name. Stable
    # ordering makes the UI predictable across refreshes.
    def _sort_key(s: Dict[str, Any]):
        return (
            0 if s["is_mcp_service"] else 1,
            0 if s["status"] == "running" else 1,
            s["service"] or s["name"],
        )

    summaries.sort(key=_sort_key)

    running = sum(1 for s in summaries if s["status"] == "running")
    healthy = sum(1 for s in summaries if s.get("health") == "healthy")
    unhealthy = sum(1 for s in summaries if s.get("health") == "unhealthy")
    mcp_total = sum(1 for s in summaries if s["is_mcp_service"])
    mcp_running = sum(
        1 for s in summaries if s["is_mcp_service"] and s["status"] == "running"
    )

    return {
        "project": project,
        "totals": {
            "containers": len(summaries),
            "running": running,
            "stopped": len(summaries) - running,
            "healthy": healthy,
            "unhealthy": unhealthy,
            "mcp_total": mcp_total,
            "mcp_running": mcp_running,
        },
        "containers": summaries,
    }

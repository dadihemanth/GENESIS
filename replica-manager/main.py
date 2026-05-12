"""Replica Manager — T122 (v6.0).

Docker-in-Docker sidecar service (port 3701) that:
  1. Receives a stack_pin from the behavioral fingerprinter (T121)
  2. Pulls the exact OSS Docker images at the matched versions
  3. Runs them in an isolated Docker network
  4. Scaffolds route stubs from observed routes
  5. Returns replica_id + base_url

This gives the orchestrator a safe replica to run destructive payloads
against without touching the production target.

Supported stack pins (highest priority first):
  - nginx + Express/Node
  - nginx + Flask
  - nginx + Django
  - Apache + PHP
  - Spring Boot (Java)
  - Ruby on Rails
"""
from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Dict, List, Optional

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

from spawner import compose_for_stack, scaffold_app, ensure_replica_network  # noqa: E402

app = FastAPI(title="GENESIS Replica Manager", version="7.0.0")

# Active replicas: replica_id → metadata
_REPLICAS: Dict[str, dict] = {}

REPLICA_NETWORK = os.getenv("REPLICA_NETWORK", "genesis_replica_net")
REPLICA_BASE_PORT = int(os.getenv("REPLICA_BASE_PORT", "4000"))
_next_port = REPLICA_BASE_PORT


def _alloc_port() -> int:
    global _next_port
    port = _next_port
    _next_port += 1
    return port


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

class SpawnRequest(BaseModel):
    stack_pin: str
    observed_routes: List[str] = []
    target_ip: str = ""


class SpawnResponse(BaseModel):
    replica_id: str
    base_url: str
    status: str


@app.post("/spawn", response_model=SpawnResponse)
async def spawn(body: SpawnRequest):
    port = _alloc_port()
    replica_id = str(uuid.uuid4())

    # Scaffold app files and compose config
    scaffold_app(body.stack_pin, port, body.observed_routes)
    compose_content = compose_for_stack(body.stack_pin, port, body.observed_routes)

    compose_dir = Path(f"/tmp/compose_{replica_id}")
    compose_dir.mkdir(parents=True, exist_ok=True)
    compose_file = compose_dir / "docker-compose.yml"
    compose_file.write_text(compose_content)

    ensure_replica_network()

    # Pull images and bring up containers in background
    try:
        subprocess.Popen(
            ["docker", "compose", "-f", str(compose_file), "up", "-d", "--pull=always"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        status = "building"
    except Exception as exc:
        logger.warning("docker compose up failed: %s", exc)
        status = "error"

    base_url = f"http://localhost:{port}"
    _REPLICAS[replica_id] = {
        "replica_id": replica_id,
        "base_url": base_url,
        "port": port,
        "stack_pin": body.stack_pin,
        "target_ip": body.target_ip,
        "compose_dir": str(compose_dir),
        "status": status,
    }
    logger.info("spawned replica %s at %s (stack: %s)", replica_id, base_url, body.stack_pin[:60])
    return SpawnResponse(replica_id=replica_id, base_url=base_url, status=status)


@app.get("/replicas")
async def list_replicas():
    return list(_REPLICAS.values())


@app.delete("/replicas/{replica_id}", status_code=204)
async def teardown(replica_id: str):
    meta = _REPLICAS.get(replica_id)
    if not meta:
        raise HTTPException(status_code=404, detail="Replica not found")
    compose_dir = meta.get("compose_dir", "")
    if compose_dir and Path(compose_dir).exists():
        try:
            subprocess.run(
                ["docker", "compose", "-f", f"{compose_dir}/docker-compose.yml", "down", "-v"],
                capture_output=True, timeout=30,
            )
        except Exception as exc:
            logger.warning("docker compose down failed for %s: %s", replica_id, exc)
    del _REPLICAS[replica_id]


@app.get("/health")
async def health():
    return {"status": "ok", "active_replicas": len(_REPLICAS)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3701)

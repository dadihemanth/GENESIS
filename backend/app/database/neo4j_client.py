"""Neo4j async driver singleton for the T21 attack knowledge graph.

Mirrors the redis_client / chroma_client pattern:
  - module-level singleton, lazily constructed
  - ``reset_neo4j_client()`` that drops the reference synchronously so a new
    Celery task on a fresh event loop doesn't inherit a dead client

The singleton uses Neo4j's async driver. All graph I/O flows through
``attack_graph.py``; this module only hands out the driver + a schema-init
hook that runs uniqueness constraints once on startup.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from app.config import settings

if TYPE_CHECKING:
    from neo4j import AsyncDriver

logger = logging.getLogger(__name__)

_driver: "AsyncDriver | None" = None
_schema_initialised: bool = False


async def get_neo4j_driver() -> "AsyncDriver":
    global _driver
    if _driver is None:
        from neo4j import AsyncGraphDatabase

        _driver = AsyncGraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password) if settings.neo4j_password else None,
            max_connection_pool_size=32,
            connection_acquisition_timeout=10.0,
        )
    return _driver


async def close_neo4j_driver() -> None:
    global _driver
    if _driver is not None:
        try:
            await _driver.close()
        except Exception as exc:  # noqa: BLE001
            logger.debug("Neo4j close failed: %s", exc)
        _driver = None


def reset_neo4j_client() -> None:
    """Drop the module-level async Neo4j driver synchronously.

    Same rationale as reset_redis_client / reset_chroma_client / reset_mongo_client.
    The async driver holds TCP connections bound to the previous event loop;
    reaching them from a fresh ``asyncio.run(...)`` raises ``RuntimeError:
    Event loop is closed``. We can't ``await close()`` here because there is
    no running loop — the next ``get_neo4j_driver()`` call will reconnect on
    the live loop. The OS reclaims the sockets.
    """
    global _driver, _schema_initialised
    _driver = None
    _schema_initialised = False


async def ensure_schema() -> None:
    """One-shot uniqueness constraints. Safe to call every startup."""
    global _schema_initialised
    if _schema_initialised:
        return
    driver = await get_neo4j_driver()
    statements = [
        "CREATE CONSTRAINT host_id IF NOT EXISTS FOR (h:Host) REQUIRE h.id IS UNIQUE",
        "CREATE CONSTRAINT service_id IF NOT EXISTS FOR (s:Service) REQUIRE s.id IS UNIQUE",
        "CREATE CONSTRAINT finding_id IF NOT EXISTS FOR (f:Finding) REQUIRE f.id IS UNIQUE",
        "CREATE CONSTRAINT credential_id IF NOT EXISTS FOR (c:Credential) REQUIRE c.id IS UNIQUE",
        "CREATE CONSTRAINT token_id IF NOT EXISTS FOR (t:Token) REQUIRE t.id IS UNIQUE",
        "CREATE CONSTRAINT privilege_id IF NOT EXISTS FOR (p:Privilege) REQUIRE p.id IS UNIQUE",
        "CREATE CONSTRAINT target_fp IF NOT EXISTS FOR (t:Target) REQUIRE t.fingerprint IS UNIQUE",
        "CREATE INDEX host_session IF NOT EXISTS FOR (h:Host) ON (h.session_id)",
        "CREATE INDEX finding_session IF NOT EXISTS FOR (f:Finding) ON (f.session_id)",
        "CREATE INDEX service_session IF NOT EXISTS FOR (s:Service) ON (s.session_id)",
    ]
    async with driver.session() as session:
        for stmt in statements:
            try:
                await session.run(stmt)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Schema stmt failed: %s — %s", stmt[:60], exc)
    _schema_initialised = True


# ── Read-only Cypher guard ────────────────────────────────────────────────
# Rejects any clause that would mutate the graph. Used by the /api/v1/graph
# endpoint that proxies Cypher from the AI's graph_query MCP tool.
_MUTATING_KEYWORDS = (
    "CREATE ", "MERGE ", "DELETE ", "SET ", "REMOVE ", "DROP ",
    "DETACH DELETE", "CALL { CREATE", "CALL { MERGE", "CALL { DELETE",
    "CALL { SET", "CALL { REMOVE", "CALL APOC.CREATE", "CALL APOC.MERGE",
    "LOAD CSV", "USING PERIODIC COMMIT", "FOREACH",
)


def is_read_only_cypher(cypher: str) -> tuple[bool, str]:
    """Return ``(is_read_only, reason)``.

    Case-insensitive keyword scan. Strips string literals first so payloads
    like ``{name: "CREATE example"}`` don't trigger false positives. Not
    bulletproof — for defence-in-depth also wrap the query in a Neo4j
    read-only session (``driver.session(default_access_mode="READ")``).
    """
    import re

    if not cypher or not cypher.strip():
        return False, "empty query"
    stripped = re.sub(r"'(?:[^'\\]|\\.)*'", "''", cypher)
    stripped = re.sub(r'"(?:[^"\\]|\\.)*"', '""', stripped)
    haystack = stripped.upper()
    for kw in _MUTATING_KEYWORDS:
        if kw in haystack:
            return False, f"mutating keyword detected: {kw.strip()}"
    return True, "ok"

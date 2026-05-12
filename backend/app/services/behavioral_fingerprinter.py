"""Behavioral fingerprinter — T121.

Deep response-byte fingerprinting beyond Wappalyzer-style header matching.
Combines TLS handshake bytes (JA3/JA4S), header ordering, default 404 page
byte sequences, error message tokenisation, microsecond-level timing patterns,
and HTTP/2 frame ordering to produce a confident stack pin.

The result is stored on the Neo4j :Target node as `fingerprint_v6` and used
by the replica_spawner (T122) to pull the exact OSS component versions.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class StackPin:
    tls_ja3: str = ""
    tls_ja4s: str = ""
    header_order: list = None
    error_tokens: list = None
    timing_p50: float = 0.0
    timing_p95: float = 0.0
    h2_frame_order: list = None
    stack_pin: str = ""

    def __post_init__(self):
        if self.header_order is None:
            self.header_order = []
        if self.error_tokens is None:
            self.error_tokens = []
        if self.h2_frame_order is None:
            self.h2_frame_order = []

    def to_dict(self) -> dict:
        return {
            "tls_ja3": self.tls_ja3,
            "tls_ja4s": self.tls_ja4s,
            "header_order": self.header_order,
            "error_tokens": self.error_tokens,
            "timing_p50": self.timing_p50,
            "timing_p95": self.timing_p95,
            "h2_frame_order": self.h2_frame_order,
            "stack_pin": self.stack_pin,
        }


async def fingerprint_target(target: str, session_id: Optional[str] = None) -> StackPin:
    """Run behavioral_fingerprint MCP tool and return a StackPin.

    Falls back gracefully if the tool isn't installed or times out.
    """
    try:
        from app.services.mcp_client import MCPClient
        client = MCPClient()
        result = await client.execute_tool("behavioral_fingerprint", {"target": target})

        pin = StackPin(
            tls_ja3=result.get("tls_ja3", ""),
            tls_ja4s=result.get("tls_ja4s", ""),
            header_order=result.get("header_order", []),
            error_tokens=result.get("error_tokens", []),
            timing_p50=float(result.get("timing_p50", 0)),
            timing_p95=float(result.get("timing_p95", 0)),
            h2_frame_order=result.get("h2_frame_order", []),
            stack_pin=result.get("stack_pin", ""),
        )

        # Persist to Neo4j :Target node
        if session_id:
            await _persist_fingerprint(target, pin)

        logger.info("behavioral_fingerprinter: %s → %s", target, pin.stack_pin or "(unknown)")
        return pin

    except Exception as exc:
        logger.warning("behavioral_fingerprinter: failed for %s — %s", target, exc)
        return StackPin()


async def _persist_fingerprint(target_ip: str, pin: StackPin) -> None:
    """Write fingerprint_v6 property to the :Target neo4j node."""
    try:
        from app.database.neo4j_client import get_neo4j_driver
        import json
        driver = await get_neo4j_driver()
        async with driver.session() as neo_sess:
            await neo_sess.run(
                """
                MERGE (t:Target {ip: $ip})
                SET t.fingerprint_v6 = $fp,
                    t.stack_pin = $stack_pin
                """,
                ip=target_ip,
                fp=json.dumps(pin.to_dict()),
                stack_pin=pin.stack_pin,
            )
    except Exception as exc:
        logger.debug("_persist_fingerprint: neo4j write failed — %s", exc)

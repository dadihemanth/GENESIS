"""Splunk HTTP Event Collector (HEC) forwarder for GENESIS findings (T143)."""
from __future__ import annotations

import logging
import time
from typing import Any, Dict

import httpx

logger = logging.getLogger(__name__)


async def forward_to_splunk(finding: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    hec_url = config.get("hec_url", "").rstrip("/")
    hec_token = config.get("hec_token", "")
    index = config.get("index", "genesis_findings")
    sourcetype = config.get("sourcetype", "genesis:finding")

    if not hec_url or not hec_token:
        return {"ok": False, "error": "missing splunk config (hec_url, hec_token)"}

    event = {
        "time": time.time(),
        "index": index,
        "sourcetype": sourcetype,
        "source": "genesis_v6",
        "event": {
            "severity": finding.get("severity", "info"),
            "title": finding.get("title") or finding.get("type"),
            "target": finding.get("target_url") or finding.get("target"),
            "session_id": finding.get("session_id"),
            "description": (finding.get("description") or "")[:500],
            "evidence": str(finding.get("evidence") or "")[:500],
            "cve_id": finding.get("cve_id"),
            "attack_class": finding.get("attack_class"),
        },
    }

    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            resp = await client.post(
                f"{hec_url}/services/collector/event",
                json=event,
                headers={"Authorization": f"Splunk {hec_token}"},
            )
            resp.raise_for_status()
        return {"ok": True, "hecStatus": resp.json().get("text", "Success")}
    except Exception as exc:
        logger.warning("Splunk HEC forward failed: %s", exc)
        return {"ok": False, "error": str(exc)}

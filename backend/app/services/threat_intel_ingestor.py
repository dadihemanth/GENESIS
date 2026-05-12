"""T129 — Threat Intelligence Ingestor.

Fetches CVE/advisory data from NVD and GitHub Advisory DB every 4 hours.
Stores results in MongoDB threat_intel_entries collection.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_ADVISORIES = "https://api.github.com/advisories"
_INGEST_BATCH_SIZE = 100


async def _fetch_nvd_cves(since_days: int = 1) -> List[Dict[str, Any]]:
    """Fetch CVEs published/modified in the last N days from NVD."""
    entries: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc)
    pub_start = (now - timedelta(days=since_days)).strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end = now.strftime("%Y-%m-%dT%H:%M:%S.000")

    params = {
        "pubStartDate": pub_start,
        "pubEndDate": pub_end,
        "resultsPerPage": 100,
    }

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(NVD_BASE, params=params)
            resp.raise_for_status()
            data = resp.json()
            for vuln in data.get("vulnerabilities", []):
                cve_item = vuln.get("cve", {})
                cve_id = cve_item.get("id", "")
                descriptions = cve_item.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
                metrics = cve_item.get("metrics", {})
                cvss_v3 = metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31") else {}
                severity = cvss_v3.get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                score = cvss_v3.get("cvssData", {}).get("baseScore", 0.0)
                weaknesses = [
                    w.get("description", [{}])[0].get("value", "")
                    for w in cve_item.get("weaknesses", [])
                ]
                configs = cve_item.get("configurations", [])
                affected_components = _extract_affected_components(configs)
                references = [r.get("url", "") for r in cve_item.get("references", [])]

                entries.append({
                    "cve_id": cve_id,
                    "source": "nvd",
                    "description": desc,
                    "severity": severity,
                    "cvss_score": score,
                    "weaknesses": weaknesses,
                    "affected_components": affected_components,
                    "poc_url": next((r for r in references if "github.com" in r and "poc" in r.lower()), None),
                    "references": references[:10],
                    "published": cve_item.get("published"),
                    "last_modified": cve_item.get("lastModified"),
                    "ingested_at": now.isoformat(),
                    "matched_targets": [],
                })
    except Exception as exc:
        logger.warning("NVD fetch failed: %s", exc)

    return entries


def _extract_affected_components(configurations: List[Any]) -> List[str]:
    """Extract CPE component strings from NVD configuration nodes."""
    components: List[str] = []
    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                uri = cpe_match.get("criteria", "")
                # CPE format: cpe:2.3:a:vendor:product:version:...
                parts = uri.split(":")
                if len(parts) >= 6:
                    product = parts[4]
                    version = parts[5] if parts[5] not in ("*", "-") else ""
                    component = product if not version else f"{product}/{version}"
                    if component and component not in components:
                        components.append(component)
    return components[:20]


async def _fetch_github_advisories(since_days: int = 1) -> List[Dict[str, Any]]:
    """Fetch GitHub Security Advisories published in the last N days."""
    entries: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc)
    since_iso = (now - timedelta(days=since_days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                GITHUB_ADVISORIES,
                params={"published": f">={since_iso}", "per_page": 50},
                headers=headers,
            )
            if resp.status_code == 200:
                for adv in resp.json():
                    cve_id = adv.get("cve_id") or adv.get("ghsa_id", "")
                    affected = [
                        f"{v.get('package', {}).get('ecosystem', '')}:{v.get('package', {}).get('name', '')}"
                        for v in adv.get("vulnerabilities", [])
                        if v.get("package", {}).get("name")
                    ]
                    entries.append({
                        "cve_id": cve_id,
                        "source": "github_advisory",
                        "description": adv.get("description", "")[:500],
                        "severity": (adv.get("severity") or "UNKNOWN").upper(),
                        "cvss_score": adv.get("cvss", {}).get("score", 0.0) if adv.get("cvss") else 0.0,
                        "weaknesses": adv.get("cwes", []),
                        "affected_components": affected[:20],
                        "poc_url": None,
                        "references": [adv.get("html_url", "")][:10],
                        "published": adv.get("published_at"),
                        "last_modified": adv.get("updated_at"),
                        "ingested_at": now.isoformat(),
                        "matched_targets": [],
                    })
    except Exception as exc:
        logger.warning("GitHub advisories fetch failed: %s", exc)

    return entries


async def run_ingestor(since_days: int = 1) -> Dict[str, Any]:
    """Fetch CVEs from all feeds and upsert into MongoDB."""
    from app.database.mongodb import get_threat_intel_collection

    nvd_entries, gh_entries = await asyncio.gather(
        _fetch_nvd_cves(since_days),
        _fetch_github_advisories(since_days),
    )
    all_entries = nvd_entries + gh_entries

    if not all_entries:
        return {"inserted": 0, "updated": 0, "total_fetched": 0}

    collection = await get_threat_intel_collection()
    inserted = 0
    updated = 0

    for entry in all_entries:
        cve_id = entry.get("cve_id", "")
        if not cve_id:
            continue
        existing = await collection.find_one({"cve_id": cve_id})
        if existing:
            await collection.update_one(
                {"cve_id": cve_id},
                {"$set": {
                    "severity": entry["severity"],
                    "cvss_score": entry["cvss_score"],
                    "affected_components": entry["affected_components"],
                    "last_modified": entry["last_modified"],
                }},
            )
            updated += 1
        else:
            await collection.insert_one(entry)
            inserted += 1

    logger.info("Threat intel ingestor: %d inserted, %d updated (total %d)", inserted, updated, len(all_entries))
    return {"inserted": inserted, "updated": updated, "total_fetched": len(all_entries)}

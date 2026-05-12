"""T144 — Compliance Reporter.

Maps GENESIS vulnerability findings to compliance framework control IDs.
Supports: PCI DSS 4.0, HIPAA, SOC 2, ISO 27001:2022, NIST CSF 2.0, OWASP ASVS 4.0.3
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Maps finding attack_class/type → framework control IDs
_PCI_DSS_MAP: Dict[str, List[str]] = {
    "SQLi": ["6.3.3", "6.4.2"],
    "XSS": ["6.3.3", "6.4.3"],
    "RCE": ["6.3.1", "6.4.1"],
    "SSRF": ["1.3.1", "6.4.1"],
    "AuthBypass": ["8.3.1", "8.3.6"],
    "InsecureTLS": ["4.2.1", "4.2.2"],
    "DefaultCreds": ["8.2.1", "8.3.6"],
    "InfoDisclosure": ["6.3.3"],
    "OpenRedirect": ["6.4.3"],
    "PathTraversal": ["6.3.3"],
    "XXE": ["6.3.3"],
    "SSTI": ["6.3.3"],
}

_HIPAA_MAP: Dict[str, List[str]] = {
    "SQLi": ["164.312(a)(2)(iv)", "164.312(e)(2)(ii)"],
    "AuthBypass": ["164.308(a)(4)", "164.312(a)(2)(i)"],
    "InsecureTLS": ["164.312(e)(1)", "164.312(e)(2)(ii)"],
    "DefaultCreds": ["164.308(a)(5)", "164.312(a)(2)(iii)"],
    "RCE": ["164.308(a)(1)", "164.312(c)(1)"],
}

_SOC2_MAP: Dict[str, List[str]] = {
    "SQLi": ["CC6.1", "CC6.6"],
    "XSS": ["CC6.1", "CC6.7"],
    "AuthBypass": ["CC6.1", "CC6.2"],
    "InsecureTLS": ["CC6.7"],
    "RCE": ["CC7.1", "CC6.6"],
    "DefaultCreds": ["CC6.1", "CC6.3"],
    "InfoDisclosure": ["CC6.1", "C1.1"],
}

_ISO27001_MAP: Dict[str, List[str]] = {
    "SQLi": ["A.8.28", "A.8.24"],
    "XSS": ["A.8.28"],
    "AuthBypass": ["A.8.5", "A.8.3"],
    "InsecureTLS": ["A.8.24"],
    "RCE": ["A.8.19", "A.8.28"],
    "DefaultCreds": ["A.8.5"],
    "InfoDisclosure": ["A.8.12"],
}

_NIST_CSF_MAP: Dict[str, List[str]] = {
    "SQLi": ["PR.DS-1", "PR.DS-5"],
    "AuthBypass": ["PR.AC-1", "PR.AC-3"],
    "InsecureTLS": ["PR.DS-2"],
    "RCE": ["DE.CM-8", "RS.MI-1"],
    "DefaultCreds": ["PR.AC-1"],
    "InfoDisclosure": ["PR.DS-5", "PR.IP-1"],
}

_OWASP_ASVS_MAP: Dict[str, List[str]] = {
    "SQLi": ["V5.3.3", "V5.3.4"],
    "XSS": ["V5.3.3", "V14.1.2"],
    "AuthBypass": ["V2.1.1", "V3.5.1"],
    "InsecureTLS": ["V9.1.1", "V9.1.2"],
    "RCE": ["V5.2.4"],
    "DefaultCreds": ["V2.1.1"],
    "PathTraversal": ["V12.3.1"],
    "XXE": ["V5.5.2"],
    "SSTI": ["V5.2.5"],
    "SSRF": ["V10.3.2"],
}

FRAMEWORK_MAPS: Dict[str, Dict[str, List[str]]] = {
    "pci_dss": _PCI_DSS_MAP,
    "hipaa": _HIPAA_MAP,
    "soc2": _SOC2_MAP,
    "iso27001": _ISO27001_MAP,
    "nist_csf": _NIST_CSF_MAP,
    "owasp_asvs": _OWASP_ASVS_MAP,
}


@dataclass
class ComplianceFinding:
    finding_id: str
    title: str
    severity: str
    attack_class: str
    control_ids: List[str]
    description: str = ""


@dataclass
class ComplianceReport:
    session_id: str
    framework: str
    total_findings: int
    mapped_findings: List[ComplianceFinding] = field(default_factory=list)
    controls_violated: List[str] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "framework": self.framework,
            "total_findings": self.total_findings,
            "mapped_findings": [
                {
                    "finding_id": f.finding_id,
                    "title": f.title,
                    "severity": f.severity,
                    "attack_class": f.attack_class,
                    "control_ids": f.control_ids,
                    "description": f.description,
                }
                for f in self.mapped_findings
            ],
            "controls_violated": sorted(set(self.controls_violated)),
            "controls_violated_count": len(set(self.controls_violated)),
            "summary": self.summary,
        }


def _normalise_attack_class(finding: Dict[str, Any]) -> str:
    """Best-effort normalisation of finding type to a canonical attack class."""
    raw = (
        finding.get("attack_class")
        or finding.get("vulnerability_type")
        or finding.get("type")
        or ""
    ).strip()
    lower = raw.lower()
    if "sql" in lower:
        return "SQLi"
    if "xss" in lower or "cross-site scripting" in lower:
        return "XSS"
    if "rce" in lower or "remote code" in lower or "command injection" in lower:
        return "RCE"
    if "ssrf" in lower:
        return "SSRF"
    if "auth" in lower and ("bypass" in lower or "broken" in lower):
        return "AuthBypass"
    if "tls" in lower or "ssl" in lower or "certificate" in lower:
        return "InsecureTLS"
    if "default" in lower and "cred" in lower:
        return "DefaultCreds"
    if "info" in lower and "disclos" in lower:
        return "InfoDisclosure"
    if "redirect" in lower:
        return "OpenRedirect"
    if "path" in lower and "travers" in lower or "lfi" in lower:
        return "PathTraversal"
    if "xxe" in lower or "xml external" in lower:
        return "XXE"
    if "ssti" in lower or "template inject" in lower:
        return "SSTI"
    return raw or "Unknown"


async def generate_report(session_id: str, framework: str) -> ComplianceReport:
    """Pull all vulnerabilities for a session and map to framework controls."""
    from app.database.mongodb import get_db as get_mongo_db

    framework = framework.lower()
    framework_map = FRAMEWORK_MAPS.get(framework)
    if not framework_map:
        raise ValueError(f"Unknown framework: {framework}. Available: {list(FRAMEWORK_MAPS.keys())}")

    db = await get_mongo_db()
    findings_cursor = db["vulnerabilities"].find({"session_id": session_id})
    findings = await findings_cursor.to_list(length=1000)

    report = ComplianceReport(
        session_id=session_id,
        framework=framework,
        total_findings=len(findings),
    )

    severity_counts: Dict[str, int] = {}
    unmapped = 0

    for finding in findings:
        attack_class = _normalise_attack_class(finding)
        control_ids = framework_map.get(attack_class, [])
        if not control_ids:
            unmapped += 1
        else:
            cf = ComplianceFinding(
                finding_id=str(finding.get("_id", "")),
                title=finding.get("title") or finding.get("type") or "Finding",
                severity=(finding.get("severity") or "info").lower(),
                attack_class=attack_class,
                control_ids=control_ids,
                description=(finding.get("description") or "")[:200],
            )
            report.mapped_findings.append(cf)
            report.controls_violated.extend(control_ids)
            sev = cf.severity
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    report.summary = {
        "total_findings": len(findings),
        "mapped_findings": len(report.mapped_findings),
        "unmapped_findings": unmapped,
        "severity_breakdown": severity_counts,
        "unique_controls_violated": len(set(report.controls_violated)),
    }

    return report

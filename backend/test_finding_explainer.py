from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.finding_explainer import build_plain_language_finding  # noqa: E402


def vuln(**kwargs):
    defaults = {
        "title": "Generic issue",
        "description": "",
        "severity": "medium",
        "cvss_score": None,
        "cve_ids": [],
        "affected_service": "demo-app",
        "port": 8080,
        "remediation": "",
        "confidence": 0.8,
        "verification_status": "confirmed",
        "verification_output": "",
        "mitre_techniques": [],
        "is_zero_day": False,
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


class FindingExplainerTests(unittest.TestCase):
    def test_sql_injection(self):
        out = build_plain_language_finding(
            vuln(title="SQL Injection in /api/search"),
            {"endpoint": "/api/search", "evidence_for": ["payload changed query result count"]},
        )
        self.assertIn("database", out["why_it_matters"].lower())
        self.assertIn("parameterized", out["solution"].lower())
        self.assertIn("recorded proof evidence", out["proof"])

    def test_xss(self):
        out = build_plain_language_finding(vuln(title="Stored XSS in /notes"))
        self.assertIn("browser", out["why_it_matters"].lower())
        self.assertIn("escape", out["solution"].lower())

    def test_lfi(self):
        out = build_plain_language_finding(vuln(title="Path Traversal / Arbitrary File Read via /download"))
        self.assertIn("read files", out["why_it_matters"].lower())
        self.assertIn("directory", out["solution"].lower())

    def test_jwt_auth(self):
        out = build_plain_language_finding(vuln(title="JWT alg=none Signature Bypass"))
        self.assertIn("token", out["why_it_matters"].lower())
        self.assertIn("jwt", out["solution"].lower())

    def test_ssrf(self):
        out = build_plain_language_finding(vuln(title="Server-Side Request Forgery on /api/fetch"))
        self.assertIn("internal systems", out["why_it_matters"].lower())
        self.assertIn("outbound", out["solution"].lower())

    def test_command_injection(self):
        out = build_plain_language_finding(vuln(title="OS Command Injection in diagnostic endpoint"))
        self.assertIn("commands", out["why_it_matters"].lower())
        self.assertIn("shell", out["solution"].lower())

    def test_cve_package(self):
        out = build_plain_language_finding(
            vuln(
                title="libpng vulnerable package",
                cve_ids=["CVE-2026-12345"],
                affected_service="libpng 1.6.54",
            )
        )
        self.assertIn("CVE-2026-12345", out["description"])
        self.assertIn("vendor security update", out["solution"].lower())

    def test_unverified_legacy(self):
        out = build_plain_language_finding(
            vuln(title="Potential auth bypass", verification_status="unverified", confidence=0.4)
        )
        self.assertIn("not completed", out["proof"].lower())
        self.assertIn("not yet a confirmed vulnerability", out["validation_note"].lower())


if __name__ == "__main__":
    unittest.main()

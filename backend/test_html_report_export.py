from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.html_report import classify_areas, escape_html, redact_sensitive, safe_text  # noqa: E402


class HtmlReportExportTests(unittest.TestCase):
    def test_html_escaping_blocks_tag_rendering(self):
        self.assertEqual(escape_html('<script>alert("x")</script>'), '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;')

    def test_redacts_common_secret_shapes(self):
        text = "Authorization: Bearer eyJabc.def.ghi password=supersecret AKIAIOSFODNN7EXAMPLE"
        redacted = redact_sensitive(text)
        self.assertIn("Authorization: Bearer [REDACTED]", redacted)
        self.assertIn("password=[REDACTED]", redacted)
        self.assertIn("[AWS_KEY_REDACTED]", redacted)

    def test_safe_text_truncates_and_redacts(self):
        text = "api_key=abcdef1234567890 " + ("x" * 80)
        out = safe_text(text, max_chars=40)
        self.assertIn("[REDACTED]", out)
        self.assertIn("[truncated: showing first 40 characters]", out)

    def test_area_inference_from_tools_and_findings(self):
        areas = classify_areas(
            ["nmap", "jwt_probe", "semgrep_scan"],
            ["SQL injection in /api/search", "SSRF metadata leak"],
            ["source taint path reaches subprocess shell command"],
        )
        self.assertIn("Reconnaissance", areas)
        self.assertIn("Authentication and Identity", areas)
        self.assertIn("Source and Artifact Analysis", areas)
        self.assertIn("Injection", areas)
        self.assertIn("SSRF and Cloud Metadata", areas)

    def test_route_and_frontend_api_are_registered(self):
        sessions_py = (ROOT / "app" / "api" / "routes" / "sessions.py").read_text(encoding="utf-8")
        api_ts = (ROOT.parent / "frontend" / "src" / "services" / "api.ts").read_text(encoding="utf-8")
        self.assertIn('/{session_id}/report.html', sessions_py)
        self.assertIn("downloadHtmlReport", api_ts)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
ORCHESTRATOR = ROOT / "app" / "services" / "ai_orchestrator.py"


def _source() -> str:
    return ORCHESTRATOR.read_text(encoding="utf-8")


class ValidationPipelineOptInTests(unittest.TestCase):
    def test_strict_validation_gate_is_opt_in_by_config(self):
        src = _source()
        self.assertIn("strict_validation_pipeline_enabled", src)
        self.assertIn('config.get("validation_pipeline_enabled") is True', src)
        self.assertIn("return False", src)
        self.assertIn("Return True only when the strict candidate-promotion gate is enabled.", src)

    def test_normal_vulnerability_blocks_still_save_findings(self):
        src = _source()
        self.assertIn("store_vulnerability_blocks_as_candidates", src)
        self.assertIn("suggestion = await self._save_vulnerability(session_id, vuln_data)", src)
        self.assertIn("Strict candidate -> proof -> promotion is an opt-in validation-lab workflow.", src)

    def test_universal_gate_wording_removed_from_runtime_paths(self):
        src = _source()
        self.assertNotIn("universal validation gate requires", src)
        self.assertNotIn("findings appear only after proof/promotion", src)


if __name__ == "__main__":
    unittest.main()

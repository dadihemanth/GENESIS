"""validation milestone 4 — domain invariant plugin loader.

Loads YAML invariant plugin files from this directory and returns them as
invariant dicts compatible with invariant_inferer's storage format.

Plugin file format (YAML):
  domain: "windows_kernel_driver"
  description: "Human-readable description"
  invariants:
    - name: "irp_lock_ordering"
      rule: "IoAcquireCancelSpinLock must be called before accessing Irp->CancelRoutine"
      severity: "critical|high|medium|low"
      applies_to: ["*.c", "*.cpp"]     # glob patterns for relevant file types
      keywords: ["IoAcquireCancelSpinLock", "CancelRoutine"]  # trigger keywords
      confidence: "high|medium|low"    # or float 0.0-1.0

Operators add domain knowledge LLMs cannot derive — kernel calling conventions,
IRP rules, lock invariants, IPC trust boundaries, codec state machines — by
dropping a YAML file into this directory. GENESIS picks it up automatically.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

_PLUGIN_DIR = Path(__file__).parent
_CONFIDENCE_MAP = {"high": "high", "medium": "medium", "low": "low", "critical": "high"}


def _confidence_str_to_float(val: Any) -> float:
    if isinstance(val, (int, float)):
        return max(0.0, min(1.0, float(val)))
    s = str(val).lower().strip()
    return {"high": 0.85, "medium": 0.6, "low": 0.35, "critical": 0.95}.get(s, 0.6)


def load_plugin_invariants(
    domain_filter: str = "",
    file_extension_filter: str = "",
) -> List[Dict[str, Any]]:
    """Load all invariant plugins from the plugins/invariants/ directory.

    Args:
        domain_filter: If set, only load plugins matching this domain name.
        file_extension_filter: If set (e.g. ".c"), only include invariants
            whose `applies_to` patterns match this extension.

    Returns a list of invariant dicts (same shape as invariant_inferer output):
      {invariant_type, hint, context, file_path, confidence, source: "plugin",
       domain, rule, keywords, applies_to}
    """
    try:
        import yaml  # type: ignore
    except ImportError:
        logger.debug("PyYAML not installed — invariant plugins not loaded. pip install pyyaml")
        return []

    result: List[Dict[str, Any]] = []
    for yaml_file in sorted(_PLUGIN_DIR.glob("*.yaml")):
        if yaml_file.name.startswith("_"):
            continue
        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                plugin = yaml.safe_load(f)
            if not isinstance(plugin, dict):
                continue
            domain = str(plugin.get("domain") or yaml_file.stem)
            if domain_filter and domain_filter.lower() not in domain.lower():
                continue
            for inv in (plugin.get("invariants") or []):
                if not isinstance(inv, dict):
                    continue
                name = str(inv.get("name") or "")
                rule = str(inv.get("rule") or "")
                if not name or not rule:
                    continue
                applies_to = inv.get("applies_to") or []
                if file_extension_filter and applies_to:
                    if not any(
                        file_extension_filter.lstrip(".") in pat.lstrip("*.")
                        for pat in applies_to
                    ):
                        continue
                keywords = inv.get("keywords") or []
                conf_raw = inv.get("confidence", "medium")
                result.append({
                    "invariant_type": name,
                    "hint": rule[:300],
                    "context": f"Domain plugin: {domain}",
                    "file_path": "*",
                    "confidence": _confidence_str_to_float(conf_raw),
                    "severity": str(inv.get("severity") or "medium").lower(),
                    "source": "plugin",
                    "domain": domain,
                    "rule": rule,
                    "keywords": keywords,
                    "applies_to": applies_to,
                })
        except Exception as exc:
            logger.warning("invariant plugin load failed (%s): %s", yaml_file.name, exc)

    logger.debug("invariant plugin loader: loaded %d invariants from %s", len(result), _PLUGIN_DIR)
    return result


def get_available_domains() -> List[str]:
    """Return the list of domain names from all loaded plugin files."""
    try:
        import yaml  # type: ignore
    except ImportError:
        return []
    domains: List[str] = []
    for yaml_file in sorted(_PLUGIN_DIR.glob("*.yaml")):
        if yaml_file.name.startswith("_"):
            continue
        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                plugin = yaml.safe_load(f)
            if isinstance(plugin, dict):
                domains.append(str(plugin.get("domain") or yaml_file.stem))
        except Exception:
            pass
    return domains

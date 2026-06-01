"""Kill-chain phase coverage tracker for the SessionJudge coverage gate.

Maps every tool call to one or more (kill-chain phase, attack class) pairs.
Tracks cumulative coverage across a session and exposes a per-phase ≥N%
gate that the MultiAgentOrchestrator uses as its fourth termination gate.

Installation and C2 use a 50% threshold because GENESIS is read-only by
design — the kill-chain file explicitly marks those phases as proxy-only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

# ---------------------------------------------------------------------------
# Phase → required attack classes
# ---------------------------------------------------------------------------

KILLCHAIN_PHASE_REQUIRED_CLASSES: Dict[str, List[str]] = {
    "recon": [
        "recon_port_scan",
        "recon_web_enum",
        "recon_subdomain",
        "recon_fingerprint",
        "recon_osint",
    ],
    "weaponization": [
        "static_analysis",
        "binary_analysis",
        "payload_construction",
        "crypto_analysis",
        "deserialization",
    ],
    "delivery": [
        "http_delivery",
        "browser_delivery",
        "protocol_delivery",
        "upload_delivery",
        "ssrf_delivery",
    ],
    "exploitation": [
        "injection",
        "xss",
        "auth_bypass",
        "idor_access_control",
        "ssti_rce",
        "deserialization_exec",
        "smuggling",
        "ad_exploitation",
    ],
    # Read-only platform — proxy classes only; 50% threshold applied below
    "installation": [
        "persistence_hypothesis",
        "privilege_escalation",
    ],
    "c2": [
        "c2_simulation",
        "exfil_channel",
    ],
    "actions_on_objectives": [
        "data_exfil",
        "lateral_movement",
        "crown_jewel_access",
        "killchain_exec",
    ],
}

KILLCHAIN_PHASES: Tuple[str, ...] = tuple(KILLCHAIN_PHASE_REQUIRED_CLASSES.keys())

# Per-phase gate thresholds (0–100). Installation and C2 are intentionally
# lower because GENESIS cannot perform live persistence/C2 by design.
PHASE_GATE_THRESHOLDS: Dict[str, float] = {
    "recon":                  80.0,
    "weaponization":          80.0,
    "delivery":               80.0,
    "exploitation":           80.0,
    "installation":           50.0,
    "c2":                     50.0,
    "actions_on_objectives":  80.0,
}

# ---------------------------------------------------------------------------
# Tool → kill-chain class mapping
# ---------------------------------------------------------------------------

TOOL_TO_KILLCHAIN_CLASSES: Dict[str, List[Tuple[str, str]]] = {
    # Recon
    "nmap_scan":               [("recon", "recon_port_scan")],
    "masscan_scan":            [("recon", "recon_port_scan")],
    "httpx_probe":             [("recon", "recon_web_enum")],
    "gobuster_scan":           [("recon", "recon_web_enum")],
    "feroxbuster_scan":        [("recon", "recon_web_enum")],
    "ffuf_fuzz":               [("recon", "recon_web_enum")],
    "amass_enum":              [("recon", "recon_subdomain")],
    "subfinder_discover":      [("recon", "recon_subdomain")],
    "dnsrecon_enumerate":      [("recon", "recon_subdomain")],
    "whatweb_identify":        [("recon", "recon_fingerprint")],
    "wafw00f_detect":          [("recon", "recon_fingerprint")],
    "wpscan_scan":             [("recon", "recon_fingerprint")],
    "sslscan_check":           [("recon", "recon_fingerprint")],
    "openssl_check":           [("recon", "recon_fingerprint")],
    "harvester_gather":        [("recon", "recon_osint")],
    "artifact_hunter":         [("recon", "recon_osint"), ("weaponization", "static_analysis")],
    # Weaponization
    "semgrep_scan":            [("weaponization", "static_analysis")],
    "bandit_scan":             [("weaponization", "static_analysis")],
    "code_pattern_search":     [("weaponization", "static_analysis")],
    "code_read":               [("weaponization", "static_analysis")],
    "binary_decompile":        [("weaponization", "binary_analysis")],
    "binary_analyzer":         [("weaponization", "binary_analysis")],
    "symbolic_exec":           [("weaponization", "binary_analysis")],
    "payload_crafter":         [("weaponization", "payload_construction"), ("delivery", "http_delivery")],
    "payload_swarm":           [("weaponization", "payload_construction")],
    "ai_request_forge":        [("weaponization", "payload_construction"), ("delivery", "http_delivery")],
    "crypto_padding_oracle":   [("weaponization", "crypto_analysis")],
    "crypto_bleichenbacher":   [("weaponization", "crypto_analysis")],
    "crypto_ecdsa_nonce_reuse":[("weaponization", "crypto_analysis")],
    "crypto_length_extension": [("weaponization", "crypto_analysis")],
    "crypto_rsa_low_e":        [("weaponization", "crypto_analysis")],
    "crypto_lattice":          [("weaponization", "crypto_analysis")],
    "crypto_jwt_confusion":    [("weaponization", "crypto_analysis")],
    "java_deserial_probe":     [("weaponization", "deserialization"), ("exploitation", "deserialization_exec")],
    "dotnet_deserial_probe":   [("weaponization", "deserialization"), ("exploitation", "deserialization_exec")],
    "php_deserial_probe":      [("weaponization", "deserialization"), ("exploitation", "deserialization_exec")],
    "python_deserial_probe":   [("weaponization", "deserialization"), ("exploitation", "deserialization_exec")],
    "ruby_deserial_probe":     [("weaponization", "deserialization"), ("exploitation", "deserialization_exec")],
    # Delivery
    "curl_probe":              [("delivery", "http_delivery")],
    "forge_runner":            [("delivery", "http_delivery"), ("installation", "persistence_hypothesis")],
    "browser_session":         [("delivery", "browser_delivery")],
    "render_and_see":          [("delivery", "browser_delivery")],
    "h2_smuggle_probe":        [("delivery", "protocol_delivery"), ("exploitation", "smuggling")],
    "method_confusion_probe":  [("delivery", "protocol_delivery")],
    "race_probe_h2_singlepacket": [("delivery", "protocol_delivery")],
    "upload_polyglot_probe":   [("delivery", "upload_delivery")],
    "ssrf_scheme_probe":       [("delivery", "ssrf_delivery")],
    "cloud_imds_probe":        [("delivery", "ssrf_delivery")],
    "dns_rebind_probe":        [("delivery", "ssrf_delivery")],
    # Exploitation
    "sqlmap_test":             [("exploitation", "injection")],
    "commix_test":             [("exploitation", "injection")],
    "second_order_sqli_probe": [("exploitation", "injection")],
    "nosql_probe":             [("exploitation", "injection")],
    "ldap_inject_probe":       [("exploitation", "injection")],
    "xsstrike_test":           [("exploitation", "xss")],
    "mxss_probe":              [("exploitation", "xss")],
    "dom_clobber_probe":       [("exploitation", "xss")],
    "csp_bypass_probe":        [("exploitation", "xss")],
    "jwt_probe":               [("exploitation", "auth_bypass")],
    "oauth_probe":             [("exploitation", "auth_bypass")],
    "saml_xsw_probe":          [("exploitation", "auth_bypass"), ("delivery", "protocol_delivery")],
    "cors_probe":              [("exploitation", "auth_bypass")],
    "idor_probe":              [("exploitation", "idor_access_control")],
    "ssti_detect":             [("exploitation", "ssti_rce")],
    "ssti_gadget_probe":       [("exploitation", "ssti_rce")],
    "http_smuggling_probe":    [("exploitation", "smuggling")],
    "impacket_run":            [("exploitation", "ad_exploitation"), ("actions_on_objectives", "lateral_movement")],
    "netexec_run":             [("exploitation", "ad_exploitation"), ("actions_on_objectives", "lateral_movement")],
    "kerbrute_run":            [("exploitation", "ad_exploitation")],
    "bloodhound_collect":      [("exploitation", "ad_exploitation"), ("actions_on_objectives", "crown_jewel_access")],
    # Installation (proxy only)
    # forge_runner already mapped above for persistence_hypothesis
    # C2 (proxy only)
    "oob_check":               [("c2", "c2_simulation")],
    "dlp_exfil_probe":         [("c2", "exfil_channel"), ("actions_on_objectives", "data_exfil")],
    # Actions on objectives
    "pivot_socks_pth":         [("actions_on_objectives", "lateral_movement")],
    "graph_query":             [("actions_on_objectives", "crown_jewel_access")],
    "killchain_probe":         [("actions_on_objectives", "killchain_exec")],
    # nuclei/nikto map to exploitation (multi-class scanner)
    "nuclei_scan":             [("exploitation", "injection"), ("exploitation", "xss")],
    "nikto_scan":              [("recon", "recon_fingerprint"), ("exploitation", "injection")],
}


# ---------------------------------------------------------------------------
# Coverage tracker
# ---------------------------------------------------------------------------

@dataclass
class KillChainCoverage:
    """Mutable coverage state accumulated during a session.

    Tracks which attack classes have been exercised per kill-chain phase by
    observing tool calls via record_tool().
    """

    phase_covered: Dict[str, Set[str]] = field(
        default_factory=lambda: {p: set() for p in KILLCHAIN_PHASES}
    )

    def record_tool(self, tool_name: str) -> List[Tuple[str, str]]:
        """Update coverage for a tool call.

        Returns list of (phase, class) pairs that were newly added (not
        previously covered). Empty list means all mappings already recorded.
        """
        added: List[Tuple[str, str]] = []
        for phase, cls in TOOL_TO_KILLCHAIN_CLASSES.get(tool_name, []):
            if cls not in self.phase_covered.get(phase, set()):
                self.phase_covered.setdefault(phase, set()).add(cls)
                added.append((phase, cls))
        return added

    def phase_pct(self, phase: str) -> float:
        """Return coverage percentage for one phase (0.0–100.0)."""
        required = KILLCHAIN_PHASE_REQUIRED_CLASSES.get(phase, [])
        if not required:
            return 100.0
        covered = len(self.phase_covered.get(phase, set()) & set(required))
        return (covered / len(required)) * 100.0

    def overall_pct(self) -> float:
        """Weighted average coverage across all 7 phases (0.0–100.0).

        Weighted by number of required classes per phase so phases with more
        requirements have proportionally more influence on the score.
        """
        total_required = sum(
            len(v) for v in KILLCHAIN_PHASE_REQUIRED_CLASSES.values()
        )
        if total_required == 0:
            return 100.0
        total_covered = sum(
            len(self.phase_covered.get(p, set()) & set(cls))
            for p, cls in KILLCHAIN_PHASE_REQUIRED_CLASSES.items()
        )
        return (total_covered / total_required) * 100.0

    def gate_passed(self) -> bool:
        """True iff every phase meets its per-phase threshold."""
        return all(
            self.phase_pct(p) >= PHASE_GATE_THRESHOLDS.get(p, 80.0)
            for p in KILLCHAIN_PHASES
        )

    def gap_report(self) -> List[Dict]:
        """Return gaps for phases below their threshold, sorted worst-first.

        Each entry: {phase, missing_classes, covered_pct, required_count,
                     covered_count, threshold}.
        """
        gaps = []
        for phase in KILLCHAIN_PHASES:
            required = KILLCHAIN_PHASE_REQUIRED_CLASSES[phase]
            covered_set = self.phase_covered.get(phase, set())
            missing = [c for c in required if c not in covered_set]
            pct = self.phase_pct(phase)
            threshold = PHASE_GATE_THRESHOLDS.get(phase, 80.0)
            if pct < threshold:
                gaps.append({
                    "phase": phase,
                    "missing_classes": missing,
                    "covered_pct": round(pct, 1),
                    "required_count": len(required),
                    "covered_count": len(required) - len(missing),
                    "threshold": threshold,
                })
        return sorted(gaps, key=lambda x: x["covered_pct"])

    def to_dict(self) -> Dict:
        """Serializable snapshot for the judge context and API response."""
        return {
            phase: {
                "required": KILLCHAIN_PHASE_REQUIRED_CLASSES[phase],
                "covered": sorted(self.phase_covered.get(phase, set())),
                "pct": round(self.phase_pct(phase), 1),
                "threshold": PHASE_GATE_THRESHOLDS.get(phase, 80.0),
                "gate_passed": self.phase_pct(phase) >= PHASE_GATE_THRESHOLDS.get(phase, 80.0),
            }
            for phase in KILLCHAIN_PHASES
        }

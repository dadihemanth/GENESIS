from __future__ import annotations

import logging
from typing import Any, Dict, List

import httpx

logger = logging.getLogger(__name__)


def _get_mcp_base_url() -> str:
    from app.config import settings
    return settings.mcp_base_url


def _get_mcp_headers() -> dict:
    from app.config import settings
    headers: dict = {}
    if settings.mcp_api_key:
        headers["X-API-Key"] = settings.mcp_api_key
    return headers


class ToolResult:
    def __init__(self, output: str, parsed: Dict[str, Any] | None, success: bool, error: str | None = None) -> None:
        self.output = output
        self.parsed = parsed
        self.success = success
        self.error = error

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


_TOOL_NAME_MAP: Dict[str, str] = {
    # Reconnaissance
    "nmap_scan":            "nmap",
    "masscan_scan":         "masscan",
    "amass_enum":           "amass",
    "subfinder_discover":   "subfinder",
    "dnsrecon_enumerate":   "dnsrecon",
    "harvester_gather":     "harvester",
    "httpx_probe":          "httpx",
    # Web Scanning
    "nikto_scan":           "nikto",
    "nuclei_scan":          "nuclei",
    "whatweb_identify":     "whatweb",
    "wafw00f_detect":       "wafw00f",
    "gobuster_scan":        "gobuster",
    "feroxbuster_scan":     "feroxbuster",
    "ffuf_fuzz":            "ffuf",
    "wpscan_scan":          "wpscan",
    "xsstrike_test":        "xsstrike",
    "sqlmap_test":          "sqlmap",
    "commix_test":          "commix",
    "arjun_discover":       "arjun",
    "curl_probe":           "curl_probe",
    # SSL / TLS
    "sslscan_check":        "sslscan",
    "openssl_check":        "openssl_check",
    # Authentication / Credentials
    "hydra_test":           "hydra",
    "john_crack":           "john",
    # Windows / Active Directory
    "enum4linux_enumerate": "enum4linux",
    "netexec_run":          "netexec",
    "impacket_run":         "impacket",
    "kerbrute_run":         "kerbrute",
    # Static Analysis
    "semgrep_scan":         "semgrep",
    "bandit_scan":          "bandit",
    # Mythos Intelligence Tools
    "payload_crafter":      "payload_crafter",
    "binary_analyzer":      "binary_analyzer",
    "code_pattern_search":  "code_pattern_search",
    # HTTP Vulnerability Analysis Tools
    "idor_probe":                "idor_probe",
    "cors_probe":                "cors_probe",
    "jwt_probe":                 "jwt_probe",
    "graphql_probe":             "graphql_probe",
    "ssti_detect":               "ssti_detect",
    "nosql_probe":               "nosql_probe",
    "cache_probe":               "cache_probe",
    "prototype_pollution_probe": "prototype_pollution_probe",
    "oauth_probe":               "oauth_probe",
    "http_smuggling_probe":      "http_smuggling_probe",
    # v4.0 Wave 1 — Novelty Engine
    "http_diff_probe":           "http_diff_probe",
    "semantic_anomaly_grader":   "semantic_anomaly_grader",
    # v4.0 Wave 2 — Parser Differential Probes
    "url_parser_diff":           "url_parser_diff",
    "json_parser_diff":          "json_parser_diff",
    "unicode_diff_probe":        "unicode_diff_probe",
    "multipart_diff_probe":      "multipart_diff_probe",
    "charset_confusion_probe":   "charset_confusion_probe",
    # v4.0 Wave 3 — HTTP Modern Protocol Probes
    "h2_smuggle_probe":          "h2_smuggle_probe",
    "method_confusion_probe":    "method_confusion_probe",
    "range_trailer_probe":       "range_trailer_probe",
    # v4.0 Wave 4 — Deserialisation Gadget Arsenal
    "java_deserial_probe":       "java_deserial_probe",
    "dotnet_deserial_probe":     "dotnet_deserial_probe",
    "php_deserial_probe":        "php_deserial_probe",
    "python_deserial_probe":     "python_deserial_probe",
    "ruby_deserial_probe":       "ruby_deserial_probe",
    "node_proto_to_gadget":      "node_proto_to_gadget",
    # v4.0 Wave 5 — Upload Pipelines & SSRF Expansion
    "upload_polyglot_probe":     "upload_polyglot_probe",
    "image_parser_probe":        "image_parser_probe",
    "ssrf_scheme_probe":         "ssrf_scheme_probe",
    "cloud_imds_probe":          "cloud_imds_probe",
    "dns_rebind_probe":          "dns_rebind_probe",
    # v4.0 Wave 6 — State-Aware Fuzzing
    "flow_recorder":             "flow_recorder",
    "flow_fuzzer":               "flow_fuzzer",
    "race_probe_h2_singlepacket": "race_probe_h2_singlepacket",
    # v4.0 Wave 7 — Auth / SSO Depth
    "saml_xsw_probe":            "saml_xsw_probe",
    "cookie_prefix_probe":       "cookie_prefix_probe",
    "cswsh_probe":               "cswsh_probe",
    # v4.0 Wave 8 — Browser-Side / DOM
    "dom_clobber_probe":         "dom_clobber_probe",
    "postmessage_probe":         "postmessage_probe",
    "mxss_probe":                "mxss_probe",
    "csp_bypass_probe":          "csp_bypass_probe",
    "xsleaks_probe":             "xsleaks_probe",
    # v4.0 Wave 9 — Templates / DB / LDAP Depth
    "ssti_gadget_probe":         "ssti_gadget_probe",
    "ldap_inject_probe":         "ldap_inject_probe",
    "second_order_sqli_probe":   "second_order_sqli_probe",
    # v4.0 Wave 10 — DoS / Algorithmic Complexity
    "redos_probe":               "redos_probe",
    "bomb_probe":                "bomb_probe",
    # v4.0 Wave 11 — LLM / Agentic Endpoints
    "llm_inject_probe":          "llm_inject_probe",
    "indirect_inject_probe":     "indirect_inject_probe",
    "rag_poison_probe":          "rag_poison_probe",
    # v4.0 Wave 12 — Non-HTTP Services
    "redis_probe":               "redis_probe",
    "grpc_probe":                "grpc_probe",
    "db_wire_probe":             "db_wire_probe",
    "mqtt_amqp_probe":           "mqtt_amqp_probe",
    # v4.0 Wave 13 — AD / Kill-Chain Completion
    "bloodhound_collect":        "bloodhound_collect",
    "password_spray_cred":       "password_spray_cred",
    "pivot_socks_pth":           "pivot_socks_pth",
    "dlp_exfil_probe":           "dlp_exfil_probe",
    "killchain_probe":           "killchain_probe",
}


def _resolve_tool_name(name: str) -> str:
    return _TOOL_NAME_MAP.get(name, name)


async def call_mcp_tool(tool_name: str, params: Dict[str, Any], timeout: float = 300.0) -> Dict[str, Any]:
    """Module-level convenience wrapper around MCPClient.execute_tool()."""
    return await MCPClient(timeout=timeout).execute_tool(tool_name, params)


class MCPClient:
    def __init__(self, timeout: float = 300.0) -> None:
        self.timeout = timeout

    async def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        base_url = _get_mcp_base_url()
        mcp_tool = _resolve_tool_name(tool_name)
        url = f"{base_url}/tools/execute"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, json={"tool": mcp_tool, "params": params}, headers=_get_mcp_headers())
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "output": data.get("output", ""),
                        "parsed": data.get("parsed", {}),
                        "success": True,
                    }
                return {
                    "output": f"MCP error HTTP {resp.status_code}: {resp.text[:1000]}",
                    "parsed": None,
                    "success": False,
                }
        except httpx.TimeoutException:
            return {
                "output": f"Tool execution timed out after {self.timeout}s",
                "parsed": None,
                "success": False,
            }
        except Exception as exc:
            logger.error("MCP tool execution failed for %s: %s", tool_name, exc)
            return {
                "output": f"Error calling MCP tool '{tool_name}': {str(exc)}",
                "parsed": None,
                "success": False,
            }

    async def list_tools(self) -> List[Dict[str, Any]]:
        base_url = _get_mcp_base_url()
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"{base_url}/tools", headers=_get_mcp_headers())
                if resp.status_code == 200:
                    data = resp.json()
                    return data if isinstance(data, list) else data.get("tools", [])
                return []
        except Exception as exc:
            logger.error("Failed to list MCP tools: %s", exc)
            return []

    async def health_check(self) -> Dict[str, Any]:
        base_url = _get_mcp_base_url()
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{base_url}/health")
                if resp.status_code == 200:
                    return {"status": "ok", "detail": resp.json()}
                return {"status": "error", "detail": f"HTTP {resp.status_code}"}
        except Exception as exc:
            return {"status": "error", "detail": str(exc)}

    async def test_tool(self, name: str) -> Dict[str, Any]:
        base_url = _get_mcp_base_url()
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(f"{base_url}/tools/{name}/test", headers=_get_mcp_headers())
                if resp.status_code == 200:
                    return {"status": "ok", "detail": resp.json()}
                return {"status": "error", "detail": f"HTTP {resp.status_code}: {resp.text[:200]}"}
        except Exception as exc:
            return {"status": "error", "detail": str(exc)}

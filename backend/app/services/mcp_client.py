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
}


def _resolve_tool_name(name: str) -> str:
    return _TOOL_NAME_MAP.get(name, name)


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

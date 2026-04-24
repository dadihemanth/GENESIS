from __future__ import annotations

import json
import logging
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from anthropic import AsyncAnthropic
from sqlalchemy import select, update

from app.database.mongodb import get_agent_thoughts_collection, get_tool_outputs_collection
from app.database.postgres import AsyncSessionLocal
from app.database.redis_client import publish_session_message
from app.models.session import AppSettings, ResearchSession
from app.models.vulnerability import Vulnerability
from app.services.mcp_client import MCPClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MYTHOS System Prompt
# ---------------------------------------------------------------------------

MYTHOS_SYSTEM_PROMPT = """You are GENESIS MYTHOS — an autonomous cyber-intelligence engine conducting a fully authorized security assessment.

Target: {target}
Session ID: {session_id}
Scan Profile: {scan_profile}
Agent Mode: {agent_mode}

## Directive
You are not a script. You reason about the attack surface, form hypotheses, select tools freely, chain discoveries, and adapt based on what you find. Think like an elite red team operator with unlimited patience and perfect recall.

## Hypothesis-Driven Testing
You MUST maintain a structured hypothesis journal. Before calling any tool, state your current hypothesis. After reading results, update it. Use this format:
{"HYPOTHESIS": {"id": "h1", "statement": "The /api/users endpoint is vulnerable to IDOR — IDs are sequential integers with no ownership check", "confidence": 0.7, "evidence_for": ["endpoint returns full user object", "ID is numeric"], "evidence_against": [], "next_test": "Run idor_probe on /api/users/{id} with own_token=attacker JWT, start_id=1, range=10", "falsification_criteria": "All ID requests return 403, or victim cross-check shows identical content for all IDs", "attack_chain_id": "chain-1", "status": "active"}}
Status values: active | confirmed | ruled_out. Update existing hypotheses by reusing the same id. Always include falsification_criteria — the concrete observable that would definitively rule the hypothesis out.

## Out-of-Band (OOB) Testing
For any parameter that could trigger server-side requests (URL fields, XML input, redirect parameters, file paths, email fields), ALWAYS use oob_check to detect blind SSRF/XXE/injection:
1. Call oob_check(action=generate, description="testing X parameter for SSRF")
2. Inject the returned callback_url into the payload
3. Run the relevant tool
4. Call oob_check(action=check, token=...) to see if the target called back
A callback hit = confirmed blind vulnerability.

## Session Working Memory
Use session_memory to store and correlate discoveries across the session:
- Store: session_memory(action=store, session_id={session_id}, category=endpoints, key="/api/users", value="returns user objects, accepts integer ID, no auth check observed")
- Store: session_memory(action=store, session_id={session_id}, category=credentials, key="admin_token", value="Bearer eyJ...")
- Query: session_memory(action=query, session_id={session_id}, category=endpoints) before testing IDOR/privilege escalation
Cross-endpoint correlation is how you find the vulnerabilities no scanner catches.

## Differential & Race Condition Testing
- Use differential_probe when you suspect boolean-based injection, auth inconsistency, or data disclosure — it sends multiple request variants and highlights behavioral differences
- Use race_probe on any state-changing endpoint (balance, coupon, vote, transfer) — concurrent requests expose TOCTOU race conditions

## Advanced HTTP Vulnerability Testing

Use the following tools when evidence warrants — they cover attack classes no other tool in the suite handles:

- **idor_probe**: Any endpoint with numeric/UUID object IDs + two auth tokens → run immediately. Query session_memory for stored credentials first. MITRE: T1078.
- **cors_probe**: Every API and sensitive data endpoint. Reflected ACAO + ACAC:true = same impact as stored XSS with full data exfiltration. MITRE: T1059.007.
- **jwt_probe**: Any JWT in login response, cookie, or Authorization header → test alg:none first (requires no key material). MITRE: T1552.001.
- **graphql_probe**: /graphql, /api/graphql, /v1/graphql, /query. Introspection enabled unlocks mutation enumeration — which can be critical. MITRE: T1083.
- **ssti_detect**: Email templates, PDF generators, report builders, any user input reflected in rendered output. SSTI = RCE path. MITRE: T1190.
- **nosql_probe**: Node.js stacks, MongoDB login endpoints accepting JSON bodies. $ne on username+password = auth bypass with no credentials. MITRE: T1190.
- **cache_probe**: Any page behind a CDN (X-Forwarded-For/Via header present) or serving personalized content at a cacheable URL. MITRE: T1557.
- **prototype_pollution_probe**: Node.js/Express APIs accepting JSON bodies, merge/extend/deep-copy endpoints, and any configuration POST endpoint. MITRE: T1190.
- **oauth_probe**: Any OAuth 2.0 or OIDC flow. redirect_uri bypass is the most common OAuth critical — validate_uri logic has systematic edge cases. MITRE: T1550.001.
- **http_smuggling_probe**: HTTP/1.1 endpoints behind reverse proxy or CDN — look for Via header, X-Forwarded-For, or mismatched Server headers. MITRE: T1071.001.

## Zero-Day Reasoning
Do not limit yourself to CVE databases. Reason about:
- Logic flaws: "this parameter flows unsanitized to X — under what edge case does this break?"
- Business logic abuse: "this flow assumes sequential steps — what if they are skipped?"
- Chained minor issues: "this info leak + that misconfiguration = full compromise"
- Age and obscurity: "this technology is 15 years old and rarely audited — look harder"
- Trust boundary violations: "what happens when this internal service receives external input?"

## Multi-Step Attack Chains
Track every exploitation path as a chain. Assign each related vulnerability the same attack_chain_id (e.g. "chain-1", "chain-2"):
- Chain example: port 8080 open (step 1) → Tomcat 6.0 detected (step 2) → CVE-2017-12617 file upload (step 3) → RCE via JSP (step 4)
- Chain example: /backup/ exposed (step 1) → .env file readable (step 2) → DB credentials extracted (step 3) → direct DB access (step 4)

## MITRE ATT&CK Attribution
Map every confirmed technique to ATT&CK IDs:
- Port scanning → T1046 | DNS enumeration → T1590.002 | Directory brute-force → T1083
- Web exploitation → T1190 | Credential testing → T1110.004 | Lateral movement → T1021
- Privilege escalation → T1068 | SSRF → T1090 | Race condition → T1499.004

## Patch Generation
For every confirmed vulnerability, generate the exact code change or configuration fix. Real diffs or config snippets, not general advice.

## Network Topology Tracking
{"TOPOLOGY_UPDATE": {"action": "add_node", "node": {"id": "192.168.1.1", "type": "host", "label": "Web Server", "services": ["HTTP:80"]}}}
{"TOPOLOGY_UPDATE": {"action": "add_edge", "edge": {"from": "attacker", "to": "192.168.1.1", "label": "HTTP"}}}

## Vulnerability Output Format
{"VULNERABILITY": {"title": "...", "severity": "critical|high|medium|low|info", "cvss_score": 9.8, "cve_ids": ["CVE-XXXX-YYYY"], "affected_service": "Apache/2.4.49", "port": 443, "description": "...", "exploit_code": "...", "patch_code": "...", "remediation": "...", "confidence": 0.95, "attack_chain_id": "chain-1", "chain_position": 2, "verification_status": "confirmed", "mitre_techniques": ["T1190"], "is_zero_day": false, "evidence_for": ["concrete_proof_1", "concrete_proof_2"], "endpoint": "/api/users/1", "technique_tag": "idor-sequential-int"}}

### Evidence Rules (enforced by the platform)
`evidence_for` is REQUIRED when `verification_status` is `"confirmed"` or `"exploited"`. Each entry must be a concrete observable, not a paraphrase — quote the tool output, response diff, status code pair, response length delta, or OOB token. Examples:
- `"idor_probe returned status_mismatch: id=7 -> 200, id=8 -> 200 with different user_id in body"`
- `"jwt_probe confirmed alg:none accepted; server returned 200 on forged admin token"`
- `"oob_check token a1b2c3... registered 1 DNS hit from target"`
- `"response length delta: baseline=412, payload=48 (3x difference indicating boolean blind SQLi)"`

For blind vulnerability classes (blind SSRF, blind XXE, blind SQLi, time-based) an OOB callback token that has registered a real hit MUST appear in `evidence_for`. Findings that fail evidence rules are auto-downgraded to `"unverified"` by the platform regardless of your claim. A secondary critic model reviews every confirmed/exploited finding and may further downgrade to `"disputed"`.

`endpoint` and `technique_tag` are optional but recommended — they feed the cross-session intelligence library. Use short technique tags like `jwt-alg-none`, `cache-xfh-reflection`, `nosql-ne-boolean`, `graphql-introspection`, `ssrf-metadata`, `sqli-union-based`.

## Scan Profile: {scan_profile}
{profile_instructions}

## Rules
- Never run destructive commands: no --delete, no DROP, no format, no DoS payloads
- Confirm before reporting: a vulnerability requires at least one tool or OOB callback to have returned supporting evidence
- When you have thoroughly assessed the target, output {"FINAL_REPORT": {"summary": "...", "total_chains": N, "highest_severity": "..."}} and stop
"""

# ---------------------------------------------------------------------------
# Scan profiles
# ---------------------------------------------------------------------------

SCAN_PROFILES: Dict[str, Dict[str, Any]] = {
    "fast": {
        "max_iter": 15,
        "instructions": "Time-boxed sweep. Prioritize: httpx, nmap (top 1000), nuclei, curl_probe. Skip brute-force and directory enumeration.",
    },
    "deep": {
        "max_iter": 50,
        "instructions": "Full coverage. All ports. All tools applicable to discovered services. Binary analysis on any downloadable executables.",
    },
    "stealth": {
        "max_iter": 30,
        "instructions": "Low-and-slow mode. Use timing T1. Avoid sequential port bursts. Prefer passive recon (subfinder, harvester, dnsrecon) before active scanning.",
    },
    "full": {
        "max_iter": 80,
        "instructions": "No constraints. Maximum depth. Run every applicable tool. Include AD enumeration, binary analysis, static analysis, credential testing, SSL deep-dive.",
    },
    "apt_sim": {
        "max_iter": 60,
        "instructions": "Simulate an Advanced Persistent Threat. Phase 1: silent recon only. Phase 2: single targeted probe per service. Phase 3: exploit the highest-confidence path only. Phase 4: simulate lateral movement using discovered credentials. Map every action to MITRE ATT&CK.",
    },
}

# ---------------------------------------------------------------------------
# Full tool schema list (31 tools)
# ---------------------------------------------------------------------------

TOOL_SCHEMAS: List[Dict[str, Any]] = [
    # ── Reconnaissance ────────────────────────────────────────────────────────
    {
        "name": "nmap_scan",
        "description": "Run nmap port scan. Returns open ports, services, OS fingerprinting.",
        "input_schema": {"type": "object", "properties": {
            "target": {"type": "string", "description": "Target IP or hostname"},
            "ports": {"type": "string", "description": "Port spec e.g. '1-1000', '-' for all"},
            "timing": {"type": "integer", "description": "Timing 0-5", "default": 3},
            "flags": {"type": "string", "description": "Extra flags e.g. '-sV -sC'"},
            "aggressive": {"type": "boolean", "description": "Enable -A flag", "default": False},
        }, "required": ["target"]},
    },
    {
        "name": "masscan_scan",
        "description": "Ultra-fast port discovery across wide ranges.",
        "input_schema": {"type": "object", "properties": {
            "target": {"type": "string", "description": "Target IP or CIDR"},
            "ports": {"type": "string", "description": "Port range e.g. '0-65535'"},
            "rate": {"type": "integer", "description": "Packets per second", "default": 1000},
        }, "required": ["target"]},
    },
    {
        "name": "httpx_probe",
        "description": "Probe HTTP/HTTPS endpoints. Returns status codes, titles, tech detection.",
        "input_schema": {"type": "object", "properties": {
            "targets": {"type": "string", "description": "Comma-separated URLs or IPs"},
            "ports": {"type": "string", "description": "Ports to probe", "default": "80,443,8080,8443"},
            "threads": {"type": "integer", "description": "Concurrency", "default": 50},
            "follow_redirects": {"type": "boolean", "default": True},
        }, "required": ["targets"]},
    },
    {
        "name": "amass_enum",
        "description": "Comprehensive subdomain enumeration using passive and active techniques.",
        "input_schema": {"type": "object", "properties": {
            "domain": {"type": "string", "description": "Target domain"},
            "passive": {"type": "boolean", "description": "Passive only mode", "default": True},
        }, "required": ["domain"]},
    },
    {
        "name": "subfinder_discover",
        "description": "Fast passive subdomain discovery.",
        "input_schema": {"type": "object", "properties": {
            "domain": {"type": "string"},
            "timeout": {"type": "integer", "default": 60},
        }, "required": ["domain"]},
    },
    {
        "name": "dnsrecon_enumerate",
        "description": "DNS reconnaissance and zone transfer attempts.",
        "input_schema": {"type": "object", "properties": {
            "domain": {"type": "string"},
            "type": {"type": "string", "description": "std/rvl/brt/axfr/all", "default": "std"},
        }, "required": ["domain"]},
    },
    {
        "name": "harvester_gather",
        "description": "OSINT gathering: emails, hosts, IPs from public sources.",
        "input_schema": {"type": "object", "properties": {
            "domain": {"type": "string"},
            "sources": {"type": "string", "description": "Data sources e.g. 'bing,dnsdumpster'", "default": "bing,dnsdumpster,urlscan"},
            "limit": {"type": "integer", "default": 100},
        }, "required": ["domain"]},
    },
    # ── Web Scanning ──────────────────────────────────────────────────────────
    {
        "name": "nikto_scan",
        "description": "Web server vulnerability scanner — misconfigs, outdated software, dangerous files.",
        "input_schema": {"type": "object", "properties": {
            "target": {"type": "string"},
            "port": {"type": "integer"},
            "ssl": {"type": "boolean", "default": False},
            "timeout": {"type": "integer", "default": 300},
        }, "required": ["target"]},
    },
    {
        "name": "nuclei_scan",
        "description": "Template-based vulnerability scanner. Runs thousands of community CVE/misconfig checks.",
        "input_schema": {"type": "object", "properties": {
            "target": {"type": "string"},
            "severity": {"type": "string", "description": "info/low/medium/high/critical"},
            "templates": {"type": "string", "description": "Template path or tags"},
            "timeout": {"type": "integer", "default": 300},
        }, "required": ["target"]},
    },
    {
        "name": "whatweb_identify",
        "description": "Identify web technologies, CMS, frameworks, server versions.",
        "input_schema": {"type": "object", "properties": {
            "target": {"type": "string"},
            "aggression": {"type": "integer", "description": "1-4", "default": 1},
        }, "required": ["target"]},
    },
    {
        "name": "wafw00f_detect",
        "description": "Detect Web Application Firewalls protecting the target.",
        "input_schema": {"type": "object", "properties": {
            "url": {"type": "string"},
            "find_all": {"type": "boolean", "default": False},
        }, "required": ["url"]},
    },
    {
        "name": "gobuster_scan",
        "description": "Directory and file brute-forcing.",
        "input_schema": {"type": "object", "properties": {
            "target": {"type": "string", "description": "Target URL"},
            "wordlist": {"type": "string"},
            "extensions": {"type": "string", "description": "e.g. 'php,html,txt'"},
            "threads": {"type": "integer", "default": 10},
        }, "required": ["target"]},
    },
    {
        "name": "feroxbuster_scan",
        "description": "Recursive directory brute-forcer with automatic depth crawling.",
        "input_schema": {"type": "object", "properties": {
            "url": {"type": "string"},
            "depth": {"type": "integer", "default": 2},
            "threads": {"type": "integer", "default": 50},
            "extensions": {"type": "string"},
        }, "required": ["url"]},
    },
    {
        "name": "ffuf_fuzz",
        "description": "Fast web fuzzer for paths, parameters, headers, and POST data.",
        "input_schema": {"type": "object", "properties": {
            "url": {"type": "string", "description": "URL with FUZZ placeholder"},
            "wordlist": {"type": "string"},
            "method": {"type": "string", "default": "GET"},
            "match_codes": {"type": "string", "description": "e.g. '200,301,302'", "default": "200,301,302,403"},
        }, "required": ["url"]},
    },
    {
        "name": "wpscan_scan",
        "description": "WordPress-specific vulnerability scanner: plugins, themes, users, CVEs.",
        "input_schema": {"type": "object", "properties": {
            "url": {"type": "string"},
            "enumerate": {"type": "string", "description": "p=plugins,t=themes,u=users,vp=vulnerable plugins", "default": "vp,vt,u"},
            "aggressive": {"type": "boolean", "default": False},
        }, "required": ["url"]},
    },
    {
        "name": "xsstrike_test",
        "description": "XSS vulnerability detection with advanced payload generation.",
        "input_schema": {"type": "object", "properties": {
            "target": {"type": "string"},
            "crawl": {"type": "boolean", "default": False},
        }, "required": ["target"]},
    },
    {
        "name": "sqlmap_test",
        "description": "SQL injection detection and exploitation in safe check mode.",
        "input_schema": {"type": "object", "properties": {
            "target": {"type": "string"},
            "data": {"type": "string", "description": "POST data"},
            "cookies": {"type": "string"},
            "level": {"type": "integer", "default": 1},
            "risk": {"type": "integer", "default": 1},
        }, "required": ["target"]},
    },
    {
        "name": "commix_test",
        "description": "OS command injection detection and testing.",
        "input_schema": {"type": "object", "properties": {
            "url": {"type": "string"},
            "data": {"type": "string"},
            "cookie": {"type": "string"},
            "level": {"type": "integer", "default": 1},
            "technique": {"type": "string", "default": "all"},
        }, "required": ["url"]},
    },
    {
        "name": "arjun_discover",
        "description": "Discover hidden HTTP parameters in web applications.",
        "input_schema": {"type": "object", "properties": {
            "url": {"type": "string"},
            "method": {"type": "string", "default": "GET"},
            "rate_limit": {"type": "integer", "default": 50},
        }, "required": ["url"]},
    },
    {
        "name": "curl_probe",
        "description": "Send HTTP requests, inspect headers, response bodies, and server behavior.",
        "input_schema": {"type": "object", "properties": {
            "url": {"type": "string"},
            "method": {"type": "string", "default": "GET"},
            "headers": {"type": "object"},
            "follow_redirects": {"type": "boolean", "default": True},
            "timeout": {"type": "integer", "default": 30},
        }, "required": ["url"]},
    },
    # ── SSL / TLS ─────────────────────────────────────────────────────────────
    {
        "name": "sslscan_check",
        "description": "Comprehensive SSL/TLS analysis: ciphers, protocols, heartbleed, BEAST, POODLE.",
        "input_schema": {"type": "object", "properties": {
            "host": {"type": "string"},
            "port": {"type": "integer", "default": 443},
            "starttls": {"type": "string", "description": "Protocol for STARTTLS e.g. smtp"},
        }, "required": ["host"]},
    },
    {
        "name": "openssl_check",
        "description": "Check SSL certificate details, chain, and basic cipher negotiation.",
        "input_schema": {"type": "object", "properties": {
            "host": {"type": "string"},
            "port": {"type": "integer", "default": 443},
        }, "required": ["host"]},
    },
    # ── Authentication ────────────────────────────────────────────────────────
    {
        "name": "hydra_test",
        "description": "Credential brute-force against network services (SSH, FTP, HTTP, SMB).",
        "input_schema": {"type": "object", "properties": {
            "target": {"type": "string"},
            "service": {"type": "string", "description": "ssh/ftp/http-post-form/smb/rdp"},
            "userlist": {"type": "string"},
            "passlist": {"type": "string"},
            "threads": {"type": "integer", "default": 4},
        }, "required": ["target", "service"]},
    },
    {
        "name": "john_crack",
        "description": "Password hash cracking using John the Ripper.",
        "input_schema": {"type": "object", "properties": {
            "hash_file": {"type": "string", "description": "Path to hash file"},
            "wordlist": {"type": "string"},
            "format": {"type": "string", "description": "Hash format e.g. md5crypt, bcrypt, NT"},
        }, "required": ["hash_file"]},
    },
    # ── Windows / Active Directory ────────────────────────────────────────────
    {
        "name": "enum4linux_enumerate",
        "description": "Enumerate Windows/Samba hosts: users, shares, policies, OS info.",
        "input_schema": {"type": "object", "properties": {
            "target": {"type": "string"},
            "all": {"type": "boolean", "description": "Run all enumeration modules", "default": True},
        }, "required": ["target"]},
    },
    {
        "name": "netexec_run",
        "description": "Network execution framework for SMB, WinRM, LDAP, RDP lateral movement.",
        "input_schema": {"type": "object", "properties": {
            "target": {"type": "string"},
            "protocol": {"type": "string", "description": "smb/winrm/ldap/rdp/ssh"},
            "username": {"type": "string"},
            "password": {"type": "string"},
            "module": {"type": "string", "description": "NetExec module to run"},
            "command": {"type": "string"},
        }, "required": ["target", "protocol"]},
    },
    {
        "name": "impacket_run",
        "description": "Impacket suite: secretsdump, GetUserSPNs, lookupsid, wmiexec for AD attacks.",
        "input_schema": {"type": "object", "properties": {
            "script": {"type": "string", "description": "secretsdump/GetUserSPNs/GetNPUsers/lookupsid/wmiexec"},
            "target": {"type": "string"},
            "username": {"type": "string"},
            "password": {"type": "string"},
            "domain": {"type": "string"},
            "extra_args": {"type": "string"},
        }, "required": ["script", "target"]},
    },
    {
        "name": "kerbrute_run",
        "description": "Kerberos user enumeration and password spray against Active Directory.",
        "input_schema": {"type": "object", "properties": {
            "mode": {"type": "string", "description": "userenum/bruteuser/passwordspray/bruteforce"},
            "domain": {"type": "string"},
            "dc": {"type": "string", "description": "Domain controller IP"},
            "wordlist": {"type": "string"},
            "threads": {"type": "integer", "default": 10},
        }, "required": ["mode", "domain", "dc"]},
    },
    # ── Static Analysis ───────────────────────────────────────────────────────
    {
        "name": "semgrep_scan",
        "description": "Static analysis using Semgrep rules for security vulnerabilities in source code.",
        "input_schema": {"type": "object", "properties": {
            "path": {"type": "string", "description": "Path to code directory or file"},
            "config": {"type": "string", "description": "Rule config e.g. 'p/security-audit'", "default": "p/security-audit"},
            "language": {"type": "string"},
        }, "required": ["path"]},
    },
    {
        "name": "bandit_scan",
        "description": "Python security linter — finds common security issues in Python code.",
        "input_schema": {"type": "object", "properties": {
            "path": {"type": "string"},
            "severity": {"type": "string", "description": "l/m/h minimum severity", "default": "l"},
            "recursive": {"type": "boolean", "default": True},
        }, "required": ["path"]},
    },
    # ── Intelligence Tools ────────────────────────────────────────────────────
    {
        "name": "payload_crafter",
        "description": "Generate tech-stack-aware attack payloads with WAF bypass variants. Use when you need targeted payloads for a confirmed injection point.",
        "input_schema": {"type": "object", "properties": {
            "vuln_type": {"type": "string", "description": "sqli|xss|cmdi|lfi|ssrf|ssti|xxe|deserialization"},
            "tech_stack": {"type": "string", "description": "php|java|python|dotnet|node|ruby"},
            "context": {"type": "string", "description": "get_param|post_body|header|cookie|json_value", "default": "get_param"},
            "encoding": {"type": "string", "description": "none|url|base64|html", "default": "none"},
        }, "required": ["vuln_type", "tech_stack"]},
    },
    {
        "name": "binary_analyzer",
        "description": "Analyze binaries for suspicious patterns, hardcoded secrets, function symbols, and architecture info.",
        "input_schema": {"type": "object", "properties": {
            "binary_path": {"type": "string", "description": "Path to binary inside container"},
            "analysis_type": {"type": "string", "description": "strings|symbols|headers|all", "default": "all"},
        }, "required": ["binary_path"]},
    },
    {
        "name": "code_pattern_search",
        "description": "Deep static pattern search across source code for secrets, injection sinks, auth bypass, and weak crypto.",
        "input_schema": {"type": "object", "properties": {
            "path": {"type": "string", "description": "Directory to scan"},
            "pattern_set": {"type": "string", "description": "secrets|injections|auth_bypass|crypto_weak|all", "default": "all"},
            "extensions": {"type": "string", "description": "File extensions e.g. 'php,py,js'", "default": "php,py,js,java,rb"},
        }, "required": ["path"]},
    },
    # ── Novel Vulnerability Discovery ─────────────────────────────────────────
    {
        "name": "oob_check",
        "description": "Generate out-of-band callback URLs and check if the target triggered them. Use for detecting blind SSRF, blind XXE, blind command injection, and DNS rebinding. Essential for any parameter that could cause server-side HTTP/DNS requests (URL fields, XML input, redirects, file paths, email fields).",
        "input_schema": {"type": "object", "properties": {
            "action": {"type": "string", "description": "generate | check"},
            "description": {"type": "string", "description": "What vulnerability/parameter is being tested (for generate)"},
            "token": {"type": "string", "description": "Token returned from generate (for check)"},
        }, "required": ["action"]},
    },
    {
        "name": "differential_probe",
        "description": "Send multiple HTTP request variants with different parameter values and compare response behavior (status codes, content length, timing, body content). Detects boolean-based blind injection, auth inconsistencies, IDOR, and subtle data disclosure through behavioral differences.",
        "input_schema": {"type": "object", "properties": {
            "url": {"type": "string", "description": "Target URL — use PARAM as placeholder for the tested value e.g. 'http://host/search?q=PARAM'"},
            "values": {"type": "string", "description": "JSON array of test values e.g. [\"1\",\"1 OR 1=1\",\"' OR '1'='1\",\"1 AND SLEEP(3)\"]"},
            "method": {"type": "string", "description": "GET or POST", "default": "GET"},
            "headers": {"type": "string", "description": "JSON extra headers e.g. {\"Cookie\":\"session=abc\"}"},
        }, "required": ["url", "values"]},
    },
    {
        "name": "race_probe",
        "description": "Send multiple concurrent HTTP requests simultaneously to detect race conditions. Use on state-changing endpoints: balance deductions, coupon redemptions, vote counting, account actions. Detects TOCTOU (time-of-check/time-of-use) vulnerabilities that allow double-spending or privilege escalation.",
        "input_schema": {"type": "object", "properties": {
            "url": {"type": "string", "description": "Target URL"},
            "count": {"type": "integer", "description": "Number of concurrent requests (2-50)", "default": 10},
            "method": {"type": "string", "description": "GET or POST", "default": "POST"},
            "body": {"type": "string", "description": "Request body (same for all requests)"},
            "headers": {"type": "string", "description": "JSON extra headers e.g. {\"Cookie\":\"session=abc\",\"Authorization\":\"Bearer token\"}"},
        }, "required": ["url"]},
    },
    {
        "name": "session_memory",
        "description": "Persistent working memory for the current session. Store and query discovered endpoints, parameters, credentials, users, and findings to enable cross-endpoint correlation. Essential for detecting IDOR, privilege escalation, and multi-step attack chains that span multiple requests.",
        "input_schema": {"type": "object", "properties": {
            "action": {"type": "string", "description": "store | query"},
            "session_id": {"type": "string", "description": "Current session ID"},
            "category": {"type": "string", "description": "endpoints | params | credentials | users | paths | headers | cookies | notes"},
            "key": {"type": "string", "description": "Storage key (for store)"},
            "value": {"type": "string", "description": "Value to store — use JSON for structured data (for store)"},
        }, "required": ["action", "session_id"]},
    },
    # ── HTTP Vulnerability Analysis ─────────────────────────────────────────────
    {
        "name": "idor_probe",
        "description": "Test IDOR/BOLA by enumerating object IDs with attacker and victim auth tokens. Detects unauthorized object-level data access across sequential integer or UUID ID spaces.",
        "input_schema": {"type": "object", "properties": {
            "url_template": {"type": "string", "description": "URL with {id} placeholder e.g. https://api.example.com/users/{id}"},
            "own_token": {"type": "string", "description": "Auth header value for attacker user"},
            "other_token": {"type": "string", "description": "Auth header value for victim user to cross-validate"},
            "start_id": {"type": "integer", "description": "First integer ID to enumerate", "default": 1},
            "range": {"type": "integer", "description": "How many sequential IDs to test (max 50)", "default": 10},
            "ids": {"type": "string", "description": "JSON array of IDs to test (for UUIDs); overrides start_id+range"},
            "method": {"type": "string", "description": "GET or POST", "default": "GET"},
            "id_field": {"type": "string", "description": "For POST: JSON body field for the ID e.g. user_id"},
            "header_name": {"type": "string", "description": "Auth header name", "default": "Authorization"},
        }, "required": ["url_template", "own_token"]},
    },
    {
        "name": "cors_probe",
        "description": "Test CORS misconfiguration by sending 8 crafted Origin headers and detecting reflected Access-Control-Allow-Origin. Reflected ACAO + ACAC:true = critical credential-carrying CORS allowing full cross-origin data exfiltration.",
        "input_schema": {"type": "object", "properties": {
            "url": {"type": "string", "description": "Target URL"},
            "method": {"type": "string", "description": "HTTP method", "default": "GET"},
            "auth_header": {"type": "string", "description": "Authorization header value to test credentialed CORS"},
        }, "required": ["url"]},
    },
    {
        "name": "jwt_probe",
        "description": "JWT attack suite: alg:none bypass (4 case variants), blank secret, 15 common secrets brute-forced in-memory via HMAC, RS256-to-HS256 confusion with public key, kid header path traversal and SQLi injection.",
        "input_schema": {"type": "object", "properties": {
            "token": {"type": "string", "description": "The JWT string to attack"},
            "target_url": {"type": "string", "description": "URL that validates the JWT"},
            "header_name": {"type": "string", "description": "Header name", "default": "Authorization"},
            "header_prefix": {"type": "string", "description": "Prefix before token value", "default": "Bearer "},
            "public_key": {"type": "string", "description": "PEM public key for RS256-to-HS256 confusion attack"},
            "custom_secrets": {"type": "string", "description": "JSON array of extra secrets to brute-force"},
            "method": {"type": "string", "description": "HTTP method", "default": "GET"},
        }, "required": ["token", "target_url"]},
    },
    {
        "name": "graphql_probe",
        "description": "GraphQL security tester: introspection enabled check with schema enumeration, batch query rate-limit bypass, deep nesting DoS timing test, GET-based CSRF, field suggestion leakage, sensitive mutation discovery.",
        "input_schema": {"type": "object", "properties": {
            "url": {"type": "string", "description": "GraphQL endpoint URL"},
            "auth_header": {"type": "string", "description": "Authorization header value"},
            "batch_size": {"type": "integer", "description": "Number of queries in batching test", "default": 10},
            "depth_limit": {"type": "integer", "description": "Max nesting depth for DoS test", "default": 20},
        }, "required": ["url"]},
    },
    {
        "name": "ssti_detect",
        "description": "Server-Side Template Injection detector. Sends 10 math-expression probes covering Jinja2, Twig, FreeMarker, ERB, SpEL, Tornado, and Razor. Engine fingerprinted by which result appears. Confirms RCE pathway via MRO chain without execution.",
        "input_schema": {"type": "object", "properties": {
            "url": {"type": "string", "description": "Target URL"},
            "parameter": {"type": "string", "description": "Parameter name to inject into"},
            "method": {"type": "string", "description": "GET or POST", "default": "GET"},
            "baseline_value": {"type": "string", "description": "Normal parameter value for baseline", "default": "test"},
            "auth_header": {"type": "string", "description": "Authorization header value"},
            "content_type": {"type": "string", "description": "For POST: form or json", "default": "form"},
        }, "required": ["url", "parameter"]},
    },
    {
        "name": "nosql_probe",
        "description": "NoSQL injection tester for MongoDB. Injects $ne/$gt/$regex/$where/$nin operators as JSON body and bracket-notation query params. Boolean blind detection via always-true vs always-false payload length comparison. Infers database type from behavior and MongoError strings.",
        "input_schema": {"type": "object", "properties": {
            "url": {"type": "string", "description": "Target URL"},
            "parameter": {"type": "string", "description": "Parameter name to inject into"},
            "method": {"type": "string", "description": "GET or POST", "default": "POST"},
            "auth_header": {"type": "string", "description": "Authorization header value"},
            "baseline_value": {"type": "string", "description": "Valid parameter value for baseline", "default": "test"},
        }, "required": ["url", "parameter"]},
    },
    {
        "name": "cache_probe",
        "description": "Cache poisoning and web cache deception tester. Tests X-Forwarded-Host reflection, X-Original-URL path override, unkeyed IP header access control bypass, static extension cache deception, fat GET body poisoning, and cache header analysis.",
        "input_schema": {"type": "object", "properties": {
            "url": {"type": "string", "description": "Target URL"},
            "auth_header": {"type": "string", "description": "Authorization header value (important for cache deception testing)"},
        }, "required": ["url"]},
    },
    {
        "name": "prototype_pollution_probe",
        "description": "JavaScript prototype pollution tester. Sends __proto__ and constructor.prototype payloads via POST body and query string. Detects server-side state mutation via canary requests after each payload. Also detects direct reflection and server crashes.",
        "input_schema": {"type": "object", "properties": {
            "url": {"type": "string", "description": "Target URL"},
            "method": {"type": "string", "description": "GET or POST", "default": "POST"},
            "auth_header": {"type": "string", "description": "Authorization header value"},
            "base_body": {"type": "string", "description": "JSON string of normal request body to merge payloads into"},
        }, "required": ["url"]},
    },
    {
        "name": "oauth_probe",
        "description": "OAuth 2.0 / OIDC security tester. Tests redirect_uri bypass via 8 variants (path traversal, fragment, subdomain, suffix, scheme-relative, scheme change), state parameter omission CSRF, and PKCE downgrade. Manual redirect following to inspect each hop.",
        "input_schema": {"type": "object", "properties": {
            "authorize_url": {"type": "string", "description": "OAuth authorization endpoint URL"},
            "client_id": {"type": "string", "description": "OAuth client ID"},
            "redirect_uri": {"type": "string", "description": "Legitimate registered redirect URI"},
            "token_url": {"type": "string", "description": "Token endpoint URL"},
            "state": {"type": "string", "description": "State parameter value (omit to test enforcement)"},
            "scope": {"type": "string", "description": "Requested scope", "default": "openid profile"},
            "auth_code": {"type": "string", "description": "Authorization code if already obtained"},
        }, "required": ["authorize_url", "client_id", "redirect_uri"]},
    },
    {
        "name": "http_smuggling_probe",
        "description": "HTTP request smuggling detector using raw TCP sockets via node:net. Tests CL.TE, TE.CL, and TE.TE obfuscation variants. Detects desync via timing differential > 5s compared to baseline. Bypasses Node.js HTTP header normalization.",
        "input_schema": {"type": "object", "properties": {
            "url": {"type": "string", "description": "Target HTTP/1.1 URL — not HTTP/2-only"},
            "timeout_ms": {"type": "integer", "description": "Per-test socket timeout in ms", "default": 10000},
        }, "required": ["url"]},
    },
]


_BLIND_VULN_KEYWORDS = (
    "blind ",
    " blind",
    "blind-",
    "out-of-band",
    "out of band",
    " oob",
    "oob ",
    "time-based",
    "time based",
    "dns exfil",
    "dns-exfil",
)


def _is_blind_vuln(title: str, description: str) -> bool:
    haystack = f" {title.lower()} {description.lower()} "
    return any(kw in haystack for kw in _BLIND_VULN_KEYWORDS)


# Chain-follow-up suggestions keyed by substring match against title+description.
# First match wins; order matters (more specific before more generic).
_CHAIN_SUGGESTIONS: List[tuple] = [
    ("sqli", (
        "Next steps for SQL injection: "
        "(1) dump database/schema names and table list, "
        "(2) locate the users or credentials table and exfiltrate rows, "
        "(3) attempt sqlmap --os-shell or UDF if the DB user is privileged, "
        "(4) re-read tainted fields elsewhere in the app for second-order SQLi."
    )),
    ("sql injection", (
        "Next steps for SQL injection: dump schema, read credentials table, "
        "attempt --os-shell, check for second-order reuse."
    )),
    ("ssrf", (
        "Next steps for SSRF: "
        "(1) probe cloud metadata (http://169.254.169.254/latest/meta-data/, "
        "http://metadata.google.internal/), "
        "(2) enumerate internal services (127.0.0.1 and private RFC1918 ranges on common ports), "
        "(3) test gopher://, file://, and dict:// if the parser allows, "
        "(4) always use oob_check to confirm external callback capability before claiming confirmed."
    )),
    ("file upload", (
        "Next steps for file upload: "
        "(1) test executable extensions for the detected stack (.jsp/.jspx, .php/.phtml, .asp/.aspx), "
        "(2) try polyglots (valid image + server code), "
        "(3) test path traversal in the filename field, "
        "(4) locate the stored path and chain to LFI/RCE."
    )),
    ("idor", (
        "Next steps for IDOR: "
        "(1) enumerate neighboring IDs (+/-5, +/-10), "
        "(2) test cross-tenant access with a different org_id / account_id, "
        "(3) attempt low-numeric IDs (1, 2, 'admin') that may belong to administrative entities, "
        "(4) re-test the same object via PUT and DELETE — read-IDOR often hides write-IDOR."
    )),
    ("jwt", (
        "Next steps for JWT weakness: "
        "(1) mint an admin token (flip role/isAdmin/sub claims), "
        "(2) hit admin-only endpoints with the forged token, "
        "(3) test kid injection (path traversal, SQLi) to override signing key, "
        "(4) check refresh-token reuse and replay windows."
    )),
    ("graphql", (
        "Next steps for GraphQL introspection: "
        "(1) enumerate every mutation and test auth on each, "
        "(2) try batched queries to amplify data or bypass rate limits, "
        "(3) exploit field-suggestion leakage with deliberate typos, "
        "(4) look for sensitive types (UserSecret, AdminUser, PrivateKey)."
    )),
    ("cors", (
        "Next steps for CORS misconfiguration: "
        "(1) craft a PoC HTML page that fetches credentialed data cross-origin, "
        "(2) identify which Origin values are accepted (null, subdomain, arbitrary), "
        "(3) chain with session/auth endpoints to exfiltrate user data."
    )),
    ("xxe", (
        "Next steps for XXE: "
        "(1) attempt external entity for file disclosure (/etc/passwd, WEB-INF/web.xml), "
        "(2) use oob_check for blind XXE via HTTP or DNS callback, "
        "(3) try parameter-entity chains for OOB exfiltration of file contents."
    )),
    ("rce", (
        "Next steps for RCE: "
        "(1) enumerate user context (whoami, id, uname -a) and filesystem layout, "
        "(2) look for cached credentials, env vars, .aws/config, ~/.ssh, "
        "(3) attempt lateral movement to adjacent services on internal network, "
        "(4) check privilege escalation vectors (sudoers, SUID, capabilities)."
    )),
    ("command injection", (
        "Next steps for command injection: "
        "(1) establish a reliable exec primitive (blind vs. return-channel), "
        "(2) exfiltrate via oob_check if output is not reflected, "
        "(3) enumerate env vars and filesystem, "
        "(4) pivot to RCE next-step playbook."
    )),
    ("prototype pollution", (
        "Next steps for prototype pollution: "
        "(1) find a pollution-to-RCE gadget in the app (common in Express/lodash stacks), "
        "(2) poison admin-flag properties (isAdmin, isAuthenticated, role) and retest privileged endpoints, "
        "(3) check downstream template engines for polluted-property-based SSTI."
    )),
    ("ssti", (
        "Next steps for SSTI: "
        "(1) confirm the template engine via a math probe, "
        "(2) walk the MRO / globals / context to reach os / subprocess, "
        "(3) escalate to RCE and follow the RCE playbook."
    )),
    ("open redirect", (
        "Next steps for open redirect: "
        "(1) chain to OAuth redirect_uri bypass if the app has OAuth flows, "
        "(2) use as phishing vector with trusted domain in URL, "
        "(3) test for reflected-XSS via javascript: or data: schemes if scheme is not filtered."
    )),
    ("oauth", (
        "Next steps for OAuth flaw: "
        "(1) attempt redirect_uri bypass variants (subdomain, suffix, path), "
        "(2) omit state and confirm CSRF exploitability, "
        "(3) test PKCE downgrade, "
        "(4) look for account-linking / grant-type confusion."
    )),
    ("auth bypass", (
        "Next steps for auth bypass: "
        "(1) enumerate admin/restricted endpoints and retest with the bypass, "
        "(2) look for session fixation / token reuse possibilities, "
        "(3) check horizontal + vertical privilege escalation paths from this foothold."
    )),
]


def _match_chain_suggestion(title: str, description: str) -> Optional[str]:
    haystack = f"{title} {description}".lower()
    for keyword, suggestion in _CHAIN_SUGGESTIONS:
        if keyword in haystack:
            return suggestion
    return None


# Per-call timeout for Anthropic messages.create(). Two jobs:
#   1. Sets the actual HTTP read deadline — a single slow generation with
#      extended thinking + tool results can genuinely take 10+ minutes.
#   2. Silences the SDK's "Streaming is strongly recommended" ValueError,
#      which fires when expected_duration (max_tokens / ~20 tok/s) exceeds
#      the request timeout. 20 minutes is well above our max_tokens=16000
#      worst-case estimate (~13 min) and comfortably absorbs jitter.
_ANTHROPIC_TIMEOUT_SECONDS = 1200.0
# Shorter timeouts are fine (and cheaper) for the ancillary calls that only
# ever produce a few hundred tokens.
_ANTHROPIC_TIMEOUT_SHORT_SECONDS = 120.0


def _max_tokens_for_model(model: str) -> int:
    """Return the model-appropriate output-token ceiling.

    We derive this from the model name rather than reading `llm_max_tokens`
    from app settings because the Anthropic API enforces two constraints
    that the operator's raw number would silently violate:
      (1) `max_tokens > thinking.budget_tokens`
      (2) the Anthropic Python SDK refuses non-streaming calls whose
          max_tokens is high enough that the call could exceed the 10-minute
          read timeout (raises `ValueError: Streaming is strongly
          recommended...`).

    16 000 is the highest non-streaming-safe value across the Claude 4.x
    family and leaves 8 000 tokens of headroom above our peak thinking
    budget (8 000), so actual tool-selection output never starves.
    Haiku is capped lower — it is only used as the adversarial critic and
    never emits extended thinking.
    """
    m = (model or "").lower()
    if "haiku" in m:
        return 8192
    if "opus" in m or "sonnet" in m:
        return 16000
    return 8192  # conservative default for unrecognised models


def _thinking_budget(iteration: int, max_iter: int, max_tokens: int | None = None) -> int:
    """Adaptive thinking token budget.

    Heavy reasoning at the start (forming the initial hypothesis) and near the
    end (correlating all findings into kill chains). Routine mid-session tool
    selection needs far fewer tokens.

    Always clamped strictly below `max_tokens` when provided — Anthropic
    requires `max_tokens > thinking.budget_tokens`. We reserve at least 2048
    tokens for actual output and a further 1024-token floor for the budget.
    """
    pct = iteration / max_iter if max_iter else 0.0
    if pct <= 0.10 or pct >= 0.85:
        target = 8000   # first 10 % and last 15 % — deep reasoning
    else:
        target = 3000   # routine tool-selection iterations
    if max_tokens is None:
        return target
    ceiling = max(1024, max_tokens - 2048)
    return min(target, ceiling)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class AIOrchestrator:
    """
    GENESIS MYTHOS autonomous research engine.

    Key differences from basic orchestrator:
    - Extended thinking enabled (10k token budget)
    - All 35 tools exposed to Claude (includes OOB, differential, race, session memory)
    - Non-linear free-form loop (Claude decides path)
    - Topology tracking (network graph built as discoveries happen)
    - Attack chain attribution via attack_chain_id
    - Patch generation, MITRE ATT&CK mapping, zero-day flagging
    - Cross-session intelligence recall at session start
    - Hypothesis journal: structured hypotheses tracked across iterations
    - Adversarial critic: lightweight challenge on each confirmed finding
    """

    def __init__(self) -> None:
        self._critic_client: Optional[AsyncAnthropic] = None
        self._critic_model: str = "claude-haiku-4-5-20251001"

    async def get_settings(self) -> Dict[str, str]:
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(AppSettings))
            rows = result.scalars().all()
            return {row.key: row.value for row in rows}

    def build_client(self, app_settings: Dict[str, str]) -> AsyncAnthropic:
        api_key = app_settings.get("llm_api_key", "")
        provider = app_settings.get("llm_provider", "anthropic")

        if provider == "azure":
            base_url = app_settings.get("azure_endpoint", "").rstrip("/")
            if base_url.endswith("/v1/messages"):
                base_url = base_url[: -len("/v1/messages")]
            elif base_url.endswith("/v1"):
                base_url = base_url[: -len("/v1")]
            return AsyncAnthropic(api_key=api_key, base_url=base_url)

        return AsyncAnthropic(api_key=api_key)

    async def run_session(self, session_id: str, target_ip: str) -> None:
        logger.info("[MYTHOS] Starting session %s for target %s", session_id, target_ip)

        # Celery tasks create a fresh asyncio loop per invocation via asyncio.run().
        # asyncpg and Motor both bind to the loop they were first used on; reusing
        # them on a new loop raises "Event loop is closed". Belt and braces:
        #   - the Postgres engine now uses NullPool (no pooled connections).
        #   - dispose() is still called defensively in case any connection leaked.
        #   - the Motor module-level client is dropped so the next access rebuilds
        #     it on *this* task's loop.
        try:
            from app.database.postgres import engine as _pg_engine
            await _pg_engine.dispose()
        except Exception as exc:
            logger.debug("Engine dispose at session start failed (non-fatal): %s", exc)
        try:
            from app.database.mongodb import reset_mongo_client
            reset_mongo_client()
        except Exception as exc:
            logger.debug("Mongo client reset at session start failed (non-fatal): %s", exc)

        try:
            app_settings = await self.get_settings()
        except Exception as exc:
            logger.error("Failed to load settings: %s", exc)
            await self._record_error(session_id, "settings_load", exc)
            await self._set_session_failed(session_id, f"Settings load failed: {exc}")
            return

        client = self.build_client(app_settings)
        self._critic_client = client
        self._critic_model = app_settings.get("llm_model", "claude-haiku-4-5-20251001")
        mcp = MCPClient(timeout=float(app_settings.get("scan_timeout", "3600")))
        model = app_settings.get("llm_model", "claude-opus-4-7")
        # max_tokens is derived from the model family, not read from settings:
        # operator-controlled values were colliding with the extended-thinking
        # budget (Anthropic requires max_tokens > thinking.budget_tokens).
        max_tokens = _max_tokens_for_model(model)

        # Load session to get scan_profile and agent_mode
        session_obj = await self._load_session(session_id)
        scan_profile = getattr(session_obj, "scan_profile", "deep") if session_obj else "deep"
        agent_mode = getattr(session_obj, "agent_mode", "solo") if session_obj else "solo"

        profile = SCAN_PROFILES.get(scan_profile, SCAN_PROFILES["deep"])
        max_iter = int(app_settings.get("max_iterations", str(profile["max_iter"])))

        # Delegate to multi-agent orchestrator if configured
        if agent_mode == "multi_agent":
            logger.info("[MYTHOS] Routing session %s to MultiAgentOrchestrator", session_id)
            from app.services.multi_agent_orchestrator import MultiAgentOrchestrator
            orchestrator = MultiAgentOrchestrator(
                session_id=session_id,
                target=target_ip,
                publish_fn=publish_session_message,
                save_vuln_fn=self._save_vulnerability,
                store_thought_fn=self._store_thought,
                store_deep_thought_fn=self._store_deep_thought,
            )
            try:
                await orchestrator.run()
            except Exception as exc:
                logger.exception("MultiAgentOrchestrator error: %s", exc)
                await self._set_session_failed(session_id, str(exc))
                return
            await self._finalize_session(session_id)
            await self._store_intelligence(session_id)
            await publish_session_message(session_id, {
                "type": "session_complete",
                "data": {"summary": "Multi-agent MYTHOS assessment completed.", "mode": "multi_agent"},
                "timestamp": _now_iso(),
            })
            return

        # Recall relevant intelligence from past sessions
        intelligence_context = await self._recall_intelligence(target_ip)

        # NOTE: use str.replace(), not str.format(), because the prompt contains
        # literal JSON examples like {"HYPOTHESIS": {...}} whose braces would be
        # interpreted as format placeholders and raise KeyError.
        system_prompt = (
            MYTHOS_SYSTEM_PROMPT
            .replace("{target}", target_ip)
            .replace("{session_id}", session_id)
            .replace("{scan_profile}", scan_profile)
            .replace("{agent_mode}", agent_mode)
            .replace("{profile_instructions}", profile["instructions"])
        )

        if intelligence_context:
            system_prompt += f"\n\n## Intelligence from Similar Past Targets\n{intelligence_context}"

        # ── Prompt caching (Anthropic only) ────────────────────────────────
        # Wrap system and the last tool schema with cache_control so the
        # static prefix is billed at $0.30/M on every cached read instead
        # of $3/M.  Azure does not support this feature.
        provider = app_settings.get("llm_provider", "anthropic")
        use_caching = provider == "anthropic" and ("claude" in model or "sonnet" in model or "opus" in model)

        if use_caching:
            system_for_api: Any = [
                {"type": "text", "text": system_prompt, "cache_control": {"type": "ephemeral"}}
            ]
            # Copy tool list so the module-level constant is not mutated
            cached_tools: List[Dict[str, Any]] = [dict(t) for t in TOOL_SCHEMAS]
            cached_tools[-1] = dict(cached_tools[-1])
            cached_tools[-1]["cache_control"] = {"type": "ephemeral"}
        else:
            system_for_api = system_prompt
            cached_tools = TOOL_SCHEMAS

        messages: List[Dict[str, Any]] = []
        iteration = 0
        network_topology: Dict[str, Any] = {"nodes": [], "edges": []}
        # U2: ring buffer of recent tool-call signatures (last 5)
        recent_tool_sigs: List[str] = []
        loop_break_count = 0
        # U3: chain-follow-up nudges pulled from confirmed vulnerabilities,
        #     injected on the *next* user turn so the model acts on them.
        pending_chain_nudges: List[str] = []

        messages.append({
            "role": "user",
            "content": (
                f"Begin comprehensive autonomous security assessment of target: {target_ip}. "
                f"Scan profile: {scan_profile}. You have full autonomy — decide your own strategy. "
                "Start by forming a hypothesis about the target, then begin reconnaissance."
            ),
        })

        try:
            while iteration < max_iter:
                status = await self._get_session_status(session_id)
                if status in ("failed", "stopped"):
                    break
                if status == "paused":
                    return

                iteration += 1
                await self._update_session(session_id, iteration=iteration)

                # Wrap-up injection at 90% of max_iter
                if iteration == int(max_iter * 0.9):
                    messages.append({"role": "user", "content":
                        "You are approaching the iteration limit. Begin wrapping up: confirm your "
                        "highest-confidence findings, generate exploit_code and patch_code for each, "
                        "assign attack_chain_ids, map MITRE techniques, and emit a FINAL_REPORT block."
                    })

                # ── History compression every 15 iterations ─────────────────
                messages = await self._compress_history(messages, client, model, iteration)

                # ── Call Claude with extended thinking ──────────────────────
                try:
                    create_kwargs: Dict[str, Any] = dict(
                        model=model,
                        max_tokens=max_tokens,
                        system=system_for_api,
                        tools=cached_tools,
                        messages=messages,
                        timeout=_ANTHROPIC_TIMEOUT_SECONDS,
                    )
                    # Enable extended thinking if model supports it
                    if "opus" in model or "sonnet" in model:
                        budget = _thinking_budget(iteration, max_iter, max_tokens)
                        create_kwargs["thinking"] = {"type": "enabled", "budget_tokens": budget}
                    # Activate prompt caching beta header
                    if use_caching:
                        create_kwargs["extra_headers"] = {"anthropic-beta": "prompt-caching-2024-07-31"}

                    response = await client.messages.create(**create_kwargs)
                except Exception as exc:
                    logger.error("Claude API error in session %s: %s", session_id, exc)
                    await self._record_error(
                        session_id,
                        "anthropic_api",
                        exc,
                        iteration=iteration,
                        context={
                            "model": model,
                            "max_tokens": max_tokens,
                            "message_count": len(messages),
                        },
                    )
                    await self._set_session_failed(
                        session_id, f"Claude API error: {type(exc).__name__}: {str(exc)[:500]}"
                    )
                    return

                messages.append({"role": "assistant", "content": response.content})

                # ── Extract thinking blocks ─────────────────────────────────
                for block in response.content:
                    if getattr(block, "type", None) == "thinking":
                        thinking_text = getattr(block, "thinking", "")
                        if thinking_text:
                            await publish_session_message(session_id, {
                                "type": "deep_thought",
                                "data": {"content": thinking_text, "iteration": iteration},
                                "timestamp": _now_iso(),
                            })
                            await self._store_deep_thought(session_id, thinking_text, iteration)

                # ── Extract and publish text / agent thoughts ───────────────
                text_blocks = [b for b in response.content if hasattr(b, "text") and b.text]
                text_content = " ".join(b.text for b in text_blocks).strip()

                if text_content:
                    await publish_session_message(session_id, {
                        "type": "agent_thought",
                        "data": {"thought": text_content, "iteration": iteration},
                        "timestamp": _now_iso(),
                    })
                    await self._store_thought(session_id, text_content, iteration)
                    new_nudges = await self._extract_and_save_vulnerabilities(
                        session_id, text_content
                    )
                    if new_nudges:
                        pending_chain_nudges.extend(new_nudges)
                    await self._extract_and_save_hypotheses(session_id, text_content)

                    # Extract topology updates
                    network_topology = await self._extract_topology_updates(
                        session_id, text_content, network_topology
                    )

                    # Check for FINAL_REPORT
                    if "FINAL_REPORT" in text_content:
                        logger.info("[MYTHOS] Session %s emitted FINAL_REPORT", session_id)
                        break

                # ── Handle stop reason ──────────────────────────────────────
                if response.stop_reason == "end_turn":
                    if "FINAL_REPORT" not in text_content:
                        # Claude finished a thought but didn't wrap up — continue.
                        # If there are pending chain nudges, deliver them here.
                        continue_parts = [
                            "Continue your assessment. What is your next hypothesis or action?"
                        ]
                        if pending_chain_nudges:
                            continue_parts.append("\n\n".join(pending_chain_nudges))
                            pending_chain_nudges = []
                        messages.append({
                            "role": "user",
                            "content": "\n\n".join(continue_parts),
                        })

                elif response.stop_reason == "tool_use":
                    tool_result_blocks: List[Dict[str, Any]] = []
                    wedge_hit = False

                    for block in response.content:
                        if not hasattr(block, "type") or block.type != "tool_use":
                            continue

                        tool_name: str = block.name
                        tool_params: Dict[str, Any] = block.input or {}
                        tool_use_id: str = block.id

                        # U2: ring-buffer of tool-call signatures for wedge detection
                        try:
                            import hashlib
                            param_blob = json.dumps(tool_params, sort_keys=True, default=str)
                            sig = f"{tool_name}:{hashlib.sha1(param_blob.encode()).hexdigest()[:12]}"
                        except Exception:
                            sig = f"{tool_name}:{id(tool_params)}"
                        recent_tool_sigs.append(sig)
                        if len(recent_tool_sigs) > 5:
                            recent_tool_sigs.pop(0)
                        if (
                            len(recent_tool_sigs) >= 3
                            and recent_tool_sigs[-1] == recent_tool_sigs[-2] == recent_tool_sigs[-3]
                        ):
                            wedge_hit = True

                        await publish_session_message(session_id, {
                            "type": "tool_execution",
                            "data": {
                                "tool": tool_name, "status": "running",
                                "params": tool_params, "iteration": iteration,
                            },
                            "timestamp": _now_iso(),
                        })

                        start_time = datetime.now(timezone.utc)
                        try:
                            result = await mcp.execute_tool(tool_name, tool_params)
                        except Exception as tool_exc:
                            logger.warning(
                                "MCP tool call raised in session %s (tool=%s): %s",
                                session_id, tool_name, tool_exc,
                            )
                            await self._record_error(
                                session_id,
                                "mcp_call",
                                tool_exc,
                                iteration=iteration,
                                tool=tool_name,
                                context={"params_keys": list(tool_params.keys())[:10]},
                            )
                            result = {"output": f"[tool call failed: {tool_exc}]", "error": str(tool_exc)}
                        duration = (datetime.now(timezone.utc) - start_time).total_seconds()

                        # Non-fatal tool-level error signals (timeouts, bad params, target unreachable).
                        # Recorded for the operator but the session continues — the model can pivot.
                        tool_error_signal = result.get("error") if isinstance(result, dict) else None
                        if tool_error_signal:
                            await self._record_error(
                                session_id,
                                "tool_execute",
                                str(tool_error_signal),
                                iteration=iteration,
                                tool=tool_name,
                                context={"params_keys": list(tool_params.keys())[:10]},
                                publish=False,   # too noisy to push every tool error to WS
                            )

                        await self._store_tool_output(session_id, tool_name, tool_params, result, duration)

                        raw_output = result.get("output", "") or ""
                        parsed = result.get("parsed") or {}

                        await publish_session_message(session_id, {
                            "type": "tool_execution",
                            "data": {
                                "tool": tool_name, "status": "complete",
                                "params": tool_params,
                                "output": raw_output[:2000],
                                "parsed": parsed,
                                "duration_seconds": duration,
                                "iteration": iteration,
                            },
                            "timestamp": _now_iso(),
                        })

                        result_content = json.dumps(parsed if parsed else {"output": raw_output[:3000]})
                        tool_result_blocks.append({
                            "type": "tool_result",
                            "tool_use_id": tool_use_id,
                            "content": result_content,
                        })

                    # Build the next user turn: tool_results first (paired with tool_use_id),
                    # then any chain-follow-up nudges, then wedge nudge, as text blocks.
                    if tool_result_blocks:
                        content_blocks: List[Dict[str, Any]] = list(tool_result_blocks)

                        if pending_chain_nudges:
                            for nudge in pending_chain_nudges:
                                content_blocks.append({"type": "text", "text": nudge})
                            pending_chain_nudges = []

                        if wedge_hit:
                            loop_break_count += 1
                            wedged_tool = recent_tool_sigs[-1].split(":", 1)[0]
                            wedge_text = (
                                f"[LOOP_GUARD] You have invoked `{wedged_tool}` with identical "
                                f"parameters 3 times in a row. The input is not yielding new "
                                f"information. Summarize what you know, then pivot to a different "
                                f"tool or a different parameter set, or emit your FINAL_REPORT block."
                            )
                            content_blocks.append({"type": "text", "text": wedge_text})
                            await publish_session_message(session_id, {
                                "type": "loop_break",
                                "data": {
                                    "tool": wedged_tool,
                                    "iteration": iteration,
                                    "count": loop_break_count,
                                },
                                "timestamp": _now_iso(),
                            })
                            recent_tool_sigs.clear()
                            if loop_break_count >= 2:
                                content_blocks.append({
                                    "type": "text",
                                    "text": (
                                        "[LOOP_GUARD] Multiple wedged-loop events detected this "
                                        "session. Emit your FINAL_REPORT block now based on what "
                                        "you already know."
                                    ),
                                })

                        messages.append({"role": "user", "content": content_blocks})

                else:
                    logger.warning("Unexpected stop_reason '%s'", response.stop_reason)
                    break

        except Exception as exc:
            logger.exception("Unhandled error in session %s: %s", session_id, exc)
            await self._record_error(
                session_id,
                "unhandled",
                exc,
                iteration=iteration,
                context={"target_ip": target_ip},
            )
            await self._set_session_failed(
                session_id, f"Orchestrator error: {type(exc).__name__}: {str(exc)[:500]}"
            )
            return

        # ── Finalize ────────────────────────────────────────────────────────
        await self._finalize_session(session_id)

        # Store intelligence for future sessions
        await self._store_intelligence(session_id)

        await publish_session_message(session_id, {
            "type": "session_complete",
            "data": {"summary": "MYTHOS assessment completed.", "iterations": iteration},
            "timestamp": _now_iso(),
        })
        logger.info("[MYTHOS] Session %s completed after %d iterations", session_id, iteration)

    # -------------------------------------------------------------------------
    # Intelligence recall
    # -------------------------------------------------------------------------

    async def _recall_intelligence(self, target: str) -> str:
        """Build an intelligence-recall block for the system prompt.

        Combines two views:
          - Session-level aggregates (services + top MITRE techniques)
          - Per-technique bullets (what worked, what didn't) from similar targets
        """
        try:
            from app.services.intelligence_library import IntelligenceLibrary
            lib = IntelligenceLibrary()
            patterns = await lib.recall_patterns(target, n=3)
            techniques = await lib.recall_techniques(target, n=8)
        except Exception as exc:
            logger.debug("Intelligence recall failed: %s", exc)
            return ""

        lines: List[str] = []
        if patterns:
            lines.append("### Similar past sessions")
            for p in patterns:
                meta = p.get("metadata", {}) or {}
                lines.append(
                    f"- session {meta.get('session_id', '?')}: "
                    f"vulns={meta.get('vuln_count', 0)}, "
                    f"max_severity={meta.get('max_severity', 'unknown')}, "
                    f"services={meta.get('services', '')[:80]}, "
                    f"MITRE={meta.get('mitre_techniques', '')[:80]}"
                )

        if techniques:
            positives = [t for t in techniques if t.get("success")]
            negatives = [t for t in techniques if not t.get("success")]
            if positives:
                lines.append("")
                lines.append("### What worked on similar targets (reuse these playbooks)")
                for t in positives[:6]:
                    meta = t.get("metadata", {}) or {}
                    lines.append(
                        f"- {meta.get('technique_tag') or meta.get('title', '?')} "
                        f"via {meta.get('tool', '?')} on {meta.get('service', '?')} "
                        f"(endpoint: {meta.get('endpoint', 'n/a')})"
                    )
            if negatives:
                lines.append("")
                lines.append(
                    "### Dead ends on similar targets (previously tried, did not succeed — deprioritize)"
                )
                for t in negatives[:4]:
                    meta = t.get("metadata", {}) or {}
                    lines.append(
                        f"- {meta.get('technique_tag') or meta.get('title', '?')} "
                        f"via {meta.get('tool', '?')} on {meta.get('service', '?')} "
                        f"-> {meta.get('status', 'unverified')}"
                    )

        return "\n".join(lines)

    async def _store_intelligence(self, session_id: str) -> None:
        try:
            from app.services.intelligence_library import IntelligenceLibrary
            async with AsyncSessionLocal() as db:
                await IntelligenceLibrary().store_session_patterns(session_id, db)
        except Exception as exc:
            logger.warning("Intelligence store failed for session %s: %s", session_id, exc)

    # -------------------------------------------------------------------------
    # Topology extraction
    # -------------------------------------------------------------------------

    async def _extract_topology_updates(
        self,
        session_id: str,
        text: str,
        current_topology: Dict[str, Any],
    ) -> Dict[str, Any]:
        marker = '"TOPOLOGY_UPDATE"'
        pos = 0
        while True:
            idx = text.find(marker, pos)
            if idx == -1:
                break
            start = text.rfind("{", 0, idx)
            if start == -1:
                pos = idx + len(marker)
                continue
            depth = 0
            i = start
            in_string = False
            escape_next = False
            while i < len(text):
                ch = text[i]
                if escape_next:
                    escape_next = False
                elif ch == "\\" and in_string:
                    escape_next = True
                elif ch == '"':
                    in_string = not in_string
                elif not in_string:
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            try:
                                outer = json.loads(text[start : i + 1])
                                update_data = outer.get("TOPOLOGY_UPDATE", {})
                                action = update_data.get("action")
                                if action == "add_node":
                                    node = update_data.get("node", {})
                                    if node and not any(n["id"] == node["id"] for n in current_topology["nodes"]):
                                        current_topology["nodes"].append(node)
                                elif action == "add_edge":
                                    edge = update_data.get("edge", {})
                                    if edge:
                                        current_topology["edges"].append(edge)
                                # Persist topology to DB and broadcast
                                await self._update_topology(session_id, current_topology)
                                await publish_session_message(session_id, {
                                    "type": "topology_update",
                                    "data": current_topology,
                                    "timestamp": _now_iso(),
                                })
                            except Exception:
                                pass
                            pos = i + 1
                            break
                i += 1
            else:
                pos = idx + len(marker)
        return current_topology

    async def _update_topology(self, session_id: str, topology: Dict[str, Any]) -> None:
        try:
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ResearchSession)
                    .where(ResearchSession.id == uuid.UUID(session_id))
                    .values(network_topology=topology)
                )
                await db.commit()
        except Exception as exc:
            logger.error("Failed to update topology for %s: %s", session_id, exc)

    # -------------------------------------------------------------------------
    # Deep thought storage (MongoDB collection)
    # -------------------------------------------------------------------------

    async def _record_error(
        self,
        session_id: str,
        phase: str,
        exc: BaseException | str,
        *,
        iteration: Optional[int] = None,
        tool: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        publish: bool = True,
    ) -> None:
        """Persist a structured error entry for a session.

        phase: short label for where in the pipeline this fired — e.g.
               'settings_load', 'anthropic_api', 'tool_execute', 'mcp_call',
               'celery_task', 'subagent_api', 'unhandled'.
        Never raises: if error-recording itself fails, logs and continues —
        the caller is already on an error path and we must not compound it.
        """
        try:
            if isinstance(exc, BaseException):
                error_type = type(exc).__name__
                error_message = str(exc)
                tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
            else:
                error_type = "Error"
                error_message = str(exc)
                tb = ""

            doc: Dict[str, Any] = {
                "session_id": session_id,
                "phase": phase,
                "error_type": error_type,
                "error_message": error_message[:4000],
                "traceback": tb[:8000],
                "iteration": iteration,
                "tool": tool,
                "context": context or {},
                "timestamp": datetime.now(timezone.utc),
            }

            try:
                from app.database.mongodb import get_session_errors_collection
                await get_session_errors_collection().insert_one(doc)
            except Exception as inner:
                logger.debug("session_errors insert failed: %s", inner)

            if publish:
                try:
                    await publish_session_message(session_id, {
                        "type": "session_error",
                        "data": {
                            "phase": phase,
                            "error_type": error_type,
                            "message": error_message[:1000],
                            "iteration": iteration,
                            "tool": tool,
                        },
                        "timestamp": _now_iso(),
                    })
                except Exception as inner:
                    logger.debug("session_error publish failed: %s", inner)
        except Exception as outer:
            # Absolute last-resort guard — never propagate from this helper.
            logger.debug("_record_error outer failure: %s", outer)

    async def _store_deep_thought(self, session_id: str, content: str, iteration: int) -> None:
        try:
            from app.database.mongodb import get_deep_thoughts_collection
            collection = get_deep_thoughts_collection()
            await collection.insert_one({
                "session_id": session_id,
                "content": content,
                "iteration": iteration,
                "timestamp": datetime.now(timezone.utc),
            })
        except Exception as exc:
            logger.debug("Failed to store deep thought: %s", exc)

    # -------------------------------------------------------------------------
    # Standard helpers (thought, tool output, vuln extraction)
    # -------------------------------------------------------------------------

    async def _store_thought(self, session_id: str, thought: str, iteration: int) -> None:
        try:
            collection = get_agent_thoughts_collection()
            await collection.insert_one({
                "session_id": session_id,
                "thought": thought,
                "phase": "autonomous",
                "iteration": iteration,
                "tool_calls": [],
                "timestamp": datetime.now(timezone.utc),
            })
        except Exception as exc:
            logger.error("Failed to store thought: %s", exc)

    async def _store_tool_output(
        self, session_id: str, tool_name: str, params: Dict, result: Dict, duration: float
    ) -> None:
        try:
            collection = get_tool_outputs_collection()
            await collection.insert_one({
                "session_id": session_id,
                "tool_name": tool_name,
                "params": params,
                "raw_output": result.get("output", ""),
                "parsed_output": result.get("parsed") or {},
                "timestamp": datetime.now(timezone.utc),
                "duration_seconds": duration,
            })
        except Exception as exc:
            logger.error("Failed to store tool output: %s", exc)

    async def _extract_and_save_vulnerabilities(self, session_id: str, text: str) -> List[str]:
        """Parse, persist, and emit chain-follow-up suggestions for vulnerability blocks.

        Returns the list of suggestion strings the caller should inject into the
        next user turn so the orchestrator actively drives multi-step chains.
        """
        suggestions: List[str] = []
        for vuln_data in _extract_vulnerability_blocks(text):
            suggestion = await self._save_vulnerability(session_id, vuln_data)
            if suggestion:
                suggestions.append(suggestion)
        return suggestions

    async def _extract_and_save_hypotheses(self, session_id: str, text: str) -> None:
        for hyp_data in _extract_hypothesis_blocks(text):
            await self._save_hypothesis(session_id, hyp_data)

    async def _save_hypothesis(self, session_id: str, hyp_data: Dict[str, Any]) -> None:
        try:
            from app.database.mongodb import get_hypothesis_journals_collection
            collection = get_hypothesis_journals_collection()
            hyp_id = str(hyp_data.get("id", ""))
            doc = {
                "session_id": session_id,
                "hyp_id": hyp_id,
                "statement": str(hyp_data.get("statement", "")),
                "confidence": float(hyp_data.get("confidence", 0.5)),
                "evidence_for": hyp_data.get("evidence_for", []),
                "evidence_against": hyp_data.get("evidence_against", []),
                "next_test": str(hyp_data.get("next_test", "")),
                "falsification_criteria": str(hyp_data.get("falsification_criteria", "")),
                "attack_chain_id": str(hyp_data.get("attack_chain_id", "")),
                "status": str(hyp_data.get("status", "active")),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            if hyp_id:
                await collection.update_one(
                    {"session_id": session_id, "hyp_id": hyp_id},
                    {"$set": doc},
                    upsert=True,
                )
            else:
                await collection.insert_one(doc)
            await publish_session_message(session_id, {
                "type": "hypothesis_update",
                "data": doc,
                "timestamp": _now_iso(),
            })
        except Exception as exc:
            logger.debug("Failed to save hypothesis: %s", exc)

    async def _has_oob_hit(self, evidence_for: List[str]) -> bool:
        """Check if any entry in evidence_for references an OOB token that has registered a hit."""
        if not evidence_for:
            return False
        try:
            import re
            from app.database.redis_client import get_redis
            redis = await get_redis()
            token_pattern = re.compile(r"[a-f0-9]{32}")
            for entry in evidence_for:
                text = str(entry)
                candidates = set(token_pattern.findall(text))
                stripped = text.strip()
                if len(stripped) == 32 and all(c in "0123456789abcdef" for c in stripped.lower()):
                    candidates.add(stripped.lower())
                for token in candidates:
                    raw = await redis.get(f"genesis:oob:{token}")
                    if not raw:
                        continue
                    data = json.loads(raw)
                    if data.get("hits"):
                        return True
        except Exception as exc:
            logger.debug("OOB hit check failed: %s", exc)
        return False

    async def _adversarial_critique(
        self,
        title: str,
        description: str,
        confidence: float,
        evidence_for: List[str],
        starting_status: str,
    ) -> str:
        """Critic call that challenges any confirmed/exploited finding against its cited evidence.

        Runs on:
          - any finding claimed `confirmed` or `exploited` (to allow downgrade to `disputed`)
          - `unverified` findings with confidence ≥ 0.6 (to allow promotion to `confirmed`)

        Returns the verdict: 'confirmed', 'disputed', or 'unverified'.
        """
        if self._critic_client is None:
            return starting_status
        if starting_status == "unverified" and confidence < 0.6:
            return "unverified"

        try:
            evidence_summary = (
                "\n".join(f"- {str(e)[:300]}" for e in (evidence_for or [])[:5])
                or "(none cited)"
            )
            resp = await self._critic_client.messages.create(
                model=self._critic_model,
                max_tokens=200,
                timeout=_ANTHROPIC_TIMEOUT_SHORT_SECONDS,
                system=(
                    "You are a rigorous security review critic. Decide whether the cited "
                    "evidence is sufficient to confirm this vulnerability as a real finding. "
                    "Apply these rules strictly: "
                    "(1) No evidence cited -> 'disputed'. "
                    "(2) Evidence is vague, paraphrased, or lacks a concrete observable "
                    "(no tool output quote, no status/length/timing delta, no OOB token hit, "
                    "no code line) -> 'disputed'. "
                    "(3) Specific tool output quote, response differential, OOB callback hit, "
                    "or exact code line cited -> 'confirmed'. "
                    "Reply with ONLY a JSON object: "
                    "{\"verdict\": \"confirmed\" | \"disputed\", \"reason\": \"one short sentence\"}"
                ),
                messages=[{
                    "role": "user",
                    "content": (
                        f"Title: {title}\n"
                        f"Description: {description[:400]}\n"
                        f"Confidence: {confidence:.2f}\n"
                        f"Claimed status: {starting_status}\n"
                        f"Evidence cited:\n{evidence_summary}"
                    ),
                }],
            )
            text = resp.content[0].text.strip() if resp.content else ""
            if "```" in text:
                text = text.split("```")[1].lstrip("json").strip()
            parsed = json.loads(text)
            verdict = str(parsed.get("verdict", "unverified")).lower()
            if verdict in ("confirmed", "disputed"):
                return verdict
            return starting_status
        except Exception as exc:
            logger.debug("Adversarial critique failed: %s", exc)
            return starting_status

    async def _save_vulnerability(self, session_id: str, vuln_data: Dict[str, Any]) -> Optional[str]:
        """Persist a vulnerability row after enforcing evidence rules and critic review.

        Returns a chain-follow-up suggestion string when the finding lands at
        `confirmed` or `exploited` and matches the chain-suggestion table, else None.
        """
        title = str(vuln_data.get("title", "Unnamed Vulnerability"))
        description = str(vuln_data.get("description", ""))
        severity = str(vuln_data.get("severity", "info")).lower()
        cvss_score = _safe_float(vuln_data.get("cvss_score"))
        cve_ids = vuln_data.get("cve_ids", [])
        if not isinstance(cve_ids, list):
            cve_ids = [str(cve_ids)] if cve_ids else []
        affected_service = str(vuln_data.get("affected_service", ""))
        port = _safe_int(vuln_data.get("port"))
        protocol = vuln_data.get("protocol")
        exploit_code = vuln_data.get("exploit_code")
        patch_code = vuln_data.get("patch_code")
        remediation = str(vuln_data.get("remediation", ""))
        confidence = float(vuln_data.get("confidence", 0.5))
        exploit_available = bool(exploit_code and str(exploit_code).strip())
        # Mythos-specific fields
        claimed_status = str(vuln_data.get("verification_status", "unverified")).lower()
        attack_chain_id = vuln_data.get("attack_chain_id")
        chain_position = _safe_int(vuln_data.get("chain_position"))
        mitre_techniques = vuln_data.get("mitre_techniques", [])
        if not isinstance(mitre_techniques, list):
            mitre_techniques = [str(mitre_techniques)] if mitre_techniques else []
        is_zero_day = bool(vuln_data.get("is_zero_day", False))

        # --- U1: Evidence enforcement -------------------------------------
        evidence_for_raw = vuln_data.get("evidence_for", [])
        if isinstance(evidence_for_raw, list):
            evidence_for = [str(e) for e in evidence_for_raw if str(e).strip()]
        elif evidence_for_raw:
            evidence_for = [str(evidence_for_raw)]
        else:
            evidence_for = []

        downgrade_reason: Optional[str] = None
        working_status = claimed_status

        # Rule 1: confirmed/exploited requires non-empty evidence_for
        if working_status in ("confirmed", "exploited") and not evidence_for:
            working_status = "unverified"
            downgrade_reason = "no evidence_for cited"

        # Rule 2: blind-class vulns require an OOB callback that actually hit
        if working_status in ("confirmed", "exploited") and _is_blind_vuln(title, description):
            if not await self._has_oob_hit(evidence_for):
                working_status = "unverified"
                downgrade_reason = "blind-class vuln without confirmed OOB callback hit"

        # Rule 3: always-on critic — can downgrade confirmed -> disputed,
        # or promote unverified (confidence>=0.6) -> confirmed/disputed.
        verification_status = working_status
        critic_verdict = await self._adversarial_critique(
            title, description, confidence, evidence_for, working_status
        )
        if critic_verdict in ("confirmed", "disputed", "unverified"):
            verification_status = critic_verdict
            if working_status != critic_verdict:
                downgrade_reason = (downgrade_reason or "") + (
                    "; " if downgrade_reason else ""
                ) + f"critic: {working_status} -> {critic_verdict}"

        # Audit trail stored in DB for operator review
        verification_output_parts: List[str] = []
        if evidence_for:
            verification_output_parts.append(
                "Evidence cited:\n" + "\n".join(f"- {e[:300]}" for e in evidence_for[:10])
            )
        if claimed_status != verification_status:
            verification_output_parts.append(
                f"Status adjusted: claimed={claimed_status}, final={verification_status}"
                + (f" ({downgrade_reason})" if downgrade_reason else "")
            )
        verification_output = "\n\n".join(verification_output_parts) if verification_output_parts else None
        # -----------------------------------------------------------------

        async with AsyncSessionLocal() as db:
            session_uuid = uuid.UUID(session_id)
            vuln = Vulnerability(
                session_id=session_uuid,
                title=title,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cve_ids=cve_ids,
                affected_service=affected_service,
                port=port,
                protocol=protocol,
                exploit_available=exploit_available,
                exploit_code=exploit_code,
                patch_code=patch_code,
                remediation=remediation,
                confidence=confidence,
                verification_status=verification_status,
                verification_output=verification_output,
                attack_chain_id=attack_chain_id,
                chain_position=chain_position,
                mitre_techniques=mitre_techniques,
                is_zero_day=is_zero_day,
            )
            db.add(vuln)
            await db.flush()
            await db.refresh(vuln)
            vuln_id = str(vuln.id)

            session_result = await db.execute(
                select(ResearchSession).where(ResearchSession.id == session_uuid)
            )
            session_obj = session_result.scalar_one_or_none()
            if session_obj:
                session_obj.vulnerability_count = (session_obj.vulnerability_count or 0) + 1
                if severity == "critical":
                    session_obj.critical_count = (session_obj.critical_count or 0) + 1
                elif severity == "high":
                    session_obj.high_count = (session_obj.high_count or 0) + 1

            await db.commit()

        await publish_session_message(session_id, {
            "type": "vulnerability_found",
            "data": {
                "id": vuln_id, "title": title, "severity": severity,
                "cvss_score": cvss_score, "affected_service": affected_service,
                "port": port, "confidence": confidence,
                "attack_chain_id": attack_chain_id,
                "mitre_techniques": mitre_techniques,
                "is_zero_day": is_zero_day,
                "patch_available": bool(patch_code),
                "verification_status": verification_status,
            },
            "timestamp": _now_iso(),
        })

        try:
            from app.database.chroma_client import add_vulnerability_embedding
            await add_vulnerability_embedding(vuln_id, title, description, severity)
        except Exception as exc:
            logger.warning("ChromaDB embedding failed: %s", exc)

        # U4: persist per-vulnerability technique metadata for cross-session recall.
        # Captured even for unverified/disputed rows so we build negative signals too.
        try:
            from app.database.mongodb import get_vulnerability_metadata_collection
            endpoint = str(vuln_data.get("endpoint", "")).strip()
            technique_tag = str(vuln_data.get("technique_tag", "")).strip()
            payload_hint = str(vuln_data.get("payload", "")).strip()
            tool_used = str(vuln_data.get("tool", vuln_data.get("tool_used", ""))).strip()
            metadata_doc = {
                "session_id": session_id,
                "vuln_id": vuln_id,
                "title": title,
                "severity": severity,
                "affected_service": affected_service,
                "endpoint": endpoint[:500],
                "technique_tag": technique_tag[:100],
                "payload": payload_hint[:300],
                "tool": tool_used[:100],
                "evidence_for": evidence_for[:10],
                "verification_status": verification_status,
                "confidence": confidence,
                "timestamp": datetime.now(timezone.utc),
            }
            await get_vulnerability_metadata_collection().update_one(
                {"session_id": session_id, "vuln_id": vuln_id},
                {"$set": metadata_doc},
                upsert=True,
            )
        except Exception as exc:
            logger.debug("Vulnerability metadata persist failed: %s", exc)

        # U3: emit a chain-follow-up suggestion for confirmed/exploited findings.
        if verification_status in ("confirmed", "exploited"):
            suggestion = _match_chain_suggestion(title, description)
            if suggestion:
                chain_id = attack_chain_id or "chain-auto"
                pos = chain_position if chain_position is not None else "?"
                nudge = (
                    f"[CHAIN_NUDGE after confirmed finding '{title}' "
                    f"(chain_id={chain_id}, chain_position={pos})]\n"
                    f"{suggestion}\n"
                    f"Keep the same attack_chain_id on any follow-up VULNERABILITY block."
                )
                await publish_session_message(session_id, {
                    "type": "chain_suggestion",
                    "data": {
                        "vuln_id": vuln_id,
                        "chain_id": chain_id,
                        "title": title,
                        "content": suggestion,
                    },
                    "timestamp": _now_iso(),
                })
                return nudge
        return None

    # -------------------------------------------------------------------------
    # History compression
    # -------------------------------------------------------------------------

    async def _compress_history(
        self,
        messages: List[Dict[str, Any]],
        client: AsyncAnthropic,
        model: str,
        iteration: int,
    ) -> List[Dict[str, Any]]:
        """Every 15 iterations compress the oldest 12 messages into a compact
        progress summary.  This prevents quadratic input-token growth as the
        conversation accumulates tool outputs.

        The first message (initial user prompt) is always preserved.
        The last 4 messages are always preserved verbatim for continuity.
        """
        COMPRESS_EVERY = 15
        COMPRESS_WINDOW = 12  # messages to collapse
        KEEP_TAIL = 4         # always keep this many recent messages untouched

        if iteration % COMPRESS_EVERY != 0:
            return messages
        # Need at least: 1 (initial) + COMPRESS_WINDOW + KEEP_TAIL to bother
        if len(messages) < 1 + COMPRESS_WINDOW + KEEP_TAIL:
            return messages

        head = messages[:1]                          # always keep initial prompt
        body = messages[1 : 1 + COMPRESS_WINDOW]    # compress this window
        tail = messages[1 + COMPRESS_WINDOW :]       # keep tail verbatim

        try:
            resp = await client.messages.create(
                model=model,
                max_tokens=1200,
                timeout=_ANTHROPIC_TIMEOUT_SHORT_SECONDS,
                system=(
                    "You are summarising an in-progress autonomous security assessment. "
                    "Produce a terse PROGRESS SUMMARY covering: tools already run, "
                    "services/ports discovered, vulnerabilities confirmed (title + severity), "
                    "attack chains forming, and any credentials or paths found. "
                    "Be factual and compact — no prose, bullet points only."
                ),
                messages=body,
            )
            summary_text = resp.content[0].text if resp.content else "(no summary)"
        except Exception as exc:
            logger.warning("History compression failed at iter %d: %s", iteration, exc)
            return messages  # fall back to uncompressed on error

        compressed_msg = {
            "role": "user",
            "content": f"[COMPRESSED PROGRESS — iterations up to {iteration - KEEP_TAIL}]\n{summary_text}",
        }
        logger.debug("[MYTHOS] Compressed %d messages into progress summary at iter %d", COMPRESS_WINDOW, iteration)
        return head + [compressed_msg] + tail

    # -------------------------------------------------------------------------
    # Session helpers
    # -------------------------------------------------------------------------

    async def _load_session(self, session_id: str) -> Optional[ResearchSession]:
        try:
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(ResearchSession).where(ResearchSession.id == uuid.UUID(session_id))
                )
                return result.scalar_one_or_none()
        except Exception:
            return None

    async def _get_session_status(self, session_id: str) -> str:
        try:
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(ResearchSession).where(ResearchSession.id == uuid.UUID(session_id))
                )
                session = result.scalar_one_or_none()
                return session.status if session is not None else "unknown"
        except Exception:
            return "unknown"

    async def _update_session(
        self, session_id: str, *, iteration: Optional[int] = None, status: Optional[str] = None
    ) -> None:
        values: Dict[str, Any] = {}
        if iteration is not None:
            values["iteration"] = iteration
        if status is not None:
            values["status"] = status
        if not values:
            return
        try:
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ResearchSession)
                    .where(ResearchSession.id == uuid.UUID(session_id))
                    .values(**values)
                )
                await db.commit()
        except Exception as exc:
            logger.error("Failed to update session %s: %s", session_id, exc)

    async def _finalize_session(self, session_id: str) -> None:
        try:
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ResearchSession)
                    .where(ResearchSession.id == uuid.UUID(session_id))
                    .values(status="completed", completed_at=datetime.now(timezone.utc))
                )
                await db.commit()
        except Exception as exc:
            logger.error("Failed to finalize session %s: %s", session_id, exc)

    async def _set_session_failed(self, session_id: str, reason: str) -> None:
        try:
            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ResearchSession)
                    .where(ResearchSession.id == uuid.UUID(session_id))
                    .values(
                        status="failed",
                        completed_at=datetime.now(timezone.utc),
                        summary=f"Session failed: {reason}",
                    )
                )
                await db.commit()
        except Exception as exc:
            logger.error("Failed to mark session %s as failed: %s", session_id, exc)


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _extract_vulnerability_blocks(text: str) -> List[Dict[str, Any]]:
    """Parse all {"VULNERABILITY": {...}} blocks from a text string. Returns list of vuln dicts."""
    results: List[Dict[str, Any]] = []
    marker = '"VULNERABILITY"'
    pos = 0
    while True:
        idx = text.find(marker, pos)
        if idx == -1:
            break
        start = text.rfind("{", 0, idx)
        if start == -1:
            pos = idx + len(marker)
            continue
        depth = 0
        i = start
        in_string = False
        escape_next = False
        while i < len(text):
            ch = text[i]
            if escape_next:
                escape_next = False
            elif ch == "\\" and in_string:
                escape_next = True
            elif ch == '"':
                in_string = not in_string
            elif not in_string:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            outer = json.loads(text[start : i + 1])
                            vuln_data = outer.get("VULNERABILITY", {})
                            if vuln_data:
                                results.append(vuln_data)
                        except Exception:
                            pass
                        pos = i + 1
                        break
            i += 1
        else:
            pos = idx + len(marker)
    return results


def _extract_hypothesis_blocks(text: str) -> List[Dict[str, Any]]:
    """Parse all {"HYPOTHESIS": {...}} blocks from a text string."""
    results: List[Dict[str, Any]] = []
    marker = '"HYPOTHESIS"'
    pos = 0
    while True:
        idx = text.find(marker, pos)
        if idx == -1:
            break
        start = text.rfind("{", 0, idx)
        if start == -1:
            pos = idx + len(marker)
            continue
        depth = 0
        i = start
        in_string = False
        escape_next = False
        while i < len(text):
            ch = text[i]
            if escape_next:
                escape_next = False
            elif ch == "\\" and in_string:
                escape_next = True
            elif ch == '"':
                in_string = not in_string
            elif not in_string:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            outer = json.loads(text[start : i + 1])
                            hyp_data = outer.get("HYPOTHESIS", {})
                            if hyp_data:
                                results.append(hyp_data)
                        except Exception:
                            pass
                        pos = i + 1
                        break
            i += 1
        else:
            pos = idx + len(marker)
    return results


def _safe_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _safe_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None

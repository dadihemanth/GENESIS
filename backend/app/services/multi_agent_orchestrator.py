from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, Dict, List, Optional, Set

from app.services.mcp_client import MCPClient

logger = logging.getLogger(__name__)

_SHARED_FINDINGS_KEY_TMPL = "genesis:session:{session_id}:shared_findings"
_SHARED_FINDINGS_MAX = 200  # cap list length to bound memory
_SHARED_FINDINGS_TTL = 7200  # 2 hours — matches typical session budget

# Tool subsets assigned to each specialized agent
_AGENT_TOOL_SETS: Dict[str, List[str]] = {
    "recon": [
        "nmap_scan", "masscan_scan", "amass_enum", "subfinder_discover",
        "dnsrecon_enumerate", "harvester_gather", "httpx_probe",
    ],
    "analyst": [
        "whatweb_identify", "wafw00f_detect", "sslscan_check",
        "curl_probe", "openssl_check", "wpscan_scan",
        "cache_probe", "http_smuggling_probe",
        # v4.0 analyst tools
        "http_diff_probe", "semantic_anomaly_grader",
        "json_parser_diff", "unicode_diff_probe",
        "second_order_sqli_probe", "flow_recorder", "flow_fuzzer",
        "csp_bypass_probe", "xsleaks_probe", "redos_probe", "bomb_probe",
        "llm_inject_probe", "indirect_inject_probe", "rag_poison_probe",
    ],
    "exploit": [
        "nuclei_scan", "nikto_scan", "sqlmap_test", "xsstrike_test",
        "commix_test", "gobuster_scan", "ffuf_fuzz", "feroxbuster_scan",
        "arjun_discover", "payload_crafter",
        "idor_probe", "cors_probe", "jwt_probe", "graphql_probe",
        "ssti_detect", "nosql_probe", "prototype_pollution_probe", "oauth_probe",
        # Verification toolkit
        "ai_request_forge", "forge_runner", "curl_probe",
        "artifact_hunter", "artifact_pull", "cve_patch_pull",
        "payload_swarm",
        # v4.0 — exploit agent gets all novel-discovery tools
        "http_diff_probe", "semantic_anomaly_grader",
        "url_parser_diff", "json_parser_diff", "unicode_diff_probe",
        "multipart_diff_probe", "charset_confusion_probe",
        "h2_smuggle_probe", "method_confusion_probe", "range_trailer_probe",
        "java_deserial_probe", "dotnet_deserial_probe", "php_deserial_probe",
        "python_deserial_probe", "ruby_deserial_probe", "node_proto_to_gadget",
        "upload_polyglot_probe", "image_parser_probe",
        "ssrf_scheme_probe", "cloud_imds_probe", "dns_rebind_probe",
        "flow_recorder", "flow_fuzzer", "race_probe_h2_singlepacket",
        "saml_xsw_probe", "cookie_prefix_probe", "cswsh_probe",
        "dom_clobber_probe", "postmessage_probe", "mxss_probe",
        "csp_bypass_probe", "xsleaks_probe",
        "ssti_gadget_probe", "ldap_inject_probe", "second_order_sqli_probe",
        "redos_probe", "bomb_probe",
        "llm_inject_probe", "indirect_inject_probe", "rag_poison_probe",
        "dlp_exfil_probe", "killchain_probe",
    ],
    "code": [
        "semgrep_scan", "bandit_scan", "binary_analyzer", "code_pattern_search",
        # Static-analysis agents need to actually READ the artifact they are
        # analysing and emit a PoC script when they find a sink worth testing.
        "artifact_hunter", "artifact_pull", "code_read", "binary_decompile",
        "forge_runner",
    ],

    # ── Tier-5 T22 specialists — activate conditionally based on Phase-1 signal
    "crypto": [
        # T26 primitive library — the whole set
        "crypto_padding_oracle", "crypto_bleichenbacher", "crypto_ecdsa_nonce_reuse",
        "crypto_length_extension", "crypto_rsa_low_e", "crypto_lattice",
        "crypto_jwt_confusion",
        # Crypto detection + verification plumbing
        "jwt_probe", "sslscan_check", "openssl_check",
        "curl_probe", "ai_request_forge", "forge_runner",
        "graph_query",
    ],
    "auth": [
        # Auth-flow detection + probe surface
        "jwt_probe", "oauth_probe", "cors_probe", "idor_probe",
        "session_memory",
        "sslscan_check", "wpscan_scan",
        # Verification
        "curl_probe", "ai_request_forge", "forge_runner",
        # Cross-over to crypto when the auth flaw hinges on a token weakness
        "crypto_jwt_confusion",
        "graph_query",
        "payload_swarm",
        # v4.0 auth specialist tools
        "saml_xsw_probe", "cookie_prefix_probe", "cswsh_probe",
        "flow_recorder", "flow_fuzzer", "race_probe_h2_singlepacket",
    ],
    "reveng": [
        "artifact_hunter", "artifact_pull", "code_read",
        "binary_decompile", "symbolic_exec", "fuzz_binary",
        "instrument_trace",
        "graph_query",
    ],
    "exploitdev": [
        "artifact_pull", "forge_runner", "ai_request_forge",
        "fuzz_binary", "symbolic_exec", "instrument_trace",
        "binary_decompile", "code_read",
        "graph_query",
        # T28 — variant fanout for exploit-primitive search.
        "payload_swarm",
    ],
    "network": [
        "nmap_scan", "masscan_scan",
        "curl_probe", "forge_runner",
        "enum4linux_enumerate", "netexec_run", "impacket_run", "kerbrute_run",
        "graph_query",
        # v4.0 non-HTTP service probes
        "redis_probe", "grpc_probe", "db_wire_probe", "mqtt_amqp_probe",
        # v4.0 AD / kill-chain tools
        "bloodhound_collect", "password_spray_cred", "pivot_socks_pth",
        "dlp_exfil_probe",
        "ssrf_scheme_probe", "cloud_imds_probe",
    ],
    # ── v5 specialist roles ──────────────────────────────────────────────────
    # T80–T85: source-aware analysis — activated when source corpus is ingested
    "source_analyst": [
        "repo_ingest", "ast_walker", "taint_engine", "invariant_inferer",
        "semgrep_scan", "bandit_scan",
        "code_read", "binary_decompile",
        "forge_runner", "artifact_pull",
        "graph_query",
    ],
    # T83/T95/T96: invariant engineering — activated when invariants are inferred
    "invariant_engineer": [
        "invariant_inferer", "symbolic_exec", "fuzz_binary",
        "instrument_trace", "forge_runner",
        "semgrep_scan",
        "graph_query",
    ],
    # ── v6 specialist roles ──────────────────────────────────────────────────
    # T137: IoT — activated on UPnP/mDNS/MQTT/Zigbee detection
    "iot": [
        "nmap_scan", "masscan_scan",
        "mqtt_amqp_probe",
        "upnp_probe", "ble_probe", "default_cred_spray",
    ],
    # T138: Mobile — activated when APK/IPA artifact pulled
    "mobile": [
        "artifact_pull", "binary_decompile",
        "apk_analyzer", "frida_hook_mobile",
        "deeplink_probe", "ssl_pinning_bypass",
    ],
    # T139: OT/ICS — activated on Modbus/DNP3/S7Comm/BACnet detection
    "ot": [
        "modbus_probe", "dnp3_probe", "s7comm_probe", "bacnet_probe",
    ],
    # T140: Embedded — activated when firmware artifact extracted
    "embedded": [
        "artifact_pull", "binary_decompile",
        "secure_boot_analyzer", "uart_probe",
    ],

    # v7.x — payload SubAgent. Always spawned in Phase 2. Generation-only
    # toolset: produces structured `payload_candidate` shared findings the
    # exploit agent picks up and runs via forge_runner / payload_swarm.
    # Routes to the `payload` role profile (typically Llama 4 / DeepSeek-R1
    # for less-restrictive payload generation).
    "payload": [
        "payload_crafter",          # build payloads from templates
        "ai_request_forge",         # craft full HTTP request structures
        "code_pattern_search",      # find target-specific injection points
    ],
}

# v7.x — every agent role gets `deliberate` so multi-agent sessions can fire
# v7.0 reasoning loops too. Solo mode is the primary path; this brings every
# specialist (recon/analyst/exploit/code/crypto/auth/reveng/exploitdev/network/
# source_analyst/invariant_engineer/iot/mobile/ot/embedded) up to parity.
for _agent_tool_list in _AGENT_TOOL_SETS.values():
    if "deliberate" not in _agent_tool_list:
        _agent_tool_list.append("deliberate")

# Four generalists always run (two per phase). Specialists are a set the
# orchestrator picks from after Phase 1 based on detected surface.
# v7.x — payload SubAgent joins as a 5th Phase-2 generalist. Always-on so
# every multi-agent run gets aggressive payload generation; emits
# SHARED_FINDING(payload_candidate) for the exploit agent to consume.
_GENERALIST_AGENTS: Set[str] = {"recon", "analyst", "exploit", "code", "payload"}
_SPECIALIST_AGENTS: Set[str] = {
    "crypto", "auth", "reveng", "exploitdev", "network",
    # v5 specialists
    "source_analyst", "invariant_engineer",
    # v6 specialists (T137-T140)
    "iot", "mobile", "ot", "embedded",
}
# Cap how many specialists we'll activate per session. Anything beyond this
# starts to dilute the adversarial critic's attention and burns credits.
# v7.x — bumped from 5 → 8 to accommodate baseline + per-target memory.
_MAX_SPECIALISTS = 8

# v7.x — Mandatory baseline specialists for multi-agent exhaustive runs.
# `_detect_surfaces` is heuristic + signal-driven so it can produce variable
# specialist sets across runs of the same target. The baseline guarantees
# crypto / auth / network / reveng / exploitdev fire EVERY exhaustive multi-
# agent session — closes the single biggest variance gap between runs.
_BASELINE_SPECIALISTS: Set[str] = {
    "crypto", "auth", "network", "reveng", "exploitdev",
}

_SHARED_USAGE_HINT = (
    "\nYou share a Redis list with the other GENESIS agents for runtime coordination. "
    "When you discover something another agent can use (open port + service, live URL/endpoint, "
    "detected framework/CMS, WAF verdict, leaked credential, auth endpoint, interesting header), "
    "emit a JSON block of the form "
    "{{\"SHARED_FINDING\": {{\"kind\": \"endpoint|port|tech|waf|cred|header|path|other\", "
    "\"value\": \"...\", \"context\": \"short note\"}}}} "
    "so the platform can broadcast it. Consume PRIOR_PHASE_FINDINGS and any SHARED_FINDINGS already "
    "in your initial context before planning your own tool calls — reuse, do not re-enumerate."
)

_VULNERABILITY_EMISSION_HINT = (
    "\nConfirmed vulnerabilities MUST be emitted as a JSON block — exact shape below — so "
    "the GENESIS platform can persist them, group them into attack chains, and render them "
    "in the Findings panel. Free-form prose descriptions are NOT stored. Use this template:\n"
    "{{\"VULNERABILITY\": {{"
    "\"title\": \"<short name>\", "
    "\"severity\": \"critical|high|medium|low|info\", "
    "\"cvss_score\": 9.8, "
    "\"cve_ids\": [\"CVE-XXXX-YYYY\"], "
    "\"affected_service\": \"<product + version>\", "
    "\"port\": 443, "
    "\"description\": \"<what it is>\", "
    "\"exploit_code\": \"<payload / PoC script>\", "
    "\"patch_code\": \"<exact diff or config>\", "
    "\"remediation\": \"<one-line fix>\", "
    "\"confidence\": 0.9, "
    "\"attack_chain_id\": \"chain-1\", "
    "\"chain_position\": 2, "
    "\"verification_status\": \"confirmed\", "
    "\"mitre_techniques\": [\"T1190\"], "
    "\"is_zero_day\": false, "
    "\"evidence_for\": [\"<tool-output quote 1>\", \"<response-delta 2>\"], "
    "\"endpoint\": \"/api/users/1\", "
    "\"technique_tag\": \"idor-sequential-int\""
    "}}}}\n"
    "Evidence rules (enforced by the platform — if you break these your finding is downgraded "
    "to 'disputed'): evidence_for is REQUIRED whenever verification_status is 'confirmed' or "
    "'exploited'. Each entry must be a CONCRETE observable: a quoted tool-output line, a status "
    "code pair, a response-length delta, an OOB callback token, or a specific code line. "
    "Paraphrases are rejected.\n"
    "Chain construction: related findings that form a single exploitation path share the same "
    "attack_chain_id (e.g. chain-1). Use chain_position 1, 2, 3... in the order of exploitation "
    "(recon hit → misconfig → RCE = 1, 2, 3). This is how the Attack Chains tab is built."
)

_VERIFICATION_DISCIPLINE_HINT = (
    "\n\nVERIFICATION DISCIPLINE — this is how you keep findings from sitting at "
    "'unverified'. The platform will downgrade any VULNERABILITY block whose "
    "evidence_for doesn't contain a concrete, quotable observable. Canned "
    "scanner output alone (nuclei match, sqlmap banner, nikto fingerprint) is "
    "NOT sufficient evidence for verification_status='confirmed' — those are "
    "leads, not proofs.\n"
    "Before you emit verification_status='confirmed' or 'exploited' on any "
    "non-trivial finding, run ONE of the following so your evidence_for cites "
    "a deterministic backend oracle result:\n"
    "  - `ai_request_forge` — you write the exact HTTP request AND an oracle "
    "    predicate (expect_status / body_must_contain / reflect_token / "
    "    diff_length_gt / response_time_gt_ms). The backend evaluates the "
    "    oracle server-side; a passing oracle is first-class evidence.\n"
    "  - `forge_runner` — a short Python/Node/Bash script in the sandbox "
    "    that demonstrates the exploit and prints a deterministic result. "
    "    Declare an oracle predicate next to the code.\n"
    "  - `curl_probe` — primitive HTTP probe for simple status/body-length "
    "    deltas you can quote verbatim.\n"
    "Your evidence_for array should include the quoted tool output, the "
    "oracle verdict, and a response-length / status delta — not paraphrases "
    "like 'the scanner flagged this'. Also set confidence explicitly (0.85–"
    "0.95 when oracle-backed; 0.5 is the default and lands at 'unverified').\n"
)

_CREATIVITY_HINT = (
    "\nNovelty discipline. Stock scanners find the bugs everyone has already found. Your job is "
    "to find the ones nobody has. Before reaching for sqlmap/nuclei/wpscan, ask: what KIND of "
    "system is this? (chatbot? webhook? file uploader? LLM-backed search? CI runner? GraphQL? "
    "real-time channel? OAuth flow?) Each scenario class has a CHARACTERISTIC novel-bug class "
    "that stock tools miss because the bug lives in the SECOND HOP — chat → LLM → tool-use → "
    "SQL; upload → AV scanner → log viewer; webhook → JSON → queue → email template. "
    "When the target fits a scenario class, do NOT just run the checklist — write a "
    "`payload_swarm` of 8-16 variants targeting your custom hypothesis (encoding axes, polyglot "
    "framing, prompt injection, race timing, content-type confusion, header/path normalisation). "
    "Variants whose novelty_score ≥ 0.5 are candidates to re-confirm in `forge_runner` with a "
    "precise oracle. Cite the scenario class in your hypothesis statement (e.g. 'class: "
    "LLM-backed chatbot, hypothesis: user input concatenated into downstream SQL via tool call'). "
    "Coverage > checklist; THINK before tooling."
)

_HYPOTHESIS_EMISSION_HINT = (
    "\nStructured hypothesis journal: every time you form a testable hypothesis, emit a JSON block "
    "of the form "
    "{{\"HYPOTHESIS\": {{\"id\": \"h1\", \"statement\": \"<one-sentence claim>\", "
    "\"confidence\": 0.6, \"evidence_for\": [\"<concrete observation>\"], "
    "\"evidence_against\": [], \"next_test\": \"<specific tool call + params>\", "
    "\"falsification_criteria\": \"<what result would rule this out>\", "
    "\"attack_chain_id\": \"chain-1\", \"status\": \"active\"}}}} "
    "before you run the tool that tests it. When a tool result confirms or refutes the hypothesis, "
    "re-emit the same JSON block with status=\"confirmed\" or status=\"ruled_out\" and updated "
    "evidence. The GENESIS platform indexes these so the operator can see what you're testing, "
    "which hypotheses survived, and which didn't — this is how your reasoning becomes auditable."
)

_AGENT_PROMPTS: Dict[str, str] = {
    "recon": (
        "You are the GENESIS Recon Agent. Your sole focus is network and DNS reconnaissance. "
        "Enumerate hosts, ports, subdomains, and services for target {target}. "
        "Use: nmap_scan (all ports), masscan_scan (fast sweep), subfinder_discover, amass_enum, "
        "dnsrecon_enumerate, harvester_gather (passive OSINT), httpx_probe (web service fingerprint). "
        "Emit TOPOLOGY_UPDATE JSON blocks whenever you discover a new host or service. "
        "When done, emit a JSON block: {{\"RECON_COMPLETE\": true, \"findings\": <summary>}}"
        + _SHARED_USAGE_HINT
    ),
    "analyst": (
        "You are the GENESIS Analyst Agent. You perform deep service analysis on target {target}. "
        "Use: whatweb_identify, wafw00f_detect, sslscan_check, openssl_check, curl_probe, wpscan_scan. "
        "Identify: web frameworks, CMS, WAF presence, TLS weaknesses, interesting headers. "
        "When done, emit: {{\"ANALYST_COMPLETE\": true, \"findings\": <summary>}}"
        + _SHARED_USAGE_HINT
        + _HYPOTHESIS_EMISSION_HINT
    ),
    "exploit": (
        "You are the GENESIS Exploit Agent. You test for vulnerabilities on target {target}. "
        "Canned scanners (nuclei_scan, nikto_scan, sqlmap_test, xsstrike_test, commix_test, "
        "gobuster_scan / feroxbuster_scan / ffuf_fuzz for directory/parameter discovery, "
        "payload_crafter, the *_probe tools) are LEADS. You MUST then verify each lead with "
        "`ai_request_forge` or `forge_runner` — oracle-backed, platform-evaluated — before "
        "emitting a VULNERABILITY block at verification_status='confirmed'. See VERIFICATION "
        "DISCIPLINE below. Prefer endpoints surfaced via PRIOR_PHASE_FINDINGS or SHARED_FINDINGS "
        "over re-discovering them yourself. If `artifact_hunter` has already surfaced exposed "
        "source/configs, pull them with `artifact_pull` and use them to craft precise payloads. "
        "When done, emit: {{\"EXPLOIT_COMPLETE\": true, \"vuln_count\": <n>}}"
        + _SHARED_USAGE_HINT
        + _VERIFICATION_DISCIPLINE_HINT
        + _VULNERABILITY_EMISSION_HINT
        + _HYPOTHESIS_EMISSION_HINT
        + _CREATIVITY_HINT
    ),
    "code": (
        "You are the GENESIS Code Analysis Agent. You perform static analysis on downloadable "
        "source code or binaries from target {target}. "
        "If earlier phases have already pulled artifacts (see PRIOR_PHASE_FINDINGS / "
        "SHARED_FINDINGS), use `code_read` or `binary_decompile` to inspect them directly. "
        "If not, call `artifact_hunter` + `artifact_pull` first to bring source/binaries into "
        "the session volume, THEN analyse. Use: semgrep_scan, bandit_scan, binary_analyzer, "
        "code_pattern_search. Look for: hardcoded secrets, injection sinks, weak crypto, "
        "unsafe deserialization. For any sink that looks reachable, author a short `forge_runner` "
        "script that demonstrates the exploit against the live target and cite the oracle "
        "verdict in evidence_for — this is what promotes a finding from 'unverified' to "
        "'confirmed'. "
        "When done, emit: {{\"CODE_COMPLETE\": true, \"findings\": <summary>}}"
        + _SHARED_USAGE_HINT
        + _VERIFICATION_DISCIPLINE_HINT
        + _VULNERABILITY_EMISSION_HINT
        + _HYPOTHESIS_EMISSION_HINT
    ),

    # ── Tier-5 T22 specialist prompts ───────────────────────────────────────
    "crypto": (
        "You are the GENESIS Crypto Specialist. You only spawn when Phase 1 detected a crypto "
        "surface on {target} (TLS/JWT/OAuth/cookie signature/cipher text). Your job is to apply "
        "the right algorithmic attack rather than hand-roll algebra. "
        "T26 primitives (one call away): crypto_padding_oracle (PKCS#7 CBC, Vaudenay), "
        "crypto_bleichenbacher (PKCS#1 v1.5 RSA), crypto_ecdsa_nonce_reuse (same-k recovery), "
        "crypto_length_extension (MD5/SHA-1/SHA-256), crypto_rsa_low_e (Håstad broadcast + "
        "Franklin-Reiter), crypto_lattice (Wiener's small-d), crypto_jwt_confusion (alg_none, "
        "hs_rs_swap, weak_secret, kid_inject). "
        "Workflow: (1) `jwt_probe`/`sslscan_check`/`openssl_check` or `curl_probe` to observe "
        "the crypto artefact; (2) pick the matching primitive; (3) `ai_request_forge` to "
        "verify the recovered artefact against the live target (pass the recovered plaintext / "
        "forged token / private key as the exploit payload and declare an oracle). "
        "A recovered plaintext, private key, or successfully-accepted forged token is "
        "first-class evidence — cite the primitive's output verbatim in evidence_for. "
        "When done, emit: {{\"CRYPTO_COMPLETE\": true, \"findings\": <summary>}}"
        + _SHARED_USAGE_HINT
        + _VERIFICATION_DISCIPLINE_HINT
        + _VULNERABILITY_EMISSION_HINT
        + _HYPOTHESIS_EMISSION_HINT
        + _CREATIVITY_HINT
    ),
    "auth": (
        "You are the GENESIS Auth Specialist. You only spawn when Phase 1 surfaced an auth flow "
        "(login / OAuth / SAML / OIDC / session cookies) on {target}. Focus exclusively on "
        "authentication and session handling — do NOT re-run generic scanners the Exploit Agent "
        "is already running in parallel. "
        "Tools: `oauth_probe` (OAuth/OIDC misconfigurations), `jwt_probe` (claim handling, "
        "alg field, kid header), `idor_probe` (cross-account access after login), `cors_probe` "
        "(SameSite / credentials-in-CORS), `session_memory` (track tokens across steps), "
        "`wpscan_scan` (if CMS). Use `crypto_jwt_confusion` when a JWT analysis reveals alg=none / "
        "HS→RS confusion / weak secret candidates. "
        "Always verify with `ai_request_forge` or `forge_runner`: a signed-in request hitting an "
        "admin endpoint, a cross-account GET succeeding, or a forged token accepted — declare an "
        "oracle (expect_status, body_must_contain, diff_length_gt). "
        "When done, emit: {{\"AUTH_COMPLETE\": true, \"findings\": <summary>}}"
        + _SHARED_USAGE_HINT
        + _VERIFICATION_DISCIPLINE_HINT
        + _VULNERABILITY_EMISSION_HINT
        + _HYPOTHESIS_EMISSION_HINT
        + _CREATIVITY_HINT
    ),
    "reveng": (
        "You are the GENESIS Reverse-Engineering Specialist. You only spawn when a native "
        "binary artefact has been pulled (.exe/.so/.dll/.jar/.apk/.elf) during Phase 1 on "
        "{target}. Your job is deep binary work the generalist Code Agent doesn't go into. "
        "Workflow: (1) `binary_decompile` for pseudo-C of interesting functions; (2) "
        "`code_read` for strings + embedded configs; (3) `symbolic_exec` to prove reachability "
        "of a suspect sink; (4) `fuzz_binary` when the input surface is parser-like; (5) "
        "`instrument_trace` (mode='frida' with an Interceptor hook, or mode='dynamorio' with "
        "dr_client='drcov' for coverage) to observe live behaviour — especially to identify "
        "WHICH branch causes a fuzz_binary crash or to dump runtime values of hidden auth "
        "comparisons found in the decompile. "
        "A finding is 'confirmed' only when you have a crashing input OR a verified reachability "
        "proof OR a live-instrumented trace showing the unsafe behaviour. Cite the instrument "
        "trace events or crash input (base64) in evidence_for. "
        "When done, emit: {{\"REVENG_COMPLETE\": true, \"findings\": <summary>}}"
        + _SHARED_USAGE_HINT
        + _VERIFICATION_DISCIPLINE_HINT
        + _VULNERABILITY_EMISSION_HINT
        + _HYPOTHESIS_EMISSION_HINT
    ),
    "exploitdev": (
        "You are the GENESIS Exploit-Dev Specialist. You only spawn when fuzz_binary produced a "
        "crash or the RevEng Specialist identified a weaponisable primitive on {target}. Turn a "
        "crash into a reliable exploit — or prove it isn't reachable. "
        "Workflow: (1) `graph_query` for any prior findings on this target that might already "
        "have taken this path (shortest_path from the host to crown-jewel nodes); (2) "
        "`binary_decompile` + `code_read` to classify the primitive (write-what-where / relative "
        "offset / info leak / heap corruption); (3) `instrument_trace` (Frida) to confirm argument "
        "shapes at the vulnerable call site; (4) `symbolic_exec` to confirm the sink is reachable "
        "from attacker-controlled input; (5) `forge_runner` to run the PoC end-to-end — that "
        "script IS your evidence. Declare an oracle that succeeds only on successful exploitation "
        "(e.g. body_must_contain='shell', or exit_code_eq=0 when the script lands a session). "
        "Be honest about hardened targets (ASLR/NX/CFI) — a partial primitive with a clear "
        "reachability proof is still a valid finding at high confidence even if you can't land a "
        "full shell. "
        "When done, emit: {{\"EXPLOITDEV_COMPLETE\": true, \"findings\": <summary>}}"
        + _SHARED_USAGE_HINT
        + _VERIFICATION_DISCIPLINE_HINT
        + _VULNERABILITY_EMISSION_HINT
        + _HYPOTHESIS_EMISSION_HINT
        + _CREATIVITY_HINT
    ),
    "network": (
        "You are the GENESIS Network Specialist. You only spawn when Phase 1 saw multiple hosts "
        "or pivot-capable services (SSH/RDP/SMB/WinRM/DB ports) on {target}. Focus on lateral "
        "movement and pivot discovery — NOT on re-running basic port scans the Recon Agent "
        "already ran. "
        "Workflow: (1) `graph_query` against the attack knowledge graph to find shortest paths "
        "from any compromised Host/Credential to unvisited Services / Privileges — use the "
        "CHAINS_INTO, GRANTS, AUTHENTICATES_TO edges; (2) `nmap_scan`/`masscan_scan` against "
        "internal ranges surfaced via SSRF or reached through an established pivot; (3) "
        "`enum4linux_enumerate`/`netexec_run`/`impacket_run`/`kerbrute_run` for Windows/AD "
        "lateral movement when credentials are in scope; (4) `forge_runner` with a small Python "
        "script to build a SOCKS-over-HTTP or similar tunnel when the stock tools don't fit. "
        "Emit TOPOLOGY_UPDATE blocks for every new host/service you discover so the shared "
        "topology and attack graph stay current. A confirmed pivot or lateral-movement primitive "
        "should include the graph_query result showing the path in evidence_for. "
        "Non-HTTP service protocol matrix: "
        "port 6379/6380 → `redis_probe` (no-auth Redis with CONFIG SET = RCE, do this first); "
        "port 5432 → `db_wire_probe` db_type=postgres (COPY FROM PROGRAM); "
        "port 3306 → `db_wire_probe` db_type=mysql (INTO OUTFILE); "
        "port 1883 → `mqtt_amqp_probe` protocol=mqtt (anonymous # subscription = full bus read); "
        "port 5672 → `mqtt_amqp_probe` protocol=amqp (RabbitMQ anon + queue enum); "
        "port 50051 → `grpc_probe` (gRPC reflection enumeration). "
        "Active Directory kill-chain: "
        "If port 88 (Kerberos) is observed, hypothesise Kerberoast → ASREProast → DCSync in sequence and "
        "execute via `kerbrute_run` (user enum first) then `impacket_run` (Kerberoast/secretsdump). "
        "If port 445 (SMB) is observed, run `netexec_run` for share enum then attempt NTLM relay if "
        "signing is disabled. Always try `password_spray_cred` for user enumeration before spray — "
        "use lockout_threshold=3 and delay_ms=30000 to avoid lockouts. "
        "When valid credentials are obtained, run `bloodhound_collect` (collection_method=DCOnly) "
        "immediately to map the AD attack graph, then use `pivot_socks_pth` for lateral movement. "
        "If data exfil channels need to be verified against DLP controls, call `dlp_exfil_probe`. "
        "When done, emit: {{\"NETWORK_COMPLETE\": true, \"findings\": <summary>}}"
        + _SHARED_USAGE_HINT
        + _VERIFICATION_DISCIPLINE_HINT
        + _VULNERABILITY_EMISSION_HINT
        + _HYPOTHESIS_EMISSION_HINT
    ),
    # ── v6 specialist prompts ─────────────────────────────────────────────────
    "iot": (
        "You are the GENESIS IoT Specialist (T137). You only spawn when Phase 1 detected "
        "UPnP/mDNS/MQTT/Zigbee/BLE services on {target}. "
        "Workflow: (1) `upnp_probe` for UPnP SSDP discovery and device description XML; "
        "(2) `mqtt_amqp_probe` (protocol=mqtt) for broker access and topic enumeration; "
        "(3) `default_cred_spray` for IoT default-credential testing across detected services; "
        "(4) `ble_probe` for Bluetooth LE device enumeration and GATT profile inspection; "
        "(5) `nmap_scan` targeting IoT-specific ports (1883, 5683, 8883, 48101). "
        "Report: unauthenticated message bus access, hardcoded/default creds, "
        "insecure firmware update channels, cleartext MQTT traffic. "
        "When done, emit: {{\"IOT_COMPLETE\": true, \"findings\": <summary>}}"
        + _SHARED_USAGE_HINT
        + _VERIFICATION_DISCIPLINE_HINT
        + _VULNERABILITY_EMISSION_HINT
    ),
    "mobile": (
        "You are the GENESIS Mobile Specialist (T138). You only spawn when an APK or IPA "
        "artifact has been pulled from {target}. "
        "Workflow: (1) `apk_analyzer` to decompile and inspect the APK/IPA manifest, "
        "hardcoded secrets, exported activities, deep links, and network config; "
        "(2) `binary_decompile` for native libraries found inside the package; "
        "(3) `deeplink_probe` to test deep link handlers for intent injection; "
        "(4) `ssl_pinning_bypass` to bypass certificate pinning and capture clear-text API traffic; "
        "(5) `frida_hook_mobile` to instrument runtime behaviour — hook auth checks, crypto calls. "
        "Report: exported components, hardcoded keys/endpoints, insecure data storage, "
        "broken SSL pinning, deep link injection, insecure IPC. "
        "When done, emit: {{\"MOBILE_COMPLETE\": true, \"findings\": <summary>}}"
        + _SHARED_USAGE_HINT
        + _VERIFICATION_DISCIPLINE_HINT
        + _VULNERABILITY_EMISSION_HINT
    ),
    "ot": (
        "You are the GENESIS OT/ICS Specialist (T139). You only spawn when Phase 1 detected "
        "Modbus/DNP3/S7Comm/BACnet services on {target}. "
        "CRITICAL SAFETY RULE: You operate in READ-ONLY mode by default. "
        "NEVER send write or actuator commands without an explicit operator_token. "
        "Workflow: (1) `modbus_probe` (read_holding_registers, read_input_registers) for "
        "Modbus TCP/RTU device enumeration and register mapping; "
        "(2) `dnp3_probe` (read_class_0) for DNP3 data object enumeration; "
        "(3) `s7comm_probe` (read_sysmsg) for Siemens S7 PLC identification; "
        "(4) `bacnet_probe` (who_is, read_property) for BACnet device discovery. "
        "Report: unauthenticated protocol access, exposed PLC/RTU data, "
        "firmware versions, dangerous function codes enabled. "
        "When done, emit: {{\"OT_COMPLETE\": true, \"findings\": <summary>}}"
        + _SHARED_USAGE_HINT
        + _VERIFICATION_DISCIPLINE_HINT
        + _VULNERABILITY_EMISSION_HINT
    ),
    "embedded": (
        "You are the GENESIS Embedded Specialist (T140). You only spawn when firmware "
        "has been extracted from {target}. "
        "Workflow: (1) `binary_decompile` for bootloader and kernel image analysis; "
        "(2) `secure_boot_analyzer` to check secure boot chain integrity and signing key exposure; "
        "(3) `uart_probe` (simulated in sandbox) to test UART console access and bootloader flags; "
        "(4) `artifact_pull` for any additional firmware components not already retrieved. "
        "Report: disabled secure boot, exposed UART root shells, hardcoded credentials in "
        "firmware, unencrypted firmware update channels, known-CVE kernel versions. "
        "When done, emit: {{\"EMBEDDED_COMPLETE\": true, \"findings\": <summary>}}"
        + _SHARED_USAGE_HINT
        + _VERIFICATION_DISCIPLINE_HINT
        + _VULNERABILITY_EMISSION_HINT
    ),

    # v7.x — payload SubAgent. Always-on in Phase 2. Generation-only:
    # produces structured `payload_candidate` shared findings the exploit
    # agent picks up and runs. Routes to the `payload` role profile (typically
    # Llama 4 Maverick / DeepSeek-R1 — less guardrail friction on offensive
    # payload generation than Anthropic models).
    "payload": (
        "You are the GENESIS Payload Generation Agent. You DO NOT execute "
        "anything against {target}. You produce CREATIVE, AGGRESSIVE payload "
        "candidates that other agents will run.\n\n"
        "Read PRIOR_PHASE_FINDINGS and SHARED_FINDINGS for: discovered "
        "endpoints, technology stack, observed defences (WAF / CSP / auth), "
        "exposed parameters, and any suspected injection sinks. For EACH "
        "high-promise sink (SQLi, SSRF, RCE, deserialisation, SSTI, prototype "
        "pollution, JWT, GraphQL, cache-poisoning, HTTP smuggling, file "
        "upload), emit ONE OR MORE `SHARED_FINDING` blocks of kind=`payload_candidate` "
        "describing a payload the exploit agent should test. Tools available "
        "to you: `payload_crafter` (template builder), `ai_request_forge` "
        "(structured HTTP request authoring), `code_pattern_search` (locate "
        "additional injection points). Use `deliberate(loop_type='counterfactual')` "
        "when a defence blocks an obvious payload — it'll surface alternates.\n\n"
        "Required emission shape — wrap each candidate in this exact JSON, "
        "and include MULTIPLE candidates per emission when the same sink "
        "warrants several payload axes (encoding, polyglot framing, second-"
        "order, content-type confusion, header/path canonicalisation):\n"
        "{{\"SHARED_FINDING\": {{\"kind\": \"payload_candidate\", "
        "\"value\": \"<short label, e.g. 'SQLi /search q= time-based'>\", "
        "\"context\": \"target_endpoint=<url> | sink_class=<sqli|ssrf|rce|...> "
        "| payload=<the actual payload string> | oracle=<what observable "
        "confirms a hit, e.g. 'response time >5s' or 'DNS callback to OOB host' "
        "or 'reflected token X in body'> | rationale=<one sentence on why "
        "this defeats the observed defence>\"}}}}\n\n"
        "Diversity is the goal. The exploit agent already runs the obvious "
        "scanner-canned payloads (sqlmap, xsstrike). YOUR value is the "
        "non-obvious axis: WAF-bypass encodings, parser differential payloads, "
        "polyglots, second-order attacks, abuse of advertised features in "
        "unintended ways. Aim for 5–10 candidates per Phase-2 round.\n\n"
        "Do NOT emit VULNERABILITY blocks — you do not verify. Do NOT call "
        "forge_runner / payload_swarm — you do not execute. The exploit "
        "agent reads your shared findings and runs them.\n\n"
        "When you have produced enough candidates for this round (~5–10), "
        "emit: {{\"PAYLOAD_COMPLETE\": true, \"candidates_emitted\": <n>}}"
        + _SHARED_USAGE_HINT
    ),
}


# ── T22 — surface detection ───────────────────────────────────────────────
_CRYPTO_SIGNALS = re.compile(
    r"\btls\b|\bssl\b|\bjwt\b|\bjws\b|\bjwe\b|\bhmac\b|\baes\b|\brsa\b|"
    r"\bencrypt(?:ed|ion)?\b|\bcipher\b|cookie[- ]?sig|padding[- ]?oracle|"
    r"\becdsa\b|\bpkcs\b|bearer\s+ey[a-z0-9_-]+\.[a-z0-9_-]+\.",
    re.IGNORECASE,
)
_AUTH_SIGNALS = re.compile(
    r"\boauth\b|\boidc\b|openid[- ]?connect|\bsaml\b|\bsso\b|"
    r"\b(?:login|signin|sign[- ]?in|authorize|authenticate|token)\b|"
    r"set-cookie|\bsession\b|\bcsrf\b|same[- ]?site",
    re.IGNORECASE,
)
_REVENG_SIGNALS = re.compile(
    r"\.(?:exe|dll|so|jar|apk|ipa|bin|elf|war|class|dylib|o)\b|"
    r"\b(?:binary|firmware|decompil|disassembl)\w*",
    re.IGNORECASE,
)
_EXPLOITDEV_SIGNALS = re.compile(
    r"\bcrash\b|\bsegfault\b|segmentation\s+fault|\bSIG(?:SEGV|ABRT|ILL|BUS)\b|"
    r"buffer\s+overflow|heap[- ]?corrupt|use[- ]after[- ]free|stack\s+smash|"
    r"\bafl\+?\+|crash_count.*[1-9]",
    re.IGNORECASE,
)
_NETWORK_PIVOT_PORTS: Set[int] = {
    22, 135, 139, 389, 445, 636, 1433, 1521, 3306, 3389,
    5432, 5900, 5985, 5986, 6379, 8443, 9200, 11211, 27017,
}
# ── v6 T137-T140 surface detection signals ────────────────────────────────
_IOT_SIGNALS = re.compile(
    r"\bupnp\b|\bmdns\b|\bssdp\b|\bmqtt\b|\bzigbee\b|\bzwave\b|\bble\b|"
    r"bluetooth[- ]?le|\bcoap\b|port\s*1883\b|port\s*5683\b|port\s*8883\b",
    re.IGNORECASE,
)
_IOT_PORTS: Set[int] = {1883, 5683, 8883, 48101, 1900}  # MQTT, CoAP, BLE-gw, UPnP

_MOBILE_SIGNALS = re.compile(
    r"\.apk\b|\.ipa\b|\bandroid\b|\bios\b|\bdex\b|\bsmali\b|"
    r"\bapktool\b|\bjadx\b",
    re.IGNORECASE,
)

_OT_SIGNALS = re.compile(
    r"\bmodbus\b|\bdnp3\b|\bs7comm\b|\bbacnet\b|\bprofibus\b|\bprofinet\b|"
    r"port\s*502\b|port\s*20000\b|port\s*47808\b|\bplc\b|\brtu\b|\bscada\b",
    re.IGNORECASE,
)
_OT_PORTS: Set[int] = {502, 20000, 47808, 44818, 2404}  # Modbus, DNP3, BACnet, EtherNet/IP, IEC104

_EMBEDDED_SIGNALS = re.compile(
    r"\bfirmware\b|\.bin\b|\bbootloader\b|\bu-boot\b|\bopenwrt\b|"
    r"\buart\b|\bjtag\b|\bspi\s+flash\b|squashfs\b|rootfs\b",
    re.IGNORECASE,
)


def _collect_ports(phase1_findings: Dict[str, Any], topology: Dict[str, Any]) -> Set[int]:
    """Best-effort port-number extraction from heterogeneous Phase 1 output."""
    ports: Set[int] = set()
    # Shared-findings kind=port (normalised)
    port_vals = (phase1_findings.get("shared_findings_by_kind") or {}).get("port", [])
    for v in port_vals:
        for m in re.finditer(r"\b(\d{1,5})\b", str(v)):
            try:
                p = int(m.group(1))
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                pass
    # Topology nodes — services may be {"port": ...} or "HTTP:80" strings
    for n in (topology.get("nodes") or []):
        for svc in (n.get("services") or []):
            if isinstance(svc, dict) and isinstance(svc.get("port"), int):
                ports.add(svc["port"])
            elif isinstance(svc, str):
                m = re.search(r":(\d{1,5})\b", svc)
                if m:
                    try:
                        ports.add(int(m.group(1)))
                    except ValueError:
                        pass
    return ports


def _count_hosts(topology: Dict[str, Any]) -> int:
    nodes = topology.get("nodes") or []
    return sum(1 for n in nodes if str(n.get("type", "")).lower() in ("host", "server", "router"))


def _detect_surfaces(
    phase1_findings: Dict[str, Any], topology: Dict[str, Any]
) -> Set[str]:
    """Which specialists should Phase 2 activate?

    Matches the plan's heuristics:
      - TLS/JWT/OAuth/SAML/cookie-signature signal → crypto, auth
      - Native-binary artifact surfaced           → reveng
      - fuzz_binary crash reported                → exploitdev
      - ≥2 hosts OR pivot-capable port             → network
      - UPnP/mDNS/MQTT/Zigbee signal              → iot   (T137)
      - APK/IPA artifact pulled                   → mobile (T138)
      - Modbus/DNP3/S7Comm/BACnet signal          → ot    (T139)
      - Firmware artifact / UART / bootloader     → embedded (T140)
    """
    text = json.dumps(phase1_findings, default=str).lower()
    activated: Set[str] = set()

    if _CRYPTO_SIGNALS.search(text):
        activated.add("crypto")
    if _AUTH_SIGNALS.search(text):
        activated.add("auth")
    if _REVENG_SIGNALS.search(text):
        activated.add("reveng")
    if _EXPLOITDEV_SIGNALS.search(text):
        activated.add("exploitdev")

    ports = _collect_ports(phase1_findings, topology)
    if _count_hosts(topology) >= 2 or (ports & _NETWORK_PIVOT_PORTS):
        activated.add("network")

    # v6 T137-T140 specialist triggers
    if _IOT_SIGNALS.search(text) or (ports & _IOT_PORTS):
        activated.add("iot")
    if _MOBILE_SIGNALS.search(text):
        activated.add("mobile")
    if _OT_SIGNALS.search(text) or (ports & _OT_PORTS):
        activated.add("ot")
    if _EMBEDDED_SIGNALS.search(text):
        activated.add("embedded")

    return activated


async def _staggered(coro: Any, delay: float) -> Any:
    """Delay a coroutine start by `delay` seconds to spread burst API calls."""
    if delay > 0:
        await asyncio.sleep(delay)
    return await coro


def _extract_shared_findings(text: str) -> List[Dict[str, Any]]:
    """Parse all {"SHARED_FINDING": {...}} blocks from an assistant text output."""
    out: List[Dict[str, Any]] = []
    marker = '"SHARED_FINDING"'
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
                            data = outer.get("SHARED_FINDING", {})
                            if isinstance(data, dict) and data.get("value"):
                                out.append(data)
                        except Exception:
                            pass
                        pos = i + 1
                        break
            i += 1
        else:
            pos = idx + len(marker)
    return out


async def _publish_shared_finding(
    session_id: str, agent_type: str, finding: Dict[str, Any]
) -> None:
    """Push a SHARED_FINDING into the per-session Redis list (capped + TTL)."""
    try:
        from app.database.redis_client import get_redis
        redis = await get_redis()
        key = _SHARED_FINDINGS_KEY_TMPL.format(session_id=session_id)
        payload = json.dumps({
            "from_agent": agent_type,
            "kind": str(finding.get("kind", "other"))[:20],
            "value": str(finding.get("value", ""))[:500],
            "context": str(finding.get("context", ""))[:500],
        })
        await redis.rpush(key, payload)
        await redis.ltrim(key, -_SHARED_FINDINGS_MAX, -1)
        await redis.expire(key, _SHARED_FINDINGS_TTL)
    except Exception as exc:
        logger.debug("Shared finding publish failed: %s", exc)


async def _read_shared_findings(session_id: str) -> List[Dict[str, Any]]:
    """Read the current shared-findings list for a session."""
    try:
        from app.database.redis_client import get_redis
        redis = await get_redis()
        key = _SHARED_FINDINGS_KEY_TMPL.format(session_id=session_id)
        raw_list = await redis.lrange(key, 0, -1)
        out: List[Dict[str, Any]] = []
        for raw in raw_list:
            try:
                out.append(json.loads(raw))
            except Exception:
                continue
        return out
    except Exception as exc:
        logger.debug("Shared findings read failed: %s", exc)
        return []


def _format_prior_findings_block(prior: Optional[Dict[str, Any]]) -> str:
    """Render a compact PRIOR_PHASE_FINDINGS JSON block for a Phase 2 agent seed."""
    if not prior:
        return ""
    try:
        compact = json.dumps(prior, default=str)[:4000]
    except Exception:
        compact = str(prior)[:4000]
    return (
        "PRIOR_PHASE_FINDINGS (from recon + analyst agents — reuse these, do NOT re-enumerate):\n"
        f"{compact}"
    )


class SubAgent:
    def __init__(
        self,
        agent_type: str,
        session_id: str,
        target: str,
        publish_fn: Any,
        # Instead of a fistful of callables, take the full AIOrchestrator
        # instance. Every extractor / storer / publisher we need lives on
        # it already, and this keeps multi-agent fully in sync with whatever
        # new extractors the main path gains over time (hypotheses today;
        # tomorrow maybe plan-tree sync, chain-nudges, etc.).
        ai_orchestrator: Any,
        # The LLM client + model + max_tokens are resolved ONCE by the main
        # orchestrator (which knows how to route anthropic / azure / bedrock /
        # custom via the provider adapter and respects the UI-stored settings)
        # and passed in. Sub-agents must NOT build their own client from the
        # static Settings object — the user's configured provider/model/key
        # live in Postgres AppSettings, not in config.py.
        client: Any,
        model: str,
        max_tokens: int,
        prior_findings: Optional[Dict[str, Any]] = None,
        intelligence_context: str = "",
    ) -> None:
        self.agent_type = agent_type
        self.session_id = session_id
        self.target = target
        self._publish = publish_fn
        self._ai = ai_orchestrator
        self._tool_names = _AGENT_TOOL_SETS[agent_type]
        self._mcp = MCPClient(timeout=300.0)
        self._prior_findings = prior_findings
        self._intelligence_context = intelligence_context
        self._client = client
        self._model = model
        self._max_tokens = max_tokens
        self._result_summary: Dict[str, Any] = {}
        # v7.x — total LLM turns this sub-agent burned. The parent multi-agent
        # orchestrator sums these across all sub-agents so the session-level
        # iteration counter (and the 50-iter floor gate) reflects real work.
        self._iteration_used: int = 0
        # v7.x — names of tools this sub-agent invoked. Aggregated by the
        # parent so the session-wide reasoning-loop backstop can decide
        # whether `deliberate` was ever called across the whole session.
        self._tools_used: set = set()
        # Track already-seen shared-findings signatures so we don't
        # re-inject the same item on every iteration of the inner loop.
        self._consumed_shared_sigs: set = set()
        # Local topology state — updated by _extract_topology_updates, which
        # also broadcasts each delta as a topology_update WS event.
        self._network_topology: Dict[str, Any] = {"nodes": [], "edges": []}

    def _system_prompt(self) -> str:
        base = _AGENT_PROMPTS[self.agent_type].format(target=self.target)
        if self._intelligence_context:
            base += f"\n\n## Intelligence from Similar Past Sessions\n{self._intelligence_context}"
        return base

    @property
    def result_summary(self) -> Dict[str, Any]:
        return self._result_summary

    def _tool_schemas(self) -> List[Dict[str, Any]]:
        # Import from the main orchestrator's schema list
        from app.services.ai_orchestrator import TOOL_SCHEMAS
        return [s for s in TOOL_SCHEMAS if s["name"] in self._tool_names]

    async def _build_shared_findings_refresh(self) -> Optional[str]:
        """Produce a refresh text block with any new shared findings this agent hasn't yet seen."""
        current = await _read_shared_findings(self.session_id)
        if not current:
            return None
        fresh: List[Dict[str, Any]] = []
        for item in current:
            # Ignore findings the current agent itself published.
            if item.get("from_agent") == self.agent_type:
                continue
            sig = f"{item.get('from_agent')}::{item.get('kind')}::{item.get('value')}"
            if sig in self._consumed_shared_sigs:
                continue
            self._consumed_shared_sigs.add(sig)
            fresh.append(item)
        if not fresh:
            return None
        try:
            payload = json.dumps(fresh, default=str)[:3000]
        except Exception:
            payload = str(fresh)[:3000]
        return (
            "SHARED_FINDINGS (new since last turn — reuse these, do NOT re-enumerate):\n"
            f"{payload}"
        )

    async def run(self) -> Dict[str, Any]:
        from datetime import datetime, timezone
        from app.services.ai_orchestrator import (
            _now_iso,
            _ANTHROPIC_TIMEOUT_SECONDS,
        )

        # v7.x — resolve the `subagent` role for THIS sub-agent's LLM calls
        # via the routing helper. Falls back to the orchestrator's primary
        # client+model when no per-role profile is configured.
        client = self._client
        model = self._model
        try:
            from app.services.llm_routing import get_client_and_model_for_role
            _ai_settings = getattr(self._ai, "_app_settings", None) or {}
            if _ai_settings:
                # v7.x — payload SubAgent uses the dedicated `payload` role
                # so it routes to a less-restrictive model (Llama 4 / DeepSeek)
                # by default. Every other sub-agent uses the generic
                # `subagent` role.
                _resolved_role = "payload" if self.agent_type == "payload" else "subagent"
                _routed_client, _routed_model, _ = await get_client_and_model_for_role(
                    _resolved_role, _ai_settings,
                )
                if _routed_client is not None and _routed_model:
                    client, model = _routed_client, _routed_model
        except Exception as _route_exc:
            logger.debug(
                "[ROUTING] subagent[%s] resolve failed (using primary): %s",
                self.agent_type, _route_exc,
            )
        messages: List[Dict[str, Any]] = []
        iteration = 0
        # Exhaustive mode: per-agent iteration cap raised. The agent's own
        # FINAL_REPORT / EXPLOIT_COMPLETE / RECON_COMPLETE block remains the
        # primary self-termination signal; this is only the safety net.
        max_iter = 40
        # v7.x — per-agent floor. Multi-agent runs ~4 generalists per phase, so
        # the per-agent floor is smaller than the session floor (default 50/3).
        try:
            from app.config import settings as _config_settings
            _session_min_iter = int(_config_settings.min_iterations)
        except Exception:
            _session_min_iter = 50
        min_iter_per_agent = max(15, _session_min_iter // 3)
        if max_iter < min_iter_per_agent:
            max_iter = min_iter_per_agent
        # v7.x — per-agent (tool, params_hash, target) dedup. Same shape as
        # single-agent — Nth+1 occurrence short-circuits with ALREADY_EXECUTED.
        # H: exploit/payload need MORE variants per probe so they get a higher
        # threshold (5 occurrences before block). recon/analyst/code stay at
        # the strict default (3 occurrences) so they don't spin on the same
        # probe.
        try:
            _base_dedup_threshold = int(_config_settings.dedup_threshold)
        except Exception:
            _base_dedup_threshold = 2
        _PER_AGENT_DEDUP_OVERRIDE = {
            "exploit": 4,
            "payload": 4,
            "exploitdev": 4,
        }
        _dedup_threshold = _PER_AGENT_DEDUP_OVERRIDE.get(
            self.agent_type, _base_dedup_threshold,
        )
        if _dedup_threshold != _base_dedup_threshold:
            logger.info(
                "[DEDUP_OVERRIDE] subagent[%s] using threshold=%d (default=%d)",
                self.agent_type, _dedup_threshold, _base_dedup_threshold,
            )
        dedup_counts: Dict[tuple, int] = {}
        dedup_first_iter: Dict[tuple, int] = {}
        # v7.x — Phase-1 coverage trackers (D). Used by recon/analyst to
        # gate *_COMPLETE on minimum coverage (5 distinct tools + 3 signals).
        self._distinct_tools_used: Set[str] = set()
        self._topology_updates_seen: int = 0
        self._hypotheses_seen: int = 0
        result_summary: Dict[str, Any] = {}
        # max_tokens was resolved by the main orchestrator from the UI-stored
        # model. Budget must stay strictly < max_tokens; leave ≥ 2048 for
        # actual output. Thinking is only enabled when the model supports it
        # (opus / sonnet) — older or non-Anthropic models will skip it below.
        agent_max_tokens = self._max_tokens
        agent_thinking_budget = min(5000, max(1024, agent_max_tokens - 2048))
        supports_thinking = "opus" in model.lower() or "sonnet" in model.lower()

        # Always start with a concrete kickoff message. Anthropic rejects a
        # `messages.create` call with an empty `messages` array, and Phase 1
        # agents (recon, analyst) have no prior findings or shared findings
        # to seed from — only the system prompt. Phase 2 agents additionally
        # get a structured PRIOR_PHASE_FINDINGS block.
        kickoff_by_agent = {
            "recon":   f"Begin reconnaissance of target {self.target}. Enumerate hosts, ports, services, DNS, and subdomains using the tools assigned to you. Emit TOPOLOGY_UPDATE JSON blocks whenever you identify a new host or service, and SHARED_FINDING blocks for anything other agents can reuse. When you have a complete picture, emit RECON_COMPLETE.",
            "analyst": f"Begin service analysis of target {self.target}. Identify web frameworks, CMS, WAF posture, TLS weaknesses, and interesting headers. Emit SHARED_FINDING blocks for tech / WAF / headers so the exploit and code agents can reuse them. When finished, emit ANALYST_COMPLETE.",
            "exploit": f"Begin vulnerability testing of target {self.target}. Use the PRIOR_PHASE_FINDINGS and any SHARED_FINDINGS already in context — do NOT re-enumerate. Emit a VULNERABILITY JSON block for each confirmed finding with full evidence_for, attack_chain_id, chain_position, mitre_techniques, exploit_code, and patch_code. When done, emit EXPLOIT_COMPLETE.",
            "code":    f"Begin static analysis. If any downloadable source or binary artifacts were surfaced by earlier phases (see PRIOR_PHASE_FINDINGS / SHARED_FINDINGS), analyse those with your assigned tools. Flag hardcoded secrets, injection sinks, weak crypto, unsafe deserialisation. When done, emit CODE_COMPLETE.",
        }
        seed_text_parts: List[str] = [
            kickoff_by_agent.get(
                self.agent_type,
                f"Begin your assigned role for target {self.target}.",
            )
        ]
        prior_block = _format_prior_findings_block(self._prior_findings)
        if prior_block:
            seed_text_parts.append(prior_block)
        initial_shared = await self._build_shared_findings_refresh()
        if initial_shared:
            seed_text_parts.append(initial_shared)
        messages.append({
            "role": "user",
            "content": "\n\n".join(seed_text_parts),
        })

        await self._publish(self.session_id, {
            "type": "agent_start",
            "data": {
                "agent_id": self.agent_type,
                "agent_type": self.agent_type,
                "target": self.target,
                "seeded_with_prior": bool(prior_block),
            },
            "timestamp": _now_iso(),
        })

        while iteration < max_iter:
            iteration += 1

            # v7.x — honour the operator's Stop button. Solo orchestrator
            # already polls; multi-agent sub-agents previously did NOT, which
            # is why a Stop click let sub-agents grind on for hours. Each
            # sub-agent now bails as soon as the session is marked stopped or
            # failed at the parent level.
            try:
                _status = await self._ai._get_session_status(self.session_id)
            except Exception:
                _status = "unknown"
            if _status in ("stopped", "failed"):
                logger.info(
                    "[STOP_POLL] subagent[%s] session=%s status=%s — terminating loop at iter=%d",
                    self.agent_type, self.session_id, _status, iteration,
                )
                break

            # Write the iteration count back to the session so the UI top-bar
            # "Iter N" counter actually moves in multi-agent mode. Multiple
            # agents run concurrently per phase, so the value jitters between
            # agents — that's fine; the user just needs to see progress.
            # Also publish a session_update so the WS stream reflects it
            # live without waiting for a DB read.
            try:
                await self._ai._update_session(self.session_id, iteration=iteration)
                await self._publish(self.session_id, {
                    "type": "session_update",
                    "data": {
                        "iteration": iteration,
                        "phase": self.agent_type,
                    },
                    "timestamp": _now_iso(),
                })
            except Exception as exc:
                logger.debug("session iteration update failed (non-fatal): %s", exc)

            try:
                create_kwargs: Dict[str, Any] = dict(
                    model=model,
                    max_tokens=agent_max_tokens,
                    system=self._system_prompt(),
                    tools=self._tool_schemas(),
                    messages=messages,
                    timeout=_ANTHROPIC_TIMEOUT_SECONDS,
                )
                if supports_thinking:
                    create_kwargs["thinking"] = {
                        "type": "enabled",
                        "budget_tokens": agent_thinking_budget,
                    }
                response = await client.messages.create(**create_kwargs)
                try:
                    from app.services.llm_usage import record_llm_usage
                    await record_llm_usage(
                        session_id=self.session_id, iteration=iteration,
                        source=f"subagent:{self.agent_type}",
                        model=model, response=response,
                        publish_fn=self._publish,
                    )
                except Exception:
                    pass
            except Exception as exc:
                logger.error("SubAgent[%s] API error: %s", self.agent_type, exc)
                try:
                    from app.services.ai_orchestrator import AIOrchestrator
                    await AIOrchestrator()._record_error(
                        self.session_id,
                        "subagent_api",
                        exc,
                        iteration=iteration,
                        context={
                            "agent_type": self.agent_type,
                            "model": model,
                        },
                    )
                except Exception as inner:
                    logger.debug("subagent error record failed: %s", inner)
                break

            # Collect content
            text_parts: List[str] = []
            tool_calls: List[Dict[str, Any]] = []
            done = False

            for block in response.content:
                btype = getattr(block, "type", None)
                if btype == "thinking":
                    thinking_text = getattr(block, "thinking", "")
                    if thinking_text:
                        # Publish for live-panel rendering, AND persist.
                        await self._publish(self.session_id, {
                            "type": "deep_thought",
                            "data": {
                                "agent_id": self.agent_type,
                                "agent_type": self.agent_type,
                                "content": f"[{self.agent_type}] {thinking_text}",
                                "iteration": iteration,
                            },
                            "timestamp": _now_iso(),
                        })
                        await self._ai._store_deep_thought(
                            self.session_id,
                            f"[{self.agent_type}] {thinking_text}",
                            iteration,
                        )
                elif btype == "text":
                    text = block.text
                    text_parts.append(text)
                    # Publish any SHARED_FINDING blocks this agent emitted
                    for finding in _extract_shared_findings(text):
                        await _publish_shared_finding(self.session_id, self.agent_type, finding)
                        await self._publish(self.session_id, {
                            "type": "shared_finding",
                            "data": {
                                "agent_id": self.agent_type,
                                "agent_type": self.agent_type,
                                "agent": self.agent_type,
                                "kind": finding.get("kind", "other"),
                                "value": str(finding.get("value", ""))[:300],
                                "context": str(finding.get("context", ""))[:300],
                            },
                            "timestamp": _now_iso(),
                        })
                    # Check completion signal — v7.x: floor-aware. The
                    # per-agent floor (min_iter_per_agent) is the bare minimum
                    # before *_COMPLETE is allowed to terminate the agent loop.
                    # Below the floor we still parse the result summary so the
                    # phase-level orchestrator has data to work with, but we
                    # do NOT set done — instead we let the loop iterate and
                    # rely on the continuation message below to keep working.
                    #
                    # v7.x — Phase-1 coverage gate (D). recon/analyst can ONLY
                    # signal complete when they have substantive coverage:
                    #   recon  : ≥5 distinct tools AND ≥3 topology updates
                    #   analyst: ≥5 distinct tools AND ≥3 hypothesis emissions
                    # Otherwise *_COMPLETE is suppressed and the loop continues.
                    # This stops thin Phase-1 from starving _detect_surfaces.
                    p1_required = self.agent_type in ("recon", "analyst")
                    p1_distinct_tools_ok = len(getattr(self, "_distinct_tools_used", set())) >= 5
                    p1_signals_ok = (
                        getattr(self, "_topology_updates_seen", 0) >= 3
                        if self.agent_type == "recon"
                        else getattr(self, "_hypotheses_seen", 0) >= 3
                        if self.agent_type == "analyst"
                        else True
                    )
                    p1_coverage_met = (not p1_required) or (
                        p1_distinct_tools_ok and p1_signals_ok
                    )
                    completion_key = f"{self.agent_type.upper()}_COMPLETE"
                    if completion_key in text:
                        try:
                            for chunk in text.split("{"):
                                if completion_key in chunk:
                                    obj = json.loads("{" + chunk.split("}")[0] + "}")
                                    result_summary = obj
                                    if iteration >= min_iter_per_agent and p1_coverage_met:
                                        done = True
                                    elif p1_required and not p1_coverage_met:
                                        logger.info(
                                            "[P1_COVERAGE_GATE] subagent[%s] suppressed "
                                            "%s — distinct_tools=%d (need 5) "
                                            "signals=%d (need 3)",
                                            self.agent_type, completion_key,
                                            len(getattr(self, "_distinct_tools_used", set())),
                                            getattr(self, "_topology_updates_seen", 0)
                                            if self.agent_type == "recon"
                                            else getattr(self, "_hypotheses_seen", 0),
                                        )
                                    break
                        except Exception:
                            if iteration >= min_iter_per_agent and p1_coverage_met:
                                done = True
                elif btype == "tool_use":
                    tool_calls.append({"name": block.name, "id": block.id, "input": block.input})

            # Store AND publish the composite thought. Publishing is how the
            # Agent Thoughts panel in the SessionViewer populates — the
            # single-agent orchestrator does the same thing on line 1429-ish.
            full_text = "\n".join(text_parts)
            if full_text.strip():
                # v7.x — Phase-1 coverage trackers: count substantive emissions
                # so the *_COMPLETE gate (recon needs ≥3 topology, analyst
                # needs ≥3 hypotheses) can fire at the right time.
                if self.agent_type == "recon":
                    self._topology_updates_seen += full_text.count("TOPOLOGY_UPDATE")
                if self.agent_type == "analyst":
                    self._hypotheses_seen += full_text.count("\"HYPOTHESIS\":")
                stamped = f"[{self.agent_type}] {full_text}"
                await self._publish(self.session_id, {
                    "type": "agent_thought",
                    "data": {"thought": stamped, "iteration": iteration, "agent_id": self.agent_type, "agent_type": self.agent_type},
                    "timestamp": _now_iso(),
                })
                await self._ai._store_thought(self.session_id, stamped, iteration)
                # Run the same extractors the single-agent orchestrator runs
                # on every text turn: vulnerabilities (with chain nudges),
                # hypotheses (written to the journal), and TOPOLOGY_UPDATE
                # JSON blocks. Without these, the Findings / Hypotheses /
                # Topology panels stay empty in multi-agent mode even though
                # the agents may have emitted the right blocks.
                try:
                    await self._ai._extract_and_save_vulnerabilities(
                        self.session_id, full_text
                    )
                except Exception as exc:
                    logger.debug("vuln extract failed (non-fatal): %s", exc)
                try:
                    await self._ai._extract_and_save_hypotheses(
                        self.session_id, full_text
                    )
                except Exception as exc:
                    logger.debug("hypothesis extract failed (non-fatal): %s", exc)
                try:
                    self._network_topology = await self._ai._extract_topology_updates(
                        self.session_id, full_text, self._network_topology
                    )
                except Exception as exc:
                    logger.debug("topology extract failed (non-fatal): %s", exc)

            messages.append({"role": "assistant", "content": response.content})

            # v7.x — per-agent floor gate. If the agent says it's done (either
            # by emitting *_COMPLETE or by ending its turn) but the floor
            # hasn't been reached, push back with a continuation message
            # instead of terminating the loop.
            if (response.stop_reason == "end_turn" or done):
                if iteration >= min_iter_per_agent:
                    break
                logger.info(
                    "[FLOOR_GATE] subagent=%s suppressed termination at "
                    "iter=%d (per-agent min=%d)",
                    self.agent_type, iteration, min_iter_per_agent,
                )
                messages.append({"role": "user", "content": (
                    f"[CONTINUE — agent floor not reached] You are at iter "
                    f"{iteration} of a min-{min_iter_per_agent} per-agent "
                    "run. Do NOT terminate. Pick the next un-tested angle "
                    "for your phase and run a probe. If you're stuck, call "
                    "`deliberate(loop_type='counterfactual'|'hypothesis_decomp', ...)` "
                    "to break the obstacle."
                )})
                done = False
                continue

            # Execute tool calls, then attach any fresh shared findings.
            if tool_calls:
                tool_results: List[Dict[str, Any]] = []
                vision_blocks: List[Dict[str, Any]] = []
                for tc in tool_calls:
                    tool_name = tc["name"]
                    tool_params = tc["input"] or {}
                    tool_use_id = tc["id"]
                    self._tools_used.add(tool_name)
                    self._distinct_tools_used.add(tool_name)

                    # v7.x — per-agent (tool, params_hash, target) dedup.
                    # 3rd occurrence short-circuits with ALREADY_EXECUTED. The
                    # 2-strike rule lets legitimate retries through.
                    _sig_key = self._ai._compute_call_signature(tool_name, tool_params)
                    _prior = dedup_counts.get(_sig_key, 0)
                    dedup_counts[_sig_key] = _prior + 1
                    if _prior >= _dedup_threshold:
                        _first_iter = dedup_first_iter.get(_sig_key, iteration)
                        synthetic = (
                            f"ALREADY_EXECUTED — tool={tool_name} "
                            f"target={_sig_key[2] or 'n/a'} first ran at "
                            f"iter {_first_iter}; this is occurrence "
                            f"#{_prior + 1}. Pick a DIFFERENT probe or "
                            "DIFFERENT parameters."
                        )
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": tool_use_id,
                            "content": synthetic,
                        })
                        logger.info(
                            "[DEDUP] subagent=%s iter=%d tool=%s target=%s "
                            "occurrence=%d (skipped)",
                            self.agent_type, iteration, tool_name,
                            _sig_key[2] or "n/a", _prior + 1,
                        )
                        continue
                    dedup_first_iter.setdefault(_sig_key, iteration)

                    # Publish a RUNNING event so the Tool Outputs panel shows
                    # a live spinner (matches the single-agent orchestrator's
                    # shape exactly — the frontend handler keys off this).
                    await self._publish(self.session_id, {
                        "type": "tool_execution",
                        "data": {
                            "tool": tool_name,
                            "status": "running",
                            "params": tool_params,
                            "iteration": iteration,
                            "agent": self.agent_type,
                        },
                        "timestamp": _now_iso(),
                    })

                    start_time = datetime.now(timezone.utc)
                    try:
                        if tool_name == "deliberate":
                            # v7.x — multi-agent parity for reasoning loops.
                            # Same dispatch shape as the single-agent path.
                            from app.services.reasoning import registry as _reasoning_registry
                            _llm_call = self._ai._make_llm_call_adapter(
                                client=self._client, model=self._model,
                                session_id=self.session_id,
                                source=f"reasoning_loop:{self.agent_type}",
                            )
                            _loop_type = str(tool_params.get("loop_type", ""))
                            _loop_inputs = tool_params.get("inputs") or {}
                            _loop_result = await _reasoning_registry.dispatch(
                                session_id=self.session_id,
                                loop_type=_loop_type,
                                inputs=_loop_inputs,
                                llm_call=_llm_call,
                            )
                            tool_result = {
                                "output": json.dumps(_loop_result, default=str)[:4000],
                                "parsed": _loop_result,
                            }
                        else:
                            tool_result = await self._mcp.execute_tool(tool_name, tool_params)
                    except Exception as tool_exc:
                        logger.warning(
                            "SubAgent[%s] tool %s raised: %s",
                            self.agent_type, tool_name, tool_exc,
                        )
                        tool_result = {
                            "output": f"[tool call failed: {tool_exc}]",
                            "error": str(tool_exc),
                        }
                    duration = (datetime.now(timezone.utc) - start_time).total_seconds()

                    parsed = tool_result.get("parsed") or {}
                    raw_output = tool_result.get("output", "") or ""

                    # Persist to Mongo so the Tool Outputs tab survives a
                    # browser refresh and feeds the historical timeline.
                    try:
                        await self._ai._store_tool_output(
                            self.session_id, tool_name, tool_params, tool_result, duration,
                        )
                    except Exception as exc:
                        logger.debug("tool-output persist failed (non-fatal): %s", exc)

                    # T6 / T12 — attach render_and_see and browser_session
                    # step screenshots as vision image blocks on the next turn.
                    if tool_name in ("render_and_see", "browser_session") and isinstance(parsed, dict):
                        screenshot_b64 = str(parsed.get("screenshot_b64") or "")
                        if screenshot_b64:
                            vision_blocks.append({
                                "type": "image",
                                "source": {
                                    "type": "base64",
                                    "media_type": str(parsed.get("screenshot_mime") or "image/png"),
                                    "data": screenshot_b64,
                                },
                            })

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        "content": raw_output,
                    })
                    # Publish the COMPLETE event with params, output tail,
                    # parsed payload, and duration — same shape the Tool
                    # Outputs panel renders in single-agent mode.
                    await self._publish(self.session_id, {
                        "type": "tool_execution",
                        "data": {
                            "tool": tool_name,
                            "status": "complete",
                            "params": tool_params,
                            "output": raw_output[:2000],
                            "parsed": parsed,
                            "duration_seconds": duration,
                            "iteration": iteration,
                            "agent": self.agent_type,
                        },
                        "timestamp": _now_iso(),
                    })

                    # Live operator-goal subtask progress: debounced, fire-and-forget.
                    try:
                        from app.services.goal_progress import schedule_recompute as _sched_goal_progress
                        _sched_goal_progress(self.session_id)
                    except Exception:  # noqa: BLE001
                        pass
                content_blocks: List[Dict[str, Any]] = list(tool_results)
                if vision_blocks:
                    content_blocks.append({
                        "type": "text",
                        "text": (
                            f"[vision] {len(vision_blocks)} screenshot(s) attached from "
                            f"render_and_see / browser_session. Reason about what the UI actually shows."
                        ),
                    })
                    content_blocks.extend(vision_blocks)
                refresh = await self._build_shared_findings_refresh()
                if refresh:
                    content_blocks.append({"type": "text", "text": refresh})
                messages.append({"role": "user", "content": content_blocks})
            else:
                break

        await self._publish(self.session_id, {
            "type": "agent_complete",
            "data": {"agent_id": self.agent_type, "agent_type": self.agent_type, "summary": result_summary},
            "timestamp": _now_iso(),
        })

        self._result_summary = result_summary
        self._iteration_used = iteration
        return result_summary


class MultiAgentOrchestrator:
    """
    Runs parallel specialized sub-agents (Recon, Analyst, Exploit, Code) for a session.
    Called by AIOrchestrator when session.agent_mode == "multi_agent".
    """

    def __init__(
        self,
        session_id: str,
        target: str,
        publish_fn: Any,
        ai_orchestrator: Any,
        client: Any,
        model: str,
        max_tokens: int,
        intelligence_context: str = "",
        min_duration_minutes: int = 0,
        session_started_at: Optional[Any] = None,
        scan_profile: str = "exhaustive",
    ) -> None:
        self.session_id = session_id
        self.target = target
        self._publish = publish_fn
        self._ai = ai_orchestrator
        self._client = client
        self._model = model
        self._max_tokens = max_tokens
        self._intelligence_context = intelligence_context
        # v7.x — wallclock floor (deep_research = 360min, exhaustive = 60min, 0 disables).
        # Refuses to terminate the rounds-loop until elapsed wallclock meets this floor.
        self._min_duration_minutes = int(min_duration_minutes)
        self._session_started_at = session_started_at
        self._scan_profile = scan_profile
        # Profile can also override max_rounds (deep_research = 10).
        try:
            from app.services.ai_orchestrator import SCAN_PROFILES as _SP
            self._max_rounds_override = int(
                _SP.get(scan_profile, {}).get("max_rounds", 0) or 0
            )
        except Exception:
            self._max_rounds_override = 0

    async def run(self) -> None:
        from app.services.ai_orchestrator import _now_iso

        # v7.x — load session-level gating params once. Same defaults as the
        # solo orchestrator so behaviour is consistent across modes.
        try:
            from app.config import settings as _config_settings
            _session_min_iter = int(_config_settings.min_iterations)
        except Exception:
            _session_min_iter = 50
        # Hard ceiling on rounds — prevents runaway credit burn if gates
        # somehow never satisfy. 5 rounds × ~100 turns/round ≈ 500 LLM turns.
        # v7.x — profile override: deep_research = 10 rounds, exhaustive = 5.
        max_rounds = self._max_rounds_override or 5

        # v7.x — Load per-target specialist memory ONCE. Subsequent rounds
        # union this into _candidate_set so a target that previously activated
        # `network` keeps activating `network` even if Phase-1 signals are
        # thinner this run. This is the core reproducibility fix: variance
        # across same-target runs becomes monotonically non-decreasing.
        self._memory_specialists: Set[str] = set()
        self._memory_specialists_with_findings: Set[str] = set()
        try:
            from app.database.mongodb import get_target_specialist_memory_collection
            mem_col = get_target_specialist_memory_collection()
            mem_doc = await mem_col.find_one({"target_ip": self.target})
            if mem_doc:
                self._memory_specialists = set(mem_doc.get("specialists") or [])
                self._memory_specialists_with_findings = set(
                    mem_doc.get("specialists_with_findings") or []
                )
                logger.info(
                    "[SPECIALIST_MEMORY] target=%s loaded prior_specialists=%s with_findings=%s",
                    self.target,
                    sorted(self._memory_specialists),
                    sorted(self._memory_specialists_with_findings),
                )
        except Exception as exc:
            logger.debug("[SPECIALIST_MEMORY] load failed (non-fatal): %s", exc)

        await self._publish(self.session_id, {
            "type": "multi_agent_start",
            "data": {
                "agents": sorted(_GENERALIST_AGENTS),
                "specialists_available": sorted(_SPECIALIST_AGENTS),
                "target": self.target,
                "min_iterations": _session_min_iter,
                "max_rounds": max_rounds,
            },
            "timestamp": _now_iso(),
        })

        def _make_agent(
            agent_type: str, prior: Optional[Dict[str, Any]] = None
        ) -> SubAgent:
            return SubAgent(
                agent_type=agent_type,
                session_id=self.session_id,
                target=self.target,
                publish_fn=self._publish,
                ai_orchestrator=self._ai,
                client=self._client,
                model=self._model,
                max_tokens=self._max_tokens,
                prior_findings=prior,
                intelligence_context=self._intelligence_context,
            )

        # ── Phase 1 (recon + analyst) — runs ONCE per session ──────────────
        recon_agent = _make_agent("recon")
        analyst_agent = _make_agent("analyst")
        recon_result, analyst_result = await asyncio.gather(
            recon_agent.run(), analyst_agent.run(), return_exceptions=True
        )
        logger.info(
            "Phase 1 complete — recon=%s analyst=%s",
            recon_result, analyst_result,
        )

        # v7.x — Stop check between Phase 1 and rounds-loop entry, so the
        # adversarial seed doesn't kick off after the operator hit Stop.
        try:
            _post_p1_status = await self._ai._get_session_status(self.session_id)
        except Exception:
            _post_p1_status = "unknown"
        if _post_p1_status in ("stopped", "failed"):
            logger.info(
                "[STOP_POLL] multi-agent session=%s status=%s — bailing before Phase 2",
                self.session_id, _post_p1_status,
            )
            await self._publish(self.session_id, {
                "type": "multi_agent_complete",
                "data": {"reason": "stopped_after_phase1", "session_iter_total": 0},
                "timestamp": _now_iso(),
            })
            return

        # Session-wide aggregates that survive across rounds. The session's
        # iteration column in PG is updated as the SUM of all sub-agent
        # iterations (max-clamped by _update_session) so the UI top-bar
        # reflects real session work, not per-agent jitter.
        session_iter_total = int(getattr(recon_agent, "_iteration_used", 0)) \
            + int(getattr(analyst_agent, "_iteration_used", 0))
        session_tools_used: Set[str] = set()
        session_tools_used |= getattr(recon_agent, "_tools_used", set())
        session_tools_used |= getattr(analyst_agent, "_tools_used", set())
        try:
            await self._ai._update_session(
                self.session_id, iteration=session_iter_total,
            )
        except Exception:
            pass

        # ── v7.x — Adversarial seed (red/blue) before Round 1's Phase 2 ────
        # Uses the Phase-1 prior_findings summary as target context. Bounded
        # at 3 rounds; persists transcripts to adversarial_reasoning so the
        # operator's Adversarial tab populates within ~30s of session start.
        try:
            _seed_prior = await self._compile_prior_findings(
                recon_agent, analyst_agent,
            )
            _seed_context = (
                str(_seed_prior.get("summary", ""))[:1500]
                or f"Target {self.target}, multi-agent exhaustive run."
            )
            _rb = await self._ai._get_red_blue(self._client, self._model)
            await _rb.synthesize(
                session_id=self.session_id,
                target_context=_seed_context[:3000],
                max_pairs=3,
                trigger="seed",
                publish_fn=self._publish,
            )
            logger.info(
                "[ADVERSARIAL] session=%s seeded red/blue after Phase 1",
                self.session_id,
            )
        except Exception as exc:
            logger.warning(
                "[ADVERSARIAL] seed dispatch failed: %s", exc,
            )

        # ── Rounds-loop around Phase 2 ─────────────────────────────────────
        # After every Phase-2 round, we check the same three session-level
        # gates the solo orchestrator uses (min_iter floor, goal-progress,
        # dedup-exhaustion-via-novel-tool-coverage) and decide whether the
        # session is genuinely done or needs another round.
        round_idx = 0
        all_phase2_results: List[Dict[str, Any]] = []
        backstop_dispatched = False
        # v7.x — adversarial follow-up state. Each high-conf hypothesis seen
        # in this session triggers at most one extra red→blue round.
        adversarial_seen: Set[str] = set()
        philosopher_fired = False
        while round_idx < max_rounds:
            round_idx += 1

            # v7.x — honour Stop button at the top of every Phase-2 round so
            # we don't kick off a brand-new fan-out (4–9 sub-agents in
            # parallel) right after the operator clicked Stop.
            try:
                _status = await self._ai._get_session_status(self.session_id)
            except Exception:
                _status = "unknown"
            if _status in ("stopped", "failed"):
                logger.info(
                    "[STOP_POLL] multi-agent session=%s status=%s — bailing before round=%d",
                    self.session_id, _status, round_idx,
                )
                break

            # Compile prior-phase findings (refreshed each round so later
            # rounds see Round-1's findings as prior context).
            prior_findings = await self._compile_prior_findings(
                recon_agent, analyst_agent,
            )
            topology = await self._load_topology()
            activated_specialists = _detect_surfaces(prior_findings, topology)
            # v7.x — Union of:
            #   1. _BASELINE_SPECIALISTS (always-on for exhaustive runs)
            #   2. _detect_surfaces output (signal-driven additions)
            #   3. self._memory_specialists (specialists that fired on prior
            #      runs of THIS target — see B below)
            # Capped at _MAX_SPECIALISTS in priority order.
            _candidate_set = (
                _BASELINE_SPECIALISTS
                | activated_specialists
                | getattr(self, "_memory_specialists", set())
            )
            specialists_ordered = [
                s for s in (
                    "ot", "iot", "embedded", "mobile",
                    "reveng", "exploitdev", "crypto", "auth", "network",
                    "source_analyst", "invariant_engineer",
                )
                if s in _candidate_set
            ][:_MAX_SPECIALISTS]
            self._specialists_baseline_used = sorted(_BASELINE_SPECIALISTS)
            self._specialists_detected = sorted(activated_specialists)
            self._specialists_inherited = sorted(getattr(self, "_memory_specialists", set()))
            self._specialists_actually_ran = list(specialists_ordered)
            logger.info(
                "[SPECIALISTS] session=%s round=%d baseline=%s detected=%s memory=%s -> ordered=%s",
                self.session_id, round_idx,
                sorted(_BASELINE_SPECIALISTS),
                sorted(activated_specialists),
                sorted(getattr(self, "_memory_specialists", set())),
                specialists_ordered,
            )

            await self._publish(self.session_id, {
                "type": "phase_transition",
                "data": {
                    "from_phase": (
                        "phase1_recon_analyst" if round_idx == 1
                        else f"phase2_round{round_idx-1}"
                    ),
                    "to_phase": f"phase2_round{round_idx}",
                    "round": round_idx,
                    "max_rounds": max_rounds,
                    "session_iter_total": session_iter_total,
                    "prior_findings": prior_findings,
                    "specialists_activated": specialists_ordered,
                    "specialists_skipped": sorted(
                        _SPECIALIST_AGENTS - set(specialists_ordered)
                    ),
                },
                "timestamp": _now_iso(),
            })
            await self._persist_phase("exploitation")

            # Phase 2 sub-agents — fresh instances each round so per-agent
            # dedup maps don't carry over and block the agent from re-trying
            # angles that became reachable thanks to the previous round.
            exploit_agent = _make_agent("exploit", prior=prior_findings)
            code_agent = _make_agent("code", prior=prior_findings)
            # v7.x — payload SubAgent. Always-on in Phase 2; routes to the
            # `payload` role profile (typically Llama 4 / DeepSeek-R1).
            # Generation-only: emits SHARED_FINDING(kind='payload_candidate')
            # which the exploit agent consumes via its shared-findings refresh.
            payload_agent = _make_agent("payload", prior=prior_findings)
            specialist_agents: Dict[str, SubAgent] = {
                name: _make_agent(name, prior=prior_findings)
                for name in specialists_ordered
            }
            phase2_coros = [exploit_agent.run(), code_agent.run(), payload_agent.run()]
            phase2_agents: List[SubAgent] = [exploit_agent, code_agent, payload_agent]
            phase2_names = ["exploit", "code", "payload"]
            for name, agent in specialist_agents.items():
                phase2_coros.append(agent.run())
                phase2_agents.append(agent)
                phase2_names.append(name)

            # v7.x — E: spawn diagnostics. Log BEFORE gather so any silent
            # crash leaves a trace; log AFTER with per-agent iteration counts
            # so the operator can see who actually ran. Surfaces the case
            # where a SubAgent (e.g. payload) was created but never executed.
            logger.info(
                "[SPAWN] session=%s round=%d agents=%s",
                self.session_id, round_idx, phase2_names,
            )

            # Stagger agent startup to spread the initial burst of API calls
            # across time. Without this, all agents fire their first request
            # simultaneously, which trips Azure's per-minute RPM quota even
            # when per-call retries succeed individually. 3 s spacing between
            # agents means 11 agents fan out over ~30 s instead of instantly.
            phase2_coros_staggered = [
                _staggered(coro, i * 3.0)
                for i, coro in enumerate(phase2_coros)
            ]
            phase2_results = await asyncio.gather(
                *phase2_coros_staggered, return_exceptions=True,
            )
            _per_agent_iters = {
                name: int(getattr(ag, "_iteration_used", 0))
                for name, ag in zip(phase2_names, phase2_agents)
            }
            logger.info(
                "[FINISHED] session=%s round=%d iter_counts=%s",
                self.session_id, round_idx, _per_agent_iters,
            )
            # Surface zero-iteration agents as warnings — those are likely
            # silent crashes worth investigating.
            for _name, _iters in _per_agent_iters.items():
                if _iters == 0:
                    logger.warning(
                        "[SPAWN] session=%s round=%d agent=%s ran 0 iterations "
                        "— check for silent crash",
                        self.session_id, round_idx, _name,
                    )
            round_result = {
                name: str(res) for name, res in zip(phase2_names, phase2_results)
            }
            all_phase2_results.append({
                "round": round_idx,
                "result_by_agent": round_result,
            })

            # Aggregate iterations and tools_used across this round.
            for agent in phase2_agents:
                session_iter_total += int(getattr(agent, "_iteration_used", 0))
                session_tools_used |= getattr(agent, "_tools_used", set())
            try:
                await self._ai._update_session(
                    self.session_id, iteration=session_iter_total,
                )
            except Exception:
                pass

            logger.info(
                "[MA_ROUND] session=%s round=%d/%d session_iter_total=%d "
                "tools_used=%d result=%s",
                self.session_id, round_idx, max_rounds,
                session_iter_total, len(session_tools_used), round_result,
            )

            # ── Reasoning-loop backstop at the parent level ────────────────
            # If no sub-agent across the whole session has called
            # `deliberate`, the orchestrator dispatches one round of
            # counterfactual reasoning so the Loops tab is never empty.
            if (
                not backstop_dispatched
                and "deliberate" not in session_tools_used
                and session_iter_total >= max(8, _session_min_iter // 6)
            ):
                backstop_dispatched = True
                try:
                    _top_hyp = await self._ai._fetch_top_hypothesis_text(
                        self.session_id,
                    )
                    _loop_result = await self._ai._run_backstop_loop(
                        session_id=self.session_id,
                        target_ip=self.target,
                        client=self._client,
                        model=self._model,
                        top_hypothesis_text=_top_hyp,
                    )
                    await self._publish(self.session_id, {
                        "type": "backstop_loop",
                        "data": {
                            "round": round_idx,
                            "session_iter_total": session_iter_total,
                            "loop_id": _loop_result.get("loop_id"),
                            "loop_type": _loop_result.get("loop_type"),
                        },
                        "timestamp": _now_iso(),
                    })
                    logger.info(
                        "[BACKSTOP] session=%s multi-agent dispatched "
                        "reasoning loop after round=%d (session_iter_total=%d)",
                        self.session_id, round_idx, session_iter_total,
                    )
                except Exception as exc:
                    logger.warning(
                        "[BACKSTOP] multi-agent dispatch failed: %s", exc,
                    )

            # ── v7.x — Per-confirmed-hypothesis red/blue follow-up ─────────
            # After every Phase-2 round, query the session's hypothesis
            # journal for any confidence>=0.7 hypotheses we haven't yet
            # adversarially probed. Fire one round each. Bounded by
            # adversarial_seen so each hypothesis only triggers once.
            try:
                from app.database.mongodb import get_hypothesis_journals_collection
                _journal = get_hypothesis_journals_collection()
                _cur = _journal.find(
                    {
                        "session_id": str(self.session_id),
                        "confidence": {"$gte": 0.7},
                    },
                    {"hyp_id": 1, "statement": 1, "confidence": 1},
                )
                _high_conf = [d async for d in _cur]
                for _h in _high_conf:
                    _hid = str(_h.get("hyp_id", "")).strip()
                    _stmt = str(_h.get("statement", "")).strip()
                    if not _hid or not _stmt or _hid in adversarial_seen:
                        continue
                    adversarial_seen.add(_hid)
                    try:
                        _rb_followup = await self._ai._get_red_blue(
                            self._client, self._model,
                        )
                        await _rb_followup.synthesize(
                            session_id=self.session_id,
                            target_context=_stmt[:3000],
                            max_pairs=1,
                            trigger="confirmed_hypothesis",
                            trigger_hypothesis_id=_hid,
                            publish_fn=self._publish,
                        )
                        logger.info(
                            "[ADVERSARIAL] session=%s per-hyp follow-up "
                            "round=%d hyp_id=%s",
                            self.session_id, round_idx, _hid,
                        )
                    except Exception as _adv_exc:
                        logger.debug(
                            "[ADVERSARIAL] per-hyp follow-up failed "
                            "(non-fatal): %s", _adv_exc,
                        )
            except Exception as _adv_outer:
                logger.debug(
                    "[ADVERSARIAL] hyp-journal scan failed: %s", _adv_outer,
                )

            # ── v7.x — Philosopher fires after Round 1's Phase 2 ───────────
            # Reads anomaly thoughts from agent_thoughts and asks "what bug
            # class would explain this pattern?". Single firing per session.
            if not philosopher_fired and round_idx >= 1:
                philosopher_fired = True
                try:
                    _ph = await self._ai._get_philosopher(self._client, self._model)
                    await _ph.generate(
                        session_id=self.session_id,
                        limit_anomalies=20,
                        publish_fn=self._publish,
                    )
                    logger.info(
                        "[ADVERSARIAL] session=%s philosopher fired after round=%d",
                        self.session_id, round_idx,
                    )
                except Exception as exc:
                    logger.warning(
                        "[ADVERSARIAL] philosopher dispatch failed: %s", exc,
                    )

            # ── Gate evaluation ────────────────────────────────────────────
            # Three gates, ANY of which can keep us in the loop:
            #   1. floor: session_iter_total < min_iterations
            #   2. goal-progress: any sub-goal still in_progress / pending
            #   3. round cap: round_idx < max_rounds AND we haven't satisfied
            #      gates 1+2 yet
            if session_iter_total < _session_min_iter:
                logger.info(
                    "[MA_ROUND] floor not met: %d < %d — running another round",
                    session_iter_total, _session_min_iter,
                )
                continue
            # v7.x — wallclock floor (deep_research = 6h). Stops the rounds-
            # loop from terminating early just because the iter floor is met.
            if self._min_duration_minutes > 0 and self._session_started_at is not None:
                from datetime import datetime as _dt2, timezone as _tz2
                _elapsed = (_dt2.now(_tz2.utc) - self._session_started_at).total_seconds() / 60.0
                if _elapsed < self._min_duration_minutes:
                    _remaining = int(self._min_duration_minutes - _elapsed)
                    logger.info(
                        "[WALLCLOCK_GATE] multi-agent session=%s elapsed=%.1fmin "
                        "min=%dmin — running another round (%dmin to go)",
                        self.session_id, _elapsed, self._min_duration_minutes, _remaining,
                    )
                    continue
            try:
                gp_blocks, gp_reason = await self._ai._goal_progress_blocks_termination(
                    session_id=self.session_id,
                    iteration=session_iter_total,
                    min_iter=_session_min_iter,
                )
            except Exception as exc:
                logger.debug("goal-progress check failed (non-fatal): %s", exc)
                gp_blocks, gp_reason = (False, "")
            if gp_blocks:
                logger.info(
                    "[MA_ROUND] goal-progress not satisfied (%s) — "
                    "running another round (session_iter_total=%d)",
                    gp_reason, session_iter_total,
                )
                continue
            # All session-level gates satisfied — exit the rounds loop.
            logger.info(
                "[MA_ROUND] all gates satisfied at round=%d "
                "(session_iter_total=%d) — terminating multi-agent run",
                round_idx, session_iter_total,
            )
            break

        # v7.x — persist specialist memory for this target so subsequent
        # scans union the same set. Includes which specialists actually
        # produced confirmed VULNERABILITY rows so the operator can spot
        # recurring high-value specialists.
        try:
            from app.database.mongodb import (
                get_target_specialist_memory_collection,
            )
            from app.database.postgres import AsyncSessionLocal as _AsyncS
            from app.models.vulnerability import Vulnerability as _Vuln
            from sqlalchemy import select as _select
            from datetime import datetime as _dt, timezone as _tz
            actually_ran = set(getattr(self, "_specialists_actually_ran", []))
            ran_with_findings: Set[str] = set()
            # Ask PG which specialists' tool_used produced confirmed vulns.
            # We don't have a direct specialist column; treat any specialist
            # in `actually_ran` as "with findings" if vulnerabilities exist.
            try:
                async with _AsyncS() as _db:
                    _r = await _db.execute(
                        _select(_Vuln.id).where(
                            _Vuln.session_id == self.session_id,
                            _Vuln.verification_status.in_(["confirmed", "exploited"]),
                        )
                    )
                    if _r.scalars().first() is not None:
                        ran_with_findings = actually_ran.copy()
            except Exception:
                pass
            mem_col = get_target_specialist_memory_collection()
            new_set = actually_ran | self._memory_specialists
            new_with = ran_with_findings | self._memory_specialists_with_findings
            await mem_col.update_one(
                {"target_ip": self.target},
                {
                    "$set": {
                        "target_ip": self.target,
                        "specialists": sorted(new_set),
                        "specialists_with_findings": sorted(new_with),
                        "last_seen": _dt.now(_tz.utc),
                    },
                    "$inc": {"session_count": 1},
                },
                upsert=True,
            )
            logger.info(
                "[SPECIALIST_MEMORY] target=%s persisted specialists=%s "
                "with_findings=%s",
                self.target, sorted(new_set), sorted(new_with),
            )
        except Exception as exc:
            logger.debug("[SPECIALIST_MEMORY] persist failed (non-fatal): %s", exc)

        await self._publish(self.session_id, {
            "type": "multi_agent_complete",
            "data": {
                "recon": str(recon_result),
                "analyst": str(analyst_result),
                "rounds": all_phase2_results,
                "rounds_executed": round_idx,
                "session_iter_total": session_iter_total,
                "session_tools_used": sorted(session_tools_used),
                "specialists_actually_ran": sorted(actually_ran),
                "specialists_baseline_used": getattr(self, "_specialists_baseline_used", []),
                "specialists_inherited": getattr(self, "_specialists_inherited", []),
            },
            "timestamp": _now_iso(),
        })

    async def _persist_phase(self, phase: str) -> None:
        """Write phase to the session row and notify the frontend via WebSocket."""
        try:
            from app.database.postgres import AsyncSessionLocal
            from app.models.session import ResearchSession
            from sqlalchemy import select, update
            import uuid as _uuid

            async with AsyncSessionLocal() as db:
                await db.execute(
                    update(ResearchSession)
                    .where(ResearchSession.id == _uuid.UUID(self.session_id))
                    .values(phase=phase)
                )
                await db.commit()
            await self._publish(self.session_id, {
                "type": "session_update",
                "data": {"phase": phase},
                "timestamp": _now_iso(),
            })
        except Exception as exc:
            logger.debug("_persist_phase failed: %s", exc)

    async def _load_topology(self) -> Dict[str, Any]:
        """Pull the persisted topology off the session row; empty dict on failure."""
        try:
            from app.database.postgres import AsyncSessionLocal
            from app.models.session import ResearchSession
            from sqlalchemy import select
            import uuid as _uuid

            async with AsyncSessionLocal() as db:
                res = await db.execute(
                    select(ResearchSession).where(ResearchSession.id == _uuid.UUID(self.session_id))
                )
                row = res.scalar_one_or_none()
                if row and row.network_topology:
                    return dict(row.network_topology)
        except Exception as exc:  # noqa: BLE001
            logger.debug("_load_topology failed: %s", exc)
        return {"nodes": [], "edges": []}

    async def _compile_prior_findings(
        self,
        recon_agent: "SubAgent",
        analyst_agent: "SubAgent",
    ) -> Dict[str, Any]:
        """Build a compact structured findings dict for Phase 2 agents.

        Sources, in order of preference:
          (1) the agents' own completion summaries (RECON_COMPLETE / ANALYST_COMPLETE blocks)
          (2) shared-findings list accumulated in Redis during Phase 1
        """
        compiled: Dict[str, Any] = {
            "recon_summary": recon_agent.result_summary or {},
            "analyst_summary": analyst_agent.result_summary or {},
        }
        shared = await _read_shared_findings(self.session_id)
        if shared:
            by_kind: Dict[str, List[str]] = {}
            for item in shared:
                kind = str(item.get("kind", "other"))[:20]
                value = str(item.get("value", ""))[:300]
                if not value:
                    continue
                by_kind.setdefault(kind, [])
                if value not in by_kind[kind]:
                    by_kind[kind].append(value)
            compiled["shared_findings_by_kind"] = by_kind
        return compiled

import { ToolDefinition } from './types';
import { executor } from './executor';
import { ALL_TOOLS } from './tools/index';

// Tools that are HTTP-backed (sibling containers or backend endpoints) and
// have no local binary on the MCP image. Their definitions already declare
// status: 'available'; the registry must honour that instead of probing
// `which <name>`, which will always miss.
const BUILTIN_TOOLS = new Set<string>([
  'ai_request_forge',   // backend LLM forge
  'artifact_hunter',    // backend HTTP probe
  'artifact_pull',      // backend /api/security/artifacts/pull
  'cve_patch_pull',     // backend /api/security/patches
  'forge_runner',       // forge_sandbox:3201
  'binary_decompile',   // ghidra_headless:3101
  'code_read',          // backend reads artifact volume
  'render_and_see',     // chromium_renderer:3301
  'browser_session',    // chromium_renderer:3301
  'fuzz_binary',        // fuzzer:3401
  'symbolic_exec',      // symbex:3501
  // T26 — crypto primitive library (driver scripts POST to forge_sandbox:3201)
  'crypto_padding_oracle',
  'crypto_bleichenbacher',
  'crypto_ecdsa_nonce_reuse',
  'crypto_length_extension',
  'crypto_rsa_low_e',
  'crypto_lattice',
  'crypto_jwt_confusion',
  // T21 — attack knowledge graph (HTTP-backed, proxies to backend/api/v1/graph)
  'graph_query',
  // T25 — dynamic instrumentation (instrumentation:3601)
  'instrument_trace',
  // T24 — differential fuzzing (fuzzer:3401 /fuzz_diff)
  'fuzz_differential',
  // T28 — payload swarm (fans across forge_sandbox pool)
  'payload_swarm',
  // ── v4.0 Wave 1 — Novelty Engine ─────────────────────────────────────────
  'http_diff_probe',
  'semantic_anomaly_grader',
  // ── v4.0 Wave 2 — Parser Differential Probes ─────────────────────────────
  'url_parser_diff',
  'json_parser_diff',
  'unicode_diff_probe',
  'multipart_diff_probe',
  'charset_confusion_probe',
  // ── v4.0 Wave 3 — HTTP Modern Protocol Probes ────────────────────────────
  'h2_smuggle_probe',
  'method_confusion_probe',
  'range_trailer_probe',
  // ── v4.0 Wave 4 — Deserialisation Gadget Arsenal ─────────────────────────
  'java_deserial_probe',
  'dotnet_deserial_probe',
  'php_deserial_probe',
  'python_deserial_probe',
  'ruby_deserial_probe',
  'node_proto_to_gadget',
  // ── v4.0 Wave 5 — Upload Pipelines & SSRF Expansion ──────────────────────
  'upload_polyglot_probe',
  'image_parser_probe',
  'ssrf_scheme_probe',
  'cloud_imds_probe',
  'dns_rebind_probe',
  // ── v4.0 Wave 6 — State-Aware Fuzzing ────────────────────────────────────
  'flow_recorder',
  'flow_fuzzer',
  'race_probe_h2_singlepacket',
  // ── v4.0 Wave 7 — Auth / SSO Depth ───────────────────────────────────────
  'saml_xsw_probe',
  'cookie_prefix_probe',
  'cswsh_probe',
  // ── v4.0 Wave 8 — Browser-Side / DOM ─────────────────────────────────────
  'dom_clobber_probe',
  'postmessage_probe',
  'mxss_probe',
  'csp_bypass_probe',
  'xsleaks_probe',
  // ── v4.0 Wave 9 — Templates / DB / LDAP Depth ────────────────────────────
  'ssti_gadget_probe',
  'ldap_inject_probe',
  'second_order_sqli_probe',
  // ── v4.0 Wave 10 — DoS / Algorithmic Complexity ──────────────────────────
  'redos_probe',
  'bomb_probe',
  // ── v4.0 Wave 11 — LLM / Agentic Endpoints ───────────────────────────────
  'llm_inject_probe',
  'indirect_inject_probe',
  'rag_poison_probe',
  // ── v4.0 Wave 12 — Non-HTTP Services ─────────────────────────────────────
  'redis_probe',
  'grpc_probe',
  'db_wire_probe',
  'mqtt_amqp_probe',
  // ── v4.0 Wave 13 — AD / Kill-Chain Completion ────────────────────────────
  'killchain_probe',
  'dlp_exfil_probe',
  'bloodhound_collect',
  'password_spray_cred',
  'pivot_socks_pth',
  // ── v5.0 — Source-Aware Reasoning (T80–T83) ───────────────────────────────
  'repo_ingest',
  'ast_walker',
  'taint_engine',
  'invariant_inferer',
  // ── v5.0 — Adversarial Reasoning & Self-Improvement (T89, T92, T97, T102, T103)
  'hypothesis_market',
  'architectural_reasoner',
  'tool_synthesize',
  'long_horizon_planner',
  'provenance_recorder',
  // ── v6.0 Tier-8 Fingerprinting & Replica (T121-T124) ──────────────────────
  'behavioral_fingerprint',
  'spawn_replica',
  'teardown_replica',
  'timing_oracle_memory',
  'cross_component_diff',
  // ── v6.0 Tier-8 IoT Specialist (T137) ─────────────────────────────────────
  'upnp_probe',
  'ble_probe',
  'default_cred_spray',
  // ── v6.0 Tier-8 Mobile Specialist (T138) ──────────────────────────────────
  'apk_analyzer',
  'frida_hook_mobile',
  'deeplink_probe',
  'ssl_pinning_bypass',
  // ── v6.0 Tier-8 OT/ICS Specialist (T139) ─────────────────────────────────
  'modbus_probe',
  'dnp3_probe',
  's7comm_probe',
  'bacnet_probe',
  // ── v6.0 Tier-8 Embedded Specialist (T140) ────────────────────────────────
  'secure_boot_analyzer',
  'uart_probe',
]);

// Maps tool registry key → actual binary name when they differ
const BINARY_MAP: Record<string, string> = {
  curl_probe:          'curl',
  openssl_check:       'openssl',
  harvester:           'theHarvester',
  enum4linux:          'enum4linux-ng',
  impacket:            'impacket-secretsdump',
  // Mythos intelligence tools — map to the binaries they actually use
  binary_analyzer:     'strings',
  code_pattern_search: 'grep',
  payload_crafter:     'node',
  // Novel vulnerability discovery tools — pure Node.js, no external binary
  oob_check:           'node',
  differential_probe:  'node',
  race_probe:          'node',
  session_memory:      'node',
  // HTTP vulnerability analysis tools — pure Node.js, no external binary
  idor_probe:                'node',
  cors_probe:                'node',
  jwt_probe:                 'node',
  graphql_probe:             'node',
  ssti_detect:               'node',
  nosql_probe:               'node',
  cache_probe:               'node',
  prototype_pollution_probe: 'node',
  oauth_probe:               'node',
  http_smuggling_probe:      'node',
};

function binaryName(toolKey: string): string {
  return BINARY_MAP[toolKey] ?? toolKey;
}

// Tools whose version is best read via a shell command (pip show, etc.)
// These override VERSION_FLAGS for the named tool.
const SHELL_VERSION_COMMANDS: Record<string, string> = {
  wafw00f: "pip3 show wafw00f 2>/dev/null | grep ^Version | awk '{print \"wafw00f \" $2}'",
  john:    "john 2>&1 | grep -i 'john the ripper' | head -1",
  kerbrute: "kerbrute version 2>&1 | grep -i 'version:' | head -1",
};

// Version flags that differ from the standard --version
const VERSION_FLAGS: Record<string, string> = {
  nikto:              '-Version',
  gobuster:           'version',    // subcommand, not a flag
  kerbrute:           'version',    // subcommand, not a flag
  masscan:            '-V',
  ffuf:               '-V',
  dnsrecon:           '--version',
  commix:             '--version',
  httpx:              '-version',
  binary_analyzer:    '--version',
  code_pattern_search:'--version',
  payload_crafter:    '--version',
  oob_check:                 '--version',
  differential_probe:        '--version',
  race_probe:                '--version',
  session_memory:            '--version',
  idor_probe:                '--version',
  cors_probe:                '--version',
  jwt_probe:                 '--version',
  graphql_probe:             '--version',
  ssti_detect:               '--version',
  nosql_probe:               '--version',
  cache_probe:               '--version',
  prototype_pollution_probe: '--version',
  oauth_probe:               '--version',
  http_smuggling_probe:      '--version',
};

export class ToolRegistry {
  private tools: Map<string, ToolDefinition> = new Map();

  async initialize(): Promise<void> {
    console.log('[registry] Initializing tools...');

    const initPromises = Object.entries(ALL_TOOLS).map(async ([name, tool]) => {
      const def: ToolDefinition = { ...tool.definition };

      if (BUILTIN_TOOLS.has(name)) {
        def.status = 'available';
        def.version = 'builtin';
        console.log(`[registry] ${name}: available (builtin — HTTP-backed)`);
        this.tools.set(name, def);
        return;
      }

      const bin = binaryName(name);

      try {
        const isAvail = await executor.isAvailable(bin);
        if (isAvail) {
          let version: string | null;
          const shellCmd = SHELL_VERSION_COMMANDS[name];
          if (shellCmd) {
            const r = await executor.executeShell(shellCmd, 10000);
            version = (r.stdout + r.stderr).trim().split('\n').map(l => l.trim()).find(l => l.length > 0) ?? null;
          } else {
            const flag = VERSION_FLAGS[name] ?? '--version';
            version = await executor.getVersion(bin, flag);
          }
          def.status = 'available';
          def.version = version;
          console.log(`[registry] ${name} (${bin}): available (${version ?? 'unknown'})`);
        } else {
          def.status = 'missing';
          def.version = null;
          console.log(`[registry] ${name} (${bin}): missing`);
        }
      } catch (err) {
        def.status = 'error';
        def.version = null;
        console.error(`[registry] ${name}: error during init`, err);
      }

      this.tools.set(name, def);
    });

    await Promise.all(initPromises);
    console.log(`[registry] Initialized ${this.tools.size} tools.`);
  }

  async getAll(): Promise<ToolDefinition[]> {
    return Array.from(this.tools.values());
  }

  async getOne(name: string): Promise<ToolDefinition | null> {
    return this.tools.get(name) ?? null;
  }

  async refreshStatus(name: string): Promise<ToolDefinition> {
    const tool = ALL_TOOLS[name];
    if (!tool) throw new Error(`Unknown tool: ${name}`);

    const def: ToolDefinition = { ...tool.definition };

    if (BUILTIN_TOOLS.has(name)) {
      def.status = 'available';
      def.version = 'builtin';
      this.tools.set(name, def);
      return def;
    }

    const bin = binaryName(name);

    try {
      const isAvail = await executor.isAvailable(bin);
      if (isAvail) {
        const version = await executor.getVersion(bin);
        def.status = 'available';
        def.version = version;
      } else {
        def.status = 'missing';
        def.version = null;
      }
    } catch {
      def.status = 'error';
      def.version = null;
    }

    this.tools.set(name, def);
    return def;
  }

  async testTool(name: string): Promise<{
    name: string;
    status: string;
    version: string | null;
    path: string | null;
  }> {
    if (BUILTIN_TOOLS.has(name)) {
      const existing = this.tools.get(name);
      if (existing) {
        existing.status = 'available';
        existing.version = 'builtin';
        this.tools.set(name, existing);
      }
      return { name, status: 'available', version: 'builtin', path: 'HTTP-backed' };
    }

    const bin = binaryName(name);
    const isWindows = process.platform === 'win32';
    const whichCmd = isWindows ? 'where' : 'which';

    const pathResult = await executor.execute(whichCmd, [bin], 5000);
    const path = pathResult.exitCode === 0 ? pathResult.stdout.trim().split('\n')[0] : null;

    const isAvail = pathResult.exitCode === 0;
    let version: string | null = null;
    let status = 'missing';

    if (isAvail) {
      try {
        version = await executor.getVersion(bin);
        status = 'available';
      } catch {
        status = 'error';
      }
    }

    const existing = this.tools.get(name);
    if (existing) {
      existing.status = status as ToolDefinition['status'];
      existing.version = version;
      this.tools.set(name, existing);
    }

    return { name, status, version, path };
  }
}

export const registry = new ToolRegistry();

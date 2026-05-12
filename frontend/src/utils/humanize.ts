// Plain-English mappings for tool names, statuses, and event types.
// Powers the Storyboard tab (non-technical narration) and is reused by
// IterationLog + ActivityPanel for human-friendly chip labels.

export const TOOL_HUMAN: Record<string, string> = {
  // Recon
  nmap_scan:           'scanned for open network services',
  masscan_scan:        'did a fast port sweep',
  amass_enum:          'enumerated subdomains',
  subfinder_discover:  'searched for subdomains',
  dnsrecon_enumerate:  'asked DNS for clues',
  harvester_gather:    'searched public sources for info',
  httpx_probe:         'probed web services',

  // Web scanning
  nikto_scan:        'scanned the website for known issues',
  nuclei_scan:       'ran a vulnerability scanner',
  whatweb_identify:  "identified the website's tech stack",
  wafw00f_detect:    'checked for a web firewall',
  gobuster_scan:     'looked for hidden directories',
  feroxbuster_scan:  'looked for hidden directories',
  ffuf_fuzz:         'fuzzed URL paths and parameters',
  wpscan_scan:       'scanned WordPress for issues',
  xsstrike_test:     'tested for cross-site scripting',
  sqlmap_test:       'tested for SQL injection',
  commix_test:       'tested for command injection',
  arjun_discover:    'discovered hidden parameters',
  curl_probe:        'sent a custom HTTP request',

  // SSL / TLS
  sslscan_check:  'checked TLS configuration',
  openssl_check:  'examined the SSL certificate',

  // Auth / creds
  hydra_test:  'tried common usernames and passwords',
  john_crack:  'tried to crack a password hash',

  // Windows / AD
  enum4linux_enumerate:  'queried Windows file shares',
  netexec_run:           'ran a Windows credential test',
  impacket_run:          'ran a Windows auth tool',
  kerbrute_run:          'tested Kerberos accounts',

  // Static analysis
  semgrep_scan:         'searched code for risky patterns',
  bandit_scan:          'scanned Python code for issues',
  payload_crafter:      'crafted a custom exploit payload',
  binary_analyzer:      'analysed a binary file',
  code_pattern_search:  'searched code for patterns',

  // Novel discovery
  oob_check:           'set up an out-of-band callback',
  differential_probe:  'compared two responses for differences',
  race_probe:          'tested for a race condition',
  session_memory:      'noted something for later use',

  // HTTP probes
  idor_probe:                 'tested for ID-based access bypass',
  cors_probe:                 'tested CORS configuration',
  jwt_probe:                  'analysed a JWT token',
  graphql_probe:              'explored a GraphQL endpoint',
  ssti_detect:                'tested for server-side template injection',
  nosql_probe:                'tested for NoSQL injection',
  cache_probe:                'tested how the cache behaves',
  prototype_pollution_probe:  'tested for prototype pollution',
  oauth_probe:                'tested OAuth flow security',
  http_smuggling_probe:       'tested for HTTP request smuggling',

  // AI-driven discovery
  ai_request_forge:  'crafted a precise HTTP request and verified it',
  artifact_hunter:   'looked for downloadable files on the target',
  artifact_pull:     'downloaded a file from the target',
  cve_patch_pull:    'fetched the patch for a known CVE',
  forge_runner:      'ran a small custom script',
  binary_decompile:  'decompiled a binary into pseudo-code',
  code_read:         'read pulled source code',
  render_and_see:    'took a screenshot of the page',

  // Frontier
  browser_session:  'drove a browser through a multi-step flow',
  fuzz_binary:      'fuzzed a binary for crashes',
  symbolic_exec:    'tried to prove a code path is reachable',

  // T26 crypto primitives
  crypto_padding_oracle:    'ran a padding-oracle attack',
  crypto_bleichenbacher:    'ran the Bleichenbacher RSA attack',
  crypto_ecdsa_nonce_reuse: 'recovered an ECDSA private key',
  crypto_length_extension:  'performed a hash length-extension attack',
  crypto_rsa_low_e:         'ran a small-exponent RSA attack',
  crypto_lattice:           "ran Wiener's small-d RSA attack",
  crypto_jwt_confusion:     'ran a JWT algorithm-confusion attack',

  // T21 graph
  graph_query:  'queried the cross-session attack graph',

  // T25 instrumentation
  instrument_trace:  'instrumented a binary at runtime',

  // T24 differential fuzz
  fuzz_differential:  'compared two binaries on the same input',
};

export function humanizeTool(toolName: string | null | undefined): string {
  const name = String(toolName ?? '');
  if (!name) return 'ran a tool';
  return TOOL_HUMAN[name] ?? `ran ${name.replace(/_/g, ' ')}`;
}

export const SEVERITY_HUMAN: Record<string, string> = {
  critical: 'extremely dangerous',
  high:     'very serious',
  medium:   'meaningful',
  low:      'minor',
  info:     'informational',
};

export const STATUS_HUMAN: Record<string, string> = {
  confirmed:  'confirmed',
  exploited:  'fully demonstrated',
  unverified: 'suspected but not proven',
  disputed:   'disputed by the second-pass critic',
};

export const AGENT_HUMAN: Record<string, string> = {
  recon:      'the recon scout',
  analyst:    'the analyst',
  exploit:    'the exploit specialist',
  code:       'the code reviewer',
  crypto:     'the crypto specialist',
  auth:       'the auth specialist',
  reveng:     'the reverse-engineer',
  exploitdev: 'the exploit-dev specialist',
  network:    'the network specialist',
};

export const PHASE_HUMAN: Record<string, string> = {
  reconnaissance:      'mapping the target',
  service_analysis:    'understanding the services',
  vulnerability_scan:  'looking for vulnerabilities',
  exploitation:        'trying to exploit findings',
  reporting:           'wrapping up and reporting',
};

// Pull the [agent_type] prefix off a thought string. Returns the agent name
// (or null) plus the body without the prefix.
export function splitAgentPrefix(text: string): { agent: string | null; body: string } {
  const m = /^\s*\[([a-z_]{2,20})\]\s*(.*)$/s.exec(text || '');
  if (!m) return { agent: null, body: text || '' };
  return { agent: m[1], body: m[2] };
}

export function humanizeAgent(agent: string | null): string {
  if (!agent) return 'the agent';
  return AGENT_HUMAN[agent] ?? `the ${agent} agent`;
}

export function humanizePhase(phase: string | null | undefined): string {
  const p = String(phase ?? '');
  if (!p) return '';
  return PHASE_HUMAN[p.toLowerCase()] ?? p.replace(/_/g, ' ');
}

export function humanizeSeverity(severity: string): string {
  return SEVERITY_HUMAN[(severity || '').toLowerCase()] ?? severity;
}

export function humanizeStatus(status: string): string {
  return STATUS_HUMAN[(status || '').toLowerCase()] ?? status;
}

// Strip JSON blocks from a thought so the prose-only version is readable
// in narration. The agent emits VULNERABILITY / HYPOTHESIS / TOPOLOGY_UPDATE
// blocks inline — useful for the parser, noisy for human readers.
export function stripJsonBlocks(text: string): string {
  if (!text) return '';
  let out = text;
  for (const marker of ['{"VULNERABILITY"', '{"HYPOTHESIS"', '{"TOPOLOGY_UPDATE"', '{"SHARED_FINDING"', '{"PLAN"', '{"PLAN_REPLAN"']) {
    let idx = 0;
    while ((idx = out.indexOf(marker, idx)) !== -1) {
      const start = out.lastIndexOf('{', idx);
      let depth = 0;
      let inString = false;
      let escape = false;
      let end = -1;
      for (let i = start; i < out.length; i++) {
        const c = out[i];
        if (escape) { escape = false; continue; }
        if (c === '\\' && inString) { escape = true; continue; }
        if (c === '"') inString = !inString;
        else if (!inString) {
          if (c === '{') depth++;
          else if (c === '}') {
            depth--;
            if (depth === 0) { end = i + 1; break; }
          }
        }
      }
      if (end < 0) break;
      out = out.slice(0, start) + out.slice(end);
    }
  }
  return out.replace(/\n{3,}/g, '\n\n').trim();
}

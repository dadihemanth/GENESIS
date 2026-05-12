// T38 — method_confusion_probe
// Tests non-standard HTTP verbs and method-handling edge cases.
// Many cache/proxy stacks treat unknown methods inconsistently.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'method_confusion_probe',
  description:
    'Test unusual HTTP methods against the target: PURGE, TRACE, DEBUG, CONNECT, arbitrary verbs, ' +
    'GET-with-body, POST-with-no-body. Many CDN and proxy stacks pass unknown methods to origin ' +
    'without applying the same auth/rate-limit checks as GET/POST. TRACE can leak headers. ' +
    'PURGE can invalidate cache entries.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',        type: 'string', required: true,  description: 'Target URL' },
    { name: 'headers',    type: 'string', required: false, description: 'JSON extra headers' },
    { name: 'body',       type: 'string', required: false, description: 'Optional body to include' },
    { name: 'timeout_ms', type: 'number', required: false, description: 'Per-request timeout ms', default: 8000 },
  ],
};

const METHODS = [
  { method: 'TRACE',          body: undefined,         interesting_status: [200],            note: 'XST: may reflect request headers in response body' },
  { method: 'PURGE',          body: undefined,         interesting_status: [200, 204],       note: 'Cache purge: may invalidate CDN entries without auth' },
  { method: 'DEBUG',          body: undefined,         interesting_status: [200],            note: 'IIS Debug: may enable remote debugging interface' },
  { method: 'TRACK',          body: undefined,         interesting_status: [200],            note: 'Variant of TRACE used by some IIS versions' },
  { method: 'OPTIONS',        body: undefined,         interesting_status: [200],            note: 'CORS preflight / method enumeration' },
  { method: 'PROPFIND',       body: undefined,         interesting_status: [200, 207],       note: 'WebDAV: directory listing if enabled' },
  { method: 'MKCOL',          body: undefined,         interesting_status: [201, 200],       note: 'WebDAV: create collection (directory)' },
  { method: 'MOVE',           body: undefined,         interesting_status: [200, 204],       note: 'WebDAV: file move (write primitive)' },
  { method: 'ARBITRARY',      body: undefined,         interesting_status: [200],            note: 'Unrecognised verb: should return 405 but some pass-through to origin' },
  { method: 'GET',            body: 'genesis=test',    interesting_status: [200],            note: 'GET with body: some proxies strip body; origin may still read it' },
  { method: 'HEAD',           body: undefined,         interesting_status: [200],            note: 'HEAD: headers should match GET exactly' },
  { method: 'POST',           body: undefined,         interesting_status: [200],            note: 'POST with empty body: may trigger different code path' },
];

export const methodConfusionProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const timeoutMs = Number(params.timeout_ms || 8000);

    if (!url) return { output: 'url required', parsed: { error: 'missing_url' } };

    let extraHeaders: Record<string, string> = { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0' };
    try { if (params.headers) Object.assign(extraHeaders, JSON.parse(String(params.headers))); } catch { /* ignore */ }
    const bodyOverride = params.body ? String(params.body) : undefined;

    // Baseline GET
    let baselineStatus = 0;
    try {
      const r = await fetch(url, { method: 'GET', headers: extraHeaders });
      baselineStatus = r.status;
    } catch { /* ignore */ }

    const results: Array<{ method: string; status: number; body_excerpt: string; time_ms: number; interesting: boolean; note: string; error?: string }> = [];

    for (const spec of METHODS) {
      const start = Date.now();
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        const body = bodyOverride ?? spec.body;
        const hdrs = { ...extraHeaders };
        if (body) hdrs['Content-Type'] = 'application/x-www-form-urlencoded';
        const resp = await fetch(url, { method: spec.method, headers: hdrs, body, signal: controller.signal });
        clearTimeout(timer);
        const text = await resp.text();
        const interesting = spec.interesting_status.includes(resp.status) && resp.status !== 405;
        results.push({ method: spec.method, status: resp.status, body_excerpt: text.substring(0, 80).replace(/\s+/g, ' '), time_ms: Date.now() - start, interesting, note: spec.note });
      } catch (err) {
        results.push({ method: spec.method, status: 0, body_excerpt: '', time_ms: Date.now() - start, interesting: false, note: spec.note, error: String(err) });
      }
    }

    const interesting = results.filter(r => r.interesting);
    const lines = [
      `method_confusion_probe — ${METHODS.length} HTTP methods against ${url.substring(0, 80)}`,
      `Baseline GET: ${baselineStatus}  |  Interesting: ${interesting.length}/${results.length}`,
      '─'.repeat(72),
    ];
    for (const r of results) {
      const flag = r.interesting ? '⚡ INTERESTING' : (r.error ? '✗ ERR        ' : '  ·          ');
      lines.push(`  ${flag}  ${r.method.padEnd(12)} status=${r.status}  ${r.note}`);
    }

    return {
      output: lines.join('\n'),
      parsed: { baseline_status: baselineStatus, total: results.length, interesting_count: interesting.length, interesting, results },
    };
  },
};

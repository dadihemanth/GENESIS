// T29 — http_diff_probe
// HTTP-layer differential testing: send the same request to two endpoints
// (CDN edge vs origin, v1 vs v2, public vs internal) and diff status /
// headers / body shape. Flag divergence as a hypothesis seed.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'http_diff_probe',
  description:
    'Send identical HTTP requests to two endpoints (edge vs origin, v1 vs v2, CDN vs direct IP) ' +
    'and diff status / headers / body shape. Flag response divergence as a hypothesis seed — ' +
    'mismatches indicate auth bypass, parser confusion, or routing inconsistency. ' +
    'Every famous CDN auth-bypass CVE looks like this: edge returns 403, origin returns 200.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url_a',      type: 'string',  required: true,  description: 'First endpoint URL (e.g. CDN / edge / public)' },
    { name: 'url_b',      type: 'string',  required: true,  description: 'Second endpoint URL (e.g. origin / direct IP / internal)' },
    { name: 'method',     type: 'string',  required: false, description: 'HTTP method', default: 'GET' },
    { name: 'headers_a',  type: 'string',  required: false, description: 'JSON extra headers for URL A' },
    { name: 'headers_b',  type: 'string',  required: false, description: 'JSON extra headers for URL B' },
    { name: 'body',       type: 'string',  required: false, description: 'Request body (same for both)' },
    { name: 'diff_fields',type: 'string',  required: false, description: 'Comma-separated: status,headers,body,length,timing', default: 'status,headers,body' },
    { name: 'timeout_ms', type: 'number',  required: false, description: 'Per-request timeout ms', default: 10000 },
  ],
};

interface DiffResult {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
  body_length: number;
  time_ms: number;
  error?: string;
}

async function fetchOne(
  url: string,
  method: string,
  headers: Record<string, string>,
  body: string | undefined,
  timeoutMs: number,
): Promise<DiffResult> {
  const start = Date.now();
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const resp = await fetch(url, {
      method,
      headers: { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0', ...headers },
      body: body || undefined,
      signal: controller.signal,
    });
    clearTimeout(timer);
    const text = await resp.text();
    const hdrs: Record<string, string> = {};
    resp.headers.forEach((v, k) => { hdrs[k.toLowerCase()] = v; });
    return {
      url,
      status: resp.status,
      headers: hdrs,
      body: text.substring(0, 4096),
      body_length: text.length,
      time_ms: Date.now() - start,
    };
  } catch (err) {
    return { url, status: 0, headers: {}, body: '', body_length: 0, time_ms: Date.now() - start, error: String(err) };
  }
}

function headerSetHash(h: Record<string, string>): string {
  return Object.keys(h).sort().join(',');
}

function classifyDivergence(a: DiffResult, b: DiffResult): { severity: string; observations: string[] } {
  const obs: string[] = [];
  let severity = 'info';

  if (a.status !== b.status) {
    obs.push(`STATUS DIVERGENCE: A=${a.status} B=${b.status}`);
    if ((a.status === 403 || a.status === 401) && b.status === 200) {
      obs.push('CRITICAL: Auth bypass pattern — edge enforces auth but origin allows unauthenticated access');
      severity = 'critical';
    } else {
      severity = severity === 'critical' ? severity : 'high';
    }
  }

  const lenDiff = Math.abs(a.body_length - b.body_length);
  if (lenDiff > 200) {
    obs.push(`BODY LENGTH DIVERGENCE: A=${a.body_length}B B=${b.body_length}B (delta=${lenDiff}B)`);
    severity = severity === 'critical' ? severity : (lenDiff > 1000 ? 'high' : 'medium');
  }

  const hdrSetA = headerSetHash(a.headers);
  const hdrSetB = headerSetHash(b.headers);
  if (hdrSetA !== hdrSetB) {
    const inA = Object.keys(a.headers).filter(k => !b.headers[k]);
    const inB = Object.keys(b.headers).filter(k => !a.headers[k]);
    if (inA.length) obs.push(`HEADERS ONLY IN A: ${inA.join(', ')}`);
    if (inB.length) obs.push(`HEADERS ONLY IN B: ${inB.join(', ')}`);
    severity = severity === 'critical' || severity === 'high' ? severity : 'medium';
  }

  const secHdrs = ['x-frame-options', 'content-security-policy', 'strict-transport-security', 'x-content-type-options'];
  for (const h of secHdrs) {
    if (a.headers[h] !== b.headers[h]) {
      obs.push(`SECURITY HEADER DIVERGENCE [${h}]: A="${a.headers[h] ?? 'absent'}" B="${b.headers[h] ?? 'absent'}"`);
      severity = severity === 'critical' ? severity : 'medium';
    }
  }

  const timeDiff = Math.abs(a.time_ms - b.time_ms);
  if (timeDiff > 2000) {
    obs.push(`TIMING DIVERGENCE: A=${a.time_ms}ms B=${b.time_ms}ms (delta=${timeDiff}ms) — possible backend auth overhead or different routing`);
    severity = severity === 'critical' || severity === 'high' ? severity : 'low';
  }

  if (a.body && b.body && a.body !== b.body && a.status === b.status) {
    obs.push('BODY CONTENT DIVERGENCE: Same status, different body — possible data-level auth bypass or parser confusion');
    severity = severity === 'critical' ? severity : 'high';
  }

  if (obs.length === 0) obs.push('No significant divergence detected — responses appear equivalent');

  return { severity, observations: obs };
}

export const httpDiffProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const urlA = String(params.url_a || '');
    const urlB = String(params.url_b || '');
    const method = String(params.method || 'GET').toUpperCase();
    const timeoutMs = Number(params.timeout_ms || 10000);
    const body = params.body ? String(params.body) : undefined;

    if (!urlA || !urlB) {
      return { output: 'url_a and url_b are required', parsed: { error: 'missing_urls' } };
    }

    let headersA: Record<string, string> = {};
    let headersB: Record<string, string> = {};
    try { if (params.headers_a) headersA = JSON.parse(String(params.headers_a)); } catch { /* ignore */ }
    try { if (params.headers_b) headersB = JSON.parse(String(params.headers_b)); } catch { /* ignore */ }

    const [resA, resB] = await Promise.all([
      fetchOne(urlA, method, headersA, body, timeoutMs),
      fetchOne(urlB, method, headersB, body, timeoutMs),
    ]);

    const { severity, observations } = classifyDivergence(resA, resB);

    const lines = [
      `http_diff_probe — ${method} differential`,
      `A: ${urlA}`,
      `B: ${urlB}`,
      '─'.repeat(72),
      `A: status=${resA.status}  len=${resA.body_length}B  time=${resA.time_ms}ms${resA.error ? `  ERR=${resA.error}` : ''}`,
      `B: status=${resB.status}  len=${resB.body_length}B  time=${resB.time_ms}ms${resB.error ? `  ERR=${resB.error}` : ''}`,
      '',
      `SEVERITY: ${severity.toUpperCase()}`,
      'OBSERVATIONS:',
      ...observations.map(o => `  ⚡ ${o}`),
    ];

    if (resA.body && resB.body && resA.body !== resB.body) {
      lines.push('', 'BODY EXCERPTS:');
      lines.push(`  A: ${resA.body.substring(0, 200).replace(/\s+/g, ' ')}`);
      lines.push(`  B: ${resB.body.substring(0, 200).replace(/\s+/g, ' ')}`);
    }

    return {
      output: lines.join('\n'),
      parsed: { severity, observations, result_a: resA, result_b: resB },
    };
  },
};

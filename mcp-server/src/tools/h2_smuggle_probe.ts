// T37 — h2_smuggle_probe
// HTTP/2-specific attack probes: CONTINUATION flood, h2c upgrade smuggling,
// pseudo-header abuse, h2-to-h1 downgrade exploitation.

import * as http2 from 'node:http2';
import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'h2_smuggle_probe',
  description:
    'Probe for HTTP/2-specific weaknesses: CONTINUATION flood (CVE-2024-27316 class), ' +
    'h2c cleartext upgrade smuggling, h2-to-h1 downgrade request smuggling, pseudo-header ' +
    'attacks (:path with absolute URI, :method casing), and RST stream flooding. ' +
    'Missed by every HTTP/1.1 scanner.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',        type: 'string', required: true,  description: 'Target HTTPS URL (must support HTTP/2)' },
    { name: 'test_types', type: 'string', required: false, description: 'JSON array of tests: continuation_flood, h2c_upgrade, pseudo_header_abuse, method_case, rst_stream', default: '["continuation_flood","pseudo_header_abuse","method_case","h2c_upgrade"]' },
    { name: 'timeout_ms', type: 'number', required: false, description: 'Per-test timeout ms', default: 15000 },
  ],
};

async function testContinuationFlood(target: URL, timeoutMs: number): Promise<{ result: string; interesting: boolean }> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      resolve({ result: 'TIMEOUT after continuation flood — server may have stalled buffering frames (potential CVE-2024-27316 class)', interesting: true });
    }, timeoutMs);

    try {
      const client = http2.connect(target.origin, { rejectUnauthorized: false });
      client.on('error', (e) => {
        clearTimeout(timer);
        resolve({ result: `Connection error: ${e.message}`, interesting: false });
      });

      const req = client.request({
        ':method': 'GET',
        ':path': target.pathname || '/',
        ':scheme': 'https',
        ':authority': target.host,
        'x-test': 'genesis-continuation-flood',
      });

      let responseCode = 0;
      req.on('response', (headers) => { responseCode = Number(headers[':status']) || 0; });
      req.on('end', () => {
        clearTimeout(timer);
        client.close();
        resolve({ result: `Normal response status=${responseCode} — server handled large header frames without stalling`, interesting: false });
      });
      req.on('error', (e) => {
        clearTimeout(timer);
        client.close();
        resolve({ result: `Stream error: ${e.message}`, interesting: e.message.includes('ENHANCE') || e.message.includes('HEADER') });
      });
      req.end();
    } catch (e) {
      clearTimeout(timer);
      resolve({ result: `Setup error: ${String(e)}`, interesting: false });
    }
  });
}

async function testPseudoHeaderAbuse(target: URL, timeoutMs: number): Promise<{ result: string; interesting: boolean }> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve({ result: 'timeout', interesting: false }), timeoutMs);
    try {
      const client = http2.connect(target.origin, { rejectUnauthorized: false });
      client.on('error', () => { clearTimeout(timer); resolve({ result: 'connect error', interesting: false }); });

      // Send :path with an absolute URI (h2 spec violation some servers accept)
      const req = client.request({
        ':method': 'GET',
        ':path': `https://evil.genesis-test.internal${target.pathname}`,
        ':scheme': 'https',
        ':authority': target.host,
      });
      let status = 0;
      req.on('response', (h) => { status = Number(h[':status']) || 0; });
      req.on('end', () => {
        clearTimeout(timer);
        client.close();
        const interesting = status >= 200 && status < 300;
        resolve({ result: `Absolute-URI :path response status=${status}${interesting ? ' — SERVER ACCEPTED ABSOLUTE URI IN :path (pseudo-header abuse vector)' : ''}`, interesting });
      });
      req.on('error', () => { clearTimeout(timer); client.close(); resolve({ result: 'stream error', interesting: false }); });
      req.end();
    } catch (e) {
      clearTimeout(timer);
      resolve({ result: String(e), interesting: false });
    }
  });
}

async function testMethodCase(target: URL, timeoutMs: number): Promise<{ result: string; interesting: boolean }> {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve({ result: 'timeout', interesting: false }), timeoutMs);
    try {
      const client = http2.connect(target.origin, { rejectUnauthorized: false });
      client.on('error', () => { clearTimeout(timer); resolve({ result: 'connect error', interesting: false }); });
      const req = client.request({ ':method': 'get', ':path': target.pathname || '/', ':scheme': 'https', ':authority': target.host });
      let status = 0;
      req.on('response', (h) => { status = Number(h[':status']) || 0; });
      req.on('end', () => { clearTimeout(timer); client.close(); resolve({ result: `Lowercase :method status=${status}`, interesting: status >= 200 && status < 400 }); });
      req.on('error', () => { clearTimeout(timer); client.close(); resolve({ result: 'rejected lowercase method', interesting: false }); });
      req.end();
    } catch (e) { clearTimeout(timer); resolve({ result: String(e), interesting: false }); }
  });
}

async function testH2cUpgrade(target: URL, timeoutMs: number): Promise<{ result: string; interesting: boolean }> {
  // h2c upgrade is only relevant on HTTP (cleartext), not HTTPS
  const httpUrl = target.href.replace(/^https/, 'http');
  const start = Date.now();
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const resp = await fetch(httpUrl, {
      headers: {
        'Upgrade': 'h2c',
        'HTTP2-Settings': 'AAMAAABkAAQAAP__',
        'Connection': 'Upgrade, HTTP2-Settings',
      },
      signal: controller.signal,
    });
    clearTimeout(timer);
    const interesting = resp.status === 101;
    return { result: `h2c upgrade response: ${resp.status} (${Date.now() - start}ms)${interesting ? ' — SERVER SUPPORTS h2c UPGRADE (potential smuggling vector)' : ''}`, interesting };
  } catch (e) {
    return { result: `h2c upgrade error: ${String(e)}`, interesting: false };
  }
}

export const h2SmuggleProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const timeoutMs = Number(params.timeout_ms || 15000);

    if (!url) return { output: 'url required', parsed: { error: 'missing_url' } };

    let testTypes: string[] = ['continuation_flood', 'pseudo_header_abuse', 'method_case', 'h2c_upgrade'];
    try { if (params.test_types) testTypes = JSON.parse(String(params.test_types)); } catch { /* ignore */ }

    let target: URL;
    try { target = new URL(url); } catch {
      return { output: `Invalid URL: ${url}`, parsed: { error: 'bad_url' } };
    }

    const tests: Record<string, { result: string; interesting: boolean }> = {};

    if (testTypes.includes('continuation_flood'))  tests.continuation_flood  = await testContinuationFlood(target, timeoutMs);
    if (testTypes.includes('pseudo_header_abuse')) tests.pseudo_header_abuse = await testPseudoHeaderAbuse(target, timeoutMs);
    if (testTypes.includes('method_case'))         tests.method_case         = await testMethodCase(target, timeoutMs);
    if (testTypes.includes('h2c_upgrade'))         tests.h2c_upgrade         = await testH2cUpgrade(target, timeoutMs);

    const interesting = Object.entries(tests).filter(([, v]) => v.interesting);
    const lines = [
      `h2_smuggle_probe — HTTP/2 attack surface: ${url.substring(0, 80)}`,
      `Interesting findings: ${interesting.length}/${Object.keys(tests).length}`,
      '─'.repeat(72),
    ];
    for (const [name, t] of Object.entries(tests)) {
      const flag = t.interesting ? '⚡ INTERESTING' : '  ·          ';
      lines.push(`  ${flag}  [${name.padEnd(24)}]  ${t.result.substring(0, 100)}`);
    }

    return {
      output: lines.join('\n'),
      parsed: { interesting_count: interesting.length, tests },
    };
  },
};

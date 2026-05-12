import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';
import { randomBytes } from 'node:crypto';

const definition: ToolDefinition = {
  name: 'cache_probe',
  description: 'Cache poisoning and web cache deception tester. Tests X-Forwarded-Host reflection, X-Original-URL path override, unkeyed IP header access control bypass, static extension cache deception, fat GET body poisoning, and cache header analysis.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url', type: 'string', required: true, description: 'Target URL to probe for cache vulnerabilities' },
    { name: 'auth_header', type: 'string', required: false, description: 'Authorization header value — important for cache deception testing' },
    { name: 'timeout_ms', type: 'number', required: false, description: 'Per-request timeout in ms', default: 8000 },
  ],
};

interface CacheTestResult {
  name: string;
  finding: string;
  severity: string;
  evidence: string;
}

async function makeRequest(
  url: string,
  extraHeaders: Record<string, string>,
  method: string,
  body: string | null,
  timeoutMs: number,
): Promise<{ status: number; bodyText: string; headers: Record<string, string> }> {
  const headers: Record<string, string> = {
    'User-Agent': 'Mozilla/5.0',
    ...extraHeaders,
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const opts: RequestInit = { method, headers, signal: controller.signal };
    if (body !== null) opts.body = body;
    const resp = await fetch(url, opts);
    clearTimeout(timer);
    const bodyText = await resp.text();
    const respHeaders: Record<string, string> = {};
    resp.headers.forEach((v, k) => { respHeaders[k.toLowerCase()] = v; });
    return { status: resp.status, bodyText, headers: respHeaders };
  } catch {
    clearTimeout(timer);
    return { status: 0, bodyText: '', headers: {} };
  }
}

function isReflected(body: string, headers: Record<string, string>, value: string): boolean {
  const lowerValue = value.toLowerCase();
  const lowerBody = body.toLowerCase();
  if (lowerBody.includes(lowerValue)) return true;
  const location = headers['location'] ?? '';
  if (location.toLowerCase().includes(lowerValue)) return true;
  const csp = headers['content-security-policy'] ?? '';
  if (csp.toLowerCase().includes(lowerValue)) return true;
  return false;
}

const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export const cacheProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const authHeader = String(params.auth_header || '');
    const timeoutMs = Number(params.timeout_ms || 8000);

    const commonHeaders: Record<string, string> = {};
    if (authHeader) commonHeaders['Authorization'] = authHeader;

    const cacheBuster = randomBytes(4).toString('hex');
    const tests: CacheTestResult[] = [];
    let maxSeverity = 'info';
    const reflectedHeaders: string[] = [];

    // Baseline (cache-busted)
    let baselineUrl: string;
    try {
      const u = new URL(url);
      u.searchParams.set('__cb', cacheBuster);
      baselineUrl = u.toString();
    } catch {
      return { output: 'Invalid URL', parsed: { error: 'invalid url' } };
    }
    const baseline = await makeRequest(baselineUrl, commonHeaders, 'GET', null, timeoutMs);
    const cacheHeaders = {
      'cache-control': baseline.headers['cache-control'] ?? '',
      'vary': baseline.headers['vary'] ?? '',
      'age': baseline.headers['age'] ?? '',
      'x-cache': baseline.headers['x-cache'] ?? '',
      'cf-cache-status': baseline.headers['cf-cache-status'] ?? '',
      'surrogate-control': baseline.headers['surrogate-control'] ?? '',
    };

    // Is the endpoint cached at all?
    const second = await makeRequest(url, commonHeaders, 'GET', null, timeoutMs);
    const isCached = Number(second.headers['age'] ?? 0) > 0
      || (second.headers['x-cache'] ?? '').toLowerCase().includes('hit')
      || (second.headers['cf-cache-status'] ?? '').toLowerCase() === 'hit';

    // Test 1: X-Forwarded-Host injection
    const evilHost = 'evil.cache-test.com';
    const xfhResult = await makeRequest(url, { ...commonHeaders, 'X-Forwarded-Host': evilHost }, 'GET', null, timeoutMs);
    if (isReflected(xfhResult.bodyText, xfhResult.headers, evilHost)) {
      reflectedHeaders.push('X-Forwarded-Host');
      const sev = isCached ? 'critical' : 'high';
      tests.push({ name: 'X-Forwarded-Host Injection', severity: sev, finding: 'reflected', evidence: `"${evilHost}" found in response${isCached ? ' + endpoint is cached = cache poisoning' : ''}` });
    } else {
      tests.push({ name: 'X-Forwarded-Host Injection', severity: 'info', finding: 'not reflected', evidence: 'Value not reflected in response' });
    }

    // Test 2: X-Original-URL override
    const origUrlResult = await makeRequest(url, { ...commonHeaders, 'X-Original-URL': '/admin' }, 'GET', null, timeoutMs);
    if (origUrlResult.status !== baseline.status && origUrlResult.status !== 0) {
      tests.push({ name: 'X-Original-URL Override', severity: 'high', finding: 'status change', evidence: `Baseline: ${baseline.status}, with X-Original-URL: /admin: ${origUrlResult.status}` });
    } else {
      const rwResult = await makeRequest(url, { ...commonHeaders, 'X-Rewrite-URL': '/admin' }, 'GET', null, timeoutMs);
      if (rwResult.status !== baseline.status && rwResult.status !== 0) {
        tests.push({ name: 'X-Rewrite-URL Override', severity: 'high', finding: 'status change', evidence: `Baseline: ${baseline.status}, with X-Rewrite-URL: /admin: ${rwResult.status}` });
      } else {
        tests.push({ name: 'X-Original-URL/X-Rewrite-URL', severity: 'info', finding: 'no effect', evidence: 'Path override headers have no effect' });
      }
    }

    // Test 3: Unkeyed IP header access control bypass
    const ipBypassResult = await makeRequest(url, { ...commonHeaders, 'X-Forwarded-For': '127.0.0.1', 'X-Real-IP': '127.0.0.1' }, 'GET', null, timeoutMs);
    if (baseline.status === 403 && ipBypassResult.status === 200) {
      tests.push({ name: 'IP Header Access Control Bypass', severity: 'high', finding: 'bypass confirmed', evidence: '403 → 200 with X-Forwarded-For: 127.0.0.1' });
    } else if (ipBypassResult.status !== baseline.status) {
      tests.push({ name: 'IP Header Behavior Change', severity: 'medium', finding: 'status changed', evidence: `Baseline: ${baseline.status}, with localhost IP headers: ${ipBypassResult.status}` });
    } else {
      tests.push({ name: 'IP Header Access Control Bypass', severity: 'info', finding: 'no effect', evidence: 'IP headers do not change access control' });
    }

    // Test 4: Web cache deception
    let deceptionUrl: string;
    try {
      const u = new URL(url);
      u.pathname = u.pathname.replace(/\/?$/, '/genesis_test.css');
      deceptionUrl = u.toString();
    } catch {
      deceptionUrl = url + '/genesis_test.css';
    }
    const deceptionResult = await makeRequest(deceptionUrl, commonHeaders, 'GET', null, timeoutMs);
    if (deceptionResult.status === 200 && deceptionResult.bodyText.length > 100) {
      const cc = deceptionResult.headers['cache-control'] ?? '';
      if (cc.includes('public') || /max-age=([1-9]\d*)/.test(cc)) {
        tests.push({ name: 'Web Cache Deception', severity: 'medium', finding: 'potentially vulnerable', evidence: `${deceptionUrl} returns 200 with cacheable Cache-Control: ${cc}` });
      } else {
        tests.push({ name: 'Web Cache Deception', severity: 'low', finding: 'path accessible', evidence: `Static extension path returns 200 but Cache-Control does not indicate public caching` });
      }
    } else {
      tests.push({ name: 'Web Cache Deception', severity: 'info', finding: 'not vulnerable', evidence: `Static extension path returns ${deceptionResult.status}` });
    }

    // Test 5: Fat GET
    const fatGetResult = await makeRequest(url, { ...commonHeaders, 'Content-Length': '22' }, 'GET', 'body=genesis_fat_test', timeoutMs);
    if (fatGetResult.bodyText !== baseline.bodyText && Math.abs(fatGetResult.bodyText.length - baseline.bodyText.length) > 50) {
      tests.push({ name: 'Fat GET Poisoning', severity: 'medium', finding: 'body affects response', evidence: `GET with body produces different response (${fatGetResult.bodyText.length} vs ${baseline.bodyText.length} bytes)` });
    } else {
      tests.push({ name: 'Fat GET Poisoning', severity: 'info', finding: 'no effect', evidence: 'Request body in GET request has no effect' });
    }

    // Cache activity analysis
    const cacheActivity = isCached ? 'ACTIVE — endpoint is cached (Age or X-Cache HIT detected)' : 'not detected in test window';
    tests.push({
      name: 'Cache Activity',
      severity: isCached ? 'info' : 'info',
      finding: cacheActivity,
      evidence: `Age: ${cacheHeaders['age'] || '-'}, X-Cache: ${cacheHeaders['x-cache'] || '-'}, CF-Cache-Status: ${cacheHeaders['cf-cache-status'] || '-'}`,
    });

    maxSeverity = tests.reduce((max, t) => (SEVERITY_RANK[t.severity] ?? 0) > (SEVERITY_RANK[max] ?? 0) ? t.severity : max, 'info');

    const divider = '─'.repeat(90);
    const rows = tests.map(t => `  [${t.severity.toUpperCase().padEnd(8)}] ${t.name}: ${t.finding}\n             Evidence: ${t.evidence}`).join('\n');

    const output = [
      `Cache Probe Results — ${url}`,
      divider,
      `Endpoint Cached: ${isCached ? 'YES' : 'not confirmed'}`,
      `Cache-Control: ${cacheHeaders['cache-control'] || '-'}`,
      `Vary: ${cacheHeaders['vary'] || '-'}`,
      divider,
      '',
      'TEST RESULTS:',
      rows,
      divider,
      `Max Severity: ${maxSeverity.toUpperCase()}`,
    ].join('\n');

    return {
      output,
      parsed: {
        is_cached: isCached,
        cache_headers: cacheHeaders,
        tests: tests as unknown as Record<string, unknown>[],
        reflected_headers: reflectedHeaders,
        max_severity: maxSeverity,
        observations: tests.filter(t => t.finding !== 'not vulnerable' && t.finding !== 'no effect' && t.finding !== 'not reflected').map(t => `${t.name}: ${t.finding}`),
      },
    };
  },
};

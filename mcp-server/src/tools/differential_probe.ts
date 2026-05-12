import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'differential_probe',
  description: 'Sends multiple HTTP requests with different parameter values and returns a behavioral comparison matrix. Detects boolean-based SQLi, auth inconsistencies, information disclosure, and timing anomalies by comparing response length, status, time, and content across inputs.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url', type: 'string', required: true, description: 'Target URL with PARAM placeholder where test values will be injected' },
    { name: 'values', type: 'string', required: true, description: 'JSON array of test values e.g. ["1","2","1 AND 1=1","1 AND 1=0","1 OR 1=1","sleep(5)"]' },
    { name: 'method', type: 'string', required: false, description: 'GET or POST', default: 'GET' },
    { name: 'headers', type: 'string', required: false, description: 'JSON object of extra headers e.g. {"Cookie":"session=abc"}' },
    { name: 'post_body', type: 'string', required: false, description: 'POST body template with PARAM placeholder' },
    { name: 'timeout_ms', type: 'number', required: false, description: 'Per-request timeout in ms', default: 8000 },
  ],
};

interface ProbeResult {
  value: string;
  status: number;
  length: number;
  time_ms: number;
  excerpt: string;
  error?: string;
}

async function probeOne(
  url: string,
  value: string,
  method: string,
  headers: Record<string, string>,
  postBody: string,
  timeoutMs: number,
): Promise<ProbeResult> {
  const resolvedUrl = url.replace('PARAM', encodeURIComponent(value));
  const resolvedBody = postBody ? postBody.replace('PARAM', value) : undefined;
  const start = Date.now();

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    const resp = await fetch(resolvedUrl, {
      method,
      headers,
      body: resolvedBody,
      signal: controller.signal,
    });
    clearTimeout(timer);

    const text = await resp.text();
    const time_ms = Date.now() - start;
    return {
      value,
      status: resp.status,
      length: text.length,
      time_ms,
      excerpt: text.substring(0, 120).replace(/\s+/g, ' '),
    };
  } catch (err: unknown) {
    return {
      value,
      status: 0,
      length: 0,
      time_ms: Date.now() - start,
      excerpt: '',
      error: String(err),
    };
  }
}

function analyzeMatrix(results: ProbeResult[]): string[] {
  const observations: string[] = [];
  const statuses = new Set(results.map(r => r.status));
  const lengths = results.map(r => r.length);
  const times = results.map(r => r.time_ms);
  const maxTime = Math.max(...times);
  const minTime = Math.min(...times);
  const avgLength = lengths.reduce((a, b) => a + b, 0) / lengths.length;

  if (statuses.size > 1) {
    observations.push(`STATUS VARIATION: Different HTTP status codes observed (${[...statuses].join(', ')}) — possible auth bypass or conditional logic`);
  }

  const lengthVariation = Math.max(...lengths) - Math.min(...lengths);
  if (lengthVariation > 50) {
    observations.push(`CONTENT VARIATION: Response length varies by ${lengthVariation} bytes — possible boolean-based injection or data disclosure`);
  }

  if (maxTime - minTime > 3000) {
    const slowResult = results.find(r => r.time_ms === maxTime);
    observations.push(`TIMING ANOMALY: Value "${slowResult?.value}" caused ${maxTime}ms response vs avg ${Math.round(avgLength)}ms — likely time-based injection`);
  }

  const errorResults = results.filter(r => r.error || r.status >= 500);
  if (errorResults.length > 0 && errorResults.length < results.length) {
    observations.push(`ERROR RESPONSES: Some values caused server errors (${errorResults.map(r => `"${r.value}"`).join(', ')}) — possible injection or unhandled input`);
  }

  if (observations.length === 0) {
    observations.push('No significant behavioral differences detected — responses appear uniform across tested values');
  }

  return observations;
}

export const differentialProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const method = String(params.method || 'GET').toUpperCase();
    const timeoutMs = Number(params.timeout_ms || 8000);
    const postBody = String(params.post_body || '');

    let values: string[] = [];
    try {
      values = JSON.parse(String(params.values || '[]'));
    } catch {
      return { output: 'values must be a valid JSON array of strings', parsed: { error: 'invalid values' } };
    }

    let headers: Record<string, string> = { 'User-Agent': 'Mozilla/5.0' };
    try {
      if (params.headers) Object.assign(headers, JSON.parse(String(params.headers)));
    } catch { /* ignore */ }

    if (method === 'POST' && postBody) headers['Content-Type'] = 'application/x-www-form-urlencoded';

    const results: ProbeResult[] = [];
    for (const value of values.slice(0, 30)) {  // cap at 30 values
      results.push(await probeOne(url, value, method, headers, postBody, timeoutMs));
    }

    const observations = analyzeMatrix(results);

    const table = results.map(r =>
      `  ${String(r.value).padEnd(25)} | ${String(r.status).padEnd(4)} | ${String(r.length).padEnd(7)} | ${String(r.time_ms).padEnd(7)}ms | ${r.excerpt.substring(0, 60)}`
    ).join('\n');

    const output = [
      `Differential Probe Results — ${url}`,
      `${'─'.repeat(80)}`,
      `  ${'Value'.padEnd(25)} | ${'Code'.padEnd(4)} | ${'Length'.padEnd(7)} | ${'Time'.padEnd(8)} | Excerpt`,
      `${'─'.repeat(80)}`,
      table,
      `${'─'.repeat(80)}`,
      '',
      'ANALYST OBSERVATIONS:',
      ...observations.map(o => `  ⚠ ${o}`),
    ].join('\n');

    return { output, parsed: { results, observations } };
  },
};

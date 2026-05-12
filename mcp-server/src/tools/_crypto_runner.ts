// Shared runner for T26 crypto-primitive tools. Each tool builds a tiny
// Python driver, POSTs to forge_sandbox, parses the JSON result the
// primitive prints on stdout, and returns a structured ToolResult.
import { ToolResult } from '../types';

const SANDBOX_URL = process.env.FORGE_SANDBOX_URL || 'http://forge_sandbox:3201';

export interface PrimitiveResult {
  ok?: boolean;
  reason?: string;
  [k: string]: unknown;
}

export async function runCryptoPrimitive(
  toolName: string,
  module: string,
  params: Record<string, unknown>,
  wallTimeS = 60,
): Promise<ToolResult> {
  const driver = [
    'import json, sys',
    `from genesis_crypto import ${module}`,
    `params = json.loads(sys.stdin.read() or "{}")`,
    `result = ${module}.attack(**params)`,
    'sys.stdout.write(json.dumps(result))',
  ].join('\n');

  const stdin = JSON.stringify(params);

  let resp: Response;
  try {
    const c = new AbortController();
    const timer = setTimeout(() => c.abort(), (wallTimeS + 10) * 1000);
    resp = await fetch(`${SANDBOX_URL}/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        lang: 'python',
        code: driver,
        stdin,
        wall_time_s: wallTimeS,
      }),
      signal: c.signal,
    });
    clearTimeout(timer);
  } catch (err) {
    return {
      output: `${toolName}: sandbox request failed: ${err}`,
      parsed: { error: String(err), sandbox_url: SANDBOX_URL, ok: false },
    };
  }

  if (!resp.ok) {
    const body = await resp.text().catch(() => '');
    return {
      output: `${toolName}: sandbox HTTP ${resp.status}: ${body.substring(0, 400)}`,
      parsed: { error: 'sandbox_http_error', status: resp.status, ok: false },
    };
  }

  const sb = await resp.json() as {
    stdout?: string; stderr?: string; exit_code?: number;
    duration_ms?: number; timed_out?: boolean; error?: string;
  };

  if (sb.error) {
    return {
      output: `${toolName}: sandbox error: ${sb.error}`,
      parsed: { error: sb.error, ok: false },
    };
  }

  const stdout = sb.stdout ?? '';
  let result: PrimitiveResult;
  try {
    result = JSON.parse(stdout.trim().split('\n').pop() || '{}');
  } catch (err) {
    return {
      output: [
        `${toolName}: failed to parse primitive output as JSON.`,
        `stdout: ${stdout.substring(0, 600)}`,
        `stderr: ${(sb.stderr ?? '').substring(0, 600)}`,
      ].join('\n'),
      parsed: {
        error: 'json_parse_failed',
        stderr: sb.stderr ?? '',
        stdout: stdout.substring(0, 2000),
        ok: false,
      },
    };
  }

  const ok = Boolean(result.ok);
  const headerLines = [
    `${toolName} — ${ok ? 'SUCCESS' : 'FAIL'}  (duration=${sb.duration_ms ?? 0}ms)`,
    '─'.repeat(70),
  ];
  if (!ok && result.reason) headerLines.push(`reason: ${result.reason}`);
  for (const [k, v] of Object.entries(result)) {
    if (k === 'ok' || k === 'reason') continue;
    const vs = typeof v === 'string' ? v : JSON.stringify(v);
    headerLines.push(`${k}: ${vs.length > 400 ? vs.substring(0, 400) + '…' : vs}`);
  }
  const stderrTail = (sb.stderr ?? '').trim();
  if (stderrTail) {
    headerLines.push('');
    headerLines.push(`stderr: ${stderrTail.substring(0, 400)}`);
  }

  return {
    output: headerLines.join('\n'),
    parsed: {
      ...result,
      ok,
      duration_ms: sb.duration_ms ?? 0,
      timed_out: Boolean(sb.timed_out),
      tool: toolName,
    },
  };
}

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

// ---------------------------------------------------------------------------
// ai_request_forge — LLM-authored HTTP exploit + declarative verification oracle
//
// Unlike every other tool in the suite, this one does NOT encode any attack
// logic of its own. The LLM writes the full HTTP request (method, URL,
// headers, body) AND declares, in structured form, what "success" looks like
// on the response — a predicate the backend evaluates deterministically.
//
// This flips ownership of exploit construction from tool to model. A passing
// oracle is accepted by the orchestrator as first-class evidence under U1.
// ---------------------------------------------------------------------------

const BACKEND_URL = process.env.BACKEND_URL || 'http://backend:8000';
const API_KEY = process.env.MCP_API_KEY || '';

const definition: ToolDefinition = {
  name: 'ai_request_forge',
  description:
    'Forge and send an LLM-authored HTTP request with a declarative verification oracle. ' +
    'Use when no catalog tool targets the bug class you want to test or when the attack ' +
    'needs to be shaped to this target\'s specific middleware. Optionally sends a baseline + ' +
    'attack pair and compares them (differential mode). Optionally auto-injects an OOB token.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'method', type: 'string', required: true, description: 'HTTP method (GET/POST/PUT/PATCH/DELETE/OPTIONS)' },
    { name: 'url', type: 'string', required: true, description: 'Full target URL' },
    { name: 'headers', type: 'string', required: false, description: 'JSON object of headers e.g. {"Authorization":"Bearer ..."}' },
    { name: 'body', type: 'string', required: false, description: 'Raw request body (string, already encoded if JSON)' },
    { name: 'oracle', type: 'string', required: true, description: 'JSON oracle declaring success. Keys: expect_status (int|array), body_must_contain (string|array), body_must_not_contain (string|array), body_regex (string), response_time_gt_ms (int), response_time_lt_ms (int), reflect_token (string — expect this exact token in response), min_length (int), max_length (int), header_must_contain (object {name: value})' },
    { name: 'baseline_body', type: 'string', required: false, description: 'Optional differential mode: a benign baseline body/URL sent alongside. If set, the oracle can reference diff_length_gt (int) and diff_status_changed (bool).' },
    { name: 'baseline_url', type: 'string', required: false, description: 'Optional: separate URL for the baseline request (defaults to url)' },
    { name: 'oob_token_placeholder', type: 'string', required: false, description: 'If set, the given literal is replaced in url/headers/body with an OOB token generated just-in-time. The returned result includes the token so you can call oob_check later.' },
    { name: 'timeout_ms', type: 'number', required: false, description: 'Per-request timeout', default: 15000 },
    { name: 'follow_redirects', type: 'boolean', required: false, description: 'Follow 3xx redirects', default: false },
    { name: 'rationale', type: 'string', required: false, description: 'One-sentence explanation of why this request should prove the bug (stored for audit trail)' },
  ],
};

interface OracleSpec {
  expect_status?: number | number[];
  body_must_contain?: string | string[];
  body_must_not_contain?: string | string[];
  body_regex?: string;
  response_time_gt_ms?: number;
  response_time_lt_ms?: number;
  reflect_token?: string;
  min_length?: number;
  max_length?: number;
  header_must_contain?: Record<string, string>;
  diff_length_gt?: number;
  diff_status_changed?: boolean;
}

interface RequestResult {
  status: number;
  length: number;
  time_ms: number;
  headers: Record<string, string>;
  body_excerpt: string;
  full_body: string;
  error?: string;
}

function parseJsonParam<T = unknown>(raw: unknown, fallback: T): T {
  if (!raw) return fallback;
  try {
    return JSON.parse(String(raw)) as T;
  } catch {
    return fallback;
  }
}

async function sendOne(
  url: string,
  method: string,
  headers: Record<string, string>,
  body: string | undefined,
  timeoutMs: number,
  followRedirects: boolean,
): Promise<RequestResult> {
  const start = Date.now();
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const resp = await fetch(url, {
      method,
      headers,
      body,
      redirect: followRedirects ? 'follow' : 'manual',
      signal: controller.signal,
    });
    clearTimeout(timer);
    const text = await resp.text();
    const headerObj: Record<string, string> = {};
    resp.headers.forEach((v, k) => { headerObj[k] = v; });
    return {
      status: resp.status,
      length: text.length,
      time_ms: Date.now() - start,
      headers: headerObj,
      body_excerpt: text.substring(0, 400).replace(/\s+/g, ' '),
      full_body: text.substring(0, 8000),
    };
  } catch (err: unknown) {
    return {
      status: 0,
      length: 0,
      time_ms: Date.now() - start,
      headers: {},
      body_excerpt: '',
      full_body: '',
      error: String(err),
    };
  }
}

interface OracleVerdict {
  verdict: 'pass' | 'fail' | 'partial';
  reasons: string[];
}

function evalOracle(
  oracle: OracleSpec,
  attack: RequestResult,
  baseline: RequestResult | null,
): OracleVerdict {
  const reasons: string[] = [];
  let passes = 0;
  let checks = 0;

  const record = (ok: boolean, msg: string): void => {
    checks += 1;
    if (ok) { passes += 1; reasons.push(`PASS: ${msg}`); }
    else { reasons.push(`FAIL: ${msg}`); }
  };

  if (oracle.expect_status !== undefined) {
    const allowed = Array.isArray(oracle.expect_status) ? oracle.expect_status : [oracle.expect_status];
    record(allowed.includes(attack.status), `expect_status ${allowed.join('|')} (got ${attack.status})`);
  }
  if (oracle.body_must_contain !== undefined) {
    const needles = Array.isArray(oracle.body_must_contain) ? oracle.body_must_contain : [oracle.body_must_contain];
    for (const n of needles) {
      record(attack.full_body.includes(n), `body must contain "${n.substring(0, 80)}"`);
    }
  }
  if (oracle.body_must_not_contain !== undefined) {
    const needles = Array.isArray(oracle.body_must_not_contain) ? oracle.body_must_not_contain : [oracle.body_must_not_contain];
    for (const n of needles) {
      record(!attack.full_body.includes(n), `body must NOT contain "${n.substring(0, 80)}"`);
    }
  }
  if (oracle.body_regex) {
    try {
      const re = new RegExp(oracle.body_regex, 's');
      record(re.test(attack.full_body), `body matches /${oracle.body_regex}/`);
    } catch {
      record(false, `body_regex invalid: /${oracle.body_regex}/`);
    }
  }
  if (oracle.response_time_gt_ms !== undefined) {
    record(attack.time_ms > oracle.response_time_gt_ms, `response_time > ${oracle.response_time_gt_ms}ms (got ${attack.time_ms}ms)`);
  }
  if (oracle.response_time_lt_ms !== undefined) {
    record(attack.time_ms < oracle.response_time_lt_ms, `response_time < ${oracle.response_time_lt_ms}ms (got ${attack.time_ms}ms)`);
  }
  if (oracle.reflect_token) {
    record(attack.full_body.includes(oracle.reflect_token), `reflect_token "${oracle.reflect_token}" appears in response`);
  }
  if (oracle.min_length !== undefined) {
    record(attack.length >= oracle.min_length, `response length >= ${oracle.min_length} (got ${attack.length})`);
  }
  if (oracle.max_length !== undefined) {
    record(attack.length <= oracle.max_length, `response length <= ${oracle.max_length} (got ${attack.length})`);
  }
  if (oracle.header_must_contain) {
    for (const [name, expected] of Object.entries(oracle.header_must_contain)) {
      const actual = attack.headers[name.toLowerCase()] || '';
      record(actual.includes(expected), `header "${name}" must contain "${expected}" (got "${actual.substring(0, 80)}")`);
    }
  }
  if (baseline) {
    if (oracle.diff_length_gt !== undefined) {
      const delta = Math.abs(attack.length - baseline.length);
      record(delta > oracle.diff_length_gt, `|attack.length - baseline.length| > ${oracle.diff_length_gt} (got ${delta})`);
    }
    if (oracle.diff_status_changed) {
      record(attack.status !== baseline.status, `attack.status (${attack.status}) != baseline.status (${baseline.status})`);
    }
  }

  if (checks === 0) {
    return { verdict: 'fail', reasons: ['oracle declared no checkable predicates'] };
  }
  if (passes === checks) return { verdict: 'pass', reasons };
  if (passes === 0) return { verdict: 'fail', reasons };
  return { verdict: 'partial', reasons };
}

async function generateOobToken(description: string): Promise<{ token: string; url: string } | null> {
  try {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (API_KEY) headers['X-API-Key'] = API_KEY;
    const resp = await fetch(
      `${BACKEND_URL}/api/v1/callback/generate?description=${encodeURIComponent(description)}`,
      { method: 'GET', headers },
    );
    const data = await resp.json() as Record<string, unknown>;
    if (data.token && data.http_url) {
      return { token: String(data.token), url: String(data.http_url) };
    }
  } catch {
    /* swallow — OOB injection is optional */
  }
  return null;
}

function substituteOobToken(
  placeholder: string,
  oobUrl: string,
  url: string,
  headers: Record<string, string>,
  body: string | undefined,
): { url: string; headers: Record<string, string>; body: string | undefined } {
  const newHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    newHeaders[k] = v.split(placeholder).join(oobUrl);
  }
  return {
    url: url.split(placeholder).join(oobUrl),
    headers: newHeaders,
    body: body ? body.split(placeholder).join(oobUrl) : body,
  };
}

export const aiRequestForgeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const method = String(params.method || 'GET').toUpperCase();
    let url = String(params.url || '');
    const timeoutMs = Number(params.timeout_ms || 15000);
    const followRedirects = Boolean(params.follow_redirects);
    const rationale = String(params.rationale || '');

    if (!url) {
      return { output: 'url required', parsed: { error: 'missing url' } };
    }

    let headers: Record<string, string> = {
      'User-Agent': 'Mozilla/5.0 (GENESIS)',
    };
    const parsedHeaders = parseJsonParam<Record<string, string>>(params.headers, {});
    Object.assign(headers, parsedHeaders);

    let body: string | undefined = params.body !== undefined && params.body !== null
      ? String(params.body) : undefined;
    if (body && !headers['Content-Type'] && !headers['content-type']) {
      // Best-effort default — JSON body if it starts with { or [, else form-urlencoded.
      const trimmed = body.trim();
      if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
        headers['Content-Type'] = 'application/json';
      } else if (method !== 'GET') {
        headers['Content-Type'] = 'application/x-www-form-urlencoded';
      }
    }

    const oracle = parseJsonParam<OracleSpec>(params.oracle, {});
    if (!oracle || typeof oracle !== 'object') {
      return { output: 'oracle must be a valid JSON object', parsed: { error: 'invalid oracle' } };
    }

    // Optional OOB token injection
    let oobInfo: { token: string; url: string } | null = null;
    const placeholder = String(params.oob_token_placeholder || '');
    if (placeholder) {
      oobInfo = await generateOobToken(rationale || 'ai_request_forge OOB probe');
      if (oobInfo) {
        const sub = substituteOobToken(placeholder, oobInfo.url, url, headers, body);
        url = sub.url;
        headers = sub.headers;
        body = sub.body;
      }
    }

    // Optional baseline (differential mode)
    let baseline: RequestResult | null = null;
    const baselineBody = params.baseline_body !== undefined && params.baseline_body !== null
      ? String(params.baseline_body) : undefined;
    const baselineUrl = params.baseline_url ? String(params.baseline_url) : null;
    if (baselineBody !== undefined || baselineUrl) {
      baseline = await sendOne(
        baselineUrl || url,
        method,
        headers,
        baselineBody !== undefined ? baselineBody : body,
        timeoutMs,
        followRedirects,
      );
    }

    const attack = await sendOne(url, method, headers, body, timeoutMs, followRedirects);
    const verdict = evalOracle(oracle, attack, baseline);

    const outputLines = [
      `ai_request_forge — ${method} ${url}`,
      `${'─'.repeat(70)}`,
      `Attack: status=${attack.status}, length=${attack.length}, time=${attack.time_ms}ms`,
      attack.error ? `  ERROR: ${attack.error}` : `  body[0..400]: ${attack.body_excerpt}`,
    ];
    if (baseline) {
      outputLines.push(
        `Baseline: status=${baseline.status}, length=${baseline.length}, time=${baseline.time_ms}ms`,
      );
      outputLines.push(`  body[0..400]: ${baseline.body_excerpt}`);
    }
    outputLines.push(`${'─'.repeat(70)}`);
    outputLines.push(`Oracle verdict: ${verdict.verdict.toUpperCase()}`);
    for (const r of verdict.reasons) outputLines.push(`  ${r}`);
    if (oobInfo) {
      outputLines.push('');
      outputLines.push(`OOB token injected: ${oobInfo.token}`);
      outputLines.push(`  -> call oob_check(action=check, token=${oobInfo.token}) later to confirm callback`);
    }
    if (rationale) {
      outputLines.push('');
      outputLines.push(`Rationale: ${rationale}`);
    }

    return {
      output: outputLines.join('\n'),
      parsed: {
        method,
        url,
        attack,
        baseline,
        oracle,
        oracle_verdict: verdict.verdict,
        oracle_reasons: verdict.reasons,
        oob_token: oobInfo?.token,
        oob_url: oobInfo?.url,
        rationale,
      },
    };
  },
};

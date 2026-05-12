import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

// ---------------------------------------------------------------------------
// browser_session — Tier-3 · T12 agentic browser.
//
// Unlike render_and_see (T6, single-page snapshot), this tool drives a
// stateful headless-Chromium session: the AI opens a session once, then
// issues a series of steps (goto, click, fill, wait, snapshot, eval_js)
// with cookies and local state preserved between them. Every step returns
// a fresh screenshot the backend attaches to the next vision turn, so the
// model can *see* each page of a multi-step flow — login, OAuth consent,
// privilege-escalation admin consoles, captcha, etc.
//
// Actions (the required `action` parameter):
//   start   — open a new browser session. Optional: viewport, cookies, headers
//   goto    — navigate to a url. Required: url
//   click   — click a selector. Required: selector
//   fill    — fill an input with value, optional submit:true presses Enter
//   press   — press a key (default Enter)
//   wait    — wait for selector (visible|hidden|attached|detached) or ms
//   snapshot — just return the current page state
//   eval_js — evaluate a JS expression in the page context (returns JSON)
//   close   — close the session and free the browser context
// ---------------------------------------------------------------------------

const RENDERER_URL = process.env.CHROMIUM_RENDERER_URL || 'http://chromium_renderer:3301';
const DEFAULT_TIMEOUT_MS = 20000;

const definition: ToolDefinition = {
  name: 'browser_session',
  description:
    'Drive a stateful headless Chromium session across multiple steps — navigate, click, fill forms, wait, evaluate JS. ' +
    'Cookies and local storage persist across steps, so you can complete login flows, OAuth consent screens, ' +
    'and multi-page admin wizards that single-shot render_and_see cannot reach. Each step returns a screenshot ' +
    'that is attached to your next vision turn.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'action', type: 'string', required: true, description: 'start | goto | click | fill | press | wait | snapshot | eval_js | close' },
    { name: 'session_id', type: 'string', required: false, description: 'Session handle returned by action=start. Required for every subsequent step.' },
    { name: 'url', type: 'string', required: false, description: 'URL (action=goto)' },
    { name: 'selector', type: 'string', required: false, description: 'CSS selector (click/fill/press/wait)' },
    { name: 'value', type: 'string', required: false, description: 'Value to fill into the selector (action=fill)' },
    { name: 'submit', type: 'boolean', required: false, description: 'If true, press Enter after fill (action=fill)' },
    { name: 'key', type: 'string', required: false, description: 'Key to press (action=press). Default Enter.' },
    { name: 'state', type: 'string', required: false, description: 'wait state: visible | hidden | attached | detached. Default visible.' },
    { name: 'ms', type: 'number', required: false, description: 'Fixed wait duration in ms (action=wait, no selector)' },
    { name: 'code', type: 'string', required: false, description: 'JavaScript expression to evaluate in the page (action=eval_js). Max 4KB.' },
    { name: 'wait_ms', type: 'number', required: false, description: 'Extra wait after navigation completes (action=goto)' },
    { name: 'timeout_ms', type: 'number', required: false, description: 'Per-step timeout', default: DEFAULT_TIMEOUT_MS },
    { name: 'viewport_width', type: 'number', required: false, description: 'Browser viewport width (action=start)', default: 1366 },
    { name: 'viewport_height', type: 'number', required: false, description: 'Browser viewport height (action=start)', default: 768 },
    { name: 'cookies', type: 'string', required: false, description: 'JSON array of {name,value,domain,...} cookies (action=start)' },
    { name: 'headers', type: 'string', required: false, description: 'JSON object of extra HTTP headers (action=start)' },
    { name: 'user_agent', type: 'string', required: false, description: 'Override the default user-agent string (action=start)' },
  ],
};

function parseJsonParam<T = unknown>(raw: unknown, fallback: T): T {
  if (!raw) return fallback;
  try { return JSON.parse(String(raw)) as T; } catch { return fallback; }
}

function s(v: unknown): string { return v == null ? '' : String(v); }
function n(v: unknown, fallback: number): number {
  const x = Number(v);
  return Number.isFinite(x) ? x : fallback;
}

async function call(endpoint: string, body: Record<string, unknown>, timeoutMs: number): Promise<Response | { _err: string }> {
  const c = new AbortController();
  const timer = setTimeout(() => c.abort(), timeoutMs + 15000);
  try {
    const resp = await fetch(`${RENDERER_URL}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: c.signal,
    });
    clearTimeout(timer);
    return resp;
  } catch (err) {
    clearTimeout(timer);
    return { _err: String(err) };
  }
}

interface StepResponse {
  step_index?: number;
  action?: string;
  action_error?: string | null;
  action_detail?: Record<string, unknown>;
  final_url?: string;
  screenshot_b64?: string;
  dom?: string;
  viewport?: { width: number; height: number };
  console_log_delta?: Array<{ type: string; text: string }>;
  network_delta?: Array<{ url: string; method: string; resource_type: string }>;
  error?: string;
}

function renderStepSummary(url: string, action: string, data: StepResponse): string {
  const b64Bytes = data.screenshot_b64 ? Math.floor(data.screenshot_b64.length * 3 / 4) : 0;
  const domBytes = data.dom ? data.dom.length : 0;
  const lines: string[] = [
    `browser_session step ${data.step_index ?? '?'} · ${action}`,
    `final_url: ${data.final_url || '?'}`,
    `screenshot: ${b64Bytes} bytes (attached to next vision turn)`,
    `dom: ${domBytes} bytes`,
    `console_delta: ${(data.console_log_delta || []).length} lines`,
    `network_delta: ${(data.network_delta || []).length}`,
  ];
  if (data.action_error) lines.push(`action_error: ${data.action_error}`);
  if ((data.console_log_delta || []).length > 0) {
    lines.push('');
    lines.push('Console delta (first 10):');
    for (const c of (data.console_log_delta || []).slice(0, 10)) {
      lines.push(`  [${c.type}] ${c.text.substring(0, 200)}`);
    }
  }
  if ((data.network_delta || []).length > 0) {
    lines.push('');
    lines.push('Network delta (first 15):');
    for (const r of (data.network_delta || []).slice(0, 15)) {
      lines.push(`  ${r.method} ${r.resource_type.padEnd(10)} ${r.url.substring(0, 120)}`);
    }
  }
  return lines.join('\n');
}

export const browserSessionTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const action = s(params.action).toLowerCase();
    if (!action) return { output: 'action required', parsed: { error: 'missing action' } };

    const timeoutMs = n(params.timeout_ms, DEFAULT_TIMEOUT_MS);

    if (action === 'start') {
      const body = {
        session_id: s(params.session_id) || undefined,
        viewport_width: n(params.viewport_width, 1366),
        viewport_height: n(params.viewport_height, 768),
        cookies: parseJsonParam<unknown[]>(params.cookies, []),
        headers: parseJsonParam<Record<string, string>>(params.headers, {}),
        user_agent: s(params.user_agent) || undefined,
      };
      const resp = await call('/session/start', body, timeoutMs);
      if ('_err' in resp) {
        return { output: `renderer unreachable: ${resp._err}`, parsed: { error: resp._err, renderer_url: RENDERER_URL } };
      }
      const data = await resp.json() as { ok?: boolean; session_id?: string; resumed?: boolean; error?: string; viewport?: unknown };
      if (data.error) return { output: `session start failed: ${data.error}`, parsed: { error: data.error } };
      return {
        output: `browser session ${data.session_id} ${data.resumed ? 'resumed' : 'started'}`,
        parsed: { session_id: data.session_id, resumed: data.resumed, viewport: data.viewport },
      };
    }

    if (action === 'close') {
      const session_id = s(params.session_id);
      if (!session_id) return { output: 'session_id required to close', parsed: { error: 'missing session_id' } };
      const resp = await call('/session/close', { session_id }, timeoutMs);
      if ('_err' in resp) return { output: `renderer unreachable: ${resp._err}`, parsed: { error: resp._err } };
      const data = await resp.json() as { ok?: boolean; closed?: boolean; steps?: number };
      return {
        output: `browser session ${session_id} closed (steps=${data.steps ?? 0})`,
        parsed: { closed: data.closed, steps: data.steps },
      };
    }

    // All other actions are step actions.
    const session_id = s(params.session_id);
    if (!session_id) return { output: 'session_id required (call action=start first)', parsed: { error: 'missing session_id' } };

    const body: Record<string, unknown> = {
      session_id,
      action,
      timeout_ms: timeoutMs,
    };
    if (params.url !== undefined) body.url = s(params.url);
    if (params.selector !== undefined) body.selector = s(params.selector);
    if (params.value !== undefined) body.value = s(params.value);
    if (params.submit !== undefined) body.submit = Boolean(params.submit);
    if (params.key !== undefined) body.key = s(params.key);
    if (params.state !== undefined) body.state = s(params.state);
    if (params.ms !== undefined) body.ms = n(params.ms, 1000);
    if (params.code !== undefined) body.code = s(params.code);
    if (params.wait_ms !== undefined) body.wait_ms = n(params.wait_ms, 0);

    const resp = await call('/session/step', body, timeoutMs);
    if ('_err' in resp) return { output: `renderer unreachable: ${resp._err}`, parsed: { error: resp._err, renderer_url: RENDERER_URL } };
    if (!resp.ok) {
      const text = await resp.text().catch(() => '');
      return {
        output: `renderer HTTP ${resp.status}: ${text.substring(0, 400)}`,
        parsed: { error: 'renderer_http_error', status: resp.status, body: text.substring(0, 400) },
      };
    }
    const data = await resp.json() as StepResponse;
    if (data.error) return { output: `step failed: ${data.error}`, parsed: { error: data.error } };

    const summary = renderStepSummary(s(params.url), action, data);
    return {
      output: summary,
      parsed: {
        step_index: data.step_index,
        action: data.action,
        action_error: data.action_error,
        action_detail: data.action_detail,
        final_url: data.final_url,
        screenshot_b64: data.screenshot_b64,      // orchestrator attaches as vision block
        screenshot_mime: 'image/png',
        dom_excerpt: (data.dom || '').substring(0, 8000),
        console_log_delta: data.console_log_delta || [],
        network_delta: (data.network_delta || []).slice(0, 40),
        viewport: data.viewport,
      },
    };
  },
};

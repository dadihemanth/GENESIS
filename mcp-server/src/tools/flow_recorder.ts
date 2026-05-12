// T51 — flow_recorder
// Record a multi-step web flow and extract it as an FSM JSON skeleton.
// Delegates to browser_session for JS execution and network capture.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'flow_recorder',
  description:
    'Drive a target\'s multi-step web flow (login → cart → coupon → checkout) and capture ' +
    'every request, response, cookie, and CSRF token into an FSM JSON skeleton. The FSM ' +
    'output is the input for flow_fuzzer. Essential for finding logic-skip, race, and ' +
    'out-of-order step vulnerabilities that no single-request scanner can find.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',         type: 'string', required: true,  description: 'Starting URL of the flow' },
    { name: 'flow_steps',  type: 'string', required: true,  description: 'JSON array of {action, selector, value?, url?} steps. Actions: click, fill, navigate, submit' },
    { name: 'auth_cookie', type: 'string', required: false, description: 'Auth cookie string to inject (format: name=value; name2=value2)' },
    { name: 'timeout_ms',  type: 'number', required: false, description: 'Total flow timeout ms', default: 60000 },
  ],
};

interface FlowStep {
  action: 'click' | 'fill' | 'navigate' | 'submit' | 'wait';
  selector?: string;
  value?: string;
  url?: string;
}

interface FsmState {
  id: string;
  url: string;
  title: string;
  cookies: Record<string, string>;
  csrf_tokens: string[];
}

interface FsmTransition {
  from: string;
  to: string;
  action: string;
  request: {
    method: string;
    url: string;
    body?: string;
    headers: Record<string, string>;
  };
  response: {
    status: number;
    body_excerpt: string;
  };
}

export const flowRecorderTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const startUrl = String(params.url || '');
    const authCookie = params.auth_cookie ? String(params.auth_cookie) : undefined;
    const timeoutMs = Number(params.timeout_ms || 60000);

    if (!startUrl) return { output: 'url required', parsed: { error: 'missing_url' } };

    let flowSteps: FlowStep[] = [];
    try { flowSteps = JSON.parse(String(params.flow_steps || '[]')); } catch {
      return { output: 'flow_steps must be a valid JSON array', parsed: { error: 'bad_flow_steps' } };
    }

    if (!Array.isArray(flowSteps) || flowSteps.length === 0) {
      return { output: 'flow_steps must be a non-empty array', parsed: { error: 'empty_flow_steps' } };
    }

    // Build a Playwright script to capture the flow
    const playwrightScript = `
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--ignore-certificate-errors'] });
  const context = await browser.newContext({
    ${authCookie ? `extraHTTPHeaders: { 'Cookie': '${authCookie.replace(/'/g, "\\'")}' },` : ''}
    recordHar: { path: '/tmp/genesis_flow.har', mode: 'full' },
    ignoreHTTPSErrors: true,
  });
  const page = await context.newPage();
  const transitions = [];
  const intercepted = [];

  page.on('request', req => intercepted.push({ type: 'request', url: req.url(), method: req.method(), headers: req.headers(), post_data: req.postData() }));
  page.on('response', resp => intercepted.push({ type: 'response', url: resp.url(), status: resp.status() }));

  let stateId = 0;
  const states = [];

  async function captureState() {
    stateId++;
    const cookies = await context.cookies();
    const cookieMap = {};
    for (const c of cookies) cookieMap[c.name] = c.value;
    const csrfTokens = await page.$$eval('input[name*="csrf"],input[name*="_token"],meta[name="csrf-token"]', els =>
      els.map(el => el.getAttribute('value') || el.getAttribute('content') || '').filter(Boolean)
    ).catch(() => []);
    const state = { id: String(stateId), url: page.url(), title: await page.title(), cookies: cookieMap, csrf_tokens: csrfTokens };
    states.push(state);
    return state;
  }

  await page.goto('${startUrl.replace(/'/g, "\\'")}', { timeout: ${Math.floor(timeoutMs / 2)}, waitUntil: 'networkidle' });
  await captureState();

  const steps = ${JSON.stringify(flowSteps)};
  for (const step of steps) {
    const prevIntercepted = intercepted.length;
    try {
      if (step.action === 'navigate' && step.url) {
        await page.goto(step.url, { timeout: 15000, waitUntil: 'networkidle' });
      } else if (step.action === 'click' && step.selector) {
        await page.click(step.selector, { timeout: 10000 });
        await page.waitForLoadState('networkidle', { timeout: 10000 }).catch(() => {});
      } else if (step.action === 'fill' && step.selector && step.value) {
        await page.fill(step.selector, step.value, { timeout: 5000 });
      } else if (step.action === 'submit' && step.selector) {
        await page.click(step.selector, { timeout: 5000 });
        await page.waitForLoadState('networkidle', { timeout: 15000 }).catch(() => {});
      } else if (step.action === 'wait') {
        await page.waitForTimeout(Number(step.value) || 1000);
      }
    } catch (e) { console.error('Step error:', step.action, e.message); }

    const newState = await captureState();
    const stepRequests = intercepted.slice(prevIntercepted);
    const mainReq = stepRequests.find(r => r.type === 'request');
    const mainResp = stepRequests.find(r => r.type === 'response');
    if (mainReq) {
      transitions.push({
        from: String(stateId - 1), to: String(stateId),
        action: step.action + (step.selector ? ':' + step.selector : ''),
        request: { method: mainReq.method, url: mainReq.url, body: mainReq.post_data, headers: mainReq.headers || {} },
        response: { status: mainResp?.status || 0, body_excerpt: '' },
      });
    }
  }

  await browser.close();
  console.log(JSON.stringify({ states, transitions, captured_requests: intercepted.length }, null, 2));
})().catch(e => { console.error(e.message); process.exit(1); });
`;

    // Execute via browser_session endpoint
    const browserUrl = 'http://chromium_renderer:3301';
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs + 5000);
      const resp = await fetch(`${browserUrl}/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ script: playwrightScript, timeout: timeoutMs }),
        signal: controller.signal,
      });
      clearTimeout(timer);

      if (!resp.ok) {
        return { output: `browser_session error: HTTP ${resp.status}`, parsed: { error: `http_${resp.status}` } };
      }

      const result = await resp.json() as { stdout?: string; stderr?: string; exit_code?: number };
      let fsm: { states: FsmState[]; transitions: FsmTransition[]; captured_requests: number } | null = null;

      try {
        fsm = JSON.parse(result.stdout || '{}');
      } catch { /* output may contain non-JSON lines */ }

      const lines = [
        `flow_recorder — captured flow from ${startUrl.substring(0, 80)}`,
        `Steps executed: ${flowSteps.length}`,
        fsm ? `States captured: ${fsm.states?.length || 0}  Transitions: ${fsm.transitions?.length || 0}  Requests: ${fsm.captured_requests || 0}` : 'FSM extraction failed',
        '─'.repeat(72),
      ];

      if (fsm?.states) {
        for (const state of fsm.states) {
          lines.push(`  State ${state.id}: ${state.url.substring(0, 80)}`);
          if (state.csrf_tokens.length) lines.push(`    CSRF tokens: ${state.csrf_tokens.join(', ').substring(0, 80)}`);
        }
      }
      if (fsm?.transitions) {
        lines.push('', 'Transitions:');
        for (const t of fsm.transitions) {
          lines.push(`  ${t.from} → ${t.to}  [${t.action}]  ${t.request.method} ${t.request.url.substring(0, 60)}`);
        }
      }

      lines.push('', 'NEXT: Pass this FSM to flow_fuzzer to test for logic-skip and race conditions');

      return {
        output: lines.join('\n'),
        parsed: { fsm, steps_executed: flowSteps.length, raw_stdout: (result.stdout || '').substring(0, 2000) },
      };
    } catch (err) {
      return { output: `Flow recorder error: ${String(err)}`, parsed: { error: String(err) } };
    }
  },
};

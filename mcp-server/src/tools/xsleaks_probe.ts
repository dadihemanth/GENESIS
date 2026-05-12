// T61 — xsleaks_probe
// Cross-site leak primitives: drives browser_session to measure observable
// state differences across origins (window.length, frame count, error events,
// scroll anchor, timing oracles).

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const BROWSER_SESSION_URL = 'http://chromium_renderer:3301';

const definition: ToolDefinition = {
  name: 'xsleaks_probe',
  description:
    'Cross-Site Leaks (XS-Leaks) probe. Drives browser_session to measure cross-origin state differences ' +
    'that leak binary information about the victim\'s authenticated state. Tests: window.length (iframe frame ' +
    'count), error/load event oracle, navigation timing, scroll-to-text-fragment, history.length delta. ' +
    'Use to infer whether a user is logged in, whether a record exists, or which role they hold.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',          type: 'string', required: true,  description: 'Target URL to probe (the "secret" URL)' },
    { name: 'oracle_types', type: 'string', required: false, description: 'JSON array of oracle types to test', default: '["window_length","error_event","timing","history_length"]' },
    { name: 'auth_cookie',  type: 'string', required: false, description: 'Auth cookie (simulates authenticated victim)' },
    { name: 'baseline_url', type: 'string', required: false, description: 'Unauthenticated/known-state URL for comparison' },
    { name: 'timeout_ms',   type: 'number', required: false, description: 'Per-oracle timeout ms', default: 30000 },
  ],
};

export const xsleaksProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const baselineUrl = params.baseline_url ? String(params.baseline_url) : url;
    const authCookie = params.auth_cookie ? String(params.auth_cookie) : undefined;
    const timeoutMs = Number(params.timeout_ms || 30000);

    if (!url) return { output: 'url required', parsed: { error: 'missing_url' } };

    let oracleTypes: string[] = ['window_length', 'error_event', 'timing', 'history_length'];
    try { if (params.oracle_types) oracleTypes = JSON.parse(String(params.oracle_types)); } catch { /* ignore */ }

    const script = `
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--ignore-certificate-errors'] });
  const results = [];

  // Helper: open page with optional cookie
  async function openPage(context, url) {
    const page = await context.newPage();
    await page.goto(url, { waitUntil: 'networkidle', timeout: 12000 }).catch(() => {});
    return page;
  }

  const targetUrl = '${url.replace(/'/g, "\\'")}';
  const baselineUrl = '${baselineUrl.replace(/'/g, "\\'")}';
  const oracleTypes = ${JSON.stringify(oracleTypes)};

  // Context 1: authenticated (with cookie)
  const authContext = await browser.newContext({
    ignoreHTTPSErrors: true,
    ${authCookie ? `extraHTTPHeaders: { 'Cookie': '${authCookie.replace(/'/g, "\\'")}' },` : ''}
  });

  // Context 2: unauthenticated
  const anonContext = await browser.newContext({ ignoreHTTPSErrors: true });

  // === Oracle: window.length (iframe frame count) ===
  if (oracleTypes.includes('window_length')) {
    try {
      const authPage = await authContext.newPage();
      await authPage.setContent('<iframe id="t" src="' + targetUrl + '"></iframe>');
      await authPage.waitForTimeout(3000);
      const authLen = await authPage.evaluate(() => {
        const f = document.getElementById('t') as HTMLIFrameElement;
        try { return f?.contentWindow?.length ?? -1; } catch { return -1; }
      }).catch(() => -1);

      const anonPage = await anonContext.newPage();
      await anonPage.setContent('<iframe id="t" src="' + targetUrl + '"></iframe>');
      await anonPage.waitForTimeout(3000);
      const anonLen = await anonPage.evaluate(() => {
        const f = document.getElementById('t') as HTMLIFrameElement;
        try { return f?.contentWindow?.length ?? -1; } catch { return -1; }
      }).catch(() => -1);

      results.push({
        oracle: 'window_length',
        auth_value: authLen,
        anon_value: anonLen,
        leaks: authLen !== anonLen && authLen >= 0 && anonLen >= 0,
        detail: 'window.length (iframe frame count) differs by auth state',
      });
      await authPage.close();
      await anonPage.close();
    } catch (e) {
      results.push({ oracle: 'window_length', error: String(e), leaks: false });
    }
  }

  // === Oracle: error vs load event ===
  if (oracleTypes.includes('error_event')) {
    try {
      for (const [label, ctx] of [['auth', authContext], ['anon', anonContext]]) {
        const page = await ctx.newPage();
        const outcome = await page.evaluate((tUrl) => {
          return new Promise((resolve) => {
            const img = document.createElement('img');
            img.onload = () => resolve('load');
            img.onerror = () => resolve('error');
            img.src = tUrl;
            setTimeout(() => resolve('timeout'), 8000);
          });
        }, targetUrl).catch(() => 'eval_error');
        results.push({ oracle: \`error_event_\${label}\`, outcome, leaks: false, detail: \`Resource fetch outcome for \${label} context\` });
        await page.close();
      }
      const authR = results.find(r => r.oracle === 'error_event_auth');
      const anonR = results.find(r => r.oracle === 'error_event_anon');
      if (authR && anonR && authR.outcome !== anonR.outcome) {
        results.push({ oracle: 'error_event', leaks: true, auth_value: authR.outcome, anon_value: anonR.outcome, detail: 'load/error event differs by auth state — binary oracle confirmed' });
      }
    } catch (e) {
      results.push({ oracle: 'error_event', error: String(e), leaks: false });
    }
  }

  // === Oracle: timing ===
  if (oracleTypes.includes('timing')) {
    try {
      const SAMPLES = 3;
      const authTimes = [];
      const anonTimes = [];
      for (let i = 0; i < SAMPLES; i++) {
        const t0 = Date.now();
        const p = await authContext.newPage();
        await p.goto(targetUrl, { waitUntil: 'networkidle', timeout: 10000 }).catch(() => {});
        authTimes.push(Date.now() - t0);
        await p.close();

        const t1 = Date.now();
        const p2 = await anonContext.newPage();
        await p2.goto(targetUrl, { waitUntil: 'networkidle', timeout: 10000 }).catch(() => {});
        anonTimes.push(Date.now() - t1);
        await p2.close();
      }
      const authAvg = authTimes.reduce((a,b)=>a+b,0)/SAMPLES;
      const anonAvg = anonTimes.reduce((a,b)=>a+b,0)/SAMPLES;
      const diff = Math.abs(authAvg - anonAvg);
      results.push({
        oracle: 'timing',
        auth_avg_ms: Math.round(authAvg),
        anon_avg_ms: Math.round(anonAvg),
        diff_ms: Math.round(diff),
        leaks: diff > 300,
        detail: diff > 300 ? 'Significant timing difference (>300ms) between auth/anon — timing oracle possible' : 'Timing difference within noise threshold',
      });
    } catch (e) {
      results.push({ oracle: 'timing', error: String(e), leaks: false });
    }
  }

  // === Oracle: history.length ===
  if (oracleTypes.includes('history_length')) {
    try {
      const authPage = await authContext.newPage();
      await authPage.goto(targetUrl, { waitUntil: 'networkidle', timeout: 10000 }).catch(() => {});
      const authHist = await authPage.evaluate(() => window.history.length).catch(() => -1);
      await authPage.close();

      const anonPage = await anonContext.newPage();
      await anonPage.goto(targetUrl, { waitUntil: 'networkidle', timeout: 10000 }).catch(() => {});
      const anonHist = await anonPage.evaluate(() => window.history.length).catch(() => -1);
      await anonPage.close();

      results.push({
        oracle: 'history_length',
        auth_value: authHist,
        anon_value: anonHist,
        leaks: authHist !== anonHist,
        detail: 'history.length differs — redirect chain reveals auth state',
      });
    } catch (e) {
      results.push({ oracle: 'history_length', error: String(e), leaks: false });
    }
  }

  await browser.close();
  console.log(JSON.stringify(results));
})().catch(e => { console.error(e.message); process.exit(1); });
`;

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs + 30000);
      const resp = await fetch(`${BROWSER_SESSION_URL}/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ script, timeout: timeoutMs }),
        signal: controller.signal,
      });
      clearTimeout(timer);

      const result = await resp.json() as { stdout?: string; stderr?: string };
      let probeResults: Array<{ oracle: string; leaks: boolean; auth_value?: unknown; anon_value?: unknown; detail?: string; error?: string }> = [];
      try { probeResults = JSON.parse(result.stdout || '[]'); } catch { /* ignore */ }

      const leaking = probeResults.filter(r => r.leaks);
      const lines = [
        `xsleaks_probe — ${oracleTypes.length} oracle types on ${url.substring(0, 80)}`,
        `Leaking oracles: ${leaking.length}/${probeResults.filter(r => !r.error).length}`,
        '─'.repeat(72),
      ];
      for (const r of probeResults) {
        const flag = r.leaks ? '⚡ LEAKS   ' : r.error ? '✗ ERR     ' : '  ·       ';
        const vals = r.auth_value !== undefined ? `  auth=${JSON.stringify(r.auth_value)}  anon=${JSON.stringify(r.anon_value)}` : '';
        lines.push(`  ${flag}  [${r.oracle.padEnd(20)}]${vals}`);
        if (r.detail) lines.push(`            ${r.detail}`);
        if (r.error) lines.push(`            Error: ${r.error.substring(0, 80)}`);
      }

      return {
        output: lines.join('\n'),
        parsed: { leaking_count: leaking.length, leaking, results: probeResults },
      };
    } catch (err) {
      return { output: `browser_session error: ${String(err)}`, parsed: { error: String(err) } };
    }
  },
};

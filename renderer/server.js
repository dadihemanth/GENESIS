// GENESIS chromium_renderer — headless Chromium service.
//
// Legacy single-shot API (Tier-2 · T6):
//   POST /render  { url, cookies?, headers?, wait_ms?, viewport_*?, timeout_ms? }
//     -> { screenshot_b64, dom, console_log, network_requests, final_url }
//
// Multi-step agentic-browser API (Tier-3 · T12):
//   POST /session/start        { session_id, viewport?, cookies?, headers? }
//   POST /session/step         { session_id, action, ... }
//       actions: goto | click | fill | press | wait | snapshot | eval_js
//   POST /session/close        { session_id }
//
// Every /session/step returns the same shape as /render (screenshot + dom +
// console + network + final_url) so the orchestrator can attach the screenshot
// to Claude's next turn on every step, not just the initial page load.
//
// Contexts are kept per session_id. Idle 5-minute eviction; hard 30-minute
// cap. An unknown session_id returns 404 so the AI can recover by calling
// session/start again.

const http = require('http');
const crypto = require('crypto');
const { chromium } = require('playwright');

const PORT = Number(process.env.PORT || 3301);
const MAX_BODY_BYTES = 128 * 1024;
const MAX_DOM_BYTES = 80 * 1024;
const MAX_CONSOLE_LINES = 50;
const MAX_NETWORK_ENTRIES = 80;
const SESSION_IDLE_MS = 5 * 60 * 1000;
const SESSION_HARD_MS = 30 * 60 * 1000;
const MAX_CONCURRENT_SESSIONS = 8;
const MAX_EVAL_JS_LEN = 4 * 1024;

let browserPromise = null;

function getBrowser() {
  if (!browserPromise) {
    browserPromise = chromium.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-dev-shm-usage'],
    }).catch((err) => {
      browserPromise = null;
      throw err;
    });
  }
  return browserPromise;
}

/** session registry keyed by session_id. Each entry holds the Playwright
 *  context, a reusable page, rolling log buffers, and timestamps. */
const SESSIONS = new Map();

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('request too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      try {
        const body = Buffer.concat(chunks).toString('utf-8');
        resolve(body ? JSON.parse(body) : {});
      } catch (err) { reject(err); }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function safeString(v, max = 500) {
  if (v == null) return '';
  const s = String(v);
  return s.length > max ? s.substring(0, max) : s;
}

function clamp(n, min, max, fallback) {
  const v = Number(n);
  if (!Number.isFinite(v)) return fallback;
  return Math.max(min, Math.min(max, v));
}

async function captureState(page) {
  let screenshotB64 = '';
  let dom = '';
  try {
    const buf = await page.screenshot({ type: 'png', fullPage: false });
    screenshotB64 = buf.toString('base64');
  } catch { /* ignore */ }
  try {
    const html = await page.content();
    dom = html.substring(0, MAX_DOM_BYTES);
  } catch { /* ignore */ }
  return { screenshot_b64: screenshotB64, dom, final_url: page.url() };
}

function attachPageListeners(page, store) {
  page.on('console', (msg) => {
    if (store.console_log.length >= MAX_CONSOLE_LINES) return;
    try {
      store.console_log.push({
        type: msg.type(),
        text: safeString(msg.text()),
      });
    } catch { /* ignore */ }
  });
  page.on('request', (req) => {
    if (store.network_requests.length >= MAX_NETWORK_ENTRIES) return;
    store.network_requests.push({
      url: safeString(req.url(), 600),
      method: req.method(),
      resource_type: req.resourceType(),
    });
  });
}

// ---------------------------------------------------------------------------
// Single-shot /render (backward-compatible with T6)
// ---------------------------------------------------------------------------

async function doRender(body) {
  const url = String(body.url || '');
  if (!url) return { error: 'url required' };

  const waitMs = clamp(body.wait_ms, 0, 10000, 1500);
  const timeoutMs = clamp(body.timeout_ms, 5000, 60000, 30000);
  const viewportWidth = clamp(body.viewport_width, 400, 2000, 1366);
  const viewportHeight = clamp(body.viewport_height, 400, 2000, 768);
  const extraHeaders = (body.headers && typeof body.headers === 'object') ? body.headers : {};
  const cookies = Array.isArray(body.cookies) ? body.cookies : [];

  let browser;
  try { browser = await getBrowser(); }
  catch (err) { return { error: `browser launch failed: ${err.message}` }; }

  const context = await browser.newContext({
    viewport: { width: viewportWidth, height: viewportHeight },
    userAgent: 'Mozilla/5.0 (GENESIS Chromium Renderer)',
    extraHTTPHeaders: extraHeaders,
    ignoreHTTPSErrors: true,
  });
  if (cookies.length > 0) {
    try { await context.addCookies(cookies); } catch { /* best effort */ }
  }
  const page = await context.newPage();
  const store = { console_log: [], network_requests: [] };
  attachPageListeners(page, store);

  const start = Date.now();
  let loadError = null;
  try {
    await page.goto(url, { timeout: timeoutMs, waitUntil: 'domcontentloaded' });
    if (waitMs > 0) await page.waitForTimeout(waitMs);
  } catch (err) {
    loadError = String(err);
  }

  const state = await captureState(page);
  const duration = Date.now() - start;

  try { await page.close(); } catch { /* ignore */ }
  try { await context.close(); } catch { /* ignore */ }

  return {
    ...state,
    load_error: loadError,
    duration_ms: duration,
    console_log: store.console_log,
    network_requests: store.network_requests,
    viewport: { width: viewportWidth, height: viewportHeight },
  };
}

// ---------------------------------------------------------------------------
// Multi-step session API (T12)
// ---------------------------------------------------------------------------

function evictStaleSessions() {
  const now = Date.now();
  for (const [sid, sess] of SESSIONS.entries()) {
    if (now - sess.last_used > SESSION_IDLE_MS || now - sess.created_at > SESSION_HARD_MS) {
      try { sess.page && sess.page.close(); } catch { /* ignore */ }
      try { sess.context && sess.context.close(); } catch { /* ignore */ }
      SESSIONS.delete(sid);
    }
  }
}

async function sessionStart(body) {
  evictStaleSessions();
  if (SESSIONS.size >= MAX_CONCURRENT_SESSIONS) {
    return { error: `too many open browser sessions (limit=${MAX_CONCURRENT_SESSIONS})` };
  }

  const session_id = String(body.session_id || crypto.randomBytes(8).toString('hex'));
  if (SESSIONS.has(session_id)) {
    return { ok: true, session_id, resumed: true };
  }

  const viewportWidth = clamp(body.viewport_width, 400, 2000, 1366);
  const viewportHeight = clamp(body.viewport_height, 400, 2000, 768);
  const extraHeaders = (body.headers && typeof body.headers === 'object') ? body.headers : {};
  const cookies = Array.isArray(body.cookies) ? body.cookies : [];
  const userAgent = safeString(body.user_agent, 300) ||
    'Mozilla/5.0 (GENESIS Chromium T12)';

  let browser;
  try { browser = await getBrowser(); }
  catch (err) { return { error: `browser launch failed: ${err.message}` }; }

  const context = await browser.newContext({
    viewport: { width: viewportWidth, height: viewportHeight },
    userAgent,
    extraHTTPHeaders: extraHeaders,
    ignoreHTTPSErrors: true,
  });
  if (cookies.length > 0) {
    try { await context.addCookies(cookies); } catch { /* best effort */ }
  }

  const page = await context.newPage();
  const store = { console_log: [], network_requests: [] };
  attachPageListeners(page, store);

  const now = Date.now();
  SESSIONS.set(session_id, {
    context,
    page,
    store,
    created_at: now,
    last_used: now,
    step_index: 0,
    viewport: { width: viewportWidth, height: viewportHeight },
  });

  return {
    ok: true,
    session_id,
    resumed: false,
    viewport: { width: viewportWidth, height: viewportHeight },
  };
}

async function sessionStep(body) {
  evictStaleSessions();
  const session_id = String(body.session_id || '');
  const sess = SESSIONS.get(session_id);
  if (!sess) return { status: 404, error: 'unknown session_id — call /session/start first' };

  sess.last_used = Date.now();
  const action = String(body.action || '').toLowerCase();
  const step_index = ++sess.step_index;
  const stepTimeoutMs = clamp(body.timeout_ms, 1000, 60000, 20000);
  const store = sess.store;
  const page = sess.page;

  // Reset per-step log views so each step's screenshot is paired with only
  // the logs it caused. Buffer consumers always see a *per-step* slice.
  const preConsoleLen = store.console_log.length;
  const preNetworkLen = store.network_requests.length;

  let action_error = null;
  let action_detail = {};

  try {
    if (action === 'goto') {
      const url = String(body.url || '');
      if (!url) throw new Error('goto requires url');
      const waitUntil = String(body.wait_until || 'domcontentloaded');
      await page.goto(url, { timeout: stepTimeoutMs, waitUntil });
      const waitMs = clamp(body.wait_ms, 0, 10000, 0);
      if (waitMs > 0) await page.waitForTimeout(waitMs);
      action_detail = { url };
    } else if (action === 'click') {
      const selector = String(body.selector || '');
      if (!selector) throw new Error('click requires selector');
      await page.click(selector, { timeout: stepTimeoutMs });
      action_detail = { selector };
    } else if (action === 'fill') {
      const selector = String(body.selector || '');
      const value = body.value == null ? '' : String(body.value);
      if (!selector) throw new Error('fill requires selector');
      await page.fill(selector, value, { timeout: stepTimeoutMs });
      if (body.submit) {
        await page.press(selector, 'Enter', { timeout: stepTimeoutMs });
      }
      action_detail = {
        selector,
        value_len: value.length,
        submitted: Boolean(body.submit),
      };
    } else if (action === 'press') {
      const selector = String(body.selector || 'body');
      const key = String(body.key || 'Enter');
      await page.press(selector, key, { timeout: stepTimeoutMs });
      action_detail = { selector, key };
    } else if (action === 'wait') {
      if (body.selector) {
        const state = String(body.state || 'visible');
        await page.waitForSelector(String(body.selector), { state, timeout: stepTimeoutMs });
        action_detail = { waited_for: body.selector, state };
      } else {
        const ms = clamp(body.ms, 0, 15000, 1000);
        await page.waitForTimeout(ms);
        action_detail = { waited_ms: ms };
      }
    } else if (action === 'snapshot') {
      // no-op; state is captured unconditionally below.
      action_detail = { noop: true };
    } else if (action === 'eval_js') {
      const code = String(body.code || '');
      if (!code) throw new Error('eval_js requires code');
      if (code.length > MAX_EVAL_JS_LEN) throw new Error(`eval_js too long (>${MAX_EVAL_JS_LEN})`);
      // Playwright's evaluate runs in the page's origin — this is intentional
      // for a pentest browser. The code runs inside the target's security
      // context; it cannot reach container internals.
      const result = await page.evaluate(code);
      let jsonResult;
      try { jsonResult = JSON.stringify(result).substring(0, 8 * 1024); }
      catch { jsonResult = safeString(String(result), 8 * 1024); }
      action_detail = { eval_result: jsonResult };
    } else {
      throw new Error(`unknown action: ${action}`);
    }
  } catch (err) {
    action_error = String(err.message || err);
  }

  const state = await captureState(page);

  return {
    step_index,
    action,
    action_error,
    action_detail,
    ...state,
    viewport: sess.viewport,
    console_log_delta: store.console_log.slice(preConsoleLen),
    network_delta: store.network_requests.slice(preNetworkLen),
  };
}

async function sessionClose(body) {
  const session_id = String(body.session_id || '');
  const sess = SESSIONS.get(session_id);
  if (!sess) return { ok: true, closed: false, reason: 'unknown session_id' };
  try { sess.page && await sess.page.close(); } catch { /* ignore */ }
  try { sess.context && await sess.context.close(); } catch { /* ignore */ }
  SESSIONS.delete(session_id);
  return { ok: true, closed: true, steps: sess.step_index };
}

// ---------------------------------------------------------------------------
// HTTP dispatch
// ---------------------------------------------------------------------------

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    return sendJson(res, 200, {
      ok: true,
      service: 'chromium_renderer',
      open_sessions: SESSIONS.size,
    });
  }
  if (req.method === 'POST' && req.url === '/render') {
    let body;
    try { body = await readJson(req); }
    catch (err) { return sendJson(res, 400, { error: `bad request: ${err.message}` }); }
    try {
      const result = await doRender(body);
      return sendJson(res, 200, result);
    } catch (err) {
      return sendJson(res, 500, { error: `render failed: ${err.message}` });
    }
  }
  if (req.method === 'POST' && req.url === '/session/start') {
    let body;
    try { body = await readJson(req); }
    catch (err) { return sendJson(res, 400, { error: `bad request: ${err.message}` }); }
    try {
      const r = await sessionStart(body);
      return sendJson(res, r.error ? 500 : 200, r);
    } catch (err) {
      return sendJson(res, 500, { error: `session start failed: ${err.message}` });
    }
  }
  if (req.method === 'POST' && req.url === '/session/step') {
    let body;
    try { body = await readJson(req); }
    catch (err) { return sendJson(res, 400, { error: `bad request: ${err.message}` }); }
    try {
      const r = await sessionStep(body);
      const status = r.status || 200;
      delete r.status;
      return sendJson(res, status, r);
    } catch (err) {
      return sendJson(res, 500, { error: `session step failed: ${err.message}` });
    }
  }
  if (req.method === 'POST' && req.url === '/session/close') {
    let body;
    try { body = await readJson(req); }
    catch (err) { return sendJson(res, 400, { error: `bad request: ${err.message}` }); }
    try {
      const r = await sessionClose(body);
      return sendJson(res, 200, r);
    } catch (err) {
      return sendJson(res, 500, { error: `session close failed: ${err.message}` });
    }
  }
  sendJson(res, 404, { error: 'not found' });
});

process.on('SIGTERM', async () => {
  try {
    for (const sess of SESSIONS.values()) {
      try { await sess.context.close(); } catch { /* ignore */ }
    }
    if (browserPromise) (await browserPromise).close();
  } catch { /* ignore */ }
  process.exit(0);
});

server.listen(PORT, () => {
  console.log(`[chromium_renderer] listening on 0.0.0.0:${PORT} (t12 multi-step)`);
});

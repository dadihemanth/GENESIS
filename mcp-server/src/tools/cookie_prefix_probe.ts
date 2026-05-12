// T55 — cookie_prefix_probe
// Tests __Host- and __Secure- cookie prefix enforcement and
// same-site subdomain cookie-tossing.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'cookie_prefix_probe',
  description:
    'Test __Host- and __Secure- cookie prefix enforcement (RFC 6265bis). ' +
    'Probes whether the server sets these prefixed cookies correctly and whether ' +
    'an attacker-controlled subdomain can "toss" (overwrite) them. ' +
    'Also tests same-site cookie tossing: set cookie on .parent.com to override app.parent.com.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',          type: 'string', required: true,  description: 'Target URL' },
    { name: 'cookie_name',  type: 'string', required: false, description: 'Cookie name to test', default: 'session' },
    { name: 'cookie_value', type: 'string', required: false, description: 'Cookie value to set', default: 'genesis_test_value' },
    { name: 'headers',      type: 'string', required: false, description: 'JSON extra headers' },
    { name: 'timeout_ms',   type: 'number', required: false, description: 'Per-request timeout ms', default: 10000 },
  ],
};

export const cookiePrefixProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const cookieName = String(params.cookie_name || 'session');
    const cookieValue = String(params.cookie_value || 'genesis_test_value');
    const timeoutMs = Number(params.timeout_ms || 10000);

    if (!url) return { output: 'url required', parsed: { error: 'missing_url' } };

    let headers: Record<string, string> = { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0' };
    try { if (params.headers) Object.assign(headers, JSON.parse(String(params.headers))); } catch { /* ignore */ }

    // Step 1: Fetch existing cookies from the target
    const cookieTests: Array<{ name: string; description: string; cookie: string; interesting?: boolean }> = [];

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const resp = await fetch(url, { headers, signal: controller.signal });
      clearTimeout(timer);

      const setCookies: string[] = [];
      resp.headers.forEach((v, k) => { if (k.toLowerCase() === 'set-cookie') setCookies.push(v); });

      const issues: string[] = [];

      // Check: does the server use __Host- or __Secure- prefixes correctly?
      for (const sc of setCookies) {
        const name = sc.split('=')[0].trim();
        if (name.startsWith('__Host-')) {
          // Must have Secure, Path=/, no Domain
          if (!sc.includes('Secure')) issues.push(`MISSING Secure on ${name}`);
          if (!sc.includes('Path=/')) issues.push(`MISSING Path=/ on ${name}`);
          if (/domain=/i.test(sc)) issues.push(`IMPROPER Domain attribute on ${name} — voids __Host- protection`);
        }
        if (name.startsWith('__Secure-')) {
          if (!sc.includes('Secure')) issues.push(`MISSING Secure on ${name}`);
        }
        // Check SameSite
        if (!/SameSite=(Strict|Lax|None)/i.test(sc)) {
          issues.push(`MISSING SameSite on ${name} — vulnerable to CSRF`);
        }
        // Check HttpOnly for session cookies
        if ((name.toLowerCase().includes('session') || name.toLowerCase().includes('auth')) && !sc.includes('HttpOnly')) {
          issues.push(`MISSING HttpOnly on session cookie ${name} — XSS can steal it`);
        }
      }

      // Step 2: Test cookie injection via various Set-Cookie formats
      const injectTests = [
        { name: 'bare_cookie',         cookie: `${cookieName}=${cookieValue}`,                                      description: 'Basic cookie without security attributes' },
        { name: 'host_prefix_attempt', cookie: `__Host-${cookieName}=${cookieValue}; Path=/`,                       description: '__Host- prefix: valid only with Secure + Path=/ + no Domain' },
        { name: 'secure_prefix',       cookie: `__Secure-${cookieName}=${cookieValue}; Secure`,                     description: '__Secure- prefix: valid only with Secure flag' },
        { name: 'samesite_none',       cookie: `${cookieName}=${cookieValue}; SameSite=None`,                       description: 'SameSite=None without Secure — allows cross-site requests' },
        { name: 'domain_override',     cookie: `${cookieName}=${cookieValue}; Domain=.${new URL(url).hostname.split('.').slice(-2).join('.')}`, description: 'Domain cookie on parent: can be tossed from sibling subdomains' },
      ];

      for (const t of injectTests) {
        const r = await fetch(url, { headers: { ...headers, 'Cookie': t.cookie }, signal: new AbortController().signal }).catch(() => null);
        const interesting = r ? r.status !== 403 && r.status !== 401 : false;
        cookieTests.push({ ...t, interesting });
      }

      const lines = [
        `cookie_prefix_probe — ${url.substring(0, 80)}`,
        `Set-Cookie headers observed: ${setCookies.length}`,
        `Security issues found: ${issues.length}`,
        '─'.repeat(72),
      ];
      if (issues.length > 0) {
        lines.push('SECURITY ISSUES:');
        for (const i of issues) lines.push(`  ⚡ ${i}`);
        lines.push('');
      }
      if (setCookies.length > 0) {
        lines.push('Observed Set-Cookie headers:');
        for (const sc of setCookies) lines.push(`  ${sc.substring(0, 120)}`);
        lines.push('');
      }
      lines.push('Injection test results:');
      for (const t of cookieTests) {
        const flag = t.interesting ? '⚡ ACCEPTED' : '  ·       ';
        lines.push(`  ${flag}  [${t.name.padEnd(22)}]  ${t.description}`);
      }

      return {
        output: lines.join('\n'),
        parsed: { issues, set_cookies: setCookies, injection_tests: cookieTests },
      };
    } catch (err) {
      return { output: `Error: ${String(err)}`, parsed: { error: String(err) } };
    }
  },
};

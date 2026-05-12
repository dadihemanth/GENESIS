import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'netexec',
  description: 'Windows/AD network enumeration — SMB shares, users, sessions, password spraying',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'target', type: 'string', required: true, description: 'Target IP, CIDR, or hostname' },
    { name: 'protocol', type: 'string', required: false, description: 'Protocol: smb, ssh, ftp, rdp, winrm, ldap', default: 'smb' },
    { name: 'username', type: 'string', required: false, description: 'Username', default: '' },
    { name: 'password', type: 'string', required: false, description: 'Password', default: '' },
    { name: 'action', type: 'string', required: false, description: 'Action: shares, users, sessions, disks, loggedon', default: 'shares' },
    { name: 'local_auth', type: 'boolean', required: false, description: 'Use local authentication', default: false },
  ],
};

interface NetexecHost {
  ip: string;
  hostname: string;
  os: string;
  signing: boolean;
  smb_v1: boolean;
}

interface NetexecParsed {
  hosts: NetexecHost[];
  shares: string[];
  users: string[];
  sessions: string[];
  authenticated: boolean;
}

function parseNetexecOutput(output: string): NetexecParsed {
  const result: NetexecParsed = { hosts: [], shares: [], users: [], sessions: [], authenticated: false };

  for (const line of output.split('\n')) {
    if (/\[+\]/.test(line)) result.authenticated = true;

    // Host line: SMB  192.168.1.1  445  HOSTNAME  [*] Windows 10 ...
    const hostMatch = line.match(/SMB\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+(\S+)\s+\[\*\]\s+(.+)/);
    if (hostMatch) {
      result.hosts.push({
        ip: hostMatch[1],
        hostname: hostMatch[2],
        os: hostMatch[3].split('(')[0].trim(),
        signing: /signing:True/i.test(line),
        smb_v1: /SMBv1:True/i.test(line),
      });
    }

    // Share lines
    const shareMatch = line.match(/SHARE\s+(\S+)\s+(?:READ|WRITE|NO ACCESS)/i);
    if (shareMatch && !result.shares.includes(shareMatch[1])) result.shares.push(shareMatch[1]);

    // User lines
    const userMatch = line.match(/user:\s*(\S+)/i);
    if (userMatch && !result.users.includes(userMatch[1])) result.users.push(userMatch[1]);

    // Session lines
    const sessionMatch = line.match(/session.*?(\S+@\S+)/i);
    if (sessionMatch) result.sessions.push(sessionMatch[1]);
  }

  return result;
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const target = String(params['target'] || '');
  const protocol = String(params['protocol'] || 'smb');
  const username = String(params['username'] || '');
  const password = String(params['password'] || '');
  const action = String(params['action'] || 'shares');
  const localAuth = Boolean(params['local_auth']);

  const args = [protocol, target];
  if (username) { args.push('-u', username); args.push('-p', password); }
  if (localAuth) args.push('--local-auth');
  args.push(`--${action}`);

  const command = `netexec ${args.join(' ')}`;
  const startTime = Date.now();

  const available = await exec.isAvailable('netexec');
  if (!available) {
    return { success: false, tool: 'netexec', output: '', parsed: {}, duration: (Date.now() - startTime) / 1000, command, error: "Tool 'netexec' not found." };
  }

  const result = await exec.execute('netexec', args, 120000);
  const duration = result.duration;
  let output = result.stdout + (result.stderr ? '\n' + result.stderr : '');
  if (output.length > 50000) output = output.substring(0, 50000) + '\n[TRUNCATED]';

  if (result.timedOut) {
    return { success: false, tool: 'netexec', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  const parsed = parseNetexecOutput(output);

  return {
    success: result.exitCode === 0,
    tool: 'netexec',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: result.exitCode !== 0 ? result.stderr.trim() || null : null,
  };
}

export const netexecTool = { definition, execute };

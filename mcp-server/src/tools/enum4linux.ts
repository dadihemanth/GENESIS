import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'enum4linux',
  description: 'SMB/NetBIOS enumeration — users, shares, groups, policies, OS info from Windows/Samba targets',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'target', type: 'string', required: true, description: 'Target IP or hostname' },
    { name: 'username', type: 'string', required: false, description: 'Username for authenticated scan', default: '' },
    { name: 'password', type: 'string', required: false, description: 'Password for authenticated scan', default: '' },
    { name: 'shares', type: 'boolean', required: false, description: 'Enumerate shares', default: true },
    { name: 'users', type: 'boolean', required: false, description: 'Enumerate users', default: true },
    { name: 'groups', type: 'boolean', required: false, description: 'Enumerate groups', default: true },
  ],
};

interface Enum4linuxParsed {
  os_info: string;
  domain: string;
  workgroup: string;
  users: string[];
  shares: Array<{ name: string; type: string; comment: string }>;
  groups: string[];
  password_policy: Record<string, string>;
}

function parseEnum4linuxOutput(output: string): Enum4linuxParsed {
  const result: Enum4linuxParsed = {
    os_info: '',
    domain: '',
    workgroup: '',
    users: [],
    shares: [],
    groups: [],
    password_policy: {},
  };

  const lines = output.split('\n');
  for (const line of lines) {
    const osMatch = line.match(/OS:\s*(.+)/);
    if (osMatch) result.os_info = osMatch[1].trim();

    const domainMatch = line.match(/Domain:\s*(.+)/);
    if (domainMatch) result.domain = domainMatch[1].trim();

    const workgroupMatch = line.match(/Workgroup:\s*(.+)/i);
    if (workgroupMatch) result.workgroup = workgroupMatch[1].trim();

    // Users: format "user: [username] rid: [rid]"
    const userMatch = line.match(/user:\s*\[([^\]]+)\]/i);
    if (userMatch && !result.users.includes(userMatch[1])) result.users.push(userMatch[1]);

    // Shares
    const shareMatch = line.match(/\s+(\S+)\s+(Disk|IPC|Printer)\s+(.*)/);
    if (shareMatch) {
      result.shares.push({ name: shareMatch[1], type: shareMatch[2], comment: shareMatch[3].trim() });
    }

    // Groups
    const groupMatch = line.match(/group:\s*\[([^\]]+)\]/i);
    if (groupMatch && !result.groups.includes(groupMatch[1])) result.groups.push(groupMatch[1]);

    // Password policy
    const pwdMatch = line.match(/^\s+(.+?):\s+(.+)$/);
    if (pwdMatch && /password|minimum|lockout|complexity/i.test(pwdMatch[1])) {
      result.password_policy[pwdMatch[1].trim()] = pwdMatch[2].trim();
    }
  }

  return result;
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const target = String(params['target'] || '');
  const username = String(params['username'] || '');
  const password = String(params['password'] || '');

  // enum4linux-ng uses different flags than original enum4linux
  const args: string[] = [target, '-A', '-oJ', `/tmp/enum4linux_${Date.now()}`];
  if (username) { args.push('-u', username); }
  if (password) { args.push('-p', password); }

  const command = `enum4linux-ng ${args.join(' ')}`;
  const startTime = Date.now();

  const available = await exec.isAvailable('enum4linux-ng');
  if (!available) {
    return { success: false, tool: 'enum4linux', output: '', parsed: {}, duration: (Date.now() - startTime) / 1000, command, error: "Tool 'enum4linux-ng' not found." };
  }

  const result = await exec.execute('enum4linux-ng', args, 120000);
  const duration = result.duration;
  let output = result.stdout + (result.stderr ? '\n' + result.stderr : '');
  if (output.length > 50000) output = output.substring(0, 50000) + '\n[TRUNCATED]';

  if (result.timedOut) {
    return { success: false, tool: 'enum4linux', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  const parsed = parseEnum4linuxOutput(output);

  return {
    success: result.exitCode === 0,
    tool: 'enum4linux',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: result.exitCode !== 0 ? result.stderr.trim() || null : null,
  };
}

export const enum4linuxTool = { definition, execute };

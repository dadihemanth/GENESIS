import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'kerbrute',
  description: 'Kerberos enumeration and brute-force — user enumeration, password spray, brute-force against AD',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'mode', type: 'string', required: true, description: 'Mode: userenum, bruteuser, passwordspray, or bruteforce' },
    { name: 'domain', type: 'string', required: true, description: 'Active Directory domain (e.g. corp.local)' },
    { name: 'dc', type: 'string', required: true, description: 'Domain controller IP or hostname' },
    { name: 'username', type: 'string', required: false, description: 'Single username (for bruteuser)', default: '' },
    { name: 'wordlist', type: 'string', required: false, description: 'Path to username or password wordlist', default: '/usr/share/wordlists/rockyou.txt' },
    { name: 'threads', type: 'number', required: false, description: 'Concurrent threads', default: 10 },
  ],
};

const ALLOWED_MODES = new Set(['userenum', 'bruteuser', 'passwordspray', 'bruteforce']);

interface KerbruteResult {
  valid_users: string[];
  valid_credentials: Array<{ username: string; password: string }>;
  locked_accounts: string[];
  total_tested: number;
}

function parseKerbruteOutput(output: string): KerbruteResult {
  const valid_users: string[] = [];
  const valid_credentials: Array<{ username: string; password: string }> = [];
  const locked_accounts: string[] = [];
  let total_tested = 0;

  for (const line of output.split('\n')) {
    const trimmed = line.trim();

    // VALID USERNAME: user@domain
    const validUserMatch = trimmed.match(/VALID USERNAME:\s*(.+)/i);
    if (validUserMatch) valid_users.push(validUserMatch[1].trim());

    // VALID LOGIN: user:password
    const validLoginMatch = trimmed.match(/VALID LOGIN:\s*([^:]+):(.+)/i);
    if (validLoginMatch) {
      valid_credentials.push({ username: validLoginMatch[1].trim(), password: validLoginMatch[2].trim() });
    }

    // LOCKED ACCOUNT: user
    const lockedMatch = trimmed.match(/LOCKED ACCOUNT:\s*(.+)/i);
    if (lockedMatch) locked_accounts.push(lockedMatch[1].trim());

    // Done! Tested X logins
    const testedMatch = trimmed.match(/Tested (\d+)/i);
    if (testedMatch) total_tested = parseInt(testedMatch[1]);
  }

  return { valid_users, valid_credentials, locked_accounts, total_tested };
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const mode = String(params['mode'] || '');
  const domain = String(params['domain'] || '');
  const dc = String(params['dc'] || '');
  const username = String(params['username'] || '');
  const wordlist = String(params['wordlist'] || '/usr/share/wordlists/rockyou.txt');
  const threads = Number(params['threads'] || 10);

  const startTime = Date.now();

  if (!ALLOWED_MODES.has(mode)) {
    return { success: false, tool: 'kerbrute', output: '', parsed: {}, duration: 0, command: '', error: `Mode '${mode}' not allowed. Use: ${[...ALLOWED_MODES].join(', ')}` };
  }

  const available = await exec.isAvailable('kerbrute');
  if (!available) {
    return { success: false, tool: 'kerbrute', output: '', parsed: {}, duration: 0, command: '', error: "Tool 'kerbrute' not found." };
  }

  const args = [mode, '--dc', dc, '--domain', domain, '--threads', String(threads)];

  if (mode === 'bruteuser' && username) {
    args.push('--username', username);
  }
  args.push(wordlist);

  const command = `kerbrute ${args.join(' ')}`;
  const result = await exec.execute('kerbrute', args, 300000);
  const duration = result.duration;

  let output = result.stdout + (result.stderr ? '\n' + result.stderr : '');
  if (output.length > 50000) output = output.substring(0, 50000) + '\n[TRUNCATED]';

  if (result.timedOut) {
    return { success: false, tool: 'kerbrute', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  const parsed = parseKerbruteOutput(result.stdout);

  return {
    success: result.exitCode === 0,
    tool: 'kerbrute',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: result.exitCode !== 0 ? result.stderr.trim() || null : null,
  };
}

export const kerbrute = { definition, execute };

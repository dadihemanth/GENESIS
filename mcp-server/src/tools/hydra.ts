import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'hydra',
  description: 'Online password brute-forcing tool',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'target', type: 'string', required: true, description: 'Target host or IP' },
    { name: 'service', type: 'string', required: false, description: 'Service to attack (ssh, ftp, http-post-form, etc.)', default: 'ssh' },
    { name: 'username', type: 'string', required: false, description: 'Username to try', default: 'admin' },
    { name: 'wordlist', type: 'string', required: false, description: 'Password wordlist path', default: '/usr/share/wordlists/rockyou.txt' },
  ],
};

interface HydraCredential {
  username: string;
  password: string;
  service: string;
}

interface HydraParsed {
  found: boolean;
  credentials: HydraCredential[];
}

function parseHydraOutput(output: string, service: string): HydraParsed {
  const credentials: HydraCredential[] = [];
  let found = false;

  const lines = output.split('\n');
  // Hydra success lines look like: [22][ssh] host: 192.168.1.1   login: admin   password: secret
  const foundRegex = /\[\d+\]\[(\S+)\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)/i;
  const dataFoundRegex = /\[DATA\]\s+(?:attack|password).*found/i;

  for (const line of lines) {
    if (dataFoundRegex.test(line)) found = true;
    const match = line.match(foundRegex);
    if (match) {
      found = true;
      credentials.push({
        service: match[1],
        username: match[3],
        password: match[4],
      });
    }
  }

  return { found, credentials };
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const target = String(params['target'] || '');
  const service = String(params['service'] || 'ssh');
  const username = String(params['username'] || 'admin');
  const wordlist = String(params['wordlist'] || '/usr/share/wordlists/rockyou.txt');

  // Safety: stop on first found, 4 threads, limit via head on wordlist not possible with spawn
  // We use -f (stop on first), -t 4 threads
  const args: string[] = [
    '-l', username,
    '-P', wordlist,
    '-t', '4',
    '-f',           // Stop after first valid credentials found
    target,
    service,
  ];

  const command = `hydra ${args.join(' ')}`;
  const startTime = Date.now();

  const available = await exec.isAvailable('hydra');
  if (!available) {
    return {
      success: false,
      tool: 'hydra',
      output: '',
      parsed: {},
      duration: (Date.now() - startTime) / 1000,
      command,
      error: "Tool 'hydra' not found. Install it first.",
    };
  }

  const result = await exec.execute('hydra', args, 600000);
  const duration = result.duration;
  let output = result.stdout + (result.stderr ? '\n' + result.stderr : '');

  if (output.length > 50000) {
    output = output.substring(0, 50000) + '\n[OUTPUT TRUNCATED]';
  }

  if (result.timedOut) {
    return { success: false, tool: 'hydra', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  const parsed = parseHydraOutput(result.stdout + result.stderr, service);

  return {
    success: result.exitCode === 0,
    tool: 'hydra',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: result.exitCode !== 0 && !parsed.found ? result.stderr.trim() || null : null,
  };
}

export const hydraTool = { definition, execute };

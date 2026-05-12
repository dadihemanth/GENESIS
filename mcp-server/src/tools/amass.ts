import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'amass',
  description: 'Deep subdomain enumeration using passive DNS, certificate logs, and APIs',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'domain', type: 'string', required: true, description: 'Target domain' },
    { name: 'passive', type: 'boolean', required: false, description: 'Passive mode only (no active DNS)', default: true },
    { name: 'timeout', type: 'number', required: false, description: 'Timeout in minutes', default: 5 },
  ],
};

interface AmassParsed {
  subdomains: string[];
  ips: string[];
  total: number;
}

function parseAmassOutput(output: string): AmassParsed {
  const subdomains: Set<string> = new Set();
  const ips: Set<string> = new Set();

  for (const line of output.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    // Format: subdomain.example.com addresses: 1.2.3.4
    const addrMatch = trimmed.match(/^([\w.-]+\.[a-z]{2,})\s+addresses:\s+([\d.,\s]+)/i);
    if (addrMatch) {
      subdomains.add(addrMatch[1]);
      addrMatch[2].split(',').forEach(ip => {
        const cleanIp = ip.trim();
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(cleanIp)) ips.add(cleanIp);
      });
      continue;
    }

    // Plain subdomain line
    if (/^[\w.-]+\.[a-z]{2,}$/.test(trimmed)) subdomains.add(trimmed);
  }

  return { subdomains: [...subdomains], ips: [...ips], total: subdomains.size };
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const domain = String(params['domain'] || '');
  const passive = params['passive'] !== false;
  const timeout = Number(params['timeout'] || 5);

  const args = ['enum', '-d', domain, '-timeout', String(timeout)];
  if (passive) args.push('-passive');

  const command = `amass ${args.join(' ')}`;
  const startTime = Date.now();

  const available = await exec.isAvailable('amass');
  if (!available) {
    return { success: false, tool: 'amass', output: '', parsed: {}, duration: (Date.now() - startTime) / 1000, command, error: "Tool 'amass' not found." };
  }

  const result = await exec.execute('amass', args, (timeout + 1) * 60000);
  const duration = result.duration;
  let output = result.stdout + (result.stderr ? '\n' + result.stderr : '');
  if (output.length > 50000) output = output.substring(0, 50000) + '\n[TRUNCATED]';

  if (result.timedOut) {
    return { success: false, tool: 'amass', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  const parsed = parseAmassOutput(result.stdout);

  return {
    success: result.exitCode === 0 || parsed.total > 0,
    tool: 'amass',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: result.exitCode !== 0 && parsed.total === 0 ? result.stderr.trim() || null : null,
  };
}

export const amassTool = { definition, execute };

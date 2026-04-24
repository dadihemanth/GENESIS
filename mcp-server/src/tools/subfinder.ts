import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'subfinder',
  description: 'Subdomain discovery tool using passive sources',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'domain', type: 'string', required: true, description: 'Target domain name' },
    { name: 'timeout', type: 'number', required: false, description: 'Timeout in seconds', default: 60 },
  ],
};

interface SubfinderParsed {
  subdomains: string[];
  count: number;
}

function parseSubfinderOutput(output: string): SubfinderParsed {
  const lines = output
    .split('\n')
    .map(l => l.trim())
    .filter(l => l.length > 0 && !l.startsWith('[') && !l.startsWith('_'));

  // Filter to only include valid-looking subdomain entries
  const subdomains = lines.filter(l => /^[a-zA-Z0-9.\-_]+\.[a-zA-Z]{2,}$/.test(l));

  return { subdomains, count: subdomains.length };
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const domain = String(params['domain'] || '');
  const timeout = Number(params['timeout'] || 60);

  const args = ['-d', domain, '-silent', '-timeout', String(timeout), '-all'];
  const command = `subfinder ${args.join(' ')}`;
  const startTime = Date.now();

  const available = await exec.isAvailable('subfinder');
  if (!available) {
    return {
      success: false,
      tool: 'subfinder',
      output: '',
      parsed: {},
      duration: (Date.now() - startTime) / 1000,
      command,
      error: "Tool 'subfinder' not found. Install it first.",
    };
  }

  const result = await exec.execute('subfinder', args, (timeout + 30) * 1000);
  const duration = result.duration;
  let output = result.stdout + (result.stderr ? '\n' + result.stderr : '');

  if (output.length > 50000) {
    output = output.substring(0, 50000) + '\n[OUTPUT TRUNCATED]';
  }

  if (result.timedOut) {
    return { success: false, tool: 'subfinder', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  const parsed = parseSubfinderOutput(result.stdout);

  return {
    success: result.exitCode === 0,
    tool: 'subfinder',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: result.exitCode !== 0 ? result.stderr.trim() || null : null,
  };
}

export const subfinderTool = { definition, execute };

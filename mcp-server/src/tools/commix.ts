import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'commix',
  description: 'OS command injection testing — automated detection and exploitation of command injection vulnerabilities',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'url', type: 'string', required: true, description: 'Target URL (e.g. http://target/page?param=value)' },
    { name: 'data', type: 'string', required: false, description: 'POST data string (e.g. "user=admin&pass=test")', default: '' },
    { name: 'cookie', type: 'string', required: false, description: 'HTTP cookie header value', default: '' },
    { name: 'level', type: 'number', required: false, description: 'Test level 1-3 (1=default, 3=thorough)', default: 1 },
    { name: 'technique', type: 'string', required: false, description: 'Injection technique: classic, timebased, fileBased, or all', default: 'all' },
  ],
};

interface CommixInjection {
  parameter: string;
  technique: string;
  payload: string;
}

interface CommixParsed {
  vulnerable: boolean;
  injections: CommixInjection[];
  os_info: string;
}

function parseCommixOutput(output: string): CommixParsed {
  const injections: CommixInjection[] = [];
  let vulnerable = false;
  let os_info = '';

  for (const line of output.split('\n')) {
    const trimmed = line.trim();

    if (/vulnerable/i.test(trimmed) || /command injection/i.test(trimmed)) {
      vulnerable = true;
    }

    const paramMatch = trimmed.match(/parameter\s+'([^']+)'/i);
    const techniqueMatch = trimmed.match(/technique:\s*(.+)/i);
    const payloadMatch = trimmed.match(/payload:\s*(.+)/i);

    if (paramMatch && techniqueMatch) {
      injections.push({
        parameter: paramMatch[1],
        technique: techniqueMatch[1].trim(),
        payload: payloadMatch ? payloadMatch[1].trim() : '',
      });
    }

    const osMatch = trimmed.match(/OS:\s*(.+)/i);
    if (osMatch) os_info = osMatch[1].trim();
  }

  return { vulnerable, injections, os_info };
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const url = String(params['url'] || '');
  const data = String(params['data'] || '');
  const cookie = String(params['cookie'] || '');
  const level = Number(params['level'] || 1);
  const technique = String(params['technique'] || 'all');

  const startTime = Date.now();

  const available = await exec.isAvailable('commix');
  if (!available) {
    return { success: false, tool: 'commix', output: '', parsed: {}, duration: 0, command: '', error: "Tool 'commix' not found." };
  }

  const args = ['--url', url, '--level', String(level), '--batch', '--no-logging'];

  if (data) args.push('--data', data);
  if (cookie) args.push('--cookie', cookie);
  if (technique !== 'all') args.push('--technique', technique);

  const command = `commix ${args.join(' ')}`;
  const result = await exec.execute('commix', args, 180000);
  const duration = result.duration;

  let output = result.stdout + (result.stderr ? '\n' + result.stderr : '');
  if (output.length > 50000) output = output.substring(0, 50000) + '\n[TRUNCATED]';

  if (result.timedOut) {
    return { success: false, tool: 'commix', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  const parsed = parseCommixOutput(result.stdout);

  return {
    success: result.exitCode === 0,
    tool: 'commix',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: result.exitCode !== 0 ? result.stderr.trim() || null : null,
  };
}

export const commixTool = { definition, execute };

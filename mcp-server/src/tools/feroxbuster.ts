import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'feroxbuster',
  description: 'Recursive web directory and file brute-forcer (fast Rust implementation)',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'url', type: 'string', required: true, description: 'Target URL' },
    { name: 'wordlist', type: 'string', required: false, description: 'Path to wordlist', default: '/usr/share/wordlists/dirb/common.txt' },
    { name: 'depth', type: 'number', required: false, description: 'Recursion depth', default: 2 },
    { name: 'threads', type: 'number', required: false, description: 'Concurrent threads', default: 50 },
    { name: 'extensions', type: 'string', required: false, description: 'Comma-separated extensions to check', default: 'php,html,js,txt' },
    { name: 'filter_codes', type: 'string', required: false, description: 'HTTP codes to filter (hide)', default: '404,403' },
  ],
};

interface FeroxEntry {
  url: string;
  status: number;
  size: number;
  words: number;
  lines: number;
}

interface FeroxbusterParsed {
  found: FeroxEntry[];
  total_found: number;
}

function parseFeroxOutput(output: string): FeroxbusterParsed {
  const found: FeroxEntry[] = [];
  const lineRegex = /^(\d{3})\s+\S+\s+(\d+)l\s+(\d+)w\s+(\d+)c\s+(https?:\/\/\S+)/;
  for (const line of output.split('\n')) {
    const m = line.match(lineRegex);
    if (m) {
      found.push({ status: parseInt(m[1]), lines: parseInt(m[2]), words: parseInt(m[3]), size: parseInt(m[4]), url: m[5] });
    }
  }
  return { found, total_found: found.length };
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const url = String(params['url'] || '');
  const wordlist = String(params['wordlist'] || '/usr/share/wordlists/dirb/common.txt');
  const depth = Number(params['depth'] || 2);
  const threads = Number(params['threads'] || 50);
  const extensions = String(params['extensions'] || 'php,html,js,txt');
  const filterCodes = String(params['filter_codes'] || '404,403');

  const args = [
    '--url', url,
    '--wordlist', wordlist,
    '--depth', String(depth),
    '--threads', String(threads),
    '--extensions', extensions,
    '--filter-status', filterCodes,
    '--no-state',
    '--quiet',
  ];

  const command = `feroxbuster ${args.join(' ')}`;
  const startTime = Date.now();

  const available = await exec.isAvailable('feroxbuster');
  if (!available) {
    return { success: false, tool: 'feroxbuster', output: '', parsed: {}, duration: (Date.now() - startTime) / 1000, command, error: "Tool 'feroxbuster' not found." };
  }

  const result = await exec.execute('feroxbuster', args, 300000);
  const duration = result.duration;
  let output = result.stdout + (result.stderr ? '\n' + result.stderr : '');
  if (output.length > 50000) output = output.substring(0, 50000) + '\n[TRUNCATED]';

  if (result.timedOut) {
    return { success: false, tool: 'feroxbuster', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  const parsed = parseFeroxOutput(result.stdout);

  return {
    success: result.exitCode === 0 || parsed.total_found > 0,
    tool: 'feroxbuster',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: result.exitCode !== 0 && parsed.total_found === 0 ? result.stderr.trim() || null : null,
  };
}

export const feroxbusterTool = { definition, execute };

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'ffuf',
  description: 'Fast web fuzzer for directory, endpoint, and parameter discovery',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'url', type: 'string', required: true, description: 'Target URL with FUZZ keyword (e.g. http://host/FUZZ)' },
    { name: 'wordlist', type: 'string', required: false, description: 'Path to wordlist', default: '/usr/share/wordlists/dirb/common.txt' },
    { name: 'extensions', type: 'string', required: false, description: 'Comma-separated extensions (e.g. php,html)', default: '' },
    { name: 'threads', type: 'number', required: false, description: 'Concurrent threads', default: 40 },
    { name: 'filter_codes', type: 'string', required: false, description: 'HTTP status codes to filter out (e.g. 404,403)', default: '404' },
    { name: 'timeout', type: 'number', required: false, description: 'Request timeout in seconds', default: 10 },
  ],
};

interface FfufResult {
  url: string;
  status: number;
  length: number;
  words: number;
  lines: number;
}

interface FfufParsed {
  results: FfufResult[];
  total_found: number;
}

function parseFfufJson(raw: string): FfufParsed {
  const results: FfufResult[] = [];
  try {
    const data = JSON.parse(raw);
    for (const r of data?.results ?? []) {
      results.push({
        url: r.url ?? '',
        status: r.status ?? 0,
        length: r.length ?? 0,
        words: r.words ?? 0,
        lines: r.lines ?? 0,
      });
    }
  } catch {
    // ignore
  }
  return { results, total_found: results.length };
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const url = String(params['url'] || '');
  const wordlist = String(params['wordlist'] || '/usr/share/wordlists/dirb/common.txt');
  const extensions = String(params['extensions'] || '');
  const threads = Number(params['threads'] || 40);
  const filterCodes = String(params['filter_codes'] || '404');
  const timeout = Number(params['timeout'] || 10);
  const outFile = `/tmp/ffuf_${Date.now()}.json`;

  const args = [
    '-u', url,
    '-w', wordlist,
    '-t', String(threads),
    '-timeout', String(timeout),
    '-fc', filterCodes,
    '-o', outFile,
    '-of', 'json',
    '-s',
  ];

  if (extensions) {
    args.push('-e', extensions.startsWith('.') ? extensions : `.${extensions.replace(/,/g, ',.')}`);
  }

  const command = `ffuf ${args.join(' ')}`;
  const startTime = Date.now();

  const available = await exec.isAvailable('ffuf');
  if (!available) {
    return { success: false, tool: 'ffuf', output: '', parsed: {}, duration: (Date.now() - startTime) / 1000, command, error: "Tool 'ffuf' not found." };
  }

  const result = await exec.execute('ffuf', args, 300000);
  const duration = result.duration;
  let output = result.stdout + (result.stderr ? '\n' + result.stderr : '');
  if (output.length > 50000) output = output.substring(0, 50000) + '\n[TRUNCATED]';

  if (result.timedOut) {
    return { success: false, tool: 'ffuf', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  let parsed: FfufParsed = { results: [], total_found: 0 };
  try {
    const { readFileSync, unlinkSync, existsSync } = await import('fs');
    if (existsSync(outFile)) {
      parsed = parseFfufJson(readFileSync(outFile, 'utf-8'));
      unlinkSync(outFile);
    }
  } catch { /* ignore */ }

  return {
    success: result.exitCode === 0 || parsed.total_found > 0,
    tool: 'ffuf',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: result.exitCode !== 0 && parsed.total_found === 0 ? result.stderr.trim() || null : null,
  };
}

export const ffufTool = { definition, execute };

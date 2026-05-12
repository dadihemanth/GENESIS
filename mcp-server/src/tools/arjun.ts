import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'arjun',
  description: 'HTTP parameter discovery — finds hidden GET/POST parameters in web applications',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'url', type: 'string', required: true, description: 'Target URL' },
    { name: 'method', type: 'string', required: false, description: 'HTTP method: GET or POST', default: 'GET' },
    { name: 'rate_limit', type: 'number', required: false, description: 'Max requests per second', default: 50 },
    { name: 'wordlist', type: 'string', required: false, description: 'Custom parameter wordlist path (uses built-in if omitted)', default: '' },
  ],
};

interface ArjunParsed {
  parameters: string[];
  total_found: number;
}

function parseArjunOutput(output: string): ArjunParsed {
  const parameters: string[] = [];

  for (const line of output.split('\n')) {
    const trimmed = line.trim();

    // Arjun logs: "[+] parameter_name"  or  "parameter_name" in its JSON output
    const paramMatch = trimmed.match(/\[\+\]\s+(.+)/);
    if (paramMatch) parameters.push(paramMatch[1].trim());

    // Try JSON output from -oJ
    try {
      const data = JSON.parse(trimmed);
      if (Array.isArray(data)) {
        for (const p of data) {
          if (typeof p === 'string' && !parameters.includes(p)) parameters.push(p);
        }
      }
    } catch { /* skip non-JSON */ }
  }

  return { parameters, total_found: parameters.length };
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const url = String(params['url'] || '');
  const method = String(params['method'] || 'GET').toUpperCase();
  const rateLimit = Number(params['rate_limit'] || 50);
  const wordlist = String(params['wordlist'] || '');

  const startTime = Date.now();

  const available = await exec.isAvailable('arjun');
  if (!available) {
    return { success: false, tool: 'arjun', output: '', parsed: {}, duration: 0, command: '', error: "Tool 'arjun' not found." };
  }

  const outFile = `/tmp/arjun_${Date.now()}.json`;
  const args = ['-u', url, '-m', method, '--rate-limit', String(rateLimit), '-oJ', outFile];
  if (wordlist) args.push('-w', wordlist);

  const command = `arjun ${args.join(' ')}`;
  const result = await exec.execute('arjun', args, 300000);
  const duration = result.duration;

  let output = result.stdout + (result.stderr ? '\n' + result.stderr : '');
  if (output.length > 30000) output = output.substring(0, 30000) + '\n[TRUNCATED]';

  if (result.timedOut) {
    return { success: false, tool: 'arjun', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  let parsed = parseArjunOutput(result.stdout);

  // Also try to read JSON output file
  try {
    const { readFileSync, unlinkSync, existsSync } = await import('fs');
    if (existsSync(outFile)) {
      const raw = readFileSync(outFile, 'utf-8');
      const data = JSON.parse(raw);
      // Arjun JSON: { "url": [...params] }
      for (const params_arr of Object.values(data)) {
        if (Array.isArray(params_arr)) {
          for (const p of params_arr) {
            if (typeof p === 'string' && !parsed.parameters.includes(p)) {
              parsed.parameters.push(p);
            }
          }
        }
      }
      parsed.total_found = parsed.parameters.length;
      unlinkSync(outFile);
    }
  } catch { /* ignore */ }

  return {
    success: result.exitCode === 0,
    tool: 'arjun',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: result.exitCode !== 0 ? result.stderr.trim() || null : null,
  };
}

export const arjunTool = { definition, execute };

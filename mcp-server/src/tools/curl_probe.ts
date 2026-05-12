import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'curl_probe',
  description: 'HTTP probing tool for analyzing web responses and SSL info',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'url', type: 'string', required: true, description: 'Target URL' },
    { name: 'method', type: 'string', required: false, description: 'HTTP method', default: 'GET' },
    { name: 'headers', type: 'array', required: false, description: 'Additional headers as ["Key: Value"]', default: [] },
    { name: 'timeout', type: 'number', required: false, description: 'Request timeout in seconds', default: 30 },
    { name: 'follow_redirects', type: 'boolean', required: false, description: 'Follow HTTP redirects', default: true },
  ],
};

interface CurlProbeParsed {
  status_code: number | null;
  headers: Record<string, string>;
  body_preview: string;
  redirect_chain: string[];
  ssl_info: Record<string, string>;
}

function parseCurlVerbose(stdout: string, stderr: string): CurlProbeParsed {
  const headers: Record<string, string> = {};
  const redirect_chain: string[] = [];
  const ssl_info: Record<string, string> = {};
  let status_code: number | null = null;

  const allOutput = stderr + '\n' + stdout;
  const lines = allOutput.split('\n');

  for (const line of lines) {
    // Status line: < HTTP/1.1 200 OK
    const statusMatch = line.match(/^[<*]\s*HTTP\/[\d.]+\s+(\d+)/);
    if (statusMatch) {
      status_code = parseInt(statusMatch[1], 10);
    }

    // Response headers: < Header-Name: value
    const headerMatch = line.match(/^<\s+([^:]+):\s*(.+)$/);
    if (headerMatch) {
      headers[headerMatch[1].trim().toLowerCase()] = headerMatch[2].trim();
    }

    // Redirect location
    const locationMatch = line.match(/^[<*]\s*[Ll]ocation:\s*(.+)$/);
    if (locationMatch) {
      redirect_chain.push(locationMatch[1].trim());
    }

    // SSL info
    if (line.includes('SSL connection using')) {
      ssl_info['protocol'] = line.replace(/.*SSL connection using/, '').trim();
    }
    if (line.includes('issuer:')) {
      ssl_info['issuer'] = line.replace(/.*issuer:/, '').trim();
    }
    if (line.includes('subject:')) {
      ssl_info['subject'] = line.replace(/.*subject:/, '').trim();
    }
    if (line.includes('expire date:')) {
      ssl_info['expire_date'] = line.replace(/.*expire date:/, '').trim();
    }
  }

  // Body preview from stdout
  const body_preview = stdout.substring(0, 2000);

  return { status_code, headers, body_preview, redirect_chain, ssl_info };
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const url = String(params['url'] || '');
  const method = String(params['method'] || 'GET').toUpperCase();
  const headers = Array.isArray(params['headers']) ? (params['headers'] as string[]) : [];
  const timeout = Number(params['timeout'] || 30);
  const followRedirects = params['follow_redirects'] !== false;

  const args: string[] = ['-v', '-s', '-m', String(timeout), '-X', method];
  if (followRedirects) args.push('-L');

  for (const h of headers) {
    if (typeof h === 'string') {
      args.push('-H', h);
    }
  }
  args.push(url);

  const command = `curl ${args.join(' ')}`;
  const startTime = Date.now();

  const available = await exec.isAvailable('curl');
  if (!available) {
    return {
      success: false,
      tool: 'curl_probe',
      output: '',
      parsed: {},
      duration: (Date.now() - startTime) / 1000,
      command,
      error: "Tool 'curl' not found. Install it first.",
    };
  }

  const result = await exec.execute('curl', args, (timeout + 10) * 1000);
  const duration = result.duration;
  let output = result.stdout + (result.stderr ? '\n--- VERBOSE ---\n' + result.stderr : '');

  if (output.length > 50000) {
    output = output.substring(0, 50000) + '\n[OUTPUT TRUNCATED]';
  }

  if (result.timedOut) {
    return { success: false, tool: 'curl_probe', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  const parsed = parseCurlVerbose(result.stdout, result.stderr);

  return {
    success: result.exitCode === 0,
    tool: 'curl_probe',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: result.exitCode !== 0 ? `curl exited with code ${result.exitCode}: ${result.stderr.trim()}` : null,
  };
}

export const curlProbeTool = { definition, execute };

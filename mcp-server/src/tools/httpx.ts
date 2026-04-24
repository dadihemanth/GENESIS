import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'httpx',
  description: 'Fast HTTP probing — discovers live web assets, titles, status codes, tech stack, screenshots',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'targets', type: 'string', required: true, description: 'Comma-separated hosts/IPs/URLs or CIDR (e.g. 10.10.0.0/24,example.com)' },
    { name: 'ports', type: 'string', required: false, description: 'Ports to probe (e.g. 80,443,8080,8443)', default: '80,443,8080,8443,8000,3000' },
    { name: 'threads', type: 'number', required: false, description: 'Concurrent threads', default: 50 },
    { name: 'timeout', type: 'number', required: false, description: 'Timeout per request (seconds)', default: 10 },
    { name: 'follow_redirects', type: 'boolean', required: false, description: 'Follow HTTP redirects', default: true },
  ],
};

interface HttpxHost {
  url: string;
  status_code: number;
  title: string;
  tech: string[];
  content_length: number;
  response_time: string;
  webserver: string;
}

interface HttpxParsed {
  live_hosts: HttpxHost[];
  total: number;
}

function parseHttpxOutput(output: string): HttpxParsed {
  const hosts: HttpxHost[] = [];

  for (const line of output.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const obj = JSON.parse(trimmed);
      if (obj.url) {
        hosts.push({
          url: obj.url,
          status_code: obj.status_code ?? 0,
          title: obj.title ?? '',
          tech: obj.tech ?? [],
          content_length: obj['content-length'] ?? 0,
          response_time: obj.time ?? '',
          webserver: obj.webserver ?? '',
        });
      }
    } catch {
      // non-JSON lines (e.g. progress output) — skip
    }
  }

  return { live_hosts: hosts, total: hosts.length };
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const targets = String(params['targets'] || '');
  const ports = String(params['ports'] || '80,443,8080,8443,8000,3000');
  const threads = Number(params['threads'] || 50);
  const timeout = Number(params['timeout'] || 10);
  const followRedirects = params['follow_redirects'] !== false;

  const startTime = Date.now();

  const available = await exec.isAvailable('httpx');
  if (!available) {
    return { success: false, tool: 'httpx', output: '', parsed: {}, duration: 0, command: '', error: "Tool 'httpx' not found." };
  }

  // Write targets to a temp file for stdin
  const { writeFileSync, unlinkSync } = await import('fs');
  const tmpFile = `/tmp/httpx_targets_${Date.now()}.txt`;
  const targetList = targets.split(',').map(t => t.trim()).filter(Boolean);
  writeFileSync(tmpFile, targetList.join('\n'));

  const args = [
    '-list', tmpFile,
    '-ports', ports,
    '-threads', String(threads),
    '-timeout', String(timeout),
    '-json',
    '-silent',
    '-title',
    '-tech-detect',
    '-status-code',
    '-content-length',
    '-web-server',
    '-response-time',
  ];

  if (followRedirects) args.push('-follow-redirects');

  const command = `httpx ${args.join(' ')}`;

  const result = await exec.execute('httpx', args, (timeout * targetList.length + 60) * 1000);
  const duration = result.duration;

  try { unlinkSync(tmpFile); } catch { /* ignore */ }

  let output = result.stdout + (result.stderr ? '\n' + result.stderr : '');
  if (output.length > 50000) output = output.substring(0, 50000) + '\n[TRUNCATED]';

  if (result.timedOut) {
    return { success: false, tool: 'httpx', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  const parsed = parseHttpxOutput(result.stdout);

  return {
    success: true,
    tool: 'httpx',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: null,
  };
}

export const httpxTool = { definition, execute };

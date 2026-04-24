import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'nikto',
  description: 'Web server vulnerability scanner',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'target', type: 'string', required: true, description: 'Target host or URL' },
    { name: 'port', type: 'number', required: false, description: 'Port number', default: 80 },
    { name: 'ssl', type: 'boolean', required: false, description: 'Use SSL/TLS', default: false },
    { name: 'timeout', type: 'number', required: false, description: 'Max scan time in seconds', default: 300 },
  ],
};

interface NiktoVuln {
  id: string;
  description: string;
  url: string;
}

interface NiktoParsed {
  vulnerabilities: NiktoVuln[];
  server_info: string;
  items_checked: number;
}

function parseNiktoOutput(output: string): NiktoParsed {
  const lines = output.split('\n');
  const vulnerabilities: NiktoVuln[] = [];
  let server_info = '';
  let items_checked = 0;

  const vulnPattern = /^\+\s+(.+)$/;
  const serverPattern = /Server:\s*(.+)/i;
  const itemsPattern = /(\d+) item\(s\) reported/i;
  const osvdbPattern = /OSVDB-(\d+)/i;
  const cvePattern = /CVE-(\d{4}-\d+)/i;

  for (const line of lines) {
    const serverMatch = line.match(serverPattern);
    if (serverMatch) {
      server_info = serverMatch[1].trim();
    }

    const itemsMatch = line.match(itemsPattern);
    if (itemsMatch) {
      items_checked = parseInt(itemsMatch[1], 10);
    }

    const vulnMatch = line.match(vulnPattern);
    if (vulnMatch) {
      const desc = vulnMatch[1].trim();
      // Skip informational headers
      if (desc.startsWith('Target IP') || desc.startsWith('Target Hostname') ||
          desc.startsWith('Target Port') || desc.startsWith('Start Time') ||
          desc.startsWith('End Time') || desc.startsWith('Nikto')) {
        continue;
      }

      let id = 'INFO';
      const osvdbMatch = desc.match(osvdbPattern);
      const cveMatch = desc.match(cvePattern);
      if (cveMatch) id = `CVE-${cveMatch[1]}`;
      else if (osvdbMatch) id = `OSVDB-${osvdbMatch[1]}`;

      // Try to extract URL from description
      const urlMatch = desc.match(/(?:\/\S+)/);
      const url = urlMatch ? urlMatch[0] : '/';

      vulnerabilities.push({ id, description: desc, url });
    }
  }

  return { vulnerabilities, server_info, items_checked };
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const target = String(params['target'] || '');
  const port = Number(params['port'] || 80);
  const ssl = Boolean(params['ssl'] || false);
  const timeout = Number(params['timeout'] || 300);

  const args: string[] = ['-h', target, '-p', String(port), '-maxtime', `${timeout}s`, '-Format', 'txt'];
  if (ssl) args.push('-ssl');

  const command = `nikto ${args.join(' ')}`;
  const startTime = Date.now();

  const available = await exec.isAvailable('nikto');
  if (!available) {
    return {
      success: false,
      tool: 'nikto',
      output: '',
      parsed: {},
      duration: (Date.now() - startTime) / 1000,
      command,
      error: "Tool 'nikto' not found. Install it first.",
    };
  }

  const result = await exec.execute('nikto', args, (timeout + 30) * 1000);
  const duration = result.duration;
  let output = result.stdout + (result.stderr ? '\n' + result.stderr : '');

  if (output.length > 50000) {
    output = output.substring(0, 50000) + '\n[OUTPUT TRUNCATED]';
  }

  if (result.timedOut) {
    return { success: false, tool: 'nikto', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  const parsed = parseNiktoOutput(result.stdout);

  return {
    success: result.exitCode === 0 || parsed.vulnerabilities.length > 0,
    tool: 'nikto',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: result.exitCode !== 0 ? result.stderr.trim() || null : null,
  };
}

export const niktoTool = { definition, execute };

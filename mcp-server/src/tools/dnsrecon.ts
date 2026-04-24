import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';
import * as fs from 'fs';

const definition: ToolDefinition = {
  name: 'dnsrecon',
  description: 'DNS enumeration and reconnaissance tool',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'domain', type: 'string', required: true, description: 'Target domain name' },
    { name: 'type', type: 'string', required: false, description: 'Enumeration type (std, brt, axfr, etc.)', default: 'std' },
  ],
};

interface DnsRecord {
  type: string;
  name: string;
  address: string;
}

interface DnsreconParsed {
  records: DnsRecord[];
  errors: string[];
}

function parseDnsreconJson(raw: string): DnsreconParsed {
  const records: DnsRecord[] = [];
  const errors: string[] = [];

  try {
    const data = JSON.parse(raw);
    const entries = Array.isArray(data) ? data : [];
    for (const entry of entries) {
      if (entry['type'] && (entry['name'] || entry['target'])) {
        records.push({
          type: entry['type'] || '',
          name: entry['name'] || entry['target'] || '',
          address: entry['address'] || entry['data'] || entry['exchange'] || '',
        });
      }
      if (entry['type'] === 'error') {
        errors.push(String(entry['message'] || entry['name'] || ''));
      }
    }
  } catch {
    // Could not parse JSON
  }

  return { records, errors };
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const domain = String(params['domain'] || '');
  const type = String(params['type'] || 'std');
  const ts = Date.now();
  const outFile = `/tmp/dnsrecon_${ts}.json`;

  const args = ['-d', domain, '-t', type, '-j', outFile];
  const command = `dnsrecon ${args.join(' ')}`;
  const startTime = Date.now();

  const available = await exec.isAvailable('dnsrecon');
  if (!available) {
    return {
      success: false,
      tool: 'dnsrecon',
      output: '',
      parsed: {},
      duration: (Date.now() - startTime) / 1000,
      command,
      error: "Tool 'dnsrecon' not found. Install it first.",
    };
  }

  const result = await exec.execute('dnsrecon', args, 300000);
  const duration = result.duration;
  let output = result.stdout + (result.stderr ? '\n' + result.stderr : '');

  if (output.length > 50000) {
    output = output.substring(0, 50000) + '\n[OUTPUT TRUNCATED]';
  }

  if (result.timedOut) {
    return { success: false, tool: 'dnsrecon', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  let parsed: DnsreconParsed = { records: [], errors: [] };

  try {
    if (fs.existsSync(outFile)) {
      const raw = fs.readFileSync(outFile, 'utf-8');
      parsed = parseDnsreconJson(raw);
      fs.unlinkSync(outFile);
    }
  } catch {
    // Ignore
  }

  return {
    success: result.exitCode === 0,
    tool: 'dnsrecon',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: result.exitCode !== 0 ? result.stderr.trim() || null : null,
  };
}

export const dnsreconTool = { definition, execute };

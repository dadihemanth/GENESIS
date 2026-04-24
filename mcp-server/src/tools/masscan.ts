import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';
import * as fs from 'fs';

const definition: ToolDefinition = {
  name: 'masscan',
  description: 'Fast TCP port scanner for large networks',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'target', type: 'string', required: true, description: 'Target IP, CIDR range' },
    { name: 'ports', type: 'string', required: false, description: 'Port range, e.g. 1-1024 or 80,443', default: '1-1024' },
    { name: 'rate', type: 'number', required: false, description: 'Packets per second rate', default: 1000 },
  ],
};

interface MasscanPort {
  port: number;
  protocol: string;
  ip: string;
}

interface MasscanParsed {
  open_ports: MasscanPort[];
  total_found: number;
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const target = String(params['target'] || '');
  const ports = String(params['ports'] || '1-1024');
  const rate = Number(params['rate'] || 1000);
  const ts = Date.now();
  const outFile = `/tmp/masscan_${ts}.json`;

  const args = [
    target,
    `-p${ports}`,
    `--rate=${rate}`,
    '--wait=3',
    '-oJ', outFile,
  ];

  const command = `masscan ${args.join(' ')}`;
  const startTime = Date.now();

  const available = await exec.isAvailable('masscan');
  if (!available) {
    return {
      success: false,
      tool: 'masscan',
      output: '',
      parsed: {},
      duration: (Date.now() - startTime) / 1000,
      command,
      error: "Tool 'masscan' not found. Install it first.",
    };
  }

  const result = await exec.execute('masscan', args, 600000);
  const duration = result.duration;
  let output = result.stdout + (result.stderr ? '\n' + result.stderr : '');

  if (output.length > 50000) {
    output = output.substring(0, 50000) + '\n[OUTPUT TRUNCATED]';
  }

  if (result.timedOut) {
    return { success: false, tool: 'masscan', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  let parsed: MasscanParsed = { open_ports: [], total_found: 0 };

  try {
    if (fs.existsSync(outFile)) {
      const raw = fs.readFileSync(outFile, 'utf-8').trim();
      // masscan JSON is a JS array literal; strip trailing comma if present
      const cleaned = raw.replace(/,\s*$/, '').replace(/^masscan\s*=\s*/, '');
      const data = JSON.parse(cleaned.startsWith('[') ? cleaned : `[${cleaned}]`);
      for (const entry of data) {
        if (entry.ports && Array.isArray(entry.ports)) {
          for (const p of entry.ports) {
            parsed.open_ports.push({
              port: p.port,
              protocol: p.proto || 'tcp',
              ip: entry.ip,
            });
          }
        }
      }
      parsed.total_found = parsed.open_ports.length;
      fs.unlinkSync(outFile);
    }
  } catch {
    // Could not parse output file — return what we have
  }

  return {
    success: result.exitCode === 0,
    tool: 'masscan',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: result.exitCode !== 0 ? result.stderr.trim() || null : null,
  };
}

export const masscanTool = { definition, execute };

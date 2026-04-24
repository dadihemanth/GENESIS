import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'nmap',
  description: 'Network port scanner and service detector',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'target', type: 'string', required: true, description: 'Target IP or hostname' },
    { name: 'ports', type: 'string', required: false, description: 'Port range, e.g. 1-1024 or 80,443', default: '1-65535' },
    { name: 'timing', type: 'string', required: false, description: 'Timing template T0-T5', default: 'T4' },
    { name: 'flags', type: 'array', required: false, description: 'Extra nmap flags', default: [] },
    { name: 'os_detect', type: 'boolean', required: false, description: 'Enable OS detection (-O)', default: false },
  ],
};

interface NmapPort {
  port: number;
  state: string;
  service: string;
  version: string;
  scripts: string[];
}

interface NmapParsed {
  ports: NmapPort[];
  os_guess: string | null;
  hosts_up: number;
  hosts_down: number;
}

function parseNmapOutput(output: string): NmapParsed {
  const lines = output.split('\n');
  const ports: NmapPort[] = [];
  let os_guess: string | null = null;
  let hosts_up = 0;
  let hosts_down = 0;

  const portRegex = /^(\d+)\/(tcp|udp)\s+(\w+)\s+(\S+)\s*(.*)?$/;
  const hostRegex = /(\d+) hosts? up.*?(\d+) hosts? down/i;
  const hostsUpOnly = /(\d+) hosts? up/i;
  const osRegex = /OS details:\s*(.+)/i;
  const osGuessRegex = /Aggressive OS guesses:\s*(.+)/i;

  for (const line of lines) {
    const portMatch = line.trim().match(portRegex);
    if (portMatch) {
      ports.push({
        port: parseInt(portMatch[1], 10),
        state: portMatch[3],
        service: portMatch[4],
        version: portMatch[5]?.trim() || '',
        scripts: [],
      });
      continue;
    }

    const scriptMatch = line.match(/^\|\s+(.+)$/);
    if (scriptMatch && ports.length > 0) {
      ports[ports.length - 1].scripts.push(scriptMatch[1].trim());
    }

    const hostMatch = line.match(hostRegex);
    if (hostMatch) {
      hosts_up = parseInt(hostMatch[1], 10);
      hosts_down = parseInt(hostMatch[2], 10);
    } else {
      const upOnly = line.match(hostsUpOnly);
      if (upOnly) hosts_up = parseInt(upOnly[1], 10);
    }

    const osMatch = line.match(osRegex) || line.match(osGuessRegex);
    if (osMatch) {
      os_guess = osMatch[1].split(',')[0].trim();
    }
  }

  return { ports, os_guess, hosts_up, hosts_down };
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const target = String(params['target'] || '');
  const ports = String(params['ports'] || '1-65535');
  const rawTiming = params['timing'] ?? 'T4';
  // Accept both integer (3) and string ("T3" / "3") forms
  const timingStr = String(rawTiming).replace(/^T/i, '');
  const timing = /^\d$/.test(timingStr) ? `T${timingStr}` : String(rawTiming);
  const flags = Array.isArray(params['flags']) ? (params['flags'] as string[]) : [];
  const osDetect = Boolean(params['os_detect'] || false);

  const args: string[] = ['-sV', '-sC', `-p${ports}`, `-${timing}`];
  if (osDetect) args.push('-O');

  // Block flags that could execute arbitrary code, write files, or load external data
  const BLOCKED_FLAG_PATTERNS = [
    /^--script/i,       // --script=, --script-args=, --script-trace, --script-updatedb
    /^--datadir/i,      // alternate NSE/script directory
    /^--servicedb/i,    // alternate service db
    /^--versiondb/i,    // alternate version db
    /^-iL/i,            // input from file
    /^--resume/i,       // resume from file
    /^-o[NXGASk]/i,    // all output-to-file flags
    /^--append-output/i,
  ];
  for (const f of flags) {
    if (typeof f !== 'string' || !f.startsWith('-')) continue;
    if (BLOCKED_FLAG_PATTERNS.some((p) => p.test(f))) {
      console.warn(`[nmap] blocked disallowed flag: ${f}`);
      continue;
    }
    args.push(f);
  }
  args.push(target);

  const command = `nmap ${args.join(' ')}`;
  const startTime = Date.now();

  const available = await exec.isAvailable('nmap');
  if (!available) {
    return {
      success: false,
      tool: 'nmap',
      output: '',
      parsed: {},
      duration: (Date.now() - startTime) / 1000,
      command,
      error: "Tool 'nmap' not found. Install it first.",
    };
  }

  const result = await exec.execute('nmap', args, 600000);
  const duration = result.duration;
  let output = result.stdout;

  if (output.length > 50000) {
    output = output.substring(0, 50000) + '\n[OUTPUT TRUNCATED - exceeded 50000 characters]';
  }

  if (result.timedOut) {
    return {
      success: false,
      tool: 'nmap',
      output,
      parsed: {},
      duration,
      command,
      error: 'Command timed out after 600 seconds',
    };
  }

  const parsed = parseNmapOutput(result.stdout);

  return {
    success: result.exitCode === 0 || parsed.ports.length > 0,
    tool: 'nmap',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: result.exitCode !== 0 && parsed.ports.length === 0 ? result.stderr.trim() || null : null,
  };
}

export const nmapTool = { definition, execute };

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'sqlmap',
  description: 'Automatic SQL injection detection and exploitation tool',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'target', type: 'string', required: true, description: 'Target URL' },
    { name: 'level', type: 'number', required: false, description: 'Detection level 1-5', default: 1 },
    { name: 'risk', type: 'number', required: false, description: 'Risk level 1-3', default: 1 },
    { name: 'data', type: 'string', required: false, description: 'POST data string', default: '' },
    { name: 'cookie', type: 'string', required: false, description: 'HTTP cookie header', default: '' },
  ],
};

interface SqlmapParameter {
  param: string;
  type: string;
  payload: string;
}

interface SqlmapParsed {
  vulnerable: boolean;
  parameters: SqlmapParameter[];
  databases: string[];
}

function parseSqlmapOutput(output: string): SqlmapParsed {
  const lines = output.split('\n');
  const parameters: SqlmapParameter[] = [];
  const databases: string[] = [];
  let vulnerable = false;

  const injectionRegex = /Parameter:\s*(.+?)\s+\((.+?)\)/i;
  const payloadRegex = /Payload:\s*(.+)/i;
  const dbRegex = /\[\*\]\s+(\S+)$/;
  const vulnRegex = /is vulnerable/i;

  let currentParam = '';
  let currentType = '';

  for (const line of lines) {
    if (vulnRegex.test(line)) vulnerable = true;

    const injMatch = line.match(injectionRegex);
    if (injMatch) {
      currentParam = injMatch[1].trim();
      currentType = injMatch[2].trim();
    }

    const payloadMatch = line.match(payloadRegex);
    if (payloadMatch && currentParam) {
      parameters.push({ param: currentParam, type: currentType, payload: payloadMatch[1].trim() });
      currentParam = '';
      currentType = '';
    }

    const dbMatch = line.match(dbRegex);
    if (dbMatch && !databases.includes(dbMatch[1])) {
      databases.push(dbMatch[1]);
    }
  }

  if (parameters.length > 0) vulnerable = true;

  return { vulnerable, parameters, databases };
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const target = String(params['target'] || '');
  const level = Math.min(5, Math.max(1, Number(params['level'] || 1)));
  const risk = Math.min(3, Math.max(1, Number(params['risk'] || 1)));
  const data = String(params['data'] || '');
  const cookie = String(params['cookie'] || '');
  const ts = Date.now();

  const args: string[] = [
    '-u', target,
    `--level=${level}`,
    `--risk=${risk}`,
    '--batch',
    '--forms',
    `--output-dir=/tmp/sqlmap_${ts}`,
  ];
  if (data) { args.push('--data'); args.push(data); }
  if (cookie) { args.push('--cookie'); args.push(cookie); }

  const command = `sqlmap ${args.join(' ')}`;
  const startTime = Date.now();

  const available = await exec.isAvailable('sqlmap');
  if (!available) {
    return {
      success: false,
      tool: 'sqlmap',
      output: '',
      parsed: {},
      duration: (Date.now() - startTime) / 1000,
      command,
      error: "Tool 'sqlmap' not found. Install it first.",
    };
  }

  const result = await exec.execute('sqlmap', args, 600000);
  const duration = result.duration;
  let output = result.stdout + (result.stderr ? '\n' + result.stderr : '');

  if (output.length > 50000) {
    output = output.substring(0, 50000) + '\n[OUTPUT TRUNCATED]';
  }

  if (result.timedOut) {
    return { success: false, tool: 'sqlmap', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  const parsed = parseSqlmapOutput(result.stdout);

  return {
    success: result.exitCode === 0,
    tool: 'sqlmap',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: result.exitCode !== 0 ? result.stderr.trim() || null : null,
  };
}

export const sqlmapTool = { definition, execute };

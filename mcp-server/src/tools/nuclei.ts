import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'nuclei',
  description: 'Fast vulnerability scanner based on templates',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'target', type: 'string', required: true, description: 'Target URL' },
    { name: 'severity', type: 'array', required: false, description: 'Severity levels to include', default: ['critical', 'high', 'medium'] },
    { name: 'timeout', type: 'number', required: false, description: 'Timeout in seconds', default: 60 },
    { name: 'templates', type: 'string', required: false, description: 'Custom templates path', default: '' },
  ],
};

interface NucleiFinding {
  template_id: string;
  name: string;
  severity: string;
  description: string;
  matched_at: string;
  extracted_results: string[];
}

interface NucleiParsed {
  findings: NucleiFinding[];
  total: number;
}

function parseNucleiOutput(output: string): NucleiParsed {
  const lines = output.split('\n').filter(l => l.trim());
  const findings: NucleiFinding[] = [];

  for (const line of lines) {
    try {
      const obj = JSON.parse(line);
      if (!obj || typeof obj !== 'object') continue;
      findings.push({
        template_id: obj['template-id'] || obj['templateID'] || '',
        name: obj['info']?.name || obj['name'] || '',
        severity: obj['info']?.severity || obj['severity'] || 'unknown',
        description: obj['info']?.description || obj['description'] || '',
        matched_at: obj['matched-at'] || obj['matchedAt'] || '',
        extracted_results: Array.isArray(obj['extracted-results']) ? obj['extracted-results'] : [],
      });
    } catch {
      // Not JSON — skip
    }
  }

  return { findings, total: findings.length };
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const target = String(params['target'] || '');
  const severity = Array.isArray(params['severity'])
    ? (params['severity'] as string[]).join(',')
    : 'critical,high,medium';
  const timeout = Number(params['timeout'] || 60);
  const templates = String(params['templates'] || '');

  const args: string[] = ['-u', target, '-severity', severity, '-json', `-timeout`, String(timeout), '-no-color', '-silent'];
  if (templates) args.push('-t', templates);

  const command = `nuclei ${args.join(' ')}`;
  const startTime = Date.now();

  const available = await exec.isAvailable('nuclei');
  if (!available) {
    return {
      success: false,
      tool: 'nuclei',
      output: '',
      parsed: {},
      duration: (Date.now() - startTime) / 1000,
      command,
      error: "Tool 'nuclei' not found. Install it first.",
    };
  }

  const result = await exec.execute('nuclei', args, (timeout + 60) * 1000);
  const duration = result.duration;
  let output = result.stdout + (result.stderr ? '\n' + result.stderr : '');

  if (output.length > 50000) {
    output = output.substring(0, 50000) + '\n[OUTPUT TRUNCATED]';
  }

  if (result.timedOut) {
    return { success: false, tool: 'nuclei', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  const parsed = parseNucleiOutput(result.stdout);

  return {
    success: true,
    tool: 'nuclei',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: null,
  };
}

export const nucleiTool = { definition, execute };

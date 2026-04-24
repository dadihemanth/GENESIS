import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'semgrep',
  description: 'Static analysis tool for finding security vulnerabilities in source code',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'path', type: 'string', required: true, description: 'Path to code to analyze' },
    { name: 'config', type: 'string', required: false, description: 'Semgrep ruleset or config', default: 'p/security-audit' },
  ],
};

interface SemgrepFinding {
  rule_id: string;
  message: string;
  severity: string;
  path: string;
  start: { line: number; col: number };
  code: string;
}

interface SemgrepStats {
  files_scanned: number;
  findings: number;
}

interface SemgrepParsed {
  findings: SemgrepFinding[];
  stats: SemgrepStats;
}

function parseSemgrepJson(raw: string): SemgrepParsed {
  const findings: SemgrepFinding[] = [];
  let stats: SemgrepStats = { files_scanned: 0, findings: 0 };

  try {
    const data = JSON.parse(raw);

    const results = Array.isArray(data['results']) ? data['results'] : [];
    for (const r of results) {
      findings.push({
        rule_id: r['check_id'] || r['rule_id'] || '',
        message: r['extra']?.message || r['message'] || '',
        severity: r['extra']?.severity || r['severity'] || 'unknown',
        path: r['path'] || '',
        start: {
          line: r['start']?.line ?? 0,
          col: r['start']?.col ?? 0,
        },
        code: r['extra']?.lines || r['code'] || '',
      });
    }

    const statsData = data['stats'] || {};
    stats = {
      files_scanned: statsData['total_files_scanned'] ?? statsData['files_scanned'] ?? 0,
      findings: findings.length,
    };
  } catch {
    // Ignore JSON parse errors
  }

  return { findings, stats };
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const path = String(params['path'] || '');
  const config = String(params['config'] || 'p/security-audit');

  const args = ['--config', config, path, '--json', '--quiet'];
  const command = `semgrep ${args.join(' ')}`;
  const startTime = Date.now();

  const available = await exec.isAvailable('semgrep');
  if (!available) {
    return {
      success: false,
      tool: 'semgrep',
      output: '',
      parsed: {},
      duration: (Date.now() - startTime) / 1000,
      command,
      error: "Tool 'semgrep' not found. Install it first.",
    };
  }

  const result = await exec.execute('semgrep', args, 600000);
  const duration = result.duration;
  let output = result.stdout + (result.stderr ? '\n' + result.stderr : '');

  if (output.length > 50000) {
    output = output.substring(0, 50000) + '\n[OUTPUT TRUNCATED]';
  }

  if (result.timedOut) {
    return { success: false, tool: 'semgrep', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  const parsed = parseSemgrepJson(result.stdout);

  return {
    success: result.exitCode === 0 || result.exitCode === 1, // semgrep exits 1 when findings exist
    tool: 'semgrep',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: result.exitCode > 1 ? result.stderr.trim() || null : null,
  };
}

export const semgrepTool = { definition, execute };

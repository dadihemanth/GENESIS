import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'bandit',
  description: 'Security linter for Python code',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'path', type: 'string', required: true, description: 'Path to Python file or directory' },
    { name: 'level', type: 'string', required: false, description: 'Minimum severity level: l, m, h', default: 'l' },
  ],
};

interface BanditIssue {
  test_id: string;
  test_name: string;
  severity: string;
  confidence: string;
  filename: string;
  line_number: number;
  issue_text: string;
  code: string;
}

interface BanditStats {
  files_scanned: number;
  findings: number;
  high: number;
  medium: number;
  low: number;
}

interface BanditParsed {
  issues: BanditIssue[];
  stats: BanditStats;
}

function parseBanditJson(raw: string): BanditParsed {
  const issues: BanditIssue[] = [];
  let stats: BanditStats = { files_scanned: 0, findings: 0, high: 0, medium: 0, low: 0 };

  try {
    const data = JSON.parse(raw);
    const results = Array.isArray(data['results']) ? data['results'] : [];

    for (const r of results) {
      issues.push({
        test_id: r['test_id'] || '',
        test_name: r['test_name'] || '',
        severity: r['issue_severity'] || r['severity'] || 'LOW',
        confidence: r['issue_confidence'] || r['confidence'] || 'LOW',
        filename: r['filename'] || '',
        line_number: r['line_number'] ?? 0,
        issue_text: r['issue_text'] || '',
        code: r['code'] || '',
      });
    }

    const metricsData = data['metrics'] || {};
    let filesScanned = 0;
    let high = 0, medium = 0, low = 0;

    for (const [key, val] of Object.entries(metricsData)) {
      if (key === '_totals') {
        const totals = val as Record<string, number>;
        high = totals['SEVERITY.HIGH'] ?? 0;
        medium = totals['SEVERITY.MEDIUM'] ?? 0;
        low = totals['SEVERITY.LOW'] ?? 0;
      } else {
        filesScanned++;
      }
    }

    stats = { files_scanned: filesScanned, findings: issues.length, high, medium, low };
  } catch {
    // Ignore
  }

  return { issues, stats };
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const path = String(params['path'] || '');
  const level = String(params['level'] || 'l');

  const levelFlag = `-${'l'.repeat(Math.max(1, ['l', 'm', 'h'].indexOf(level) + 1))}`;
  const args = ['-r', path, '-f', 'json', levelFlag];
  const command = `bandit ${args.join(' ')}`;
  const startTime = Date.now();

  const available = await exec.isAvailable('bandit');
  if (!available) {
    return {
      success: false,
      tool: 'bandit',
      output: '',
      parsed: {},
      duration: (Date.now() - startTime) / 1000,
      command,
      error: "Tool 'bandit' not found. Install it first.",
    };
  }

  const result = await exec.execute('bandit', args, 300000);
  const duration = result.duration;
  let output = result.stdout + (result.stderr ? '\n' + result.stderr : '');

  if (output.length > 50000) {
    output = output.substring(0, 50000) + '\n[OUTPUT TRUNCATED]';
  }

  if (result.timedOut) {
    return { success: false, tool: 'bandit', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  const parsed = parseBanditJson(result.stdout);

  return {
    success: result.exitCode === 0 || result.exitCode === 1, // bandit exits 1 when issues found
    tool: 'bandit',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: result.exitCode > 1 ? result.stderr.trim() || null : null,
  };
}

export const banditTool = { definition, execute };

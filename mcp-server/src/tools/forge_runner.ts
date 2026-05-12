import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';
import { runOnSandbox, poolSize } from '../sandbox_pool';

// ---------------------------------------------------------------------------
// forge_runner — dispatch LLM-authored scripts to the forge_sandbox pool.
//
// The sandbox enforces resource + egress limits. This MCP tool is a thin
// adapter that (a) forwards the script via the round-robin pool dispatcher,
// (b) evaluates an optional oracle against stdout, and (c) returns a
// structured ToolResult compatible with the orchestrator's oracle-evidence
// path (T2/T5 U1 gate).
// ---------------------------------------------------------------------------

const definition: ToolDefinition = {
  name: 'forge_runner',
  description:
    'Execute an LLM-authored Python/Node/Bash script in a rootless, seccomp-restricted sandbox. ' +
    'Egress is limited to the target IP and the OOB domain. Wall-time capped (default 60s, max 180s). ' +
    'Declare a success predicate via an oracle so a passing oracle is accepted as evidence (U1).',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'lang', type: 'string', required: true, description: 'python | node | bash' },
    { name: 'code', type: 'string', required: true, description: 'Script body (≤ 8 KB)' },
    { name: 'stdin', type: 'string', required: false, description: 'Optional stdin' },
    { name: 'wall_time_s', type: 'number', required: false, description: 'Max wall-time (hard max 180)', default: 60 },
    { name: 'target_hint', type: 'string', required: false, description: 'Informational: target IP/host — logged for audit' },
    { name: 'oracle', type: 'string', required: false, description: 'JSON oracle: body_must_contain (string|array), body_regex (string), exit_code_eq (int), min_length (int)' },
    { name: 'rationale', type: 'string', required: false, description: 'One sentence: what the script proves' },
  ],
};

interface OracleSpec {
  body_must_contain?: string | string[];
  body_regex?: string;
  exit_code_eq?: number;
  min_length?: number;
}

interface OracleVerdict { verdict: 'pass' | 'fail' | 'partial'; reasons: string[] }

function parseJsonParam<T = unknown>(raw: unknown, fallback: T): T {
  if (!raw) return fallback;
  try { return JSON.parse(String(raw)) as T; } catch { return fallback; }
}

function evalOracle(oracle: OracleSpec, stdout: string, exitCode: number): OracleVerdict {
  const reasons: string[] = [];
  let checks = 0;
  let passes = 0;
  const record = (ok: boolean, msg: string) => {
    checks += 1;
    if (ok) { passes += 1; reasons.push(`PASS: ${msg}`); }
    else { reasons.push(`FAIL: ${msg}`); }
  };

  if (oracle.body_must_contain !== undefined) {
    const needles = Array.isArray(oracle.body_must_contain) ? oracle.body_must_contain : [oracle.body_must_contain];
    for (const n of needles) {
      record(stdout.includes(n), `stdout contains "${n.substring(0, 80)}"`);
    }
  }
  if (oracle.body_regex) {
    try {
      const re = new RegExp(oracle.body_regex, 's');
      record(re.test(stdout), `stdout matches /${oracle.body_regex}/`);
    } catch {
      record(false, `body_regex invalid: /${oracle.body_regex}/`);
    }
  }
  if (oracle.exit_code_eq !== undefined) {
    record(exitCode === oracle.exit_code_eq, `exit_code == ${oracle.exit_code_eq} (got ${exitCode})`);
  }
  if (oracle.min_length !== undefined) {
    record(stdout.length >= oracle.min_length, `stdout length >= ${oracle.min_length} (got ${stdout.length})`);
  }

  if (checks === 0) return { verdict: 'fail', reasons: ['no oracle predicates declared'] };
  if (passes === checks) return { verdict: 'pass', reasons };
  if (passes === 0) return { verdict: 'fail', reasons };
  return { verdict: 'partial', reasons };
}

export const forgeRunnerTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const lang = String(params.lang || 'python').toLowerCase() as 'python' | 'node' | 'bash';
    const code = String(params.code || '');
    const stdin = String(params.stdin || '');
    const wallTimeS = Math.min(180, Math.max(1, Number(params.wall_time_s || 60)));
    const targetHint = String(params.target_hint || '');
    const rationale = String(params.rationale || '');

    if (!code.trim()) return { output: 'code required', parsed: { error: 'missing code' } };
    if (!['python', 'node', 'bash'].includes(lang)) {
      return { output: `unsupported lang "${lang}". Use python|node|bash.`, parsed: { error: 'bad lang' } };
    }

    const dispatch = await runOnSandbox({ lang, code, stdin, wall_time_s: wallTimeS });
    if (!dispatch.ok || !dispatch.body) {
      return {
        output: `sandbox pool failed (${poolSize()} replicas): ${dispatch.error}`,
        parsed: { error: dispatch.error || 'pool_failed', pool_size: poolSize() },
      };
    }
    const result = dispatch.body;
    if (result.error) {
      return { output: `sandbox error: ${result.error}`, parsed: { error: result.error, replica: dispatch.replica } };
    }

    const stdout = result.stdout || '';
    const stderr = result.stderr || '';
    const exitCode = result.exit_code ?? -1;
    const timedOut = Boolean(result.timed_out);

    const oracle = parseJsonParam<OracleSpec>(params.oracle, {});
    const hasOracle = Object.keys(oracle).length > 0;
    const verdict: OracleVerdict = hasOracle
      ? evalOracle(oracle, stdout, exitCode)
      : { verdict: 'fail', reasons: ['no oracle supplied — verdict is advisory only'] };

    const outLines = [
      `forge_runner (${lang}, ${wallTimeS}s wall-time, target=${targetHint || 'unspecified'}, replica=${dispatch.replica})`,
      `${'─'.repeat(70)}`,
      `exit_code=${exitCode} duration=${result.duration_ms}ms timed_out=${timedOut}`,
      '',
      'STDOUT:',
      stdout.substring(0, 4000) || '(empty)',
      '',
      'STDERR:',
      stderr.substring(0, 1500) || '(empty)',
      '',
      `Oracle verdict: ${verdict.verdict.toUpperCase()}${hasOracle ? '' : ' (no oracle)'}`,
    ];
    for (const r of verdict.reasons) outLines.push(`  ${r}`);
    if (rationale) {
      outLines.push('');
      outLines.push(`Rationale: ${rationale}`);
    }

    return {
      output: outLines.join('\n'),
      parsed: {
        lang,
        wall_time_s: wallTimeS,
        target_hint: targetHint,
        replica: dispatch.replica,
        exit_code: exitCode,
        duration_ms: result.duration_ms ?? 0,
        timed_out: timedOut,
        stdout,
        stderr,
        stdout_truncated: Boolean(result.stdout_truncated),
        oracle: hasOracle ? oracle : null,
        oracle_verdict: verdict.verdict,
        oracle_reasons: verdict.reasons,
        rationale,
      },
    };
  },
};

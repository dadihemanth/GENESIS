import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';
import { resolveBinaryArg, ArtifactResolveError } from './_artifact_resolver';

// ---------------------------------------------------------------------------
// instrument_trace — Tier-5 · T25 dynamic instrumentation.
//
// Point Frida (spawn mode) or DynamoRIO at a pulled binary artifact. The
// caller provides either a Frida JS hook script (mode="frida") or a
// DynamoRIO client name (mode="dynamorio", client ∈ {drcov, drstrace,
// drltrace}) and receives a structured trace / coverage summary back as
// evidence.
//
// The instrumented binary runs INSIDE the instrumentation container,
// against its own /tmp — NOT against the target. So there's no egress to
// the target from this tool path.
// ---------------------------------------------------------------------------

const INSTRUMENTATION_URL =
  process.env.INSTRUMENTATION_URL || 'http://instrumentation:3601';

const HARD_MAX_WALL_TIME_S = 180;
const DEFAULT_WALL_TIME_S = 30;

const definition: ToolDefinition = {
  name: 'instrument_trace',
  description:
    'Dynamic instrumentation via Frida (spawn mode) or DynamoRIO. ' +
    'mode="frida": supply hook_spec as a Frida JS script — use Interceptor.attach(...) + send({...}) to emit trace events. ' +
    'mode="dynamorio": supply dr_client ∈ {drcov (coverage bitmap), drstrace (syscall trace), drltrace (library-call trace)}. ' +
    'Binary must have been pulled via artifact_pull and live under /data/security/artifacts. ' +
    'Argv sanitised against shell metachars; wall_time capped at 180s. ' +
    'Pair with binary_decompile (T4) for symbol addresses to hook, and with fuzz_binary (T9) — trace the crashing path with Frida to identify the exact tainted variable.',
  status: 'available',
  version: '0.1.0',
  parameters: [
    { name: 'mode', type: 'string', required: true, description: 'frida | dynamorio' },
    { name: 'binary_path', type: 'string', required: false, description: 'Absolute path under /data/security/artifacts. Either this or artifact_id + session_id.' },
    { name: 'artifact_id', type: 'string', required: false, description: 'T23: sha256 of a pulled artifact; resolver fetches bytes (from local or MinIO).' },
    { name: 'session_id', type: 'string', required: false, description: 'Session UUID (required with artifact_id).' },
    { name: 'argv', type: 'string', required: false, description: 'JSON array of argv parts (max 32, 512 chars each, shell metachars rejected)' },
    { name: 'stdin_b64', type: 'string', required: false, description: 'Base64-encoded stdin (max 1 MB)' },
    { name: 'hook_spec', type: 'string', required: false, description: 'Frida JS hook script (frida mode). Max 64 KB. Use send({...}) to emit trace events.' },
    { name: 'dr_client', type: 'string', required: false, description: 'DynamoRIO client: drcov | drstrace | drltrace (dynamorio mode)' },
    { name: 'wall_time_s', type: 'number', required: false, description: 'Hard max 180s', default: DEFAULT_WALL_TIME_S },
    { name: 'rationale', type: 'string', required: false, description: 'One sentence: what the hook is looking for' },
  ],
};

function parseJsonParam<T = unknown>(raw: unknown, fallback: T): T {
  if (!raw) return fallback;
  try { return JSON.parse(String(raw)) as T; } catch { return fallback; }
}

interface InstrumentResponse {
  ok?: boolean;
  mode?: string;
  reason?: string;
  available?: boolean;
  // Frida
  frida_version?: string;
  events?: Array<Record<string, unknown>>;
  events_truncated?: boolean;
  // Common
  exit_code?: number | null;
  timed_out?: boolean;
  duration_ms?: number;
  stdout_tail?: string;
  stderr_tail?: string;
  // DynamoRIO
  dr_version?: string | null;
  dr_client?: string;
  coverage_summary?: Record<string, unknown>;
  target_stdout_tail?: string;
  target_stderr_tail?: string;
}

export const instrumentTraceTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const mode = String(params.mode || '').toLowerCase();
    if (!['frida', 'dynamorio'].includes(mode)) {
      return {
        output: 'mode must be "frida" or "dynamorio"',
        parsed: { error: 'bad_mode', ok: false },
      };
    }

    let binaryPath = '';
    try {
      const resolved = await resolveBinaryArg(params);
      if (resolved) binaryPath = resolved.path;
    } catch (err) {
      if (err instanceof ArtifactResolveError) {
        return { output: `artifact resolve failed: ${err.message}`, parsed: { error: err.message, ok: false } };
      }
      throw err;
    }
    if (!binaryPath) {
      return { output: 'binary_path (or artifact_id + session_id) required', parsed: { error: 'missing_binary_path', ok: false } };
    }

    const argv = parseJsonParam<string[]>(params.argv, []);
    const stdinB64 = params.stdin_b64 ? String(params.stdin_b64) : '';
    const wallTimeS = Math.min(HARD_MAX_WALL_TIME_S, Math.max(1, Number(params.wall_time_s ?? DEFAULT_WALL_TIME_S)));
    const rationale = String(params.rationale || '');

    const payload: Record<string, unknown> = {
      mode,
      binary_path: binaryPath,
      argv,
      stdin_b64: stdinB64 || undefined,
      wall_time_s: wallTimeS,
    };
    if (mode === 'frida') {
      const hook = String(params.hook_spec || '');
      payload.hook_spec = hook;
    } else {
      payload.dr_client = String(params.dr_client || 'drcov').toLowerCase();
    }

    let resp: Response;
    try {
      const c = new AbortController();
      const timer = setTimeout(() => c.abort(), (wallTimeS + 30) * 1000);
      resp = await fetch(`${INSTRUMENTATION_URL}/instrument`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: c.signal,
      });
      clearTimeout(timer);
    } catch (err) {
      return {
        output: `instrumentation service unreachable: ${err}`,
        parsed: { error: String(err), instrumentation_url: INSTRUMENTATION_URL, ok: false },
      };
    }

    const body = await resp.text();
    let data: InstrumentResponse;
    try {
      data = JSON.parse(body) as InstrumentResponse;
    } catch (_err) {
      return {
        output: `instrumentation HTTP ${resp.status}: ${body.substring(0, 400)}`,
        parsed: { error: 'non_json_response', status: resp.status, body: body.substring(0, 2000), ok: false },
      };
    }

    if (!data.ok) {
      const reason = data.reason || `HTTP ${resp.status}`;
      const avail = data.available === false ? ' (tool not available in image)' : '';
      return {
        output: `instrument_trace FAIL: ${reason}${avail}`,
        parsed: { ok: false, mode, reason, available: data.available ?? true },
      };
    }

    const lines: string[] = [];
    if (mode === 'frida') {
      const evts = data.events ?? [];
      lines.push(
        `instrument_trace frida (v${data.frida_version ?? '?'}) — ${evts.length} event${evts.length === 1 ? '' : 's'}` +
        (data.events_truncated ? ', TRUNCATED' : ''),
      );
      lines.push(`exit_code=${data.exit_code ?? '?'}  timed_out=${data.timed_out}  duration=${data.duration_ms}ms`);
      lines.push('─'.repeat(70));
      for (const ev of evts.slice(0, 50)) {
        const s = JSON.stringify(ev);
        lines.push(s.length > 400 ? `${s.substring(0, 400)}…` : s);
      }
      if (evts.length > 50) lines.push(`... ${evts.length - 50} more events ...`);
      if (data.stdout_tail) {
        lines.push('');
        lines.push('stdout:');
        lines.push(data.stdout_tail.substring(0, 1500));
      }
      if (data.stderr_tail) {
        lines.push('');
        lines.push('stderr:');
        lines.push(data.stderr_tail.substring(0, 1500));
      }
    } else {
      lines.push(
        `instrument_trace dynamorio (${data.dr_client}, v${data.dr_version ?? '?'})`,
      );
      lines.push(`exit_code=${data.exit_code ?? '?'}  timed_out=${data.timed_out}  duration=${data.duration_ms}ms`);
      lines.push('─'.repeat(70));
      if (data.coverage_summary) {
        lines.push(`coverage_summary: ${JSON.stringify(data.coverage_summary)}`);
      }
      if (data.target_stdout_tail) {
        lines.push('');
        lines.push('target stdout:');
        lines.push(data.target_stdout_tail.substring(0, 1500));
      }
      if (data.target_stderr_tail) {
        lines.push('');
        lines.push('target stderr:');
        lines.push(data.target_stderr_tail.substring(0, 1500));
      }
    }
    if (rationale) {
      lines.push('');
      lines.push(`Rationale: ${rationale}`);
    }

    return {
      output: lines.join('\n'),
      parsed: {
        ok: true,
        mode,
        rationale,
        ...data,
      },
    };
  },
};

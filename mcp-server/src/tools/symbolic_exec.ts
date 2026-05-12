import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';
import { resolveBinaryArg, ArtifactResolveError } from './_artifact_resolver';

// ---------------------------------------------------------------------------
// symbolic_exec — Tier-3 · T10 angr reachability / constraint solver.
//
// Given a binary artifact (pulled via artifact_pull, T3) and a target address
// (usually from binary_decompile, T4), asks: "can execution reach this
// address? under what symbolic input?" Returns a base64 input that, when
// fed to stdin or argv, makes the target reachable — or a definite
// "unreachable under these constraints" verdict.
//
// The AI uses this to narrow the input space before fuzzing (T9) or to
// prove a decompiled sink is actually callable before writing a forge
// request (T2). Pair it with fuzz_binary: angr narrows, AFL++ brute-forces
// the narrowed space.
// ---------------------------------------------------------------------------

const SYMBEX_URL = process.env.SYMBEX_URL || 'http://symbex:3501';
const DEFAULT_WALL_S = 60;

const definition: ToolDefinition = {
  name: 'symbolic_exec',
  description:
    'Ask angr whether a binary artifact can reach a target address and, if so, what symbolic stdin/argv input makes it happen. ' +
    'Use after binary_decompile (T4) identifies a suspect sink function to confirm reachability before crafting exploits. ' +
    'Hard wall-clock cap (180 s). Binary must live under /data/security/artifacts.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'binary_path', type: 'string', required: false, description: 'Path under /data/security/artifacts (from artifact_pull). Either this or artifact_id+session_id.' },
    { name: 'artifact_id', type: 'string', required: false, description: 'T23: sha256 of a pulled artifact; resolver fetches bytes (from local or MinIO).' },
    { name: 'session_id', type: 'string', required: false, description: 'Session UUID (required with artifact_id).' },
    { name: 'find_addr', type: 'string', required: true, description: 'Target address as integer or "0x..." hex string' },
    { name: 'avoid_addrs', type: 'string', required: false, description: 'JSON array of addresses to avoid' },
    { name: 'start_addr', type: 'string', required: false, description: 'Optional alternate start address (default = entry_state)' },
    { name: 'stdin_len', type: 'number', required: false, description: 'Number of symbolic stdin bytes to solve for (0-1024). 0 = no symbolic stdin.', default: 0 },
    { name: 'argv_symbolic_lens', type: 'string', required: false, description: 'JSON array of per-argv byte lengths (0 = concrete "")' },
    { name: 'wall_time_s', type: 'number', required: false, description: 'Wall-clock cap (5-180)', default: DEFAULT_WALL_S },
  ],
};

function parseJsonParam<T = unknown>(raw: unknown, fallback: T): T {
  if (!raw) return fallback;
  try { return JSON.parse(String(raw)) as T; } catch { return fallback; }
}

interface SymbexResponse {
  ok?: boolean;
  error?: string;
  reached?: boolean;
  explored_states?: number;
  duration_seconds?: number;
  binary?: string;
  find_addr?: string;
  avoid_count?: number;
  stdin_input_b64?: string;
  stdin_length?: number;
  argv_inputs_b64?: string[];
  note?: string;
}

export const symbolicExecTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    let binaryPath = '';
    try {
      const resolved = await resolveBinaryArg(params);
      if (resolved) binaryPath = resolved.path;
    } catch (err) {
      if (err instanceof ArtifactResolveError) {
        return { output: `artifact resolve failed: ${err.message}`, parsed: { error: err.message } };
      }
      throw err;
    }
    const findAddr = String(params.find_addr || '').trim();
    if (!binaryPath) return { output: 'binary_path (or artifact_id + session_id) required', parsed: { error: 'missing binary_path' } };
    if (!findAddr) return { output: 'find_addr required', parsed: { error: 'missing find_addr' } };

    const wallSec = Math.max(5, Math.min(180, Number(params.wall_time_s || DEFAULT_WALL_S)));

    const payload = {
      binary_path: binaryPath,
      find_addr: findAddr,
      avoid_addrs: parseJsonParam<string[]>(params.avoid_addrs, []),
      start_addr: params.start_addr != null ? String(params.start_addr) : undefined,
      stdin_len: Math.max(0, Math.min(1024, Number(params.stdin_len || 0))),
      argv_symbolic_lens: parseJsonParam<number[]>(params.argv_symbolic_lens, []),
      wall_time_s: wallSec,
    };

    const c = new AbortController();
    const timer = setTimeout(() => c.abort(), (wallSec + 45) * 1000);
    let resp: Response;
    try {
      resp = await fetch(`${SYMBEX_URL}/reachability`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: c.signal,
      });
    } catch (err) {
      return { output: `symbex unreachable: ${err}`, parsed: { error: String(err), symbex_url: SYMBEX_URL } };
    } finally {
      clearTimeout(timer);
    }

    const data = await resp.json() as SymbexResponse;
    if (!resp.ok || !data.ok) {
      return {
        output: `symbex error: ${data.error || `HTTP ${resp.status}`}`,
        parsed: { error: data.error || `http_${resp.status}` },
      };
    }

    const lines: string[] = [
      `symbolic_exec · ${data.binary}`,
      `find_addr: ${data.find_addr}   avoid_count: ${data.avoid_count ?? 0}`,
      `reached: ${data.reached ? 'YES' : 'no'}   states_explored: ${data.explored_states}   duration: ${data.duration_seconds}s`,
      data.note ? `note: ${data.note}` : '',
    ].filter(Boolean) as string[];

    if (data.reached) {
      if (data.stdin_input_b64) {
        lines.push(`stdin_input_b64 (${data.stdin_length} bytes): ${data.stdin_input_b64.substring(0, 120)}${data.stdin_input_b64.length > 120 ? '…' : ''}`);
      }
      if (data.argv_inputs_b64 && data.argv_inputs_b64.length > 0) {
        lines.push(`argv_inputs_b64 (${data.argv_inputs_b64.length} args):`);
        for (const a of data.argv_inputs_b64.slice(0, 6)) {
          lines.push(`  ${a.substring(0, 100)}`);
        }
      }
    }

    return {
      output: lines.join('\n'),
      parsed: {
        reached: Boolean(data.reached),
        explored_states: data.explored_states,
        duration_seconds: data.duration_seconds,
        find_addr: data.find_addr,
        avoid_count: data.avoid_count,
        stdin_input_b64: data.stdin_input_b64,
        stdin_length: data.stdin_length,
        argv_inputs_b64: data.argv_inputs_b64 || [],
        note: data.note,
      },
    };
  },
};

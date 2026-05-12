import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';
import { resolveBinaryArg, ArtifactResolveError } from './_artifact_resolver';

// ---------------------------------------------------------------------------
// fuzz_binary — Tier-3 · T9 coverage-guided fuzzing.
//
// Point the fuzzer at an artifact pulled via artifact_pull (T3), give it an
// initial seed corpus (base64-encoded inputs), and run AFL++ or honggfuzz for
// a bounded duration. Crashes come back inline (base64) so the AI can reason
// about them, write a forge request that demonstrates the bug, or hand the
// crash to symbolic_exec (T10) for a reachability check.
// ---------------------------------------------------------------------------

const FUZZER_URL = process.env.FUZZER_URL || 'http://fuzzer:3401';
const DEFAULT_DURATION = 60;

const definition: ToolDefinition = {
  name: 'fuzz_binary',
  description:
    'Coverage-guided fuzz a user-mode binary artifact (pulled via artifact_pull) with AFL++. ' +
    'Provide an initial seed corpus (base64 strings) and an argv template with @@ for the input-file placeholder. ' +
    'Returns crash samples, corpus count, and fuzzer stdout/stderr. Duration is capped at 600 s per call. ' +
    'Optional `grammar` param (T24) seeds AFL++ with a format-specific dictionary — currently ships: ' +
    'json, xml, http, js, yaml, toml, sql, jwt, dns, tls, pdf, protobuf, asn1, msgpack, cbor. ' +
    'Use the grammar when the target parses a known structured format; finds crashes orders of ' +
    'magnitude faster than pure random mutation on strict parsers.',
  status: 'available',
  version: '1.1.0',
  parameters: [
    { name: 'binary_path', type: 'string', required: false, description: 'Absolute path to binary inside /data/security/artifacts (from artifact_pull). Either this or artifact_id+session_id.' },
    { name: 'artifact_id', type: 'string', required: false, description: 'T23: sha256 of an already-pulled artifact. Resolver fetches bytes (from local or MinIO) before fuzzing. Requires session_id.' },
    { name: 'session_id', type: 'string', required: false, description: 'Session UUID (required with artifact_id).' },
    { name: 'seeds', type: 'string', required: true, description: 'JSON array of base64-encoded seed inputs — at least 1' },
    { name: 'argv_template', type: 'string', required: false, description: 'JSON array of argv parts, exactly one "@@" placeholder for the input file. Default ["@@"].' },
    { name: 'duration_seconds', type: 'number', required: false, description: 'Fuzz run duration (10-600)', default: DEFAULT_DURATION },
    { name: 'engine', type: 'string', required: false, description: 'afl++ (only supported engine in this build)', default: 'afl++' },
    { name: 'grammar', type: 'string', required: false, description: 'Optional grammar dictionary name (json|xml|http|js|yaml|toml|sql|jwt|dns|tls|pdf|protobuf|asn1|msgpack|cbor). Unknown names are a soft fallback to pure random mutation.' },
  ],
};

function parseJsonParam<T = unknown>(raw: unknown, fallback: T): T {
  if (!raw) return fallback;
  try { return JSON.parse(String(raw)) as T; } catch { return fallback; }
}

interface FuzzResponse {
  ok?: boolean;
  error?: string;
  run_id?: string;
  engine?: string;
  binary?: string;
  duration_seconds?: number;
  requested_duration_seconds?: number;
  seed_count?: number;
  corpus_count?: number;
  crash_count?: number;
  crashes?: Array<{ filename: string; size: number; input_b64: string }>;
  exit_code?: number | null;
  stdout_tail?: string;
  stderr_tail?: string;
  grammar?: string | null;
  grammar_used?: boolean;
}

export const fuzzBinaryTool = {
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
    if (!binaryPath) return { output: 'binary_path (or artifact_id + session_id) required', parsed: { error: 'missing binary_path' } };

    const seeds = parseJsonParam<string[]>(params.seeds, []);
    if (!Array.isArray(seeds) || seeds.length === 0) {
      return { output: 'seeds required (JSON array of base64 strings)', parsed: { error: 'missing seeds' } };
    }

    const argv = parseJsonParam<string[]>(params.argv_template, ['@@']);
    const duration = Math.max(10, Math.min(600, Number(params.duration_seconds || DEFAULT_DURATION)));
    const engine = String(params.engine || 'afl++').toLowerCase();
    const grammar = String(params.grammar || '').trim().toLowerCase();

    const payload: Record<string, unknown> = {
      binary_path: binaryPath,
      seeds,
      argv_template: argv,
      duration_seconds: duration,
      engine,
    };
    if (grammar) payload.grammar = grammar;

    const c = new AbortController();
    const timer = setTimeout(() => c.abort(), (duration + 60) * 1000);
    let resp: Response;
    try {
      resp = await fetch(`${FUZZER_URL}/fuzz`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: c.signal,
      });
    } catch (err) {
      return { output: `fuzzer unreachable: ${err}`, parsed: { error: String(err), fuzzer_url: FUZZER_URL } };
    } finally {
      clearTimeout(timer);
    }

    if (!resp.ok) {
      const body = await resp.text().catch(() => '');
      return {
        output: `fuzzer HTTP ${resp.status}: ${body.substring(0, 400)}`,
        parsed: { error: 'fuzzer_http_error', status: resp.status, body: body.substring(0, 400) },
      };
    }

    const data = await resp.json() as FuzzResponse;
    if (!data.ok) {
      return { output: `fuzz run failed: ${data.error || 'unknown'}`, parsed: { error: data.error } };
    }

    const lines: string[] = [
      `fuzz_binary ${data.engine} · run=${data.run_id}`,
      `binary: ${data.binary}`,
      `duration: ${data.duration_seconds}s (requested ${data.requested_duration_seconds}s)`,
      `seeds: ${data.seed_count}   corpus: ${data.corpus_count}   crashes: ${data.crash_count}`,
    ];
    if (data.grammar) {
      lines.push(`grammar: ${data.grammar}${data.grammar_used ? ' (seeded)' : ' (missing — fell back to random mutation)'}`);
    }
    if (data.crash_count && data.crashes) {
      lines.push('');
      lines.push('Crashes:');
      for (const crash of data.crashes.slice(0, 6)) {
        lines.push(`  ${crash.filename} (${crash.size} bytes)`);
      }
    }
    if (data.stderr_tail) {
      lines.push('');
      lines.push('stderr_tail:');
      lines.push(data.stderr_tail.substring(0, 1500));
    }

    return {
      output: lines.join('\n'),
      parsed: {
        run_id: data.run_id,
        engine: data.engine,
        duration_seconds: data.duration_seconds,
        seed_count: data.seed_count,
        corpus_count: data.corpus_count,
        crash_count: data.crash_count,
        crashes: data.crashes || [],
        exit_code: data.exit_code,
        stdout_tail: (data.stdout_tail || '').substring(0, 1500),
        stderr_tail: (data.stderr_tail || '').substring(0, 1500),
        grammar: data.grammar ?? null,
        grammar_used: Boolean(data.grammar_used),
      },
    };
  },
};

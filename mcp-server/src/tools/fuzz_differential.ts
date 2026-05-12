import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

// ---------------------------------------------------------------------------
// fuzz_differential — T24 differential fuzzer.
//
// Runs each seed through TWO binaries and reports semantic disagreements.
// Classic "same input, two implementations" check: useful for patched vs
// unpatched builds, or for divergence-finding across competing parsers
// (OpenSSL vs BoringSSL on a malformed ClientHello, say). This is NOT
// coverage-guided — the caller provides the seed corpus; pair with
// fuzz_binary to generate the corpus first and re-use it here.
// ---------------------------------------------------------------------------

const FUZZER_URL = process.env.FUZZER_URL || 'http://fuzzer:3401';
const DEFAULT_DURATION = 60;

const definition: ToolDefinition = {
  name: 'fuzz_differential',
  description:
    'Differential fuzz: run each seed through two binaries and report divergent behaviour. ' +
    'oracle="stdout" flags when the two implementations produce different stdout; ' +
    '"exit_code" flags different exit codes; "both" flags either. Pair with fuzz_binary: ' +
    'run AFL++ on the patched binary to produce a crash + interesting corpus, then hand the ' +
    'corpus to fuzz_differential pointed at patched + unpatched to validate the fix landed. ' +
    'Per-seed wall-time 5s; total run duration capped at 600s; up to 32 divergences returned.',
  status: 'available',
  version: '0.1.0',
  parameters: [
    { name: 'binaries', type: 'string', required: true, description: 'JSON array with exactly two artifact paths under /data/security/artifacts' },
    { name: 'seeds', type: 'string', required: true, description: 'JSON array of base64-encoded seed inputs — at least 1, cap 64' },
    { name: 'argv_template', type: 'string', required: false, description: 'JSON array of argv parts with exactly one "@@" placeholder' },
    { name: 'oracle', type: 'string', required: false, description: 'stdout | exit_code | both (default both)' },
    { name: 'duration_seconds', type: 'number', required: false, description: 'Overall run budget (1-600)', default: DEFAULT_DURATION },
    { name: 'rationale', type: 'string', required: false, description: 'One sentence: what divergence would prove' },
  ],
};

function parseJsonParam<T = unknown>(raw: unknown, fallback: T): T {
  if (!raw) return fallback;
  try { return JSON.parse(String(raw)) as T; } catch { return fallback; }
}

interface DiffResponse {
  ok?: boolean;
  error?: string;
  run_id?: string;
  binary_a?: string;
  binary_b?: string;
  oracle?: string;
  duration_seconds?: number;
  requested_duration_seconds?: number;
  seeds_tried?: number;
  seeds_skipped?: number;
  divergence_count?: number;
  divergences?: Array<{
    seed_index: number;
    seed_sha1: string;
    seed_b64: string;
    reasons: string[];
    trace_a: Record<string, unknown>;
    trace_b: Record<string, unknown>;
  }>;
  hit_divergence_cap?: boolean;
}

export const fuzzDifferentialTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const binaries = parseJsonParam<string[]>(params.binaries, []);
    if (!Array.isArray(binaries) || binaries.length !== 2) {
      return {
        output: 'binaries must be a JSON array of exactly 2 artifact paths',
        parsed: { error: 'bad_binaries_arg', ok: false },
      };
    }

    const seeds = parseJsonParam<string[]>(params.seeds, []);
    if (!Array.isArray(seeds) || seeds.length === 0) {
      return {
        output: 'seeds required (JSON array of base64 strings)',
        parsed: { error: 'missing_seeds', ok: false },
      };
    }

    const argv = parseJsonParam<string[]>(params.argv_template, ['@@']);
    const oracle = String(params.oracle || 'both').toLowerCase();
    const duration = Math.max(1, Math.min(600, Number(params.duration_seconds || DEFAULT_DURATION)));
    const rationale = String(params.rationale || '');

    const payload = {
      binaries,
      seeds,
      argv_template: argv,
      oracle,
      duration_seconds: duration,
    };

    let resp: Response;
    try {
      const c = new AbortController();
      const timer = setTimeout(() => c.abort(), (duration + 60) * 1000);
      resp = await fetch(`${FUZZER_URL}/fuzz_diff`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: c.signal,
      });
      clearTimeout(timer);
    } catch (err) {
      return {
        output: `fuzzer unreachable: ${err}`,
        parsed: { error: String(err), fuzzer_url: FUZZER_URL, ok: false },
      };
    }

    if (!resp.ok) {
      const body = await resp.text().catch(() => '');
      return {
        output: `fuzzer HTTP ${resp.status}: ${body.substring(0, 400)}`,
        parsed: { error: 'fuzzer_http_error', status: resp.status, body: body.substring(0, 2000), ok: false },
      };
    }

    const data = await resp.json() as DiffResponse;
    if (!data.ok) {
      return {
        output: `fuzz_differential failed: ${data.error || 'unknown'}`,
        parsed: { error: data.error, ok: false },
      };
    }

    const divs = data.divergences ?? [];
    const lines: string[] = [
      `fuzz_differential · run=${data.run_id}  oracle=${data.oracle}`,
      `binary A: ${data.binary_a}`,
      `binary B: ${data.binary_b}`,
      `duration: ${data.duration_seconds}s (requested ${data.requested_duration_seconds}s)`,
      `seeds tried: ${data.seeds_tried}  skipped: ${data.seeds_skipped}  divergences: ${data.divergence_count}${data.hit_divergence_cap ? ' (hit cap)' : ''}`,
    ];
    if (divs.length > 0) {
      lines.push('');
      lines.push('Divergences:');
      for (const d of divs.slice(0, 8)) {
        lines.push(`  seed#${d.seed_index} sha1=${d.seed_sha1}  ${d.reasons.join('; ')}`);
      }
      if (divs.length > 8) lines.push(`  … ${divs.length - 8} more`);
    }
    if (rationale) {
      lines.push('');
      lines.push(`Rationale: ${rationale}`);
    }

    return {
      output: lines.join('\n'),
      parsed: {
        ok: true,
        run_id: data.run_id,
        binary_a: data.binary_a,
        binary_b: data.binary_b,
        oracle: data.oracle,
        duration_seconds: data.duration_seconds,
        seeds_tried: data.seeds_tried,
        seeds_skipped: data.seeds_skipped,
        divergence_count: data.divergence_count,
        divergences: divs,
        hit_divergence_cap: Boolean(data.hit_divergence_cap),
        rationale,
      },
    };
  },
};

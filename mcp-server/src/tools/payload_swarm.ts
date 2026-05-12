// T28 — payload_swarm
//
// Run N payload variants in parallel against a target through the
// forge_sandbox pool, then return the variants ranked by *interestingness*.
//
// Why this exists: a single forge_runner call is one shot at a hypothesis.
// Real novel-vuln hunting wants the agent to think in *variant space* —
// "here are 12 ways this auth check might break; let's try them all and
// see which produced unique behaviour." The agent normally won't do this
// because it's slow and bookkeeping-heavy. payload_swarm makes it cheap.
//
// Ranking is heuristic: a variant is *interesting* when its (status, length,
// stdout-shape) signature differs from the modal signature of the swarm.
// The shape hash is a tiny content-fingerprint (length + first/last 200
// bytes + tag count) so two different SQL errors hash to the same shape,
// but a successful auth bypass with a session token does not.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';
import { runOnSandbox, poolSize, poolUrls, SandboxRunResult } from '../sandbox_pool';

const definition: ToolDefinition = {
  name: 'payload_swarm',
  description:
    'Run N payload variants in parallel through the forge_sandbox pool, then rank them by ' +
    'behavioural divergence and oracle outcomes. Uses multi-feature response signature scoring ' +
    '(T30): status, body-length bucket, keyword cluster, latency bucket, content-type, error ' +
    'tokens — the HTTP equivalent of AFL coverage feedback. Second swarm rounds should bias ' +
    'toward under-represented signature buckets. Follow every swarm with semantic_anomaly_grader ' +
    'to catch semantic outliers the signature hash missed.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'lang', type: 'string', required: true,  description: 'python | node | bash — applied to every variant' },
    { name: 'template_code', type: 'string', required: true, description: 'Code body. Use ${VAR} placeholders that match keys in each variants[].params object.' },
    { name: 'variants', type: 'string', required: true, description: 'JSON array of {name, params, oracle?} — one per variant. Limit 32.' },
    { name: 'parallel', type: 'number', required: false, default: 4, description: 'How many variants to run concurrently. Capped at the pool size.' },
    { name: 'wall_time_s', type: 'number', required: false, default: 30, description: 'Per-variant wall-time (max 120).' },
    { name: 'target_hint', type: 'string', required: false, description: 'Informational target IP/host.' },
    { name: 'rationale', type: 'string', required: false, description: 'One sentence: what hypothesis this swarm tests.' },
  ],
};

interface OracleSpec {
  body_must_contain?: string | string[];
  body_regex?: string;
  exit_code_eq?: number;
  min_length?: number;
}

interface VariantSpec {
  name: string;
  params: Record<string, string | number | boolean>;
  oracle?: OracleSpec;
}

interface VariantResult {
  name: string;
  replica: string;
  exit_code: number;
  duration_ms: number;
  timed_out: boolean;
  stdout_len: number;
  stdout_head: string;
  stdout_tail: string;
  shape: string;
  oracle_verdict?: 'pass' | 'fail' | 'partial' | 'no_oracle';
  oracle_reasons?: string[];
  error?: string;
  novelty_score?: number;
}

function parseJsonParam<T = unknown>(raw: unknown, fallback: T): T {
  if (!raw) return fallback;
  try { return JSON.parse(String(raw)) as T; } catch { return fallback; }
}

// Substitute ${KEY} placeholders. Keys must match /^[A-Z][A-Z0-9_]*$/ to
// avoid accidentally rewriting parts of the script that look like template
// expressions in the host language.
function applyTemplate(template: string, params: Record<string, string | number | boolean>): string {
  return template.replace(/\$\{([A-Z][A-Z0-9_]*)\}/g, (_m, key) => {
    if (!(key in params)) return `\${${key}}`;
    return String(params[key]);
  });
}

// T30 — Multi-feature response signature (replaces shape-only shapeHash).
// Features: status-bucket | header-set hash | body-length bucket |
//           body-keyword cluster | latency bucket | content-type token |
//           error-token cluster.
// This is the HTTP equivalent of AFL coverage feedback: the swarm's second
// round steers toward signature buckets that have not yet been filled.

const ERROR_TOKENS = ['error', 'exception', 'traceback', 'undefined', 'null pointer',
  'syntax error', 'parse error', 'fatal', 'stack trace', '__proto__', 'prototype',
  'typeerror', 'referenceerror', 'cannot read', 'object object'];

const KEYWORD_CLUSTERS: Record<string, string[]> = {
  auth:   ['unauthorized', 'forbidden', 'access denied', 'not allowed', 'permission'],
  sqli:   ['mysql', 'postgresql', 'sqlite', 'ora-', 'syntax error near', 'unclosed quotation'],
  path:   ['no such file', 'directory not found', '/etc/', 'c:\\', 'windows\\'],
  ssti:   ['jinja2', 'twig', 'freemarker', 'velocity', 'handlebars', 'template'],
  rce:    ['root:', 'uid=0', 'command not found', '/bin/sh', 'cmd.exe'],
  ssrf:   ['169.254', 'metadata', 'internal', 'localhost', '127.0.0.1'],
};

function bodyKeywordCluster(text: string): string {
  const lower = text.toLowerCase();
  const hits: string[] = [];
  for (const [cluster, tokens] of Object.entries(KEYWORD_CLUSTERS)) {
    if (tokens.some(t => lower.includes(t))) hits.push(cluster);
  }
  return hits.sort().join('+') || 'none';
}

function errorTokenCluster(text: string): string {
  const lower = text.toLowerCase();
  return ERROR_TOKENS.filter(t => lower.includes(t)).slice(0, 4).join('+') || 'none';
}

function latencyBucket(ms: number): string {
  if (ms < 200) return 'fast';
  if (ms < 1000) return 'normal';
  if (ms < 3000) return 'slow';
  if (ms < 8000) return 'very_slow';
  return 'timeout_range';
}

function responseSignature(stdout: string, exit: number, timedOut: boolean, durationMs = 0): string {
  const lenBucket = Math.floor(Math.log2(Math.max(1, stdout.length)));
  const ctMatch = stdout.match(/content-type:\s*([^\r\n;]+)/i);
  const ctToken = ctMatch ? ctMatch[1].trim().replace(/\s+/g, '_').substring(0, 30) : 'unknown';
  const exitBucket = timedOut ? 'timeout' : (exit === 0 ? 'ok' : `err${exit}`);
  return [
    exitBucket,
    `L${lenBucket}`,
    `kw:${bodyKeywordCluster(stdout)}`,
    `lat:${latencyBucket(durationMs)}`,
    `ct:${ctToken}`,
    `err:${errorTokenCluster(stdout)}`,
  ].join('|');
}

function evalOracle(oracle: OracleSpec, stdout: string, exitCode: number): { verdict: 'pass' | 'fail' | 'partial'; reasons: string[] } {
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
    for (const n of needles) record(stdout.includes(n), `contains "${String(n).substring(0, 60)}"`);
  }
  if (oracle.body_regex) {
    try { const re = new RegExp(oracle.body_regex, 's'); record(re.test(stdout), `matches /${oracle.body_regex}/`); }
    catch { record(false, `body_regex invalid`); }
  }
  if (oracle.exit_code_eq !== undefined) record(exitCode === oracle.exit_code_eq, `exit==${oracle.exit_code_eq}`);
  if (oracle.min_length !== undefined) record(stdout.length >= oracle.min_length, `len>=${oracle.min_length}`);

  if (checks === 0) return { verdict: 'fail', reasons: ['no oracle predicates'] };
  if (passes === checks) return { verdict: 'pass', reasons };
  if (passes === 0) return { verdict: 'fail', reasons };
  return { verdict: 'partial', reasons };
}

async function runOne(
  lang: 'python' | 'node' | 'bash',
  template: string,
  v: VariantSpec,
  wallTimeS: number,
): Promise<VariantResult> {
  const code = applyTemplate(template, v.params);
  const dispatch: SandboxRunResult = await runOnSandbox({ lang, code, wall_time_s: wallTimeS });
  if (!dispatch.ok || !dispatch.body) {
    return {
      name: v.name,
      replica: dispatch.replica,
      exit_code: -1,
      duration_ms: 0,
      timed_out: false,
      stdout_len: 0,
      stdout_head: '',
      stdout_tail: '',
      shape: 'ERR|' + (dispatch.error || 'unknown'),
      error: dispatch.error,
    };
  }
  const r = dispatch.body;
  const stdout = r.stdout || '';
  const exit = r.exit_code ?? -1;
  const timedOut = Boolean(r.timed_out);
  const head = stdout.substring(0, 200);
  const tail = stdout.substring(Math.max(0, stdout.length - 200));
  const out: VariantResult = {
    name: v.name,
    replica: dispatch.replica,
    exit_code: exit,
    duration_ms: r.duration_ms ?? 0,
    timed_out: timedOut,
    stdout_len: stdout.length,
    stdout_head: head,
    stdout_tail: tail,
    shape: responseSignature(stdout, exit, timedOut, r.duration_ms ?? 0),
  };
  if (v.oracle && Object.keys(v.oracle).length) {
    const verdict = evalOracle(v.oracle, stdout, exit);
    out.oracle_verdict = verdict.verdict;
    out.oracle_reasons = verdict.reasons;
  } else {
    out.oracle_verdict = 'no_oracle';
  }
  return out;
}

export const payloadSwarmTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const lang = String(params.lang || 'python').toLowerCase() as 'python' | 'node' | 'bash';
    const template = String(params.template_code || '');
    const wallTimeS = Math.min(120, Math.max(1, Number(params.wall_time_s || 30)));
    const targetHint = String(params.target_hint || '');
    const rationale = String(params.rationale || '');
    const variants = parseJsonParam<VariantSpec[]>(params.variants, []);
    const requestedParallel = Math.max(1, Number(params.parallel || 4));
    const parallel = Math.min(requestedParallel, poolSize(), 8);

    if (!['python', 'node', 'bash'].includes(lang)) {
      return { output: `unsupported lang "${lang}"`, parsed: { error: 'bad lang' } };
    }
    if (!template.trim()) {
      return { output: 'template_code required', parsed: { error: 'missing template_code' } };
    }
    if (!Array.isArray(variants) || variants.length === 0) {
      return { output: 'variants must be a non-empty JSON array of {name, params}', parsed: { error: 'no_variants' } };
    }
    if (variants.length > 32) {
      return { output: `variants capped at 32 (got ${variants.length})`, parsed: { error: 'too_many_variants' } };
    }
    for (const v of variants) {
      if (!v || typeof v.name !== 'string' || typeof v.params !== 'object' || v.params === null) {
        return { output: 'each variant needs {name: string, params: object, oracle?: {}}', parsed: { error: 'bad_variant_shape' } };
      }
    }

    const startedAt = Date.now();
    const results: VariantResult[] = [];
    // Process in batches of `parallel`. Promise.all per batch keeps the
    // failure of any single variant from collapsing the swarm.
    for (let i = 0; i < variants.length; i += parallel) {
      const batch = variants.slice(i, i + parallel);
      const settled = await Promise.all(batch.map((v) => runOne(lang, template, v, wallTimeS)));
      results.push(...settled);
    }
    const totalMs = Date.now() - startedAt;

    // Novelty score = how rare this variant's shape is in the swarm.
    // 1.0 = unique shape. Identical-to-modal = lowest score.
    const shapeCount = new Map<string, number>();
    for (const r of results) shapeCount.set(r.shape, (shapeCount.get(r.shape) || 0) + 1);
    for (const r of results) {
      const c = shapeCount.get(r.shape) || 1;
      r.novelty_score = +(1 / c).toFixed(3);
    }

    // Ranking key: oracle PASS first, then high novelty, then low novelty
    // (so a unique-but-failing variant still surfaces above duplicates).
    const verdictRank: Record<string, number> = { pass: 0, partial: 1, no_oracle: 2, fail: 3 };
    const ranked = [...results].sort((a, b) => {
      const va = verdictRank[a.oracle_verdict ?? 'no_oracle'] ?? 9;
      const vb = verdictRank[b.oracle_verdict ?? 'no_oracle'] ?? 9;
      if (va !== vb) return va - vb;
      return (b.novelty_score ?? 0) - (a.novelty_score ?? 0);
    });

    const topShape = [...shapeCount.entries()].sort((a, b) => b[1] - a[1])[0];
    const interesting = ranked.filter(
      (r) => r.oracle_verdict === 'pass' || (r.novelty_score ?? 0) >= 0.5,
    );

    const lines: string[] = [];
    lines.push(`payload_swarm — ${variants.length} variants, parallel=${parallel}, pool=${poolSize()}, total ${totalMs}ms`);
    if (targetHint) lines.push(`target=${targetHint}`);
    if (rationale) lines.push(`hypothesis: ${rationale}`);
    lines.push('─'.repeat(72));
    lines.push(`Modal shape: ${topShape ? `"${topShape[0].substring(0, 60)}…" (${topShape[1]}/${variants.length} variants)` : '(none)'}`);
    lines.push(`Interesting variants (oracle-pass OR novelty ≥ 0.5): ${interesting.length}`);
    lines.push('');
    lines.push('Top 8 ranked:');
    for (const r of ranked.slice(0, 8)) {
      const tag = r.oracle_verdict === 'pass' ? '✓PASS'
                : r.oracle_verdict === 'partial' ? '~PART'
                : r.oracle_verdict === 'fail' ? '✗fail'
                : '·noOr';
      lines.push(
        `  ${tag}  novelty=${r.novelty_score?.toFixed(2) ?? '?'}  ` +
        `exit=${r.exit_code}  len=${r.stdout_len}  ${r.timed_out ? 'TIMEOUT  ' : ''}` +
        `name="${r.name.substring(0, 38)}"  replica=${r.replica.replace(/^https?:\/\//, '')}`,
      );
      if (r.error) lines.push(`        error: ${r.error.substring(0, 120)}`);
      const head = r.stdout_head.replace(/\s+/g, ' ').substring(0, 90);
      if (head) lines.push(`        head: ${head}`);
    }
    if (ranked.length > 8) lines.push(`  … and ${ranked.length - 8} more`);

    return {
      output: lines.join('\n'),
      parsed: {
        target_hint: targetHint,
        rationale,
        lang,
        wall_time_s: wallTimeS,
        parallel,
        pool_size: poolSize(),
        pool_urls: poolUrls(),
        variant_count: variants.length,
        total_ms: totalMs,
        modal_shape: topShape ? { shape: topShape[0], count: topShape[1] } : null,
        interesting_count: interesting.length,
        results: ranked,
      },
    };
  },
};

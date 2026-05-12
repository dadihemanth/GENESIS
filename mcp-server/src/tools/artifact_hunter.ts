import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

// ---------------------------------------------------------------------------
// artifact_hunter — surface exposure probe
//
// Given a target URL or IP, probes a curated list of common artifact-exposure
// endpoints: leaked .git/.svn, webpack sourcemaps referenced by served JS,
// Docker registry v2 catalog, Spring Boot actuator endpoints, OpenAPI/Swagger,
// /WEB-INF/, /META-INF/, S3 listings. Does NOT download — returns a candidate
// list for the LLM to triage. Pair with artifact_pull for retrieval.
// ---------------------------------------------------------------------------

const definition: ToolDefinition = {
  name: 'artifact_hunter',
  description:
    'Probe the target for exposed artifacts (binaries, source, config leaks). Returns a list of ' +
    'downloadable candidate URIs so the model can decide what to pull. Does not download anything.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'target', type: 'string', required: true, description: 'Target URL or IP (e.g. http://1.2.3.4:8080)' },
    { name: 'checks', type: 'string', required: false, description: 'Comma-separated subset: git,sourcemaps,docker,swagger,actuator,webinf,wellknown,composer,all', default: 'all' },
    { name: 'timeout_ms', type: 'number', required: false, description: 'Per-request timeout', default: 10000 },
  ],
};

interface Candidate {
  uri: string;
  kind: string;
  rationale: string;
  status?: number;
  size_hint?: number;
}

function normalizeBase(target: string): string {
  let t = target.trim();
  if (!/^https?:\/\//i.test(t)) {
    t = `http://${t}`;
  }
  // Strip trailing slash
  return t.replace(/\/+$/, '');
}

async function head(url: string, timeoutMs: number): Promise<{ status: number; len: number; body: string }> {
  try {
    const c = new AbortController();
    const timer = setTimeout(() => c.abort(), timeoutMs);
    const resp = await fetch(url, {
      method: 'GET',
      signal: c.signal,
      headers: { 'User-Agent': 'Mozilla/5.0 (GENESIS/MYTHOS artifact_hunter)' },
      redirect: 'manual',
    });
    clearTimeout(timer);
    const body = resp.status < 400 ? (await resp.text()).substring(0, 4000) : '';
    return { status: resp.status, len: body.length, body };
  } catch {
    return { status: 0, len: 0, body: '' };
  }
}

async function probeGitRepo(base: string, timeoutMs: number, out: Candidate[]): Promise<void> {
  const head_ = await head(`${base}/.git/HEAD`, timeoutMs);
  if (head_.status === 200 && /^ref: /.test(head_.body.trim())) {
    out.push({ uri: `${base}/.git/HEAD`, kind: 'git', rationale: `.git/HEAD exposed (${head_.body.trim().substring(0, 80)})`, status: 200 });
    // Probe common follow-ups
    for (const p of ['config', 'index', 'logs/HEAD', 'refs/heads/main', 'refs/heads/master']) {
      const r = await head(`${base}/.git/${p}`, timeoutMs);
      if (r.status === 200) {
        out.push({ uri: `${base}/.git/${p}`, kind: 'git', rationale: `.git/${p} readable`, status: 200, size_hint: r.len });
      }
    }
  }
  const svn = await head(`${base}/.svn/entries`, timeoutMs);
  if (svn.status === 200 && svn.body.length > 0) {
    out.push({ uri: `${base}/.svn/entries`, kind: 'svn', rationale: '.svn/entries exposed', status: 200 });
  }
  const ds = await head(`${base}/.DS_Store`, timeoutMs);
  if (ds.status === 200 && ds.len > 0) {
    out.push({ uri: `${base}/.DS_Store`, kind: 'metadata', rationale: '.DS_Store exposed — reveals directory listing', status: 200 });
  }
  const bzr = await head(`${base}/.bzr/branch/last-revision`, timeoutMs);
  if (bzr.status === 200 && bzr.len > 0) {
    out.push({ uri: `${base}/.bzr/branch/last-revision`, kind: 'bzr', rationale: '.bzr bazaar repo exposed', status: 200 });
  }
  const hg = await head(`${base}/.hg/requires`, timeoutMs);
  if (hg.status === 200 && hg.len > 0) {
    out.push({ uri: `${base}/.hg/requires`, kind: 'hg', rationale: '.hg mercurial repo exposed', status: 200 });
  }
}

async function probeSourcemaps(base: string, timeoutMs: number, out: Candidate[]): Promise<void> {
  // Fetch root HTML, look for .js references, then probe for a sibling .js.map
  const root = await head(base, timeoutMs);
  if (root.status !== 200 || !root.body) return;
  const jsRefs = new Set<string>();
  const re = /(?:src|href)\s*=\s*["']([^"']+\.js)(?:\?[^"']*)?["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(root.body)) !== null) {
    jsRefs.add(m[1]);
    if (jsRefs.size >= 5) break;
  }
  for (const ref of jsRefs) {
    const mapUrl = ref.startsWith('http') ? `${ref}.map` : `${base}/${ref.replace(/^\//, '')}.map`;
    const r = await head(mapUrl, timeoutMs);
    if (r.status === 200 && r.body.includes('"sources"')) {
      out.push({ uri: mapUrl, kind: 'sourcemap', rationale: `webpack sourcemap exposed for ${ref}`, status: 200, size_hint: r.len });
    }
  }
}

async function probeDockerRegistry(base: string, timeoutMs: number, out: Candidate[]): Promise<void> {
  const cat = await head(`${base}/v2/_catalog`, timeoutMs);
  if (cat.status === 200 && cat.body.includes('"repositories"')) {
    out.push({ uri: `${base}/v2/_catalog`, kind: 'docker_catalog', rationale: 'Docker registry v2 catalog exposed', status: 200 });
    try {
      const parsed = JSON.parse(cat.body) as { repositories?: string[] };
      for (const repo of (parsed.repositories || []).slice(0, 10)) {
        out.push({ uri: `${base}/v2/${repo}/tags/list`, kind: 'docker_repo', rationale: `Docker repo "${repo}" tags readable`, status: 200 });
      }
    } catch { /* ignore */ }
  }
  // Also check for the ping endpoint which often confirms an open registry with no auth.
  const ping = await head(`${base}/v2/`, timeoutMs);
  if (ping.status === 200 && (ping.body === '{}' || ping.body.length === 0)) {
    out.push({ uri: `${base}/v2/`, kind: 'docker_ping', rationale: 'Docker registry v2 ping returns 200 with empty body (anonymous access)', status: 200 });
  }
}

async function probeSwagger(base: string, timeoutMs: number, out: Candidate[]): Promise<void> {
  const paths = ['/swagger.json', '/openapi.json', '/v2/api-docs', '/v3/api-docs', '/api-docs', '/swagger/v1/swagger.json', '/swagger/index.html'];
  for (const p of paths) {
    const r = await head(`${base}${p}`, timeoutMs);
    if (r.status === 200 && (r.body.includes('"swagger"') || r.body.includes('"openapi"') || r.body.includes('<title>Swagger UI'))) {
      out.push({ uri: `${base}${p}`, kind: 'openapi', rationale: `OpenAPI/Swagger schema exposed at ${p}`, status: 200, size_hint: r.len });
    }
  }
}

async function probeActuator(base: string, timeoutMs: number, out: Candidate[]): Promise<void> {
  // Spring Boot actuator — check a few well-known paths (including the /actuator prefix variant)
  const paths = [
    '/actuator', '/actuator/env', '/actuator/heapdump', '/actuator/mappings',
    '/actuator/beans', '/actuator/threaddump', '/actuator/configprops', '/actuator/loggers',
    '/env', '/heapdump', '/trace', '/mappings',
  ];
  for (const p of paths) {
    const r = await head(`${base}${p}`, timeoutMs);
    if (r.status === 200 && r.len > 0) {
      out.push({ uri: `${base}${p}`, kind: 'actuator', rationale: `Spring Boot actuator exposed: ${p}`, status: 200, size_hint: r.len });
    }
  }
}

async function probeWebinf(base: string, timeoutMs: number, out: Candidate[]): Promise<void> {
  const paths = ['/WEB-INF/web.xml', '/WEB-INF/classes/application.properties', '/META-INF/MANIFEST.MF', '/META-INF/context.xml'];
  for (const p of paths) {
    const r = await head(`${base}${p}`, timeoutMs);
    if (r.status === 200 && r.len > 0 && !r.body.includes('<html')) {
      out.push({ uri: `${base}${p}`, kind: 'java_config', rationale: `Java config exposed: ${p}`, status: 200, size_hint: r.len });
    }
  }
}

async function probeWellKnown(base: string, timeoutMs: number, out: Candidate[]): Promise<void> {
  const paths = ['/.env', '/.env.local', '/.env.production', '/config.json', '/wp-config.php.bak', '/backup.sql', '/database.sql', '/dump.sql'];
  for (const p of paths) {
    const r = await head(`${base}${p}`, timeoutMs);
    if (r.status === 200 && r.len > 0) {
      out.push({ uri: `${base}${p}`, kind: 'config_leak', rationale: `Config/backup leak: ${p}`, status: 200, size_hint: r.len });
    }
  }
}

async function probeComposer(base: string, timeoutMs: number, out: Candidate[]): Promise<void> {
  const paths = ['/composer.json', '/composer.lock', '/package.json', '/package-lock.json', '/yarn.lock', '/Pipfile.lock', '/requirements.txt', '/Gemfile.lock', '/go.mod', '/go.sum'];
  for (const p of paths) {
    const r = await head(`${base}${p}`, timeoutMs);
    if (r.status === 200 && r.len > 0 && !r.body.includes('<html')) {
      out.push({ uri: `${base}${p}`, kind: 'dependency_manifest', rationale: `Dependency manifest exposed: ${p} — feeds cve_patch_pull`, status: 200, size_hint: r.len });
    }
  }
}

export const artifactHunterTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const target = String(params.target || '');
    if (!target) return { output: 'target required', parsed: { error: 'missing target' } };

    const base = normalizeBase(target);
    const timeoutMs = Number(params.timeout_ms || 10000);
    const checks = String(params.checks || 'all').toLowerCase().split(',').map(s => s.trim()).filter(Boolean);
    const all = checks.includes('all');

    const candidates: Candidate[] = [];
    const probes: Array<[string, () => Promise<void>]> = [
      ['git',         () => probeGitRepo(base, timeoutMs, candidates)],
      ['sourcemaps',  () => probeSourcemaps(base, timeoutMs, candidates)],
      ['docker',      () => probeDockerRegistry(base, timeoutMs, candidates)],
      ['swagger',     () => probeSwagger(base, timeoutMs, candidates)],
      ['actuator',    () => probeActuator(base, timeoutMs, candidates)],
      ['webinf',      () => probeWebinf(base, timeoutMs, candidates)],
      ['wellknown',   () => probeWellKnown(base, timeoutMs, candidates)],
      ['composer',    () => probeComposer(base, timeoutMs, candidates)],
    ];

    for (const [name, fn] of probes) {
      if (all || checks.includes(name)) {
        try { await fn(); } catch { /* individual probe failure is non-fatal */ }
      }
    }

    const lines = [
      `artifact_hunter — ${base}`,
      `${'─'.repeat(70)}`,
    ];
    if (candidates.length === 0) {
      lines.push('No exposed artifacts detected across the selected probes.');
    } else {
      for (const c of candidates) {
        lines.push(`  [${c.kind}] ${c.uri}`);
        lines.push(`      ${c.rationale}`);
      }
      lines.push('');
      lines.push(`${candidates.length} candidate(s). Use artifact_pull with the URIs above to download.`);
    }

    return {
      output: lines.join('\n'),
      parsed: { base, count: candidates.length, candidates },
    };
  },
};

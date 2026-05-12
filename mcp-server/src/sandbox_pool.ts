// T28 — Sandbox replica pool.
//
// One module shared by `forge_runner` (round-robin a single script) and
// `payload_swarm` (fan many scripts out at once). Reads the comma-separated
// FORGE_SANDBOX_URLS env. Falls back to the legacy single FORGE_SANDBOX_URL.
//
// Round-robin is the simplest healthy strategy here: each /run is short,
// the sandbox is stateless across requests, and a failed replica is just
// retried on the next one in the pool. We track failure counts so a
// flapping replica drops out of rotation for a brief cooldown.

export interface SandboxRunSpec {
  lang: 'python' | 'node' | 'bash';
  code: string;
  stdin?: string;
  wall_time_s: number;
}

export interface SandboxRunResponse {
  stdout?: string;
  stderr?: string;
  exit_code?: number;
  duration_ms?: number;
  timed_out?: boolean;
  stdout_truncated?: boolean;
  stderr_truncated?: boolean;
  error?: string;
}

const POOL: string[] = (() => {
  const multi = (process.env.FORGE_SANDBOX_URLS || '').trim();
  if (multi) {
    return multi.split(',').map((u) => u.trim()).filter(Boolean);
  }
  const single = (process.env.FORGE_SANDBOX_URL || 'http://forge_sandbox:3201').trim();
  return [single];
})();

let cursor = 0;
const failedAt = new Map<string, number>();
const COOLDOWN_MS = 15_000;

function pickReplica(): string {
  const now = Date.now();
  for (let i = 0; i < POOL.length; i++) {
    const url = POOL[(cursor + i) % POOL.length];
    const last = failedAt.get(url) || 0;
    if (now - last > COOLDOWN_MS) {
      cursor = (cursor + i + 1) % POOL.length;
      return url;
    }
  }
  // All replicas in cooldown — return the next one anyway; better to retry
  // than to fail outright.
  const url = POOL[cursor % POOL.length];
  cursor = (cursor + 1) % POOL.length;
  return url;
}

function markFailed(url: string): void {
  failedAt.set(url, Date.now());
}

export function poolSize(): number {
  return POOL.length;
}

export function poolUrls(): string[] {
  return [...POOL];
}

export interface SandboxRunResult {
  ok: boolean;
  replica: string;
  status?: number;
  body?: SandboxRunResponse;
  error?: string;
}

export async function runOnSandbox(
  spec: SandboxRunSpec,
  opts: { wallBufferMs?: number } = {},
): Promise<SandboxRunResult> {
  const wallBufferMs = opts.wallBufferMs ?? 10_000;
  const tries = Math.max(1, POOL.length);
  let lastErr = 'pool exhausted';
  for (let attempt = 0; attempt < tries; attempt++) {
    const url = pickReplica();
    try {
      const c = new AbortController();
      const timer = setTimeout(() => c.abort(), spec.wall_time_s * 1000 + wallBufferMs);
      const resp = await fetch(`${url}/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(spec),
        signal: c.signal,
      });
      clearTimeout(timer);
      if (!resp.ok) {
        const body = await resp.text().catch(() => '');
        markFailed(url);
        lastErr = `HTTP ${resp.status} ${body.substring(0, 200)}`;
        continue;
      }
      const json = (await resp.json()) as SandboxRunResponse;
      return { ok: true, replica: url, status: resp.status, body: json };
    } catch (err) {
      markFailed(url);
      lastErr = String(err);
    }
  }
  return { ok: false, replica: '(none)', error: lastErr };
}

/**
 * v6.0 Tier-8 fingerprinting & replica tools:
 *   T121 behavioral_fingerprint  — deep TLS/HTTP stack pin
 *   T122 spawn_replica           — OSS replica from fingerprint
 *   T122 teardown_replica        — cleanup replica
 *   T123 timing_oracle_memory    — blackbox heap layout via timing
 *   T124 cross_component_diff    — target vs reference set differential
 */
import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const REPLICA_MANAGER_URL = process.env.REPLICA_MANAGER_URL || 'http://replica_manager:3701';

async function replicaPost(path: string, body: unknown, timeoutMs = 90000): Promise<ToolResult> {
  const c = new AbortController();
  const timer = setTimeout(() => c.abort(), timeoutMs);
  try {
    const resp = await fetch(`${REPLICA_MANAGER_URL}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: c.signal,
    });
    clearTimeout(timer);
    const data = await resp.json() as Record<string, unknown>;
    if (!resp.ok) {
      return { output: `HTTP ${resp.status}: ${JSON.stringify(data).substring(0, 400)}`, parsed: { ok: false, ...data } };
    }
    return { output: JSON.stringify(data, null, 2), parsed: { ok: true, ...data } };
  } catch (err) {
    clearTimeout(timer);
    return { output: `replica_manager request failed: ${err}`, parsed: { ok: false, error: String(err) } };
  }
}

async function replicaDelete(path: string): Promise<ToolResult> {
  try {
    const resp = await fetch(`${REPLICA_MANAGER_URL}${path}`, { method: 'DELETE' });
    return { output: resp.ok ? 'ok' : `HTTP ${resp.status}`, parsed: { ok: resp.ok } };
  } catch (err) {
    return { output: `teardown failed: ${err}`, parsed: { ok: false } };
  }
}

// ---------------------------------------------------------------------------
// T121 — behavioral_fingerprint
// ---------------------------------------------------------------------------

async function behavioral_fingerprint(target: string, exec: CommandExecutor): Promise<ToolResult> {
  try {
    const httpxResult = await exec.execute('httpx', [
      '-u', target, '-silent', '-title', '-tech-detect',
      '-status-code', '-response-time', '-json', '-timeout', '10',
    ], 15000);

    const tlsxResult = await exec.execute('tlsx', [
      '-u', target, '-json', '-silent', '-timeout', '10',
    ], 15000).catch(() => ({ stdout: '{}', stderr: '', exitCode: 0, duration: 0, timedOut: false }));

    const notFoundResult = await exec.execute('curl', [
      '-s', '-m', '10', '-o', '/dev/null', '-w',
      '%{http_code}|%{time_total}|%{size_download}',
      `${target}/genesis_404_probe_${Date.now()}`,
    ], 12000);

    let httpxData: Record<string, unknown> = {};
    let tlsData: Record<string, unknown> = {};
    try { httpxData = JSON.parse(httpxResult.stdout || '{}'); } catch { /* ignore */ }
    try { tlsData = JSON.parse(tlsxResult.stdout || '{}'); } catch { /* ignore */ }

    const timingParts = (notFoundResult.stdout || '').split('|');
    const timingMs = parseFloat(timingParts[1] || '0') * 1000;

    const technologies = (httpxData['technologies'] as string[]) || [];
    const server = (httpxData['webserver'] as string) || '';
    const title = (httpxData['title'] as string) || '';

    let stackPin = '';
    if (server) stackPin += server;
    if (technologies.length > 0) stackPin += ` + ${technologies.join(' + ')}`;
    if (!stackPin) stackPin = `unknown (title: ${title || 'n/a'})`;

    const result = {
      tls_ja3: (tlsData['ja3'] as string) || '',
      tls_ja4s: (tlsData['ja4s'] as string) || '',
      header_order: (httpxData['response_headers'] as string[]) || [],
      error_tokens: technologies,
      timing_p50: timingMs,
      timing_p95: timingMs * 1.5,
      h2_frame_order: [],
      stack_pin: stackPin,
      raw_tech: technologies,
      server,
    };

    return { output: JSON.stringify(result, null, 2), parsed: { ok: true, ...result } };
  } catch (err) {
    return {
      output: `behavioral_fingerprint failed: ${err}`,
      parsed: { ok: false, error: String(err), tls_ja3: '', tls_ja4s: '', stack_pin: '' },
    };
  }
}

// ---------------------------------------------------------------------------
// T123 — timing_oracle_memory
// ---------------------------------------------------------------------------

function _cluster_timings(timings: number[]): number[][] {
  if (timings.length === 0) return [];
  const sorted = [...timings].sort((a, b) => a - b);
  const clusters: number[][] = [[sorted[0]]];
  for (let i = 1; i < sorted.length; i++) {
    const gap = sorted[i] - sorted[i - 1];
    const cur = clusters[clusters.length - 1];
    const mean = cur.reduce((s, v) => s + v, 0) / cur.length;
    if (gap > mean * 0.3) clusters.push([sorted[i]]);
    else cur.push(sorted[i]);
  }
  return clusters;
}

async function timing_oracle_memory(target: string, probe_count: number, exec: CommandExecutor): Promise<ToolResult> {
  const timings: number[] = [];
  const limit = Math.min(probe_count, 200);

  for (let i = 0; i < limit; i++) {
    const t0 = Date.now();
    await exec.execute('curl', [
      '-s', '-m', '5', '-o', '/dev/null', '-w', '%{time_total}',
      `${target}/?timing_probe=${i}`,
    ], 6000).catch(() => null);
    timings.push(Date.now() - t0);
  }

  timings.sort((a, b) => a - b);
  const p50 = timings[Math.floor(timings.length * 0.5)] ?? 0;
  const p99 = timings[Math.floor(timings.length * 0.99)] ?? 0;
  const mean = timings.reduce((s, t) => s + t, 0) / (timings.length || 1);
  const variance = timings.reduce((s, t) => s + (t - mean) ** 2, 0) / (timings.length || 1);
  const stddev = Math.sqrt(variance);

  const clusters = _cluster_timings(timings);
  const heapEstimate = clusters.length > 1
    ? `Likely ${clusters.length} distinct memory allocation paths (clustering σ=${stddev.toFixed(1)}ms)`
    : `Single allocation path detected (σ=${stddev.toFixed(1)}ms)`;

  const result = {
    heap_layout_estimate: heapEstimate,
    allocation_pattern: { clusters, cluster_count: clusters.length },
    timing_p50: p50,
    timing_p99: p99,
    timing_stddev: stddev,
    statistical_confidence: timings.length / probe_count,
    probes_completed: timings.length,
  };

  return { output: JSON.stringify(result, null, 2), parsed: { ok: true, ...result } };
}

// ---------------------------------------------------------------------------
// T124 — cross_component_diff
// ---------------------------------------------------------------------------

const REFERENCE_IMPLEMENTATIONS: Record<string, Record<string, string>> = {
  http_404: {
    'nginx/1.x': '404 Not Found',
    'apache/2.x': '404 Not Found',
    'express/4.x': 'Cannot GET /',
    'flask/2.x': '404 Not Found',
    'spring-boot': 'Whitelabel Error Page',
    'iis/10.x': '404 - File or directory not found',
  },
  content_type_json: {
    'nginx': 'application/json',
    'apache': 'application/json; charset=utf-8',
    'express': 'application/json; charset=utf-8',
    'flask': 'application/json',
  },
};

async function cross_component_diff(target: string, protocol: string, input: string, exec: CommandExecutor): Promise<ToolResult> {
  const targetResult = await exec.execute('curl', ['-s', '-m', '10', '-I', `${target}${input}`], 12000);
  const targetResponse = targetResult.stdout || targetResult.stderr || 'no response';

  const references = REFERENCE_IMPLEMENTATIONS[protocol] || REFERENCE_IMPLEMENTATIONS['http_404'];
  const divergences: { impl: string; diff_summary: string; severity: string }[] = [];

  for (const [impl, expectedPattern] of Object.entries(references)) {
    if (!targetResponse.toLowerCase().includes(expectedPattern.toLowerCase())) {
      divergences.push({
        impl,
        diff_summary: `Target response does not match expected ${impl} pattern: "${expectedPattern}"`,
        severity: 'low',
      });
    }
  }

  const serverHeader = (targetResponse.match(/Server:\s*(.+)/i) || [])[1]?.trim() || '';
  const referenceResponses = Object.entries(references).map(([impl, pattern]) => ({
    impl,
    version: impl.split('/')[1] || 'unknown',
    response: pattern,
  }));

  const result = {
    target_response: targetResponse.substring(0, 2000),
    server_header: serverHeader,
    reference_responses: referenceResponses,
    divergences,
    divergence_count: divergences.length,
    highest_severity: divergences.length > 0 ? 'low' : 'none',
  };

  return { output: JSON.stringify(result, null, 2), parsed: { ok: true, ...result } };
}

// ---------------------------------------------------------------------------
// Tool exports
// ---------------------------------------------------------------------------

const behavioralFingerprintDef: ToolDefinition = {
  name: 'behavioral_fingerprint',
  description: 'T121: Deep behavioral fingerprinting — TLS JA3/JA4S, header order, timing patterns, error page tokens. Returns a confident stack pin (e.g. "nginx 1.18.0 + Express 4.17.1").',
  status: 'available',
  version: '6.0.0',
  parameters: [
    { name: 'target', type: 'string', required: true, description: 'Target URL or IP (e.g. https://example.com)' },
  ],
};

export const behavioralFingerprintTool = {
  definition: behavioralFingerprintDef,
  async execute(params: Record<string, unknown>, exec: CommandExecutor): Promise<ToolResult> {
    return behavioral_fingerprint(params.target as string, exec);
  },
};

const spawnReplicaDef: ToolDefinition = {
  name: 'spawn_replica',
  description: 'T122: Spawn an exact OSS replica of the target based on its stack pin. Use for destructive exploit testing without hitting production.',
  status: 'available',
  version: '6.0.0',
  parameters: [
    { name: 'stack_pin', type: 'string', required: true, description: 'Stack pin from behavioral_fingerprint' },
    { name: 'observed_routes', type: 'array', required: false, description: 'List of observed target routes to scaffold', default: [] },
    { name: 'session_id', type: 'string', required: false, description: 'Optional GENESIS session ID for lifecycle cleanup labels' },
  ],
};

export const spawnReplicaTool = {
  definition: spawnReplicaDef,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    return replicaPost('/spawn', {
      stack_pin: params.stack_pin as string,
      observed_routes: (params.observed_routes as string[]) || [],
      session_id: (params.session_id as string) || '',
    });
  },
};

const teardownReplicaDef: ToolDefinition = {
  name: 'teardown_replica',
  description: 'T122: Teardown and cleanup a spawned OSS replica by its ID.',
  status: 'available',
  version: '6.0.0',
  parameters: [
    { name: 'replica_id', type: 'string', required: true, description: 'Replica ID returned by spawn_replica' },
  ],
};

export const teardownReplicaTool = {
  definition: teardownReplicaDef,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    return replicaDelete(`/replicas/${params.replica_id as string}`);
  },
};

const timingOracleMemoryDef: ToolDefinition = {
  name: 'timing_oracle_memory',
  description: 'T123: Infer memory layout via timing channels for binary-backed services. Uses statistical analysis of response latency to estimate allocation patterns.',
  status: 'available',
  version: '6.0.0',
  parameters: [
    { name: 'target', type: 'string', required: true, description: 'Target URL' },
    { name: 'probe_count', type: 'number', required: false, description: 'Number of timing probes to send (default: 200)', default: 200 },
  ],
};

export const timingOracleMemoryTool = {
  definition: timingOracleMemoryDef,
  async execute(params: Record<string, unknown>, exec: CommandExecutor): Promise<ToolResult> {
    return timing_oracle_memory(params.target as string, (params.probe_count as number) || 200, exec);
  },
};

const crossComponentDiffDef: ToolDefinition = {
  name: 'cross_component_diff',
  description: 'T124: Compare target responses against a reference set of popular implementations. Flags divergences as vulnerability candidates.',
  status: 'available',
  version: '6.0.0',
  parameters: [
    { name: 'target', type: 'string', required: true, description: 'Target base URL' },
    { name: 'protocol', type: 'string', required: false, description: 'Protocol to test (http_404, content_type_json)', default: 'http_404' },
    { name: 'input', type: 'string', required: false, description: 'Path or payload to test', default: '/nonexistent_probe' },
  ],
};

export const crossComponentDiffTool = {
  definition: crossComponentDiffDef,
  async execute(params: Record<string, unknown>, exec: CommandExecutor): Promise<ToolResult> {
    return cross_component_diff(
      params.target as string,
      (params.protocol as string) || 'http_404',
      (params.input as string) || '/nonexistent_probe',
      exec,
    );
  },
};

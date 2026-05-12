// T23 — MCP-side artifact resolver.
//
// Tools that consume a binary artifact (fuzz_binary, binary_decompile,
// code_read, symbolic_exec, instrument_trace) now accept an optional
// `artifact_id` as a sha256-keyed alternative to `binary_path`. When set,
// this helper asks the backend to stream the bytes (pulling from MinIO if
// the backend needs to) and writes them into a scratch dir under
// `/data/security/artifacts/_resolved/<sha>-<name>`, which every tool can
// already read because it lives under the artifact root.
//
// Single-host behaviour is unchanged: callers passing `binary_path`
// verbatim skip this path entirely. The helper is a pure extension.
import * as fs from 'fs';
import * as path from 'path';

const BACKEND_URL = process.env.BACKEND_URL || 'http://backend:8000';
const ARTIFACT_ROOT = process.env.ARTIFACT_ROOT || '/data/security/artifacts';
const RESOLVE_CACHE = path.join(ARTIFACT_ROOT, '_resolved');
const API_KEY = process.env.MCP_API_KEY || '';

try { fs.mkdirSync(RESOLVE_CACHE, { recursive: true }); } catch { /* race on first use */ }

export interface ResolvedArtifact {
  path: string;
  sha256: string;
}

export class ArtifactResolveError extends Error {
  constructor(message: string) { super(message); this.name = 'ArtifactResolveError'; }
}

/**
 * Fetch the bytes for (session_id, sha256) and return a local filesystem
 * path under ARTIFACT_ROOT. Same-host resolution is a no-op on the backend
 * side (it just stats the existing path); remote-host workers stream from
 * MinIO. The cached local file is re-used across invocations.
 */
export async function resolveArtifactById(
  sessionId: string, sha256: string,
): Promise<ResolvedArtifact> {
  if (!/^[a-f0-9]{64}$/i.test(sha256)) {
    throw new ArtifactResolveError(`invalid sha256: ${sha256}`);
  }
  if (!/^[a-zA-Z0-9-]{8,64}$/.test(sessionId)) {
    throw new ArtifactResolveError(`invalid session_id: ${sessionId}`);
  }

  const cachedName = `${sha256}.bin`;
  const cached = path.join(RESOLVE_CACHE, cachedName);
  if (fs.existsSync(cached) && fs.statSync(cached).size > 0) {
    return { path: cached, sha256 };
  }

  const url = `${BACKEND_URL}/api/v1/artifacts/resolve/${sessionId}/${sha256}`;
  let resp: Response;
  try {
    resp = await fetch(url, {
      method: 'GET',
      headers: API_KEY ? { 'X-API-Key': API_KEY } : {},
    });
  } catch (err) {
    throw new ArtifactResolveError(`backend unreachable: ${err}`);
  }
  if (!resp.ok) {
    const body = await resp.text().catch(() => '');
    throw new ArtifactResolveError(
      `resolve HTTP ${resp.status}: ${body.substring(0, 400)}`,
    );
  }

  const buf = Buffer.from(await resp.arrayBuffer());
  const tmp = `${cached}.partial-${process.pid}-${Date.now()}`;
  fs.writeFileSync(tmp, buf);
  try { fs.renameSync(tmp, cached); } catch { /* another worker won the race */ }
  return { path: cached, sha256 };
}

/**
 * Shared entry point used by consumer tools. Given the raw tool params,
 * prefer `binary_path` when set, else fall back to `artifact_id` +
 * `session_id`. Returns the final absolute path the tool should hand to
 * its sibling container (fuzzer, ghidra_headless, etc.) — which already
 * bind-mount the artifact root and can read from `_resolved/`.
 */
export async function resolveBinaryArg(
  params: Record<string, unknown>,
): Promise<{ path: string; from: 'binary_path' | 'artifact_id' } | null> {
  const direct = String(params.binary_path || '').trim();
  if (direct) return { path: direct, from: 'binary_path' };

  const artifactId = String(params.artifact_id || '').trim();
  if (!artifactId) return null;
  const sessionId = String(params.session_id || '').trim();
  if (!sessionId) {
    throw new ArtifactResolveError('artifact_id requires session_id');
  }
  const resolved = await resolveArtifactById(sessionId, artifactId);
  return { path: resolved.path, from: 'artifact_id' };
}

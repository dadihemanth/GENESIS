import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

// ---------------------------------------------------------------------------
// artifact_pull — fetch a single exposed artifact into the session's volume
//
// Downloads the URI to /data/security/artifacts/{session}/{sha256[:12]}-{basename}
// and registers metadata (sha256, size, mime, source_url, kind) with the backend
// via POST /api/v1/artifacts. Size-capped per artifact + session. Never executes.
// ---------------------------------------------------------------------------

const BACKEND_URL = process.env.BACKEND_URL || 'http://backend:8000';
const API_KEY = process.env.MCP_API_KEY || '';
const ARTIFACT_ROOT = process.env.ARTIFACT_ROOT || '/data/security/artifacts';
const SESSION_SIZE_CAP = Number(process.env.ARTIFACT_SESSION_CAP_BYTES || 500 * 1024 * 1024);

const definition: ToolDefinition = {
  name: 'artifact_pull',
  description:
    'Download a single exposed artifact URI into the session volume. Records sha256/size/mime/kind, ' +
    'enforces per-artifact and per-session size caps, never executes. Returns the on-disk path for ' +
    'use with binary_decompile / code_read.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'session_id', type: 'string', required: true, description: 'Current session ID' },
    { name: 'uri', type: 'string', required: true, description: 'URL of the artifact' },
    { name: 'kind', type: 'string', required: false, description: 'binary|source|config|archive|sourcemap|other', default: 'other' },
    { name: 'max_bytes', type: 'number', required: false, description: 'Per-artifact cap', default: 104857600 },
  ],
};

function safeBasename(uri: string): string {
  try {
    const u = new URL(uri);
    const last = u.pathname.split('/').filter(Boolean).pop() || 'artifact';
    return last.replace(/[^A-Za-z0-9._-]/g, '_').substring(0, 80) || 'artifact';
  } catch {
    return 'artifact';
  }
}

async function registerArtifact(metadata: Record<string, unknown>): Promise<void> {
  try {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (API_KEY) headers['X-API-Key'] = API_KEY;
    await fetch(`${BACKEND_URL}/api/v1/artifacts`, {
      method: 'POST',
      headers,
      body: JSON.stringify(metadata),
    });
  } catch {
    /* backend may be unavailable for registration — still keep the file */
  }
}

async function sessionSizeUsed(sessionDir: string): Promise<number> {
  try {
    const entries = await fs.promises.readdir(sessionDir);
    let total = 0;
    for (const e of entries) {
      try {
        const st = await fs.promises.stat(path.join(sessionDir, e));
        total += st.size;
      } catch { /* ignore */ }
    }
    return total;
  } catch {
    return 0;
  }
}

export const artifactPullTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const sessionId = String(params.session_id || '').trim();
    const uri = String(params.uri || '').trim();
    const kind = String(params.kind || 'other').trim() || 'other';
    const maxBytes = Math.min(Number(params.max_bytes || 104857600), SESSION_SIZE_CAP);

    if (!sessionId || !uri) {
      return { output: 'session_id and uri required', parsed: { error: 'missing params' } };
    }

    // Scope path to the session so cross-session pulls can't collide.
    const safeSession = sessionId.replace(/[^A-Za-z0-9_-]/g, '_').substring(0, 64);
    const sessionDir = path.join(ARTIFACT_ROOT, safeSession);
    try {
      await fs.promises.mkdir(sessionDir, { recursive: true });
    } catch (err) {
      return { output: `mkdir failed: ${err}`, parsed: { error: String(err) } };
    }

    const used = await sessionSizeUsed(sessionDir);
    if (used >= SESSION_SIZE_CAP) {
      return {
        output: `session artifact cap reached (${used} / ${SESSION_SIZE_CAP} bytes)`,
        parsed: { error: 'session_cap_reached', used, cap: SESSION_SIZE_CAP },
      };
    }

    // Download with streaming size cap
    const start = Date.now();
    let resp: Response;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 60_000);
      resp = await fetch(uri, {
        method: 'GET',
        redirect: 'follow',
        signal: controller.signal,
        headers: { 'User-Agent': 'Mozilla/5.0 (GENESIS/MYTHOS artifact_pull)' },
      });
      clearTimeout(timer);
    } catch (err) {
      return { output: `fetch failed: ${err}`, parsed: { error: String(err), uri } };
    }

    if (!resp.ok) {
      return {
        output: `HTTP ${resp.status} for ${uri}`,
        parsed: { error: 'non-ok-status', status: resp.status, uri },
      };
    }

    const mime = resp.headers.get('content-type') || 'application/octet-stream';
    const clHeader = resp.headers.get('content-length');
    const contentLength = clHeader ? Number(clHeader) : undefined;
    if (contentLength !== undefined && contentLength > maxBytes) {
      return {
        output: `artifact exceeds max_bytes (${contentLength} > ${maxBytes})`,
        parsed: { error: 'size_exceeds_cap', declared_size: contentLength, cap: maxBytes, uri },
      };
    }

    // Stream-read with an enforced cap (Content-Length can lie).
    const chunks: Buffer[] = [];
    let received = 0;
    const reader = resp.body?.getReader();
    if (!reader) {
      return { output: 'no response body', parsed: { error: 'no_body' } };
    }
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value) continue;
        received += value.byteLength;
        if (received > maxBytes) {
          try { await reader.cancel(); } catch { /* ignore */ }
          return {
            output: `artifact exceeded max_bytes mid-stream (${received} > ${maxBytes})`,
            parsed: { error: 'size_exceeds_cap', received, cap: maxBytes, uri },
          };
        }
        if (used + received > SESSION_SIZE_CAP) {
          try { await reader.cancel(); } catch { /* ignore */ }
          return {
            output: 'session cap would be exceeded — aborting pull',
            parsed: { error: 'session_cap_reached', used, received, cap: SESSION_SIZE_CAP, uri },
          };
        }
        chunks.push(Buffer.from(value));
      }
    } catch (err) {
      return { output: `stream failed: ${err}`, parsed: { error: String(err), uri } };
    }

    const buf = Buffer.concat(chunks);
    const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
    const base = safeBasename(uri);
    const filename = `${sha256.substring(0, 12)}-${base}`;
    const diskPath = path.join(sessionDir, filename);
    try {
      await fs.promises.writeFile(diskPath, buf, { mode: 0o600 });
    } catch (err) {
      return { output: `write failed: ${err}`, parsed: { error: String(err) } };
    }

    const duration = Date.now() - start;
    const metadata = {
      session_id: sessionId,
      uri,
      path: diskPath,
      sha256,
      size: buf.byteLength,
      mime,
      kind,
      duration_ms: duration,
    };
    await registerArtifact(metadata);

    return {
      output: [
        `artifact_pull: ${uri}`,
        `  sha256: ${sha256}`,
        `  size: ${buf.byteLength} bytes`,
        `  mime: ${mime}`,
        `  kind: ${kind}`,
        `  path: ${diskPath}`,
        `  duration: ${duration}ms`,
        '',
        'Feed the path into binary_decompile (for executables) or code_read (for source).',
      ].join('\n'),
      parsed: metadata,
    };
  },
};

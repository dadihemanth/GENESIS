import * as fs from 'fs';
import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';
import { resolveArtifactById, ArtifactResolveError } from './_artifact_resolver';

// ---------------------------------------------------------------------------
// binary_decompile — Ghidra-headless pseudo-C dump for a pulled artifact
//
// Paginated because a large binary's top-25 functions easily exceed the
// context window. Chunk 0 returns program metadata + symbol table + strings.
// Chunks 1..N return function pseudocode in groups sized by `max_bytes`.
// ---------------------------------------------------------------------------

const GHIDRA_URL = process.env.GHIDRA_URL || 'http://ghidra_headless:3101';
const BACKEND_URL = process.env.BACKEND_URL || 'http://backend:8000';
const API_KEY = process.env.MCP_API_KEY || '';

const definition: ToolDefinition = {
  name: 'binary_decompile',
  description:
    'Ghidra-headless pseudo-C decompilation of a pulled binary artifact. Returns top-N functions by ' +
    'xref count, symbol table, and cross-referenced strings. Paginated (chunk 0 = metadata+symbols+strings, ' +
    'chunks 1+ = function pseudocode).',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'artifact_path', type: 'string', required: false, description: 'Path returned by artifact_pull' },
    { name: 'sha256', type: 'string', required: false, description: 'Alternative: look up the artifact by hash' },
    { name: 'session_id', type: 'string', required: false, description: 'Required when using sha256 lookup' },
    { name: 'top_n', type: 'number', required: false, description: 'Number of top-xref functions to decompile', default: 25 },
    { name: 'chunk', type: 'number', required: false, description: 'Pagination chunk (0 = metadata + strings + symbols)', default: 0 },
    { name: 'max_bytes', type: 'number', required: false, description: 'Approx max chunk size', default: 60000 },
  ],
};

interface DecompileFunction {
  name: string;
  address: string;
  xref_count: number;
  signature?: string;
  pseudocode: string;
}

interface DecompileResult {
  error?: string;
  program?: { name?: string; language?: string };
  functions?: DecompileFunction[];
  symbols?: Array<{ name: string; type: string; address: string }>;
  strings?: Array<{ value: string; address: string; xrefs: string[] }>;
  sha256?: string;
  analyze_duration_ms?: number;
  top_n?: number;
  cached?: boolean;
}

async function resolvePath(params: Record<string, unknown>): Promise<string | { error: string }> {
  const direct = String(params.artifact_path || '').trim();
  if (direct) return direct;
  const sha = String(params.sha256 || '').trim();
  const sessionId = String(params.session_id || '').trim();
  if (!sha || !sessionId) {
    return { error: 'provide artifact_path OR (sha256 + session_id)' };
  }
  try {
    const headers: Record<string, string> = {};
    if (API_KEY) headers['X-API-Key'] = API_KEY;
    const resp = await fetch(
      `${BACKEND_URL}/api/v1/artifacts/lookup?session_id=${encodeURIComponent(sessionId)}&sha256=${encodeURIComponent(sha)}`,
      { method: 'GET', headers },
    );
    if (!resp.ok) return { error: `artifact lookup HTTP ${resp.status}` };
    const doc = await resp.json() as Record<string, unknown>;
    const p = String(doc.path || '');
    // T23 — on a remote worker the registered path may not exist locally.
    // If it's missing OR empty, fall back to the MinIO-backed resolver,
    // which streams the bytes into the artifact cache under ARTIFACT_ROOT.
    if (p && fs.existsSync(p)) {
      try {
        if (fs.statSync(p).size > 0) return p;
      } catch { /* fall through to resolver */ }
    }
    try {
      const resolved = await resolveArtifactById(sessionId, sha);
      return resolved.path;
    } catch (err) {
      if (err instanceof ArtifactResolveError) {
        return { error: `artifact not reachable on this worker: ${err.message}` };
      }
      throw err;
    }
  } catch (err) {
    return { error: `artifact lookup failed: ${err}` };
  }
}

export const binaryDecompileTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const pathOrErr = await resolvePath(params);
    if (typeof pathOrErr !== 'string') {
      return { output: pathOrErr.error, parsed: { error: pathOrErr.error } };
    }
    const artifactPath = pathOrErr;
    const topN = Math.max(3, Math.min(60, Number(params.top_n || 25)));
    const chunk = Math.max(0, Number(params.chunk || 0));
    const maxBytes = Math.max(10000, Math.min(80000, Number(params.max_bytes || 60000)));

    let decomp: DecompileResult;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 620_000);
      const resp = await fetch(`${GHIDRA_URL}/decompile`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ artifact_path: artifactPath, top_n: topN }),
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (!resp.ok) {
        const text = await resp.text().catch(() => '');
        return { output: `ghidra HTTP ${resp.status}: ${text.substring(0, 400)}`, parsed: { error: 'ghidra_http_error', status: resp.status } };
      }
      decomp = await resp.json() as DecompileResult;
    } catch (err) {
      return { output: `ghidra request failed: ${err}`, parsed: { error: String(err) } };
    }

    if (decomp.error) {
      return { output: `ghidra error: ${decomp.error}`, parsed: { ...decomp } as Record<string, unknown> };
    }

    const functions = decomp.functions || [];
    const totalFunctions = functions.length;

    // Chunk 0: metadata + strings + symbols. Chunks >=1: functions paginated by size.
    if (chunk === 0) {
      const lines: string[] = [
        `binary_decompile — ${artifactPath}`,
        `sha256=${decomp.sha256 || '?'}`,
        `program: ${decomp.program?.name || '?'} (${decomp.program?.language || '?'})`,
        `functions decompiled: ${totalFunctions} (top_n requested: ${topN})`,
        `cached: ${Boolean(decomp.cached)}, analyze_ms: ${decomp.analyze_duration_ms ?? '?'}`,
        '',
        `Strings (${(decomp.strings || []).length}):`,
      ];
      for (const s of (decomp.strings || []).slice(0, 60)) {
        const xref = (s.xrefs || [])[0] || '';
        lines.push(`  [${s.address}] "${s.value.substring(0, 140)}"` + (xref ? `  (xref ${xref})` : ''));
      }
      lines.push('');
      lines.push(`Symbols (${(decomp.symbols || []).length}):`);
      for (const s of (decomp.symbols || []).slice(0, 80)) {
        lines.push(`  [${s.address}] (${s.type}) ${s.name}`);
      }
      lines.push('');
      lines.push(`Function index (call binary_decompile again with chunk=1..N for pseudocode):`);
      for (let i = 0; i < totalFunctions; i++) {
        const f = functions[i];
        lines.push(`  ${i + 1}. ${f.name} @ ${f.address} (xref=${f.xref_count}) ${f.signature || ''}`);
      }

      return {
        output: lines.join('\n'),
        parsed: {
          chunk: 0,
          total_functions: totalFunctions,
          sha256: decomp.sha256,
          program: decomp.program,
          symbols: decomp.symbols?.slice(0, 80),
          strings: decomp.strings?.slice(0, 60),
          function_index: functions.map((f, i) => ({ index: i + 1, name: f.name, address: f.address, xref_count: f.xref_count })),
        },
      };
    }

    // Function chunks
    const start = (chunk - 1);
    if (start >= totalFunctions) {
      return {
        output: `chunk ${chunk} out of range (only ${totalFunctions} functions available; use chunk 1..${totalFunctions})`,
        parsed: { error: 'chunk_out_of_range', chunk, total_functions: totalFunctions },
      };
    }

    // Pack functions from `start` onward until max_bytes is reached
    const packed: DecompileFunction[] = [];
    let bytes = 0;
    for (let i = start; i < totalFunctions; i++) {
      const f = functions[i];
      const size = (f.pseudocode || '').length;
      if (bytes + size > maxBytes && packed.length > 0) break;
      packed.push(f);
      bytes += size;
    }

    const nextChunk = start + packed.length + 1;
    const hasMore = (start + packed.length) < totalFunctions;

    const lines: string[] = [
      `binary_decompile — chunk ${chunk} (functions ${start + 1}..${start + packed.length} of ${totalFunctions})`,
      '',
    ];
    for (const f of packed) {
      lines.push(`// ─────────────────────────────────────────────────────────`);
      lines.push(`// ${f.name} @ ${f.address}  (xref=${f.xref_count})`);
      lines.push(`// ${f.signature || ''}`);
      lines.push('');
      lines.push(f.pseudocode || '// (no pseudocode returned)');
      lines.push('');
    }
    if (hasMore) {
      lines.push(`[more functions remain — call binary_decompile again with chunk=${nextChunk}]`);
    }

    return {
      output: lines.join('\n'),
      parsed: {
        chunk,
        functions: packed,
        has_more: hasMore,
        next_chunk: hasMore ? nextChunk : null,
        total_functions: totalFunctions,
      },
    };
  },
};

/**
 * v5 source-analysis MCP tools: T80 repo_ingest, T81 ast_walker, T82 taint_engine,
 * T83 invariant_inferer.  All forward to the backend /api/v1/source/* endpoints.
 */
import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const BACKEND_URL = process.env.BACKEND_URL || 'http://backend:8000';
const API_KEY = process.env.MCP_API_KEY || '';

function headers(): Record<string, string> {
  return {
    'Content-Type': 'application/json',
    ...(API_KEY ? { 'X-API-Key': API_KEY } : {}),
  };
}

async function backendPost(path: string, body: unknown, timeoutMs = 120000): Promise<ToolResult> {
  const c = new AbortController();
  const timer = setTimeout(() => c.abort(), timeoutMs);
  try {
    const resp = await fetch(`${BACKEND_URL}${path}`, {
      method: 'POST',
      headers: headers(),
      body: JSON.stringify(body),
      signal: c.signal,
    });
    clearTimeout(timer);
    const data = await resp.json() as Record<string, unknown>;
    if (!resp.ok) {
      return { output: `HTTP ${resp.status}: ${JSON.stringify(data).substring(0, 400)}`, parsed: { ok: false, ...data } };
    }
    return { output: JSON.stringify(data, null, 2).substring(0, 4000), parsed: { ok: true, ...data } };
  } catch (err) {
    clearTimeout(timer);
    return { output: `request failed: ${err}`, parsed: { ok: false, error: String(err) } };
  }
}

// ── T80: repo_ingest ──────────────────────────────────────────────────────

const repoIngestDef: ToolDefinition = {
  name: 'repo_ingest',
  description:
    'T80 — Clone a git repository and embed its source code into the source_corpus vector ' +
    'collection. Returns file count, detected languages, and entry points. Required before ' +
    'using ast_walker or taint_engine on a target. Supports public HTTPS/SSH git URLs.',
  status: 'available',
  version: '5.0.0',
  parameters: [
    { name: 'session_id', type: 'string', required: true, description: 'Current session ID.' },
    { name: 'repo_url', type: 'string', required: false, description: 'HTTPS/SSH git URL to clone.' },
    { name: 'local_path', type: 'string', required: false, description: 'Local filesystem path (container-visible) if already available.' },
    { name: 'max_files', type: 'number', required: false, description: 'Maximum source files to ingest (default 500).', default: 500 },
  ],
};

export const repoIngestTool = {
  definition: repoIngestDef,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const session_id = String(params.session_id || '').trim();
    if (!session_id) return { output: 'session_id required', parsed: { ok: false } };
    if (!params.repo_url && !params.local_path) {
      return { output: 'repo_url or local_path required', parsed: { ok: false } };
    }
    return backendPost('/api/v1/source/ingest', {
      session_id,
      repo_url: params.repo_url || null,
      local_path: params.local_path || null,
      max_files: Number(params.max_files ?? 500),
    }, 300000);
  },
};

// ── T81: ast_walker ───────────────────────────────────────────────────────

const astWalkerDef: ToolDefinition = {
  name: 'ast_walker',
  description:
    'T81 — Query the ingested source corpus for sinks, user input sources, or dataflow paths. ' +
    'query_type: "sinks" | "inputs" | "dataflow" | "symbol". ' +
    'For dataflow, supply source_pattern and sink_pattern. For symbol, supply symbol name.',
  status: 'available',
  version: '5.0.0',
  parameters: [
    { name: 'session_id', type: 'string', required: true, description: 'Current session ID.' },
    { name: 'query_type', type: 'string', required: true, description: 'sinks | inputs | dataflow | symbol' },
    { name: 'language', type: 'string', required: false, description: 'Filter by language (python, javascript, java, go, php).' },
    { name: 'source_pattern', type: 'string', required: false, description: 'Source pattern for dataflow queries.' },
    { name: 'sink_pattern', type: 'string', required: false, description: 'Sink pattern for dataflow queries.' },
    { name: 'symbol', type: 'string', required: false, description: 'Symbol name for symbol queries.' },
    { name: 'n_results', type: 'number', required: false, description: 'Max results to return (default 10).', default: 10 },
  ],
};

export const astWalkerTool = {
  definition: astWalkerDef,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const session_id = String(params.session_id || '').trim();
    if (!session_id) return { output: 'session_id required', parsed: { ok: false } };
    return backendPost('/api/v1/source/ast-query', {
      session_id,
      query_type: params.query_type,
      language: params.language || null,
      source_pattern: params.source_pattern || null,
      sink_pattern: params.sink_pattern || null,
      symbol: params.symbol || null,
      n_results: Number(params.n_results ?? 10),
    });
  },
};

// ── T82: taint_engine ─────────────────────────────────────────────────────

const taintEngineDef: ToolDefinition = {
  name: 'taint_engine',
  description:
    'T82 — Run full source-to-sink taint analysis on the ingested source corpus. ' +
    'Returns ranked taint paths with CWE mappings and confidence scores. ' +
    'High-confidence paths are automatically stored in the hypothesis market.',
  status: 'available',
  version: '5.0.0',
  parameters: [
    { name: 'session_id', type: 'string', required: true, description: 'Current session ID.' },
    { name: 'language', type: 'string', required: false, description: 'Limit analysis to one language.' },
    { name: 'n_paths', type: 'number', required: false, description: 'Max taint paths to return (default 20).', default: 20 },
  ],
};

export const taintEngineTool = {
  definition: taintEngineDef,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const session_id = String(params.session_id || '').trim();
    if (!session_id) return { output: 'session_id required', parsed: { ok: false } };
    return backendPost('/api/v1/source/taint', {
      session_id,
      language: params.language || null,
      n_paths: Number(params.n_paths ?? 20),
    });
  },
};

// ── T83: invariant_inferer ────────────────────────────────────────────────

const invariantInfererDef: ToolDefinition = {
  name: 'invariant_inferer',
  description:
    'T83 — Infer runtime invariants (auth requirements, value constraints, ordering rules) ' +
    'from the ingested source corpus. Stores results in both ChromaDB and MongoDB for use ' +
    'by T95 (invariant_violator) and T96 (model_checker).',
  status: 'available',
  version: '5.0.0',
  parameters: [
    { name: 'session_id', type: 'string', required: true, description: 'Current session ID.' },
    { name: 'target_ip', type: 'string', required: false, description: 'Target IP for cross-session storage.', default: '' },
    { name: 'target_id', type: 'string', required: false, description: 'Optional engagement target ID.', default: '' },
  ],
};

export const invariantInfererTool = {
  definition: invariantInfererDef,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const session_id = String(params.session_id || '').trim();
    if (!session_id) return { output: 'session_id required', parsed: { ok: false } };
    return backendPost('/api/v1/source/invariants', {
      session_id,
      target_ip: String(params.target_ip || ''),
      target_id: String(params.target_id || ''),
    });
  },
};

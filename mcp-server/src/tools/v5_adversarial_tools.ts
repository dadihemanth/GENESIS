/**
 * v5 adversarial reasoning MCP tools: T87 red_blue_dialectic, T88 philosopher_agent,
 * T89 hypothesis market, T92 architectural_reasoner, T97 tool_synthesize,
 * T102 long_horizon_planner, T103 provenance_recorder.
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

async function backendGet(path: string, timeoutMs = 30000): Promise<ToolResult> {
  const c = new AbortController();
  const timer = setTimeout(() => c.abort(), timeoutMs);
  try {
    const resp = await fetch(`${BACKEND_URL}${path}`, {
      method: 'GET',
      headers: API_KEY ? { 'X-API-Key': API_KEY } : {},
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

// ── T89: hypothesis_market ────────────────────────────────────────────────

export const hypothesisMarketTool = {
  definition: {
    name: 'hypothesis_market',
    description:
      'T89 — Submit a hypothesis to the confidence-staked market, retrieve top-staked ' +
      'hypotheses for the session, or add evidence. ' +
      'action: "submit" | "list" | "allocate" | "evidence". ' +
      'High-stake hypotheses receive proportionally more iteration budget.',
    status: 'available',
    version: '5.0.0',
    parameters: [
      { name: 'action', type: 'string', required: true, description: 'submit | list | allocate | evidence' },
      { name: 'session_id', type: 'string', required: true, description: 'Current session ID.' },
      { name: 'text', type: 'string', required: false, description: 'Hypothesis text (for submit).' },
      { name: 'hypothesis_type', type: 'string', required: false, description: 'Attack class (for submit).', default: 'generic' },
      { name: 'confidence_stake', type: 'number', required: false, description: '0–1 confidence stake (for submit).', default: 0.5 },
      { name: 'hypothesis_id', type: 'string', required: false, description: 'Target hypothesis ID (for evidence).' },
      { name: 'evidence_text', type: 'string', required: false, description: 'Evidence text (for evidence).' },
      { name: 'supports', type: 'boolean', required: false, description: 'True if evidence supports, false if against.', default: true },
    ],
  } as ToolDefinition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const action = String(params.action || '').trim();
    const session_id = String(params.session_id || '').trim();
    if (!session_id) return { output: 'session_id required', parsed: { ok: false } };
    switch (action) {
      case 'submit':
        return backendPost('/api/v1/hypotheses/submit', {
          session_id,
          text: String(params.text || ''),
          hypothesis_type: String(params.hypothesis_type || 'generic'),
          confidence_stake: Number(params.confidence_stake ?? 0.5),
          proposer_agent: 'orchestrator',
        });
      case 'list':
        return backendGet(`/api/v1/hypotheses/${session_id}?limit=20`);
      case 'allocate':
        return backendGet(`/api/v1/hypotheses/${session_id}/allocate?total_budget=20&top_n=3`);
      case 'evidence': {
        const hyp_id = String(params.hypothesis_id || '');
        if (!hyp_id) return { output: 'hypothesis_id required for evidence action', parsed: { ok: false } };
        return backendPost(`/api/v1/hypotheses/${hyp_id}/evidence`, {
          evidence_text: String(params.evidence_text || ''),
          supports: Boolean(params.supports ?? true),
        });
      }
      default:
        return { output: `unknown action: ${action}`, parsed: { ok: false } };
    }
  },
};

// ── T92: architectural_reasoner ───────────────────────────────────────────

export const architecturalReasonerTool = {
  definition: {
    name: 'architectural_reasoner',
    description:
      'T92 — Analyze architecture artifacts (OpenAPI spec JSON, Docker Compose YAML, or notes) ' +
      'to extract trust boundaries, unauthenticated endpoints, privilege seams, and generate ' +
      'attack hypotheses. Stores threat model in the session target_brief.',
    status: 'available',
    version: '5.0.0',
    parameters: [
      { name: 'session_id', type: 'string', required: true, description: 'Current session ID.' },
      { name: 'openapi_spec', type: 'string', required: false, description: 'OpenAPI spec JSON string.' },
      { name: 'compose_config', type: 'string', required: false, description: 'Docker Compose YAML/JSON string.' },
      { name: 'architecture_notes', type: 'string', required: false, description: 'Free-text architecture description.' },
    ],
  } as ToolDefinition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const session_id = String(params.session_id || '').trim();
    if (!session_id) return { output: 'session_id required', parsed: { ok: false } };
    let openapi: unknown = null;
    let compose: unknown = null;
    if (params.openapi_spec) {
      try { openapi = JSON.parse(String(params.openapi_spec)); } catch (_) { /* pass raw */ }
    }
    if (params.compose_config) {
      try { compose = JSON.parse(String(params.compose_config)); } catch (_) { /* pass raw */ }
    }
    return backendPost('/api/v1/source/architecture', {
      session_id,
      openapi_spec: openapi,
      compose_config: compose,
      architecture_notes: String(params.architecture_notes || ''),
    });
  },
};

// ── T97: tool_synthesize ──────────────────────────────────────────────────

export const toolSynthesizeTool = {
  definition: {
    name: 'tool_synthesize',
    description:
      'T97 — Synthesize a new security testing tool from a natural-language description. ' +
      'The LLM writes a Python forge_runner-compatible script, validates it in the sandbox, ' +
      'and registers it in the synthesized_tools registry. Returns tool_name on success.',
    status: 'available',
    version: '5.0.0',
    parameters: [
      { name: 'description', type: 'string', required: true, description: 'Natural-language description of the capability needed.' },
      { name: 'capability_tag', type: 'string', required: false, description: 'Capability category for the tool registry.', default: 'custom' },
      { name: 'session_id', type: 'string', required: false, description: 'Session that triggered synthesis.', default: '' },
      { name: 'example_input', type: 'string', required: false, description: 'JSON string of example stdin input.' },
      { name: 'example_output', type: 'string', required: false, description: 'JSON string of expected stdout output.' },
    ],
  } as ToolDefinition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    let exInput: unknown = null;
    let exOutput: unknown = null;
    if (params.example_input) {
      try { exInput = JSON.parse(String(params.example_input)); } catch (_) { /* ignore */ }
    }
    if (params.example_output) {
      try { exOutput = JSON.parse(String(params.example_output)); } catch (_) { /* ignore */ }
    }
    return backendPost('/api/v1/provenance/tools/synthesize', {
      description: String(params.description || ''),
      capability_tag: String(params.capability_tag || 'custom'),
      session_id: String(params.session_id || ''),
      example_input: exInput,
      example_output: exOutput,
    }, 180000);
  },
};

// ── T102: long_horizon_planner ────────────────────────────────────────────

export const longHorizonPlannerTool = {
  definition: {
    name: 'long_horizon_planner',
    description:
      'T102 — Manage the cross-session rolling attack tree for a target. ' +
      'action: "get" | "add_question" | "resolve_question". ' +
      'Use "get" to see unresolved threads from prior sessions. ' +
      'Use "add_question" to record an open attack thread for future sessions.',
    status: 'available',
    version: '5.0.0',
    parameters: [
      { name: 'action', type: 'string', required: true, description: 'get | add_question | resolve_question' },
      { name: 'target_ip', type: 'string', required: true, description: 'Target IP address.' },
      { name: 'session_id', type: 'string', required: false, description: 'Current session ID.', default: '' },
      { name: 'question', type: 'string', required: false, description: 'Open question text (for add_question).' },
      { name: 'question_id', type: 'string', required: false, description: 'Question ID to resolve (for resolve_question).' },
      { name: 'resolution', type: 'string', required: false, description: 'Resolution text (for resolve_question).', default: '' },
      { name: 'priority', type: 'number', required: false, description: '0–1 priority (for add_question).', default: 0.5 },
    ],
  } as ToolDefinition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const target_ip = String(params.target_ip || '').trim();
    if (!target_ip) return { output: 'target_ip required', parsed: { ok: false } };
    const action = String(params.action || '').trim();
    switch (action) {
      case 'get':
        return backendGet(`/api/v1/source/long-horizon/${encodeURIComponent(target_ip)}`);
      case 'add_question':
        return backendPost('/api/v1/source/long-horizon/question', {
          target_ip,
          question: String(params.question || ''),
          source_session_id: String(params.session_id || ''),
          priority: Number(params.priority ?? 0.5),
        });
      case 'resolve_question':
        return backendPost('/api/v1/source/long-horizon/resolve', {
          target_ip,
          question_id: String(params.question_id || ''),
          resolution: String(params.resolution || ''),
        });
      default:
        return { output: `unknown action: ${action}`, parsed: { ok: false } };
    }
  },
};

// ── T103: provenance_recorder ─────────────────────────────────────────────

export const provenanceRecorderTool = {
  definition: {
    name: 'provenance_recorder',
    description:
      'T103 — Record or retrieve the full reasoning provenance chain for a confirmed finding. ' +
      'action: "record" | "get" | "search". ' +
      'Use "record" after confirming a vulnerability to persist its discovery trace. ' +
      'Use "get" to retrieve an existing chain. Use "search" for semantic similarity.',
    status: 'available',
    version: '5.0.0',
    parameters: [
      { name: 'action', type: 'string', required: true, description: 'record | get | search' },
      { name: 'session_id', type: 'string', required: false, description: 'Session ID (for record/get).' },
      { name: 'finding_id', type: 'string', required: false, description: 'Vulnerability ID (for record/get).' },
      { name: 'query', type: 'string', required: false, description: 'Semantic search query (for search).' },
      { name: 'n_results', type: 'number', required: false, description: 'Max results for search.', default: 5 },
    ],
  } as ToolDefinition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const action = String(params.action || '').trim();
    switch (action) {
      case 'record': {
        const session_id = String(params.session_id || '');
        if (!session_id) return { output: 'session_id required', parsed: { ok: false } };
        return backendPost(`/api/v1/provenance/${session_id}/record`, {});
      }
      case 'get': {
        const finding_id = String(params.finding_id || '');
        if (!finding_id) return { output: 'finding_id required', parsed: { ok: false } };
        return backendGet(`/api/v1/provenance/${finding_id}`);
      }
      case 'search': {
        const q = String(params.query || '').trim();
        if (!q) return { output: 'query required', parsed: { ok: false } };
        return backendGet(
          `/api/v1/provenance/search?q=${encodeURIComponent(q)}&n_results=${Number(params.n_results ?? 5)}`,
        );
      }
      default:
        return { output: `unknown action: ${action}`, parsed: { ok: false } };
    }
  },
};

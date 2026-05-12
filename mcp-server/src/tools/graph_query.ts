import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

// ---------------------------------------------------------------------------
// graph_query — read-only Cypher runner for the T21 attack knowledge graph.
//
// The tool forwards to the backend (`POST /api/v1/graph/query`) which applies
// a read-only Cypher filter + runs the query in a Neo4j READ-mode session
// with a 30s timeout and a 10k row cap. Mutating clauses (CREATE/MERGE/
// DELETE/SET/REMOVE) are rejected with HTTP 400.
// ---------------------------------------------------------------------------

const BACKEND_URL = process.env.BACKEND_URL || 'http://backend:8000';
const API_KEY = process.env.MCP_API_KEY || '';

const definition: ToolDefinition = {
  name: 'graph_query',
  description:
    'Run a read-only Cypher query against the cross-session attack knowledge graph (T21). ' +
    'Node labels: Host, Service, Finding, Credential, Token, Privilege, Target. ' +
    'Edge types: LISTENS_ON, AUTHENTICATES_TO, GRANTS, CHAINS_INTO, AFFECTS, AFFECTS_HOST, ON_TARGET. ' +
    'Every finding, host, service, and credential discovered by any session on this target is queryable. ' +
    'Scope with `WHERE n.session_id = $sid` for current-session only, or omit for cross-session. ' +
    'Mutating clauses (CREATE/MERGE/DELETE/SET/REMOVE) are rejected. 10k row cap, 30s timeout.',
  status: 'available',
  version: '0.1.0',
  parameters: [
    { name: 'cypher', type: 'string', required: true, description: 'Read-only Cypher query.' },
    { name: 'params', type: 'string', required: false, description: 'JSON object of bound parameters (e.g. {"sid": "..."}).' },
    { name: 'row_cap', type: 'number', required: false, description: 'Max rows (default 10000, max 50000).', default: 10000 },
    { name: 'timeout_s', type: 'number', required: false, description: 'Max seconds (default 30, max 120).', default: 30 },
  ],
};

export const graphQueryTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const cypher = String(params.cypher || '').trim();
    if (!cypher) return { output: 'cypher required', parsed: { error: 'missing cypher', ok: false } };

    let paramsObj: Record<string, unknown> = {};
    if (params.params) {
      try {
        paramsObj = typeof params.params === 'string'
          ? JSON.parse(params.params)
          : (params.params as Record<string, unknown>);
      } catch (err) {
        return {
          output: `params must be valid JSON: ${err}`,
          parsed: { error: 'invalid params JSON', ok: false },
        };
      }
    }
    const rowCap = Math.min(50000, Math.max(1, Number(params.row_cap ?? 10000)));
    const timeoutS = Math.min(120, Math.max(1, Number(params.timeout_s ?? 30)));

    let resp: Response;
    try {
      const c = new AbortController();
      const timer = setTimeout(() => c.abort(), (timeoutS + 10) * 1000);
      resp = await fetch(`${BACKEND_URL}/api/v1/graph/query`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(API_KEY ? { 'X-API-Key': API_KEY } : {}),
        },
        body: JSON.stringify({
          cypher,
          params: paramsObj,
          row_cap: rowCap,
          timeout_s: timeoutS,
        }),
        signal: c.signal,
      });
      clearTimeout(timer);
    } catch (err) {
      return {
        output: `graph_query request failed: ${err}`,
        parsed: { error: String(err), ok: false },
      };
    }

    if (!resp.ok) {
      const body = await resp.text().catch(() => '');
      return {
        output: `graph_query HTTP ${resp.status}: ${body.substring(0, 400)}`,
        parsed: { error: 'backend_http_error', status: resp.status, body: body.substring(0, 2000), ok: false },
      };
    }

    const result = await resp.json() as { ok?: boolean; rows?: unknown[]; truncated?: boolean; error?: string };
    const rows = result.rows ?? [];
    const truncated = Boolean(result.truncated);

    const outLines = [
      `graph_query (${rows.length} row${rows.length === 1 ? '' : 's'}${truncated ? ', TRUNCATED' : ''})`,
      '─'.repeat(70),
    ];
    const preview = rows.slice(0, 25);
    for (const row of preview) {
      outLines.push(JSON.stringify(row).substring(0, 500));
    }
    if (rows.length > preview.length) {
      outLines.push(`... ${rows.length - preview.length} more rows ...`);
    }
    if (rows.length === 0) outLines.push('(no rows)');

    return {
      output: outLines.join('\n'),
      parsed: {
        ok: true,
        rows,
        row_count: rows.length,
        truncated,
        cypher,
        params: paramsObj,
      },
    };
  },
};

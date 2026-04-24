import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const BACKEND_URL = process.env.BACKEND_URL || 'http://backend:8000';
const API_KEY = process.env.MCP_API_KEY || '';

const definition: ToolDefinition = {
  name: 'session_memory',
  description: 'Persistent working memory for the current session. Store and query discovered endpoints, parameters, credentials, users, and other findings to enable cross-endpoint correlation. Essential for detecting IDOR, privilege escalation, and multi-step attack chains.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'action', type: 'string', required: true, description: 'store | query' },
    { name: 'session_id', type: 'string', required: true, description: 'Current session ID' },
    { name: 'category', type: 'string', required: false, description: 'endpoints | params | credentials | users | paths | headers | cookies | notes' },
    { name: 'key', type: 'string', required: false, description: 'Storage key (for store)' },
    { name: 'value', type: 'string', required: false, description: 'Value to store (for store). Use JSON for structured data.' },
  ],
};

async function apiCall(path: string, method = 'GET', body?: unknown): Promise<unknown> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (API_KEY) headers['X-API-Key'] = API_KEY;
  const resp = await fetch(`${BACKEND_URL}/api/v1/session-memory${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  return resp.json();
}

export const sessionMemoryTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const action = String(params.action || '').toLowerCase();
    const sessionId = String(params.session_id || '');
    const category = String(params.category || 'notes');
    const key = String(params.key || '');
    const value = String(params.value || '');

    if (!sessionId) return { output: 'session_id is required', parsed: { error: 'missing session_id' } };

    try {
      if (action === 'store') {
        if (!key) return { output: 'key is required for store', parsed: { error: 'missing key' } };
        await apiCall(`/${sessionId}/store`, 'POST', { category, key, value });
        return {
          output: `Stored in ${category}: "${key}" = "${value.substring(0, 100)}"`,
          parsed: { status: 'ok', category, key },
        };
      }

      if (action === 'query') {
        const qs = category !== 'notes' ? `?category=${encodeURIComponent(category)}&key=${encodeURIComponent(key)}` : '';
        const data = await apiCall(`/${sessionId}/query${qs}`) as Record<string, unknown>;
        const text = JSON.stringify(data, null, 2);
        return {
          output: `Session memory query (category=${category || 'all'}):\n${text.substring(0, 3000)}`,
          parsed: data,
        };
      }

      return { output: `Unknown action "${action}". Use store or query.`, parsed: { error: 'unknown action' } };
    } catch (err) {
      return { output: `Session memory error: ${err}`, parsed: { error: String(err) } };
    }
  },
};

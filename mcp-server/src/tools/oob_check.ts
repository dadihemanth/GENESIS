import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const BACKEND_URL = process.env.BACKEND_URL || 'http://backend:8000';
const API_KEY = process.env.MCP_API_KEY || '';

const definition: ToolDefinition = {
  name: 'oob_check',
  description: 'Out-of-band callback manager for detecting blind SSRF, blind XXE, blind SQLi, and blind command injection. Generate a unique callback URL to inject into payloads, then check if the target called back.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'action', type: 'string', required: true, description: 'generate | check' },
    { name: 'token', type: 'string', required: false, description: 'Token to check (required for action=check)' },
    { name: 'description', type: 'string', required: false, description: 'What this token is probing e.g. "SSRF via profile_url parameter"' },
  ],
};

async function apiRequest(path: string, method = 'GET'): Promise<unknown> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (API_KEY) headers['X-API-Key'] = API_KEY;
  const resp = await fetch(`${BACKEND_URL}/api/v1/callback${path}`, { method, headers });
  return resp.json();
}

export const oobCheckTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const action = String(params.action || '').toLowerCase();
    const description = String(params.description || '');
    const token = String(params.token || '');

    try {
      if (action === 'generate') {
        const data = await apiRequest(`/generate?description=${encodeURIComponent(description)}`) as Record<string, unknown>;
        return {
          output: JSON.stringify({
            token: data.token,
            callback_url: data.http_url,
            usage: `Inject this URL into SSRF/XXE/SQLi payloads. After the tool runs, call oob_check with action=check and this token to see if the target reached back.`,
            description,
          }, null, 2),
          parsed: data,
        };
      }

      if (action === 'check') {
        if (!token) return { output: 'token required for action=check', parsed: { error: 'missing token' } };
        const data = await apiRequest(`/check/${token}`) as Record<string, unknown>;
        const triggered = Boolean(data.triggered);
        return {
          output: triggered
            ? `OOB CALLBACK TRIGGERED! Token ${token} received ${data.hit_count} hit(s).\nThis CONFIRMS the vulnerability — the target server made an outbound request to our callback URL.\nHits: ${JSON.stringify(data.hits, null, 2)}`
            : `No callback received yet for token ${token}. The payload may not have been executed, or the target has no outbound access.`,
          parsed: data,
        };
      }

      return { output: `Unknown action "${action}". Use generate or check.`, parsed: { error: 'unknown action' } };
    } catch (err) {
      return { output: `OOB check error: ${err}`, parsed: { error: String(err) } };
    }
  },
};

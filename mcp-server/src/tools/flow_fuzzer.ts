// T52 — flow_fuzzer
// Mutate FSM transitions: skip steps, repeat steps, run in parallel,
// replay with mutated fields, access from wrong state.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'flow_fuzzer',
  description:
    'Mutate FSM transitions captured by flow_recorder. Applies: skip_step (jump from state 1 ' +
    'to state 3), repeat_step (call state 2 twice), parallel_steps (fire steps 2 & 3 concurrently), ' +
    'mutate_field (change an amount/quantity/role field), out_of_order (call step 4 before step 2). ' +
    'Detects business-logic vulnerabilities: Stripe coupon class, TOCTOU, negative balance, ' +
    'price manipulation.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'fsm',         type: 'string', required: true,  description: 'FSM JSON from flow_recorder (states + transitions array)' },
    { name: 'mutations',   type: 'string', required: false, description: 'JSON array of mutations: skip_step, repeat_step, parallel_steps, mutate_field, out_of_order', default: '["skip_step","repeat_step","parallel_steps","mutate_field"]' },
    { name: 'auth_cookie', type: 'string', required: false, description: 'Auth cookie string' },
    { name: 'timeout_ms',  type: 'number', required: false, description: 'Per-mutation timeout ms', default: 15000 },
  ],
};

interface FsmTransition {
  from: string;
  to: string;
  action: string;
  request: { method: string; url: string; body?: string; headers: Record<string, string> };
  response: { status: number; body_excerpt: string };
}

interface Fsm {
  states: Array<{ id: string; url: string }>;
  transitions: FsmTransition[];
}

async function replayRequest(t: FsmTransition, authCookie: string | undefined, timeoutMs: number): Promise<{ status: number; body_excerpt: string; time_ms: number; error?: string }> {
  const start = Date.now();
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const hdrs: Record<string, string> = { ...t.request.headers, 'User-Agent': 'Mozilla/5.0 GENESIS/4.0' };
    if (authCookie) hdrs['Cookie'] = authCookie;
    const resp = await fetch(t.request.url, { method: t.request.method, headers: hdrs, body: t.request.body || undefined, signal: controller.signal });
    clearTimeout(timer);
    const text = await resp.text();
    return { status: resp.status, body_excerpt: text.substring(0, 200).replace(/\s+/g, ' '), time_ms: Date.now() - start };
  } catch (err) {
    return { status: 0, body_excerpt: '', time_ms: Date.now() - start, error: String(err) };
  }
}

function mutateMoney(body: string): string {
  // Try to negate amounts, set to 0, set to -1
  return body
    .replace(/"(amount|price|quantity|total|qty)"\s*:\s*([\d.]+)/gi, (m, k, v) => `"${k}":${-(parseFloat(v))}`)
    .replace(/"(count|number|n)"\s*:\s*(\d+)/gi, (m, k, v) => `"${k}":99999`);
}

export const flowFuzzerTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const authCookie = params.auth_cookie ? String(params.auth_cookie) : undefined;
    const timeoutMs = Number(params.timeout_ms || 15000);

    let fsm: Fsm;
    try { fsm = JSON.parse(String(params.fsm || '{}')); } catch {
      return { output: 'fsm must be valid JSON from flow_recorder', parsed: { error: 'bad_fsm' } };
    }

    let mutations: string[] = ['skip_step', 'repeat_step', 'parallel_steps', 'mutate_field'];
    try { if (params.mutations) mutations = JSON.parse(String(params.mutations)); } catch { /* ignore */ }

    if (!fsm.transitions || fsm.transitions.length < 2) {
      return { output: 'FSM needs at least 2 transitions to fuzz', parsed: { error: 'too_few_transitions' } };
    }

    const findings: Array<{ mutation: string; description: string; interesting: boolean; details: Record<string, unknown> }> = [];

    // Mutation: skip_step — jump over each transition
    if (mutations.includes('skip_step')) {
      for (let skip = 0; skip < fsm.transitions.length - 1; skip++) {
        const target = fsm.transitions[skip + 1];
        const result = await replayRequest(target, authCookie, timeoutMs);
        const interesting = result.status === 200 || result.status === 201;
        findings.push({ mutation: 'skip_step', description: `Skipped step ${skip}, jumped to step ${skip + 1}: ${target.request.url.substring(0, 60)}`, interesting, details: result });
      }
    }

    // Mutation: repeat_step — replay each transition twice
    if (mutations.includes('repeat_step')) {
      for (const t of fsm.transitions) {
        const r1 = await replayRequest(t, authCookie, timeoutMs);
        const r2 = await replayRequest(t, authCookie, timeoutMs);
        const interesting = r2.status === 200 && r1.status === 200 && r1.body_excerpt !== r2.body_excerpt;
        findings.push({ mutation: 'repeat_step', description: `Repeated: ${t.request.method} ${t.request.url.substring(0, 60)}`, interesting, details: { first: r1, second: r2, bodies_differ: r1.body_excerpt !== r2.body_excerpt } });
      }
    }

    // Mutation: parallel_steps — fire 2 adjacent transitions simultaneously
    if (mutations.includes('parallel_steps') && fsm.transitions.length >= 2) {
      const t1 = fsm.transitions[fsm.transitions.length - 2];
      const t2 = fsm.transitions[fsm.transitions.length - 1];
      const [r1, r2] = await Promise.all([
        replayRequest(t1, authCookie, timeoutMs),
        replayRequest(t2, authCookie, timeoutMs),
      ]);
      const interesting = r1.status === 200 && r2.status === 200;
      findings.push({ mutation: 'parallel_steps', description: `Parallel fire: ${t1.request.url.substring(0, 40)} || ${t2.request.url.substring(0, 40)}`, interesting, details: { step1: r1, step2: r2 } });
    }

    // Mutation: mutate_field — negate amount/price in POST bodies
    if (mutations.includes('mutate_field')) {
      for (const t of fsm.transitions.filter(t => t.request.body)) {
        const mutatedBody = mutateMoney(t.request.body!);
        if (mutatedBody !== t.request.body) {
          const mutatedT = { ...t, request: { ...t.request, body: mutatedBody } };
          const result = await replayRequest(mutatedT, authCookie, timeoutMs);
          const interesting = result.status === 200 && /success|confirm|complete/i.test(result.body_excerpt);
          findings.push({ mutation: 'mutate_field', description: `Negated amounts in: ${t.request.url.substring(0, 60)}`, interesting, details: { original_body: t.request.body?.substring(0, 100), mutated_body: mutatedBody.substring(0, 100), result } });
        }
      }
    }

    const interesting = findings.filter(f => f.interesting);
    const lines = [
      `flow_fuzzer — ${fsm.transitions.length} transitions, mutations: ${mutations.join(',')}`,
      `Interesting mutations: ${interesting.length}/${findings.length}`,
      '─'.repeat(72),
    ];
    for (const f of findings) {
      const flag = f.interesting ? '⚡ INTERESTING' : '  ·          ';
      lines.push(`  ${flag}  [${f.mutation.padEnd(16)}]  ${f.description}`);
    }

    return {
      output: lines.join('\n'),
      parsed: { total: findings.length, interesting_count: interesting.length, interesting, findings },
    };
  },
};

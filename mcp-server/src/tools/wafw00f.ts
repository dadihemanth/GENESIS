import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'wafw00f',
  description: 'WAF detection — identifies web application firewalls and their vendor by fingerprinting responses',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'url', type: 'string', required: true, description: 'Target URL (e.g. https://example.com)' },
    { name: 'find_all', type: 'boolean', required: false, description: 'Probe for all WAFs instead of stopping at first match', default: false },
  ],
};

interface WafResult {
  url: string;
  waf_detected: boolean;
  waf_name: string;
  waf_manufacturer: string;
}

interface Wafw00fParsed {
  results: WafResult[];
  waf_detected: boolean;
}

function parseWafw00fOutput(output: string): Wafw00fParsed {
  const results: WafResult[] = [];
  let wafDetected = false;

  for (const line of output.split('\n')) {
    const trimmed = line.trim();

    // "The site http://example.com is behind Cloudflare (Cloudflare Inc.) WAF."
    const behindMatch = trimmed.match(/The site (.+?) is behind (.+?) \((.+?)\)/i);
    if (behindMatch) {
      wafDetected = true;
      results.push({
        url: behindMatch[1],
        waf_detected: true,
        waf_name: behindMatch[2].trim(),
        waf_manufacturer: behindMatch[3].trim(),
      });
    }

    // "No WAF detected by the fingerprints"
    if (/no waf detected/i.test(trimmed)) {
      results.push({ url: '', waf_detected: false, waf_name: '', waf_manufacturer: '' });
    }
  }

  return { results, waf_detected: wafDetected };
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const url = String(params['url'] || '');
  const findAll = Boolean(params['find_all']);

  const startTime = Date.now();

  const available = await exec.isAvailable('wafw00f');
  if (!available) {
    return { success: false, tool: 'wafw00f', output: '', parsed: {}, duration: 0, command: '', error: "Tool 'wafw00f' not found." };
  }

  const args = [url];
  if (findAll) args.push('-a');

  const command = `wafw00f ${args.join(' ')}`;
  const result = await exec.execute('wafw00f', args, 60000);
  const duration = result.duration;

  let output = result.stdout + (result.stderr ? '\n' + result.stderr : '');
  if (output.length > 20000) output = output.substring(0, 20000) + '\n[TRUNCATED]';

  if (result.timedOut) {
    return { success: false, tool: 'wafw00f', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  const parsed = parseWafw00fOutput(result.stdout);

  return {
    success: result.exitCode === 0,
    tool: 'wafw00f',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: result.exitCode !== 0 ? result.stderr.trim() || null : null,
  };
}

export const wafw00fTool = { definition, execute };

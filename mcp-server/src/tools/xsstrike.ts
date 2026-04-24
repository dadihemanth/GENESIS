import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'xsstrike',
  description: 'Advanced XSS detection and exploitation suite',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'target', type: 'string', required: true, description: 'Target URL' },
    { name: 'crawl', type: 'boolean', required: false, description: 'Enable crawling mode', default: false },
  ],
};

interface XssPayload {
  url: string;
  parameter: string;
  payload: string;
  type: string;
}

interface XsstrikeParsed {
  vulnerable: boolean;
  payloads: XssPayload[];
}

function parseXsstrike(output: string): XsstrikeParsed {
  const payloads: XssPayload[] = [];
  let vulnerable = false;

  const lines = output.split('\n');
  const payloadRegex = /\[~\]\s*Payload:\s*(.+)/i;
  const paramRegex = /\[~\]\s*Parameter:\s*(.+)/i;
  const vulnRegex = /\[!\]\s*(?:XSS Found|Vulnerable|reflected)/i;
  const reflectedRegex = /reflected.*payload/i;

  let currentParam = '';
  let currentUrl = '';

  for (const line of lines) {
    if (vulnRegex.test(line) || reflectedRegex.test(line)) {
      vulnerable = true;
    }

    const paramMatch = line.match(paramRegex);
    if (paramMatch) currentParam = paramMatch[1].trim();

    const payloadMatch = line.match(payloadRegex);
    if (payloadMatch) {
      payloads.push({
        url: currentUrl,
        parameter: currentParam,
        payload: payloadMatch[1].trim(),
        type: 'reflected',
      });
      vulnerable = true;
    }

    // Try to extract URL from line
    const urlMatch = line.match(/https?:\/\/\S+/);
    if (urlMatch) currentUrl = urlMatch[0];
  }

  return { vulnerable, payloads };
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const target = String(params['target'] || '');
  const crawl = Boolean(params['crawl'] || false);

  // Try primary location, fallback to PATH
  const xsstrikePaths = ['/opt/XSStrike/xsstrike.py', 'xsstrike.py'];
  let scriptPath = xsstrikePaths[0];

  const args: string[] = [];
  let baseCmd = 'python3';

  // Check if python3 is available and which script path works
  const pythonAvailable = await exec.isAvailable('python3');
  if (!pythonAvailable) {
    const python3Alt = await exec.isAvailable('python');
    if (!python3Alt) {
      return {
        success: false,
        tool: 'xsstrike',
        output: '',
        parsed: {},
        duration: 0,
        command: `python3 ${scriptPath} -u "${target}"`,
        error: "Tool 'xsstrike' not found. Python3 not available.",
      };
    }
    baseCmd = 'python';
  }

  // Build args
  const scriptArgs = [scriptPath, '-u', target, '--timeout', '30'];
  if (crawl) scriptArgs.push('--crawl');

  const command = `${baseCmd} ${scriptArgs.join(' ')}`;
  const startTime = Date.now();

  let result = await exec.execute(baseCmd, scriptArgs, 120000);

  // If primary path fails (not found), try fallback
  if (result.exitCode !== 0 && (result.stderr.includes('No such file') || result.stderr.includes('can\'t open'))) {
    scriptPath = xsstrikePaths[1];
    const fallbackArgs = [scriptPath, '-u', target, '--timeout', '30'];
    if (crawl) fallbackArgs.push('--crawl');
    result = await exec.execute(baseCmd, fallbackArgs, 120000);
  }

  const duration = result.duration;
  let output = result.stdout + (result.stderr ? '\n' + result.stderr : '');

  if (output.length > 50000) {
    output = output.substring(0, 50000) + '\n[OUTPUT TRUNCATED]';
  }

  if (result.timedOut) {
    return { success: false, tool: 'xsstrike', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  const isNotFound =
    result.stderr.includes('No such file') ||
    result.stderr.includes("can't open") ||
    result.exitCode === 2;

  if (isNotFound) {
    return {
      success: false,
      tool: 'xsstrike',
      output: '',
      parsed: {},
      duration,
      command,
      error: "Tool 'xsstrike' not found. Install it first at /opt/XSStrike/xsstrike.py.",
    };
  }

  const parsed = parseXsstrike(result.stdout);

  return {
    success: result.exitCode === 0,
    tool: 'xsstrike',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: result.exitCode !== 0 ? result.stderr.trim() || null : null,
  };
}

export const xsstrikeTool = { definition, execute };

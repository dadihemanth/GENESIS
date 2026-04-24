import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';
import * as fs from 'fs';

const definition: ToolDefinition = {
  name: 'whatweb',
  description: 'Web application fingerprinting tool',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'target', type: 'string', required: true, description: 'Target URL' },
    { name: 'aggression', type: 'number', required: false, description: 'Aggression level 1-4', default: 1 },
  ],
};

interface WhatwebTechnology {
  name: string;
  version: string;
  confidence: number;
  string: string;
}

interface WhatwebParsed {
  technologies: WhatwebTechnology[];
  http_status: number | null;
  title: string;
}

function parseWhatwebJson(raw: string): WhatwebParsed {
  const technologies: WhatwebTechnology[] = [];
  let http_status: number | null = null;
  let title = '';

  try {
    // WhatWeb JSON output is an array of result objects
    const data = JSON.parse(raw);
    const results = Array.isArray(data) ? data : [data];

    for (const result of results) {
      if (result.http_status) http_status = result.http_status;

      const plugins = result.plugins || {};
      for (const [name, info] of Object.entries(plugins)) {
        if (name === 'Title') {
          const titleInfo = info as Record<string, unknown>;
          const strings = titleInfo['string'] as string[] | undefined;
          if (strings && strings.length > 0) title = strings[0];
        }

        const pluginInfo = info as Record<string, unknown>;
        const version = ((pluginInfo['version'] as string[] | undefined) || [])[0] || '';
        const confidence = (pluginInfo['confidence'] as number | undefined) ?? 100;
        const str = ((pluginInfo['string'] as string[] | undefined) || [])[0] || '';

        technologies.push({ name, version, confidence, string: str });
      }
    }
  } catch {
    // Ignore parse errors
  }

  return { technologies, http_status, title };
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const target = String(params['target'] || '');
  const aggression = Math.min(4, Math.max(1, Number(params['aggression'] || 1)));
  const ts = Date.now();
  const logFile = `/tmp/whatweb_${ts}.json`;

  const args = [`--aggression=${aggression}`, `--log-json=${logFile}`, target];
  const command = `whatweb ${args.join(' ')}`;
  const startTime = Date.now();

  const available = await exec.isAvailable('whatweb');
  if (!available) {
    return {
      success: false,
      tool: 'whatweb',
      output: '',
      parsed: {},
      duration: (Date.now() - startTime) / 1000,
      command,
      error: "Tool 'whatweb' not found. Install it first.",
    };
  }

  const result = await exec.execute('whatweb', args, 120000);
  const duration = result.duration;
  let output = result.stdout + (result.stderr ? '\n' + result.stderr : '');

  if (output.length > 50000) {
    output = output.substring(0, 50000) + '\n[OUTPUT TRUNCATED]';
  }

  if (result.timedOut) {
    return { success: false, tool: 'whatweb', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  let parsed: WhatwebParsed = { technologies: [], http_status: null, title: '' };

  try {
    if (fs.existsSync(logFile)) {
      const raw = fs.readFileSync(logFile, 'utf-8');
      parsed = parseWhatwebJson(raw);
      fs.unlinkSync(logFile);
    }
  } catch {
    // Ignore file errors
  }

  return {
    success: result.exitCode === 0,
    tool: 'whatweb',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: result.exitCode !== 0 ? result.stderr.trim() || null : null,
  };
}

export const whatwebTool = { definition, execute };

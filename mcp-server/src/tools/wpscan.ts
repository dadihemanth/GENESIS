import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'wpscan',
  description: 'WordPress vulnerability scanner — plugins, themes, users, CVEs',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'url', type: 'string', required: true, description: 'Target WordPress URL' },
    { name: 'enumerate', type: 'string', required: false, description: 'What to enumerate: u=users, p=plugins, t=themes, vp=vulnerable plugins', default: 'u,vp,vt' },
    { name: 'threads', type: 'number', required: false, description: 'Request threads', default: 5 },
    { name: 'api_token', type: 'string', required: false, description: 'WPScan API token for vulnerability data', default: '' },
  ],
};

interface WpscanVuln {
  title: string;
  cve: string;
  fixed_in: string;
}

interface WpscanPlugin {
  name: string;
  version: string;
  vulnerabilities: WpscanVuln[];
}

interface WpscanParsed {
  wordpress_version: string;
  is_wordpress: boolean;
  users: string[];
  plugins: WpscanPlugin[];
  themes: string[];
  vulnerabilities_found: number;
}

function parseWpscanJson(raw: string): WpscanParsed {
  const result: WpscanParsed = {
    wordpress_version: '',
    is_wordpress: false,
    users: [],
    plugins: [],
    themes: [],
    vulnerabilities_found: 0,
  };

  try {
    const data = JSON.parse(raw);
    result.is_wordpress = true;

    if (data.version?.number) result.wordpress_version = data.version.number;

    for (const [name, info] of Object.entries(data.plugins ?? {})) {
      const p = info as Record<string, unknown>;
      const vulns: WpscanVuln[] = ((p.vulnerabilities as unknown[]) ?? []).map((v: unknown) => {
        const vv = v as Record<string, unknown>;
        return { title: String(vv.title ?? ''), cve: String((vv.references as Record<string,unknown>)?.cve ?? ''), fixed_in: String(vv.fixed_in ?? '') };
      });
      result.plugins.push({ name, version: String((p.version as Record<string,unknown>)?.number ?? ''), vulnerabilities: vulns });
      result.vulnerabilities_found += vulns.length;
    }

    for (const [name] of Object.entries(data.themes ?? {})) result.themes.push(name);
    for (const [, user] of Object.entries(data.users ?? {})) {
      const u = user as Record<string, unknown>;
      if (u.username) result.users.push(String(u.username));
    }
  } catch { /* ignore */ }

  return result;
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const url = String(params['url'] || '');
  const enumerate = String(params['enumerate'] || 'u,vp,vt');
  const threads = Number(params['threads'] || 5);
  const apiToken = String(params['api_token'] || '');
  const outFile = `/tmp/wpscan_${Date.now()}.json`;

  const args = [
    '--url', url,
    '--enumerate', enumerate,
    '--request-timeout', '10',
    '--connect-timeout', '5',
    '--throttle', String(Math.max(1, Math.floor(1000 / threads))),
    '--format', 'json',
    '--output', outFile,
    '--no-banner',
    '--disable-tls-checks',
  ];

  if (apiToken) args.push('--api-token', apiToken);

  const command = `wpscan ${args.join(' ')}`;
  const startTime = Date.now();

  const available = await exec.isAvailable('wpscan');
  if (!available) {
    return { success: false, tool: 'wpscan', output: '', parsed: {}, duration: (Date.now() - startTime) / 1000, command, error: "Tool 'wpscan' not found." };
  }

  const result = await exec.execute('wpscan', args, 180000);
  const duration = result.duration;
  let output = result.stdout + (result.stderr ? '\n' + result.stderr : '');
  if (output.length > 50000) output = output.substring(0, 50000) + '\n[TRUNCATED]';

  if (result.timedOut) {
    return { success: false, tool: 'wpscan', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  let parsed: WpscanParsed = { wordpress_version: '', is_wordpress: false, users: [], plugins: [], themes: [], vulnerabilities_found: 0 };
  try {
    const { readFileSync, unlinkSync, existsSync } = await import('fs');
    if (existsSync(outFile)) {
      parsed = parseWpscanJson(readFileSync(outFile, 'utf-8'));
      unlinkSync(outFile);
    }
  } catch { /* ignore */ }

  return {
    success: result.exitCode === 0 || result.exitCode === 5,
    tool: 'wpscan',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: result.exitCode !== 0 && result.exitCode !== 5 ? result.stderr.trim() || null : null,
  };
}

export const wpscanTool = { definition, execute };

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';
import * as fs from 'fs';
import * as path from 'path';

const definition: ToolDefinition = {
  name: 'gobuster',
  description: 'Directory and file brute-forcer for web servers',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'target', type: 'string', required: true, description: 'Target URL' },
    { name: 'wordlist', type: 'string', required: false, description: 'Path to wordlist', default: '/usr/share/wordlists/dirb/common.txt' },
    { name: 'extensions', type: 'array', required: false, description: 'File extensions to check', default: ['php', 'html', 'txt'] },
    { name: 'threads', type: 'number', required: false, description: 'Number of concurrent threads', default: 10 },
  ],
};

interface GobusterPath {
  path: string;
  status: number;
  size: number;
}

interface GobusterParsed {
  paths: GobusterPath[];
  total_found: number;
}

const SAFE_WORDLIST_DIRS = [
  '/usr/share/wordlists',
  '/usr/share/dirb/wordlists',
  '/data/security/wordlists',
];

function isWordlistPathSafe(p: string): boolean {
  const resolved = path.resolve(p);
  return SAFE_WORDLIST_DIRS.some(
    (dir) => resolved === dir || resolved.startsWith(dir + path.sep)
  );
}

const SAFE_FALLBACKS = [
  '/usr/share/wordlists/dirb/common.txt',
  '/usr/share/wordlists/dirb/small.txt',
  '/usr/share/dirb/wordlists/common.txt',
];

function resolveWordlist(preferred: string): string {
  // Only honour caller-supplied path if it resolves within a safe directory
  if (isWordlistPathSafe(preferred) && fs.existsSync(preferred)) {
    return preferred;
  }
  // Fall back to known-safe paths
  for (const wl of SAFE_FALLBACKS) {
    if (fs.existsSync(wl)) return wl;
  }
  return SAFE_FALLBACKS[0]; // Let gobuster produce a clear "not found" error
}

function parseGobusterOutput(output: string): GobusterParsed {
  const lines = output.split('\n');
  const paths: GobusterPath[] = [];

  // Gobuster output format: /path (Status: 200) [Size: 1234]
  const lineRegex = /^(\S+)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]/;

  for (const line of lines) {
    const match = line.trim().match(lineRegex);
    if (match) {
      paths.push({
        path: match[1],
        status: parseInt(match[2], 10),
        size: parseInt(match[3], 10),
      });
    }
  }

  return { paths, total_found: paths.length };
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const target = String(params['target'] || '');
  const preferredWordlist = String(params['wordlist'] || '/usr/share/wordlists/dirb/common.txt');
  const extensions = Array.isArray(params['extensions'])
    ? (params['extensions'] as string[]).join(',')
    : 'php,html,txt';
  const threads = Number(params['threads'] || 10);

  const wordlist = resolveWordlist(preferredWordlist);

  const args = [
    'dir',
    '-u', target,
    '-w', wordlist,
    '-x', extensions,
    '-t', String(threads),
    '-q',
    '--no-color',
  ];

  const command = `gobuster ${args.join(' ')}`;
  const startTime = Date.now();

  const available = await exec.isAvailable('gobuster');
  if (!available) {
    return {
      success: false,
      tool: 'gobuster',
      output: '',
      parsed: {},
      duration: (Date.now() - startTime) / 1000,
      command,
      error: "Tool 'gobuster' not found. Install it first.",
    };
  }

  const result = await exec.execute('gobuster', args, 600000);
  const duration = result.duration;
  let output = result.stdout + (result.stderr ? '\n' + result.stderr : '');

  if (output.length > 50000) {
    output = output.substring(0, 50000) + '\n[OUTPUT TRUNCATED]';
  }

  if (result.timedOut) {
    return { success: false, tool: 'gobuster', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  const parsed = parseGobusterOutput(result.stdout);

  return {
    success: result.exitCode === 0 || parsed.paths.length > 0,
    tool: 'gobuster',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: result.exitCode !== 0 && parsed.paths.length === 0 ? result.stderr.trim() || null : null,
  };
}

export const gobusterTool = { definition, execute };

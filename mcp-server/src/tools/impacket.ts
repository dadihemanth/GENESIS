import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'impacket',
  description: 'Windows/AD exploitation — secretsdump (credential extraction), GetUserSPNs (Kerberoasting), lookupsid',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'script', type: 'string', required: true, description: 'Impacket script: secretsdump, GetUserSPNs, lookupsid, GetNPUsers, smbclient' },
    { name: 'target', type: 'string', required: true, description: 'Target: [domain/]user:pass@host or just host' },
    { name: 'extra_args', type: 'string', required: false, description: 'Extra arguments passed verbatim', default: '' },
  ],
};

const ALLOWED_SCRIPTS = new Set([
  'secretsdump', 'GetUserSPNs', 'GetNPUsers', 'lookupsid',
  'smbclient', 'rpcdump', 'reg', 'atexec', 'wmiexec',
]);

interface ImpacketParsed {
  hashes: string[];
  spns: string[];
  users: string[];
  shares: string[];
}

function parseImpacketOutput(output: string, script: string): ImpacketParsed {
  const result: ImpacketParsed = { hashes: [], spns: [], users: [], shares: [] };

  for (const line of output.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('[*]') || trimmed.startsWith('[+]') || trimmed.startsWith('[-]')) continue;

    if (script === 'secretsdump') {
      // NTLM hash lines: Administrator:500:aad3b435...:31d6...:::
      if (/^[^:]+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::/.test(trimmed)) {
        result.hashes.push(trimmed);
      }
      // $krb5... Kerberos hashes
      if (trimmed.startsWith('$krb5')) result.hashes.push(trimmed);
    }

    if (script === 'GetUserSPNs') {
      if (trimmed.startsWith('$krb5tgs')) result.spns.push(trimmed);
      const userMatch = trimmed.match(/^([\w.-]+)\s+\d/);
      if (userMatch) result.users.push(userMatch[1]);
    }

    if (script === 'GetNPUsers') {
      if (trimmed.startsWith('$krb5asrep')) result.spns.push(trimmed);
    }

    if (script === 'lookupsid') {
      const sidMatch = trimmed.match(/\d+:\s+\S+\s+\\(\S+)/);
      if (sidMatch) result.users.push(sidMatch[1]);
    }

    if (script === 'smbclient') {
      const shareMatch = trimmed.match(/^\s+(\S+)\s+(Disk|IPC|Printer)/);
      if (shareMatch) result.shares.push(shareMatch[1]);
    }
  }

  return result;
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const script = String(params['script'] || '');
  const target = String(params['target'] || '');
  const extraArgs = String(params['extra_args'] || '');

  const startTime = Date.now();

  if (!ALLOWED_SCRIPTS.has(script)) {
    return { success: false, tool: 'impacket', output: '', parsed: {}, duration: 0, command: '', error: `Script '${script}' not allowed. Use: ${[...ALLOWED_SCRIPTS].join(', ')}` };
  }

  const binaryName = `impacket-${script}`;
  const args = [target, ...(extraArgs ? extraArgs.split(' ').filter(Boolean) : [])];
  const command = `${binaryName} ${args.join(' ')}`;

  const available = await exec.isAvailable(binaryName);
  if (!available) {
    return { success: false, tool: 'impacket', output: '', parsed: {}, duration: (Date.now() - startTime) / 1000, command, error: `Tool '${binaryName}' not found.` };
  }

  const result = await exec.execute(binaryName, args, 120000);
  const duration = result.duration;
  let output = result.stdout + (result.stderr ? '\n' + result.stderr : '');
  if (output.length > 50000) output = output.substring(0, 50000) + '\n[TRUNCATED]';

  if (result.timedOut) {
    return { success: false, tool: 'impacket', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  const parsed = parseImpacketOutput(output, script);

  return {
    success: result.exitCode === 0,
    tool: 'impacket',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: result.exitCode !== 0 ? result.stderr.trim() || null : null,
  };
}

export const impacketTool = { definition, execute };

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'harvester',
  description: 'OSINT tool — harvests emails, hosts, subdomains, IPs from public sources',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'domain', type: 'string', required: true, description: 'Target domain to harvest' },
    { name: 'sources', type: 'string', required: false, description: 'Comma-separated sources (bing,crtsh,dnsdumpster,hackertarget,otx,rapiddns)', default: 'bing,crtsh,dnsdumpster,hackertarget' },
    { name: 'limit', type: 'number', required: false, description: 'Max results per source', default: 100 },
  ],
};

interface HarvesterParsed {
  emails: string[];
  hosts: string[];
  ips: string[];
  total_emails: number;
  total_hosts: number;
}

function parseHarvesterOutput(output: string): HarvesterParsed {
  const emails: Set<string> = new Set();
  const hosts: Set<string> = new Set();
  const ips: Set<string> = new Set();

  const lines = output.split('\n');
  let section = '';

  for (const line of lines) {
    const trimmed = line.trim();
    if (/\[\*\]\s*Emails/i.test(trimmed)) { section = 'emails'; continue; }
    if (/\[\*\]\s*Hosts/i.test(trimmed)) { section = 'hosts'; continue; }
    if (/\[\*\]\s*IPs/i.test(trimmed)) { section = 'ips'; continue; }
    if (trimmed.startsWith('[*]') || trimmed.startsWith('[+]') || trimmed.startsWith('[-]')) {
      section = '';
    }

    if (!trimmed || trimmed.startsWith('[')) continue;

    if (section === 'emails' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) {
      emails.add(trimmed.toLowerCase());
    } else if (section === 'hosts' && /^[\w.-]+\.[a-z]{2,}/.test(trimmed)) {
      hosts.add(trimmed.toLowerCase());
    } else if (section === 'ips' && /^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed)) {
      ips.add(trimmed);
    }

    // Also extract emails anywhere in output
    const emailMatches = trimmed.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g);
    if (emailMatches) emailMatches.forEach(e => emails.add(e.toLowerCase()));
  }

  return {
    emails: [...emails],
    hosts: [...hosts],
    ips: [...ips],
    total_emails: emails.size,
    total_hosts: hosts.size,
  };
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const domain = String(params['domain'] || '');
  const sources = String(params['sources'] || 'bing,crtsh,dnsdumpster,hackertarget');
  const limit = Number(params['limit'] || 100);

  const args = ['-d', domain, '-b', sources, '-l', String(limit), '-f', `/tmp/harvester_${Date.now()}`];
  const command = `theHarvester ${args.join(' ')}`;
  const startTime = Date.now();

  const available = await exec.isAvailable('theHarvester');
  if (!available) {
    return { success: false, tool: 'harvester', output: '', parsed: {}, duration: (Date.now() - startTime) / 1000, command, error: "Tool 'theHarvester' not found." };
  }

  const result = await exec.execute('theHarvester', args, 120000);
  const duration = result.duration;
  let output = result.stdout + (result.stderr ? '\n' + result.stderr : '');
  if (output.length > 50000) output = output.substring(0, 50000) + '\n[TRUNCATED]';

  if (result.timedOut) {
    return { success: false, tool: 'harvester', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  const parsed = parseHarvesterOutput(result.stdout);

  return {
    success: true,
    tool: 'harvester',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: null,
  };
}

export const harvesterTool = { definition, execute };

// T75 — bloodhound_collect
// Runs bloodhound-python to collect AD attack-graph data.
// Returns Cypher-compatible JSON for Neo4j import.

import * as fs from 'fs';
import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'bloodhound_collect',
  description:
    'Active Directory attack-graph collection via BloodHound. Runs bloodhound-python to collect ' +
    'domain objects, group memberships, ACLs, sessions, and trust relationships. Returns data ' +
    'importable into Neo4j for attack-path analysis (shortest path to Domain Admin).',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'dc_host',           type: 'string', required: true,  description: 'Domain controller hostname/IP' },
    { name: 'domain',            type: 'string', required: true,  description: 'Active Directory domain name (e.g. corp.local)' },
    { name: 'username',          type: 'string', required: true,  description: 'Domain username' },
    { name: 'password',          type: 'string', required: true,  description: 'Domain password or NTLM hash (format: LMHASH:NTHASH)' },
    { name: 'collection_method', type: 'string', required: false, description: 'Collection method: All / DCOnly / Session / Trusts / Default', default: 'DCOnly' },
    { name: 'timeout_ms',        type: 'number', required: false, description: 'Execution timeout ms', default: 120000 },
  ],
};

export const bloodhoundCollectTool = {
  definition,
  async execute(params: Record<string, unknown>, exec: CommandExecutor): Promise<ToolResult> {
    const dcHost = String(params.dc_host || '');
    const domain = String(params.domain || '');
    const username = String(params.username || '');
    const password = String(params.password || '');
    const collectionMethod = String(params.collection_method || 'DCOnly');
    const timeoutMs = Number(params.timeout_ms || 120000);

    if (!dcHost) return { output: 'dc_host required', parsed: { error: 'missing_dc_host' } };
    if (!domain) return { output: 'domain required', parsed: { error: 'missing_domain' } };
    if (!username) return { output: 'username required', parsed: { error: 'missing_username' } };
    if (!password) return { output: 'password required', parsed: { error: 'missing_password' } };

    const isHash = /^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$/.test(password);
    const authArgs: string[] = isHash ? ['--hashes', password] : ['-p', password];

    const outDir = `/tmp/genesis_bh_${Date.now()}`;
    fs.mkdirSync(outDir, { recursive: true });

    const args = [
      '-d', domain,
      '-u', username,
      ...authArgs,
      '-dc', dcHost,
      '-c', collectionMethod,
      '--zip',
      '--outputdir', outDir,
    ];

    try {
      const result = await exec.execute('bloodhound-python', args, timeoutMs);
      const interesting = result.exitCode === 0 && result.stdout.includes('.zip');

      const lines = [
        `bloodhound_collect — ${domain}  DC=${dcHost}  method=${collectionMethod}`,
        `Status: ${interesting ? '⚡ SUCCESS — data collected' : 'failed or no output'}`,
        '─'.repeat(72),
        result.stdout.substring(0, 500),
      ];

      if (interesting) {
        lines.push('');
        lines.push(`Output: ${outDir}/`);
        lines.push('Import: upload .zip to BloodHound GUI or: neo4j bulk import');
        lines.push('Cypher: MATCH p=shortestPath((u:User)-[*1..]->(g:Group {name:"DOMAIN ADMINS@' + domain.toUpperCase() + '"})) RETURN p');
      }

      return {
        output: lines.join('\n'),
        parsed: { success: interesting, output_dir: outDir, stdout: result.stdout.substring(0, 500) },
      };
    } catch (err) {
      return { output: `bloodhound_collect error: ${String(err)}`, parsed: { error: String(err) } };
    }
  },
};

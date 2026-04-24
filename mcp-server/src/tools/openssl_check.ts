import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'openssl_check',
  description: 'TLS/SSL certificate inspection tool',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'host', type: 'string', required: true, description: 'Target hostname' },
    { name: 'port', type: 'number', required: false, description: 'Target port', default: 443 },
  ],
};

interface CertInfo {
  subject: string;
  issuer: string;
  valid_from: string;
  valid_to: string;
  san: string[];
}

interface OpensslParsed {
  certificate: CertInfo;
  tls_version: string;
  cipher: string;
  expired: boolean;
}

function parseOpensslOutput(output: string): OpensslParsed {
  let subject = '';
  let issuer = '';
  let valid_from = '';
  let valid_to = '';
  const san: string[] = [];
  let tls_version = '';
  let cipher = '';
  let expired = false;

  const lines = output.split('\n');

  for (const line of lines) {
    const subjectMatch = line.match(/^\s*subject=(.+)$/i) || line.match(/^subject:\s*(.+)$/i);
    if (subjectMatch) subject = subjectMatch[1].trim();

    const issuerMatch = line.match(/^\s*issuer=(.+)$/i) || line.match(/^issuer:\s*(.+)$/i);
    if (issuerMatch) issuer = issuerMatch[1].trim();

    const notBeforeMatch = line.match(/Not Before:\s*(.+)/i);
    if (notBeforeMatch) valid_from = notBeforeMatch[1].trim();

    const notAfterMatch = line.match(/Not After\s*:\s*(.+)/i);
    if (notAfterMatch) valid_to = notAfterMatch[1].trim();

    // SAN entries: DNS:example.com, DNS:www.example.com
    const sanMatch = line.match(/DNS:([^,\s]+)/g);
    if (sanMatch) {
      for (const s of sanMatch) {
        const domain = s.replace('DNS:', '').trim();
        if (!san.includes(domain)) san.push(domain);
      }
    }

    const tlsMatch = line.match(/Protocol\s*:\s*(.+)/i);
    if (tlsMatch) tls_version = tlsMatch[1].trim();

    const cipherMatch = line.match(/Cipher\s*:\s*(.+)/i);
    if (cipherMatch) cipher = cipherMatch[1].trim();

    if (line.includes('verify error') && line.includes('certificate has expired')) {
      expired = true;
    }
    if (line.toLowerCase().includes('certificate:') && line.toLowerCase().includes('expired')) {
      expired = true;
    }
  }

  // Check expiry by parsing valid_to date
  if (valid_to && !expired) {
    try {
      const expDate = new Date(valid_to);
      if (!isNaN(expDate.getTime()) && expDate < new Date()) {
        expired = true;
      }
    } catch { /* ignore */ }
  }

  return {
    certificate: { subject, issuer, valid_from, valid_to, san },
    tls_version,
    cipher,
    expired,
  };
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const host = String(params['host'] || '');
  const port = Number(params['port'] || 443);

  // On Windows, /dev/null doesn't exist — use nul
  const isWindows = process.platform === 'win32';
  const nullDevice = isWindows ? 'nul' : '/dev/null';

  const command = `openssl s_client -connect ${host}:${port} -showcerts < ${nullDevice} 2>&1`;
  const startTime = Date.now();

  const available = await exec.isAvailable('openssl');
  if (!available) {
    return {
      success: false,
      tool: 'openssl_check',
      output: '',
      parsed: {},
      duration: (Date.now() - startTime) / 1000,
      command,
      error: "Tool 'openssl' not found. Install it first.",
    };
  }

  const result = await exec.executeShell(command, 30000);
  const duration = result.duration;
  let output = result.stdout + (result.stderr ? '\n' + result.stderr : '');

  if (output.length > 50000) {
    output = output.substring(0, 50000) + '\n[OUTPUT TRUNCATED]';
  }

  if (result.timedOut) {
    return { success: false, tool: 'openssl_check', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  const combined = result.stdout + '\n' + result.stderr;
  const parsed = parseOpensslOutput(combined);

  return {
    success: result.exitCode === 0,
    tool: 'openssl_check',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: result.exitCode !== 0 ? result.stderr.trim() || null : null,
  };
}

export const opensslCheckTool = { definition, execute };

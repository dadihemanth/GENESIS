import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'sslscan',
  description: 'SSL/TLS vulnerability scanner — detects weak ciphers, Heartbleed, POODLE, BEAST, CRIME',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'host', type: 'string', required: true, description: 'Target hostname or IP' },
    { name: 'port', type: 'number', required: false, description: 'Target port', default: 443 },
    { name: 'starttls', type: 'string', required: false, description: 'STARTTLS protocol (smtp, imap, ftp, xmpp)', default: '' },
  ],
};

interface SslscanParsed {
  heartbleed: boolean;
  poodle: boolean;
  beast: boolean;
  crime: boolean;
  weak_ciphers: string[];
  supported_protocols: string[];
  cert_subject: string;
  cert_issuer: string;
  cert_expiry: string;
  cert_expired: boolean;
}

function parseSslscanOutput(output: string): SslscanParsed {
  const result: SslscanParsed = {
    heartbleed: false,
    poodle: false,
    beast: false,
    crime: false,
    weak_ciphers: [],
    supported_protocols: [],
    cert_subject: '',
    cert_issuer: '',
    cert_expiry: '',
    cert_expired: false,
  };

  const lines = output.split('\n');
  for (const line of lines) {
    if (/heartbleed.*vulnerable/i.test(line)) result.heartbleed = true;
    if (/poodle.*vulnerable/i.test(line)) result.poodle = true;
    if (/beast.*vulnerable/i.test(line)) result.beast = true;
    if (/crime.*vulnerable/i.test(line)) result.crime = true;

    // Protocols
    const protoMatch = line.match(/^\s*(TLSv\d[\.\d]*|SSLv\d[\.\d]*)\s+enabled/i);
    if (protoMatch) result.supported_protocols.push(protoMatch[1]);

    // Weak ciphers (RC4, DES, EXPORT, NULL, anon)
    if (/\b(RC4|DES|EXPORT|NULL|anon|ADH|AECDH|3DES)\b/i.test(line) && /Accepted|enabled/i.test(line)) {
      const cipherMatch = line.match(/\b([A-Z0-9_-]{6,})\b/);
      if (cipherMatch) result.weak_ciphers.push(cipherMatch[1]);
    }

    // Certificate fields
    const subjectMatch = line.match(/Subject:\s*(.+)/);
    if (subjectMatch) result.cert_subject = subjectMatch[1].trim();

    const issuerMatch = line.match(/Issuer:\s*(.+)/);
    if (issuerMatch) result.cert_issuer = issuerMatch[1].trim();

    const expiryMatch = line.match(/(?:Not After|Expiry)\s*:\s*(.+)/i);
    if (expiryMatch) result.cert_expiry = expiryMatch[1].trim();

    if (/expired|EXPIRED/i.test(line) && /certificate/i.test(line)) result.cert_expired = true;
  }

  return result;
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const host = String(params['host'] || '');
  const port = Number(params['port'] || 443);
  const starttls = String(params['starttls'] || '');
  const target = `${host}:${port}`;

  const args = ['--no-colour', '--show-certificate', target];
  if (starttls) args.splice(2, 0, `--starttls-${starttls}`);

  const command = `sslscan ${args.join(' ')}`;
  const startTime = Date.now();

  const available = await exec.isAvailable('sslscan');
  if (!available) {
    return { success: false, tool: 'sslscan', output: '', parsed: {}, duration: (Date.now() - startTime) / 1000, command, error: "Tool 'sslscan' not found." };
  }

  const result = await exec.execute('sslscan', args, 60000);
  const duration = result.duration;
  let output = result.stdout + (result.stderr ? '\n' + result.stderr : '');
  if (output.length > 30000) output = output.substring(0, 30000) + '\n[TRUNCATED]';

  if (result.timedOut) {
    return { success: false, tool: 'sslscan', output, parsed: {}, duration, command, error: 'Timed out' };
  }

  const parsed = parseSslscanOutput(result.stdout);

  return {
    success: result.exitCode === 0,
    tool: 'sslscan',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: result.exitCode !== 0 ? result.stderr.trim() || null : null,
  };
}

export const sslscanTool = { definition, execute };

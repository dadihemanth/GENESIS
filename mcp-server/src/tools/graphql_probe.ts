import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'graphql_probe',
  description: 'GraphQL security tester: introspection enabled check with schema enumeration, batch query rate-limit bypass, deep nesting DoS timing test, GET-based CSRF detection, field suggestion leakage, sensitive mutation discovery.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'url', type: 'string', required: true, description: 'GraphQL endpoint URL e.g. https://api.example.com/graphql' },
    { name: 'auth_header', type: 'string', required: false, description: 'Authorization header value' },
    { name: 'batch_size', type: 'number', required: false, description: 'Number of queries in batching test', default: 10 },
    { name: 'depth_limit', type: 'number', required: false, description: 'Max nesting depth for DoS test', default: 20 },
    { name: 'timeout_ms', type: 'number', required: false, description: 'Per-request timeout in ms', default: 12000 },
  ],
};

interface GqlFinding {
  test: string;
  severity: string;
  detail: string;
}

function buildHeaders(authHeader: string): Record<string, string> {
  const h: Record<string, string> = {
    'Content-Type': 'application/json',
    'User-Agent': 'Mozilla/5.0',
  };
  if (authHeader) h['Authorization'] = authHeader;
  return h;
}

async function gqlPost(
  url: string,
  query: string,
  headers: Record<string, string>,
  timeoutMs: number,
  body?: unknown,
): Promise<{ status: number; bodyText: string; time_ms: number }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const start = Date.now();
  try {
    const resp = await fetch(url, {
      method: 'POST',
      headers,
      body: body !== undefined ? JSON.stringify(body) : JSON.stringify({ query }),
      signal: controller.signal,
    });
    clearTimeout(timer);
    const bodyText = await resp.text();
    return { status: resp.status, bodyText, time_ms: Date.now() - start };
  } catch {
    clearTimeout(timer);
    return { status: 0, bodyText: '', time_ms: Date.now() - start };
  }
}

function buildNestedQuery(depth: number): string {
  const open = Array(depth).fill('a {').join(' ');
  const close = Array(depth).fill('}').join(' ');
  return `{ ${open} __typename ${close} }`;
}

const SENSITIVE_PATTERNS = /admin|delete|remove|update|user|password|reset|grant|privilege|role|token|secret|internal/i;

export const graphqlProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const url = String(params.url || '');
    const authHeader = String(params.auth_header || '');
    const batchSize = Math.min(Number(params.batch_size ?? 10), 50);
    const depthLimit = Math.min(Number(params.depth_limit ?? 20), 30);
    const timeoutMs = Number(params.timeout_ms || 12000);

    const headers = buildHeaders(authHeader);
    const findings: GqlFinding[] = [];

    // Test 1: Introspection
    const introspectionQuery = `{
      __schema {
        queryType { name }
        types { name kind fields { name type { name kind ofType { name } } } }
        mutationType { name }
        subscriptionType { name }
      }
    }`;

    const introResult = await gqlPost(url, introspectionQuery, headers, timeoutMs);
    let introspectionEnabled = false;
    let schemaTypes: string[] = [];
    let mutationNames: string[] = [];
    let sensitiveTypes: string[] = [];

    if (introResult.bodyText.includes('"__schema"')) {
      introspectionEnabled = true;
      findings.push({ test: 'Introspection', severity: 'info', detail: 'GraphQL introspection is enabled — full schema is publicly readable' });

      try {
        const parsed = JSON.parse(introResult.bodyText);
        const types = parsed?.data?.__schema?.types ?? [];
        schemaTypes = types.map((t: Record<string, unknown>) => String(t.name)).filter((n: string) => !n.startsWith('__'));
        sensitiveTypes = schemaTypes.filter((n: string) => SENSITIVE_PATTERNS.test(n));

        // Extract mutations
        for (const type of types) {
          if (type && (type.name === 'Mutation' || (typeof type.name === 'string' && type.name.toLowerCase().includes('mutation')))) {
            const fields = (type.fields as Array<Record<string, unknown>> | null) ?? [];
            mutationNames = fields.map((f: Record<string, unknown>) => String(f.name));
          }
        }

        const sensitiveMutations = mutationNames.filter(n => SENSITIVE_PATTERNS.test(n));
        if (sensitiveMutations.length > 0) {
          findings.push({ test: 'Sensitive Mutations', severity: 'high', detail: `Sensitive mutations found: ${sensitiveMutations.join(', ')}` });
        }
        if (sensitiveTypes.length > 0) {
          findings.push({ test: 'Sensitive Types', severity: 'medium', detail: `Sensitive types in schema: ${sensitiveTypes.join(', ')}` });
        }
      } catch { /* schema parse failed */ }
    } else {
      findings.push({ test: 'Introspection', severity: 'info', detail: 'Introspection disabled (good)' });
    }

    // Test 2: Field suggestion leakage (even when introspection is disabled)
    const typeResult = await gqlPost(url, '{ __type(name: "User") { fields { name } } }', headers, timeoutMs);
    if (typeResult.bodyText.includes('"fields"') && !typeResult.bodyText.includes('"fields":null')) {
      findings.push({ test: 'Field Suggestion Leakage', severity: 'low', detail: '__type query works even with introspection disabled — partial schema exposure' });
    }

    const typoResult = await gqlPost(url, '{ usr { id } }', headers, timeoutMs);
    if (typoResult.bodyText.toLowerCase().includes('did you mean')) {
      findings.push({ test: 'Field Suggestion Leakage', severity: 'low', detail: 'Server returns "Did you mean..." on typos — field names can be enumerated via suggestions' });
    }

    // Test 3: Batching
    const batchBody = Array.from({ length: batchSize }, () => ({ query: '{ __typename }' }));
    const batchResult = await gqlPost(url, '', headers, timeoutMs, batchBody);
    let batchingEnabled = false;
    try {
      const parsed = JSON.parse(batchResult.bodyText);
      if (Array.isArray(parsed) && parsed.length === batchSize) {
        batchingEnabled = true;
        findings.push({ test: 'Batching', severity: 'medium', detail: `Query batching enabled — ${batchSize} queries accepted in single request, bypasses per-request rate limiting` });
      }
    } catch { /* not JSON array */ }

    // Test 4: Deep nesting DoS
    const baselineResult = await gqlPost(url, '{ __typename }', headers, Math.min(timeoutMs, 5000));
    const baselineTime = baselineResult.time_ms;
    const nestedQuery = buildNestedQuery(depthLimit);
    const nestedResult = await gqlPost(url, nestedQuery, headers, timeoutMs);
    const dosRatio = baselineTime > 0 ? nestedResult.time_ms / baselineTime : 0;
    if (nestedResult.time_ms > 5000 || dosRatio > 5) {
      findings.push({ test: 'Deep Nesting DoS', severity: 'medium', detail: `Nested query (depth ${depthLimit}) took ${nestedResult.time_ms}ms vs baseline ${baselineTime}ms (${dosRatio.toFixed(1)}x) — no query depth limit enforced` });
    }

    // Test 5: GET-based CSRF
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let getCsrfPossible = false;
    try {
      const getUrl = `${url}?query=${encodeURIComponent('{ __typename }')}`;
      const getResp = await fetch(getUrl, { method: 'GET', headers: { 'User-Agent': 'Mozilla/5.0' }, signal: controller.signal });
      clearTimeout(timer);
      const getBody = await getResp.text();
      if (getResp.status === 200 && getBody.includes('__typename')) {
        getCsrfPossible = true;
        findings.push({ test: 'GET-based CSRF', severity: 'medium', detail: 'GraphQL queries accepted via GET request — cross-site request forgery possible without CSRF token' });
      }
    } catch {
      clearTimeout(timer);
    }

    const schemaSummary = introspectionEnabled ? {
      types: schemaTypes.length,
      mutations: mutationNames.length,
      sensitive_types: sensitiveTypes,
    } : null;

    const maxSeverity = findings.reduce((max, f) => {
      const rank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
      return (rank[f.severity] ?? 0) > (rank[max] ?? 0) ? f.severity : max;
    }, 'info');

    const divider = '─'.repeat(80);
    const rows = findings.map(f => `  [${f.severity.toUpperCase().padEnd(8)}] ${f.test}: ${f.detail}`).join('\n');

    const output = [
      `GraphQL Probe Results — ${url}`,
      divider,
      `Introspection: ${introspectionEnabled ? 'ENABLED (info finding)' : 'disabled'}`,
      `Batching: ${batchingEnabled ? 'ENABLED (rate-limit bypass possible)' : 'disabled'}`,
      `GET CSRF: ${getCsrfPossible ? 'POSSIBLE' : 'not detected'}`,
      `Nesting ${depthLimit}x: ${nestedResult.time_ms}ms (baseline: ${baselineTime}ms)`,
      ...(schemaSummary ? [`Schema: ${schemaSummary.types} types, ${schemaSummary.mutations} mutations`] : []),
      divider,
      '',
      'FINDINGS:',
      rows || '  No significant findings',
    ].join('\n');

    return {
      output,
      parsed: {
        introspection_enabled: introspectionEnabled,
        schema_summary: schemaSummary as Record<string, unknown> | null,
        batching_enabled: batchingEnabled,
        get_csrf_possible: getCsrfPossible,
        dos_ratio: Math.round(dosRatio * 10) / 10,
        findings: findings as unknown as Record<string, unknown>[],
        max_severity: maxSeverity,
      },
    };
  },
};

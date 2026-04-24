import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';
import * as path from 'path';

const definition: ToolDefinition = {
  name: 'code_pattern_search',
  description: 'Deep grep-based static analysis — scans source code for secrets, injection sinks, auth bypass patterns, and weak cryptography',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'path', type: 'string', required: true, description: 'Directory or file path to scan' },
    { name: 'pattern_set', type: 'string', required: false, description: 'secrets|injections|auth_bypass|crypto_weak|all', default: 'all' },
    { name: 'extensions', type: 'string', required: false, description: 'Comma-separated extensions, e.g. php,py,js', default: 'php,py,js,rb,java,ts,go,cs' },
  ],
};

interface PatternDef {
  name: string;
  pattern: string;
  risk: 'critical' | 'high' | 'medium' | 'low';
  description: string;
}

const PATTERN_SETS: Record<string, PatternDef[]> = {
  secrets: [
    { name: 'hardcoded_password',     pattern: '(?i)password\\s*[=:]\\s*[\'"][^\'"]{6,}[\'"]',              risk: 'critical', description: 'Hardcoded password literal' },
    { name: 'hardcoded_secret',       pattern: '(?i)secret(_?key)?\\s*[=:]\\s*[\'"][^\'"]{8,}[\'"]',        risk: 'critical', description: 'Hardcoded secret/key' },
    { name: 'aws_access_key',         pattern: 'AKIA[0-9A-Z]{16}',                                          risk: 'critical', description: 'AWS Access Key ID' },
    { name: 'aws_secret_key',         pattern: '(?i)aws_secret_access_key\\s*[=:]\\s*[\'"]?[A-Za-z0-9+/]{40}', risk: 'critical', description: 'AWS Secret Access Key' },
    { name: 'jwt_secret',             pattern: '(?i)jwt.secret\\s*[=:]\\s*[\'"][^\'"]{10,}[\'"]',           risk: 'critical', description: 'JWT signing secret' },
    { name: 'private_key',            pattern: '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',           risk: 'critical', description: 'Private key embedded in code' },
    { name: 'api_key',                pattern: '(?i)api_?key\\s*[=:]\\s*[\'"][A-Za-z0-9_\\-]{16,}[\'"]',   risk: 'high',     description: 'API key literal' },
    { name: 'connection_string',      pattern: '(?i)(mysql|postgres|mongodb|mssql|redis):\\/\\/[^:]+:[^@]+@', risk: 'high',   description: 'Database connection string with credentials' },
    { name: 'bearer_token',           pattern: '(?i)authorization\\s*[=:]\\s*[\'"]bearer\\s+[A-Za-z0-9._\\-]{20,}[\'"]', risk: 'high', description: 'Hardcoded bearer token' },
    { name: 'github_token',           pattern: 'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}',          risk: 'critical', description: 'GitHub personal access token' },
  ],
  injections: [
    { name: 'php_get_unfiltered',     pattern: '\\$_GET\\[[\'"]?\\w+[\'"]?\\]',                            risk: 'high',     description: 'Unfiltered $_GET usage' },
    { name: 'php_post_unfiltered',    pattern: '\\$_POST\\[[\'"]?\\w+[\'"]?\\]',                           risk: 'high',     description: 'Unfiltered $_POST usage' },
    { name: 'php_request_unfiltered', pattern: '\\$_REQUEST\\[[\'"]?\\w+[\'"]?\\]',                        risk: 'high',     description: 'Unfiltered $_REQUEST usage' },
    { name: 'php_eval',               pattern: '\\beval\\s*\\(',                                           risk: 'critical', description: 'eval() call — code injection risk' },
    { name: 'php_system',             pattern: '\\b(system|passthru|shell_exec|proc_open|popen)\\s*\\(',   risk: 'critical', description: 'OS command execution function' },
    { name: 'python_eval',            pattern: '\\beval\\s*\\(',                                           risk: 'critical', description: 'Python eval() — code injection' },
    { name: 'python_shell_true',      pattern: 'subprocess\\.(call|run|Popen)\\(.*shell\\s*=\\s*True',     risk: 'critical', description: 'Python shell=True subprocess' },
    { name: 'js_eval',                pattern: '\\beval\\s*\\(',                                           risk: 'critical', description: 'JavaScript eval' },
    { name: 'node_child_concat',      pattern: '(exec|execSync|spawn)\\s*\\(.*\\+',                        risk: 'high',     description: 'Node.js child_process with string concat' },
    { name: 'sql_string_concat',      pattern: '(?i)(select|insert|update|delete).*["\']\\s*\\+',          risk: 'high',     description: 'SQL query built with string concatenation' },
    { name: 'xxe_xml_parser',         pattern: '(?i)(DocumentBuilderFactory|SimpleXMLElement|DOMParser)',  risk: 'medium',   description: 'XML parser — verify XXE protection' },
    { name: 'deserialization',        pattern: '(?i)(unserialize\\s*\\(|pickle\\.loads?\\s*\\(|readObject\\s*\\()', risk: 'critical', description: 'Unsafe deserialization' },
  ],
  auth_bypass: [
    { name: 'strcmp_weak_compare',    pattern: '\\bstrcmp\\s*\\(',                                         risk: 'high',     description: 'strcmp — timing attack or PHP type juggling risk' },
    { name: 'md5_password_hash',      pattern: '\\bmd5\\s*\\(',                                            risk: 'high',     description: 'MD5 used for password hashing' },
    { name: 'sha1_password_hash',     pattern: '\\bsha1\\s*\\(',                                           risk: 'high',     description: 'SHA1 used for password hashing' },
    { name: 'loose_comparison',       pattern: '==\\s*0\\b|0\\s*==|==\\s*(true|false|null|""|\'\')',       risk: 'high',     description: 'Loose comparison — PHP type juggling' },
    { name: 'jwt_none_alg',           pattern: '(?i)(algorithm.*none|alg.*none|verify.*=.*false)',         risk: 'critical', description: '"none" algorithm JWT bypass pattern' },
    { name: 'disabled_auth',          pattern: '(?i)(skip_?auth|bypass_?auth|disable_?auth|no_?auth\\s*=\\s*true)', risk: 'critical', description: 'Auth bypass flag in code' },
    { name: 'mass_assignment',        pattern: "fillable\\s*=\\s*\\['\\*'\\]|attr_accessible\\s+:all",     risk: 'high',     description: 'Mass assignment vulnerability' },
  ],
  crypto_weak: [
    { name: 'des_cipher',             pattern: '(?i)\\bDES\\b|TripleDES|DES\\.new\\(|Cipher\\.getInstance\\("DES', risk: 'high', description: 'DES/3DES — weak cipher' },
    { name: 'rc4_cipher',             pattern: '(?i)\\bRC4\\b|Arcfour|RC4\\.new\\(',                       risk: 'high',     description: 'RC4 — broken stream cipher' },
    { name: 'md5_crypto',             pattern: '(?i)MD5\\.new\\(|hashlib\\.md5\\(|MessageDigest\\.getInstance\\("MD5', risk: 'medium', description: 'MD5 in cryptographic context' },
    { name: 'sha1_crypto',            pattern: '(?i)hashlib\\.sha1\\(|MessageDigest\\.getInstance\\("SHA-1|SHA1\\.new\\(', risk: 'medium', description: 'SHA-1 in cryptographic context' },
    { name: 'ecb_mode',               pattern: '(?i)ECB|Cipher\\.getInstance\\("AES/ECB|AES\\.MODE_ECB',   risk: 'high',     description: 'ECB mode — deterministic, insecure' },
    { name: 'rand_not_secure',        pattern: '(?i)\\bMath\\.random\\(\\)|random\\.random\\(\\)|\\brand\\(\\)|mt_rand\\(', risk: 'medium', description: 'Non-cryptographically-secure RNG' },
    { name: 'ssl_verify_false',       pattern: '(?i)(verify\\s*=\\s*False|InsecureRequestWarning|CERT_NONE)', risk: 'high',   description: 'SSL certificate verification disabled' },
  ],
};

interface Match {
  file: string;
  line: number;
  pattern_name: string;
  risk: string;
  description: string;
  matched_text: string;
}

interface SearchResult {
  matches: Match[];
  total_count: number;
  risk_summary: Record<string, number>;
  files_scanned: number;
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const startTime = Date.now();
  const scanPath = String(params['path'] || '');
  const patternSet = String(params['pattern_set'] || 'all').toLowerCase();
  const extensions = String(params['extensions'] || 'php,py,js,rb,java,ts,go,cs')
    .split(',').map(e => e.trim().replace(/^\./, ''));

  if (!scanPath) {
    return {
      success: false,
      tool: 'code_pattern_search',
      output: 'path is required',
      parsed: {},
      duration: (Date.now() - startTime) / 1000,
      command: 'code_pattern_search',
      error: 'Missing path parameter',
    };
  }

  const validSets = ['secrets', 'injections', 'auth_bypass', 'crypto_weak', 'all'];
  if (!validSets.includes(patternSet)) {
    return {
      success: false,
      tool: 'code_pattern_search',
      output: `Invalid pattern_set '${patternSet}'. Valid: ${validSets.join('|')}`,
      parsed: {},
      duration: (Date.now() - startTime) / 1000,
      command: 'code_pattern_search',
      error: 'Invalid parameter',
    };
  }

  const setsToRun = patternSet === 'all'
    ? ['secrets', 'injections', 'auth_bypass', 'crypto_weak']
    : [patternSet];

  const allMatches: Match[] = [];
  const fileSet = new Set<string>();
  const includeFlags = extensions.map(ext => `--include=*.${ext}`);

  for (const setName of setsToRun) {
    for (const patDef of PATTERN_SETS[setName]) {
      const grepArgs = ['-rn', '-E', patDef.pattern, scanPath, ...includeFlags, '--max-count=20'];
      const result = await exec.execute('grep', grepArgs, 30000);

      if (result.exitCode === 0 && result.stdout.trim()) {
        const lines = result.stdout.trim().split('\n').slice(0, 20);
        for (const line of lines) {
          const firstColon = line.indexOf(':');
          const secondColon = line.indexOf(':', firstColon + 1);
          if (firstColon === -1 || secondColon === -1) continue;

          const file = line.substring(0, firstColon);
          const lineNum = parseInt(line.substring(firstColon + 1, secondColon), 10);
          const text = line.substring(secondColon + 1).trim();

          fileSet.add(file);
          allMatches.push({
            file,
            line: isNaN(lineNum) ? 0 : lineNum,
            pattern_name: patDef.name,
            risk: patDef.risk,
            description: patDef.description,
            matched_text: text.substring(0, 300),
          });
        }
      }
    }
  }

  const riskSummary: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const m of allMatches) {
    riskSummary[m.risk] = (riskSummary[m.risk] || 0) + 1;
  }

  const parsed: SearchResult = {
    matches: allMatches,
    total_count: allMatches.length,
    risk_summary: riskSummary,
    files_scanned: fileSet.size,
  };

  const outputLines = [
    `=== Code Pattern Search: ${scanPath} ===`,
    `Pattern set: ${patternSet} | Extensions: ${extensions.join(', ')}`,
    `Total findings: ${allMatches.length} | Files with findings: ${fileSet.size}`,
    `Risk summary: CRITICAL=${riskSummary['critical']} HIGH=${riskSummary['high']} MEDIUM=${riskSummary['medium']} LOW=${riskSummary['low']}`,
    '',
  ];

  for (const risk of ['critical', 'high', 'medium', 'low']) {
    const group = allMatches.filter(m => m.risk === risk);
    if (group.length === 0) continue;
    outputLines.push(`--- ${risk.toUpperCase()} (${group.length}) ---`);
    for (const m of group) {
      outputLines.push(`[${m.pattern_name}] ${path.basename(m.file)}:${m.line}`);
      outputLines.push(`  ${m.description}`);
      outputLines.push(`  > ${m.matched_text.substring(0, 120)}`);
    }
    outputLines.push('');
  }

  let output = outputLines.join('\n');
  if (output.length > 50000) output = output.substring(0, 50000) + '\n[OUTPUT TRUNCATED]';

  return {
    success: true,
    tool: 'code_pattern_search',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration: (Date.now() - startTime) / 1000,
    command: `code_pattern_search ${scanPath} (${patternSet})`,
    error: null,
  };
}

export const codePatternSearchTool = { definition, execute };

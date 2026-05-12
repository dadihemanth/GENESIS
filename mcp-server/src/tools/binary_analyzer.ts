import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';

const definition: ToolDefinition = {
  name: 'binary_analyzer',
  description: 'Analyzes compiled binaries using strings, file, readelf, and objdump to extract security-relevant information',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'binary_path', type: 'string', required: true, description: 'Absolute path to the binary inside the container' },
    { name: 'analysis_type', type: 'string', required: false, description: 'strings|symbols|headers|all', default: 'all' },
  ],
};

const SUSPICIOUS_PATTERNS = [
  // Credentials / secrets
  { name: 'hardcoded_password', pattern: /(?:password|passwd|secret|key|token|api_?key)\s*[=:]\s*["']?[A-Za-z0-9!@#$%^&*]{6,}/i },
  { name: 'aws_key', pattern: /AKIA[0-9A-Z]{16}/ },
  { name: 'jwt_secret', pattern: /[A-Za-z0-9+/]{40,}={0,2}/ },
  { name: 'private_key_header', pattern: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  // Dangerous functions
  { name: 'system_call', pattern: /\bsystem\s*\(/ },
  { name: 'exec_call', pattern: /\bexec[vlpe]{0,2}\s*\(/ },
  { name: 'unsafe_copy', pattern: /\bstrcpy\s*\(|sprintf\s*\(/ },
  { name: 'popen_call', pattern: /\bpopen\s*\(/ },
  // SQL fragments
  { name: 'sql_fragment', pattern: /SELECT\s+\*\s+FROM|INSERT\s+INTO|DELETE\s+FROM|DROP\s+TABLE/i },
  // Network indicators
  { name: 'hardcoded_ip', pattern: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/ },
  { name: 'c2_domain', pattern: /https?:\/\/[a-z0-9.-]+\.[a-z]{2,}\/[a-zA-Z0-9\/?&=_-]{5,}/ },
  // Debug / backdoor hints
  { name: 'debug_code', pattern: /\bdebug\b|backdoor|admin123|test123|default_password/i },
];

function findSuspicious(stringsOutput: string): Array<{pattern_name: string; matched_text: string}> {
  const findings: Array<{pattern_name: string; matched_text: string}> = [];
  const lines = stringsOutput.split('\n');

  for (const line of lines) {
    for (const { name, pattern } of SUSPICIOUS_PATTERNS) {
      const m = line.match(pattern);
      if (m) {
        findings.push({
          pattern_name: name,
          matched_text: line.trim().substring(0, 200),
        });
        break; // one match per line
      }
    }
  }

  return findings;
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const startTime = Date.now();
  const binaryPath = String(params['binary_path'] || '');
  const analysisType = String(params['analysis_type'] || 'all').toLowerCase();

  if (!binaryPath) {
    return {
      success: false,
      tool: 'binary_analyzer',
      output: 'binary_path is required',
      parsed: {},
      duration: (Date.now() - startTime) / 1000,
      command: 'binary_analyzer',
      error: 'Missing binary_path parameter',
    };
  }

  const sections: string[] = [];
  const parsed: Record<string, unknown> = {
    binary_path: binaryPath,
    analysis_type: analysisType,
  };

  // ── file type ──────────────────────────────────────────────────────────────
  const fileResult = await exec.execute('file', [binaryPath], 10000);
  const fileType = fileResult.stdout.trim();
  parsed['file_type'] = fileType;
  sections.push(`=== FILE TYPE ===\n${fileType}`);

  // ── strings ───────────────────────────────────────────────────────────────
  if (['strings', 'all'].includes(analysisType)) {
    const strResult = await exec.execute('strings', ['-n', '8', binaryPath], 30000);
    let strOut = strResult.stdout;
    if (strOut.length > 20000) strOut = strOut.substring(0, 20000) + '\n[TRUNCATED]';

    const suspicious = findSuspicious(strOut);
    parsed['interesting_strings'] = strOut.split('\n').filter(l => l.length > 6).slice(0, 100);
    parsed['suspicious_patterns'] = suspicious;

    sections.push(`=== STRINGS (interesting) ===\n${
      (strOut.split('\n').filter(l => l.length > 6).slice(0, 50)).join('\n')
    }`);

    if (suspicious.length > 0) {
      sections.push(`=== SUSPICIOUS PATTERNS (${suspicious.length}) ===\n${
        suspicious.map(s => `[${s.pattern_name}] ${s.matched_text}`).join('\n')
      }`);
    }
  }

  // ── headers / ELF info ────────────────────────────────────────────────────
  if (['headers', 'all'].includes(analysisType)) {
    const readelfResult = await exec.execute('readelf', ['-h', binaryPath], 15000);
    let readelfOut = readelfResult.stdout.trim();
    if (readelfOut.length > 5000) readelfOut = readelfOut.substring(0, 5000) + '\n[TRUNCATED]';

    // Extract key fields
    const archMatch = readelfOut.match(/Machine:\s+(.+)/);
    const classMatch = readelfOut.match(/Class:\s+(.+)/);
    const osMatch = readelfOut.match(/OS\/ABI:\s+(.+)/);
    parsed['architecture'] = archMatch ? archMatch[1].trim() : 'unknown';
    parsed['elf_class'] = classMatch ? classMatch[1].trim() : 'unknown';
    parsed['os_abi'] = osMatch ? osMatch[1].trim() : 'unknown';

    sections.push(`=== ELF HEADERS ===\n${readelfOut}`);

    // Dynamic dependencies
    const depsResult = await exec.execute('readelf', ['-d', binaryPath], 15000);
    const depsOut = depsResult.stdout;
    const libs = [...depsOut.matchAll(/\(NEEDED\)\s+Shared library: \[([^\]]+)\]/g)].map(m => m[1]);
    parsed['linked_libraries'] = libs;
    if (libs.length > 0) {
      sections.push(`=== LINKED LIBRARIES ===\n${libs.join('\n')}`);
    }
  }

  // ── symbols ───────────────────────────────────────────────────────────────
  if (['symbols', 'all'].includes(analysisType)) {
    const nmResult = await exec.execute('nm', ['-D', '--defined-only', binaryPath], 20000);
    let nmOut = nmResult.stdout;
    if (nmOut.length > 10000) nmOut = nmOut.substring(0, 10000) + '\n[TRUNCATED]';

    const symbols = nmOut.split('\n')
      .filter(l => l.trim())
      .map(l => l.split(/\s+/).pop() || '')
      .filter(s => s.length > 2);

    parsed['function_symbols'] = symbols.slice(0, 200);
    sections.push(`=== SYMBOLS (${symbols.length}) ===\n${symbols.slice(0, 50).join('\n')}`);
  }

  // ── disassembly snippet ───────────────────────────────────────────────────
  if (analysisType === 'all') {
    const objdumpResult = await exec.execute(
      'objdump',
      ['-d', '--no-show-raw-insn', '--section=.text', binaryPath],
      60000
    );
    let objOut = objdumpResult.stdout;
    if (objOut.length > 8000) objOut = objOut.substring(0, 8000) + '\n[TRUNCATED — full disassembly omitted]';
    sections.push(`=== DISASSEMBLY (.text snippet) ===\n${objOut}`);
  }

  const output = sections.join('\n\n');

  return {
    success: !fileResult.timedOut,
    tool: 'binary_analyzer',
    output,
    parsed,
    duration: (Date.now() - startTime) / 1000,
    command: `binary_analyzer ${binaryPath} (type: ${analysisType})`,
    error: null,
  };
}

export const binaryAnalyzerTool = { definition, execute };

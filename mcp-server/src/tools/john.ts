import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';
import * as fs from 'fs';
import * as path from 'path';

const definition: ToolDefinition = {
  name: 'john',
  description: 'John the Ripper password cracker — cracks captured hashes (MD5, SHA, NTLM, bcrypt)',
  status: 'missing',
  version: null,
  parameters: [
    { name: 'hash', type: 'string', required: true, description: 'Hash string or path to hash file. Format: user:hash or just hash' },
    { name: 'format', type: 'string', required: false, description: 'Hash format (nt, md5, sha256, bcrypt, raw-sha1, etc.)', default: '' },
    { name: 'wordlist', type: 'string', required: false, description: 'Wordlist path', default: '/usr/share/wordlists/rockyou.txt' },
    { name: 'rules', type: 'string', required: false, description: 'Mangling rules to apply (Jumbo, KoreLogic)', default: '' },
  ],
};

const SAFE_HASH_DIRS = ['/tmp', '/data/security'];

interface JohnParsed {
  cracked: Array<{ user: string; password: string }>;
  total_cracked: number;
}

function parseJohnOutput(output: string): JohnParsed {
  const cracked: Array<{ user: string; password: string }> = [];

  for (const line of output.split('\n')) {
    // John output: "password         (user)"
    const m = line.match(/^(.+?)\s+\(([^)]+)\)/);
    if (m && !line.startsWith('Using') && !line.startsWith('Loaded') && !line.startsWith('Press')) {
      cracked.push({ password: m[1].trim(), user: m[2].trim() });
    }
  }

  return { cracked, total_cracked: cracked.length };
}

async function execute(
  params: Record<string, unknown>,
  exec: CommandExecutor
): Promise<ToolResult> {
  const hash = String(params['hash'] || '');
  const format = String(params['format'] || '');
  const wordlist = String(params['wordlist'] || '/usr/share/wordlists/rockyou.txt');
  const rules = String(params['rules'] || '');

  const startTime = Date.now();

  // Write hash to a temp file if it doesn't look like a file path
  let hashFile = hash;
  let tempFile = '';
  if (!fs.existsSync(hash) || !SAFE_HASH_DIRS.some(d => path.resolve(hash).startsWith(d))) {
    tempFile = `/tmp/john_hash_${Date.now()}.txt`;
    fs.writeFileSync(tempFile, hash + '\n');
    hashFile = tempFile;
  }

  const args = [hashFile, `--wordlist=${wordlist}`, '--pot=/tmp/john.pot'];
  if (format) args.push(`--format=${format}`);
  if (rules) args.push(`--rules=${rules}`);

  const command = `john ${args.join(' ')}`;

  const available = await exec.isAvailable('john');
  if (!available) {
    if (tempFile) try { fs.unlinkSync(tempFile); } catch { /* ignore */ }
    return { success: false, tool: 'john', output: '', parsed: {}, duration: (Date.now() - startTime) / 1000, command, error: "Tool 'john' not found." };
  }

  // Run crack
  const result = await exec.execute('john', args, 120000);

  // Always run --show to get cracked passwords
  const showResult = await exec.execute('john', [hashFile, '--show', '--pot=/tmp/john.pot', ...(format ? [`--format=${format}`] : [])], 10000);

  if (tempFile) try { fs.unlinkSync(tempFile); } catch { /* ignore */ }

  const duration = result.duration;
  const allOutput = [result.stdout, result.stderr, showResult.stdout].filter(Boolean).join('\n');
  let output = allOutput.length > 30000 ? allOutput.substring(0, 30000) + '\n[TRUNCATED]' : allOutput;

  const parsed = parseJohnOutput(showResult.stdout || result.stdout);

  return {
    success: parsed.total_cracked > 0 || result.exitCode === 0,
    tool: 'john',
    output,
    parsed: parsed as unknown as Record<string, unknown>,
    duration,
    command,
    error: parsed.total_cracked === 0 && result.exitCode !== 0 ? 'No passwords cracked' : null,
  };
}

export const johnTool = { definition, execute };

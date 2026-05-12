import { ToolDefinition, ToolResult } from '../types';
import { CommandExecutor } from '../executor';
import * as fs from 'fs';
import * as path from 'path';

// ---------------------------------------------------------------------------
// code_read — filesystem reader / grep-lite for pulled source artifacts
//
// Three modes based on which params are set:
//  - artifact_path only: tree listing (up to 500 files, skipping heavy/binary)
//  - artifact_path + file: return the contents of that specific file
//  - artifact_path + symbol: ripgrep-lite across the tree for the symbol
//
// Hard-scoped to /data/security/artifacts to prevent path traversal.
// ---------------------------------------------------------------------------

const ARTIFACT_ROOT = process.env.ARTIFACT_ROOT || '/data/security/artifacts';

const definition: ToolDefinition = {
  name: 'code_read',
  description:
    'Read pulled source artifacts. Default mode lists files (skipping binaries). Set `file` to read a ' +
    'specific relative path. Set `symbol` to grep across the tree. All paths are scoped to the session ' +
    'artifact tree; traversal outside is rejected.',
  status: 'available',
  version: '1.0.0',
  parameters: [
    { name: 'artifact_path', type: 'string', required: true, description: 'Path returned by artifact_pull (a file or a directory)' },
    { name: 'file', type: 'string', required: false, description: 'Relative path inside the artifact tree to read' },
    { name: 'symbol', type: 'string', required: false, description: 'Grep-like symbol / substring to search for' },
    { name: 'max_bytes', type: 'number', required: false, description: 'Max bytes returned', default: 60000 },
  ],
};

// File extensions we are willing to read as text.
const TEXT_EXTENSIONS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.py', '.pyi', '.pyx',
  '.java', '.kt', '.scala', '.groovy',
  '.go', '.rs', '.rb', '.php', '.phtml',
  '.c', '.h', '.cc', '.cpp', '.hpp', '.cxx',
  '.cs', '.vb', '.fs',
  '.sh', '.bash', '.zsh',
  '.yaml', '.yml', '.json', '.toml', '.ini', '.cfg', '.env', '.properties',
  '.xml', '.html', '.htm', '.vue', '.svelte',
  '.md', '.txt', '.sql', '.graphql', '.proto',
  '.pl', '.pm', '.lua', '.ex', '.exs', '.swift', '.m', '.mm',
]);

const SKIP_DIRS = new Set([
  'node_modules', '.git', '.svn', '.hg', 'dist', 'build', '__pycache__',
  'target', 'out', 'bin', 'obj', '.gradle', '.idea', '.vscode', 'vendor', '.next',
]);

function resolveSafe(base: string, rel?: string): string | null {
  const abs = rel ? path.resolve(base, rel) : path.resolve(base);
  if (!abs.startsWith(path.resolve(ARTIFACT_ROOT))) return null;
  return abs;
}

function listTree(root: string, maxFiles: number): { files: string[]; truncated: boolean } {
  const out: string[] = [];
  const stack: string[] = [root];
  let truncated = false;
  while (stack.length > 0) {
    const cur = stack.pop() as string;
    let entries: fs.Dirent[] = [];
    try {
      entries = fs.readdirSync(cur, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      if (out.length >= maxFiles) { truncated = true; break; }
      const full = path.join(cur, e.name);
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name)) continue;
        stack.push(full);
        continue;
      }
      out.push(full);
    }
    if (out.length >= maxFiles) { truncated = true; break; }
  }
  return { files: out, truncated };
}

function isTextFile(p: string): boolean {
  const ext = path.extname(p).toLowerCase();
  if (TEXT_EXTENSIONS.has(ext)) return true;
  // No extension — inspect first 512 bytes for binary signature
  try {
    const fd = fs.openSync(p, 'r');
    const buf = Buffer.alloc(512);
    const n = fs.readSync(fd, buf, 0, 512, 0);
    fs.closeSync(fd);
    // Treat as text if all bytes printable / common whitespace
    for (let i = 0; i < n; i++) {
      const c = buf[i];
      if (c === 0) return false;
      if (c < 32 && c !== 9 && c !== 10 && c !== 13) return false;
    }
    return true;
  } catch {
    return false;
  }
}

function grepOne(file: string, needle: string, maxMatches: number, maxBytesPerFile: number): string[] {
  const matches: string[] = [];
  try {
    const st = fs.statSync(file);
    if (st.size > maxBytesPerFile) return [];
    if (!isTextFile(file)) return [];
    const text = fs.readFileSync(file, { encoding: 'utf-8' });
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes(needle)) {
        matches.push(`${file}:${i + 1}: ${lines[i].substring(0, 300)}`);
        if (matches.length >= maxMatches) break;
      }
    }
  } catch { /* ignore */ }
  return matches;
}

export const codeReadTool = {
  definition,
  async execute(params: Record<string, unknown>, _exec: CommandExecutor): Promise<ToolResult> {
    const artifactPathRaw = String(params.artifact_path || '').trim();
    const file = String(params.file || '').trim();
    const symbol = String(params.symbol || '').trim();
    const maxBytes = Math.max(1000, Math.min(100000, Number(params.max_bytes || 60000)));

    if (!artifactPathRaw) {
      return { output: 'artifact_path required', parsed: { error: 'missing artifact_path' } };
    }
    const root = resolveSafe(artifactPathRaw);
    if (!root) {
      return { output: 'artifact_path outside /data/security/artifacts', parsed: { error: 'path_outside_root' } };
    }

    let rootStat: fs.Stats;
    try { rootStat = fs.statSync(root); } catch (err) {
      return { output: `stat failed: ${err}`, parsed: { error: String(err) } };
    }

    // --- Mode 3: specific file read ---
    if (file) {
      const abs = resolveSafe(rootStat.isDirectory() ? root : path.dirname(root), file);
      if (!abs) return { output: 'file path outside artifact tree', parsed: { error: 'path_outside_root' } };
      try {
        const st = fs.statSync(abs);
        if (!st.isFile()) return { output: 'not a regular file', parsed: { error: 'not_file' } };
        if (st.size > maxBytes * 2) {
          return {
            output: `file too large (${st.size} bytes, cap ${maxBytes * 2})`,
            parsed: { error: 'file_too_large', size: st.size, cap: maxBytes * 2 },
          };
        }
        const buf = fs.readFileSync(abs);
        if (buf.slice(0, Math.min(buf.length, 512)).includes(0)) {
          return { output: `file appears binary — use binary_decompile instead`, parsed: { error: 'binary_content' } };
        }
        const text = buf.toString('utf-8').substring(0, maxBytes);
        return {
          output: `${abs} (${buf.length} bytes)\n${'─'.repeat(70)}\n${text}`,
          parsed: { mode: 'file', path: abs, size: buf.length, truncated: buf.length > maxBytes },
        };
      } catch (err) {
        return { output: `read failed: ${err}`, parsed: { error: String(err) } };
      }
    }

    // --- Mode 2: symbol grep ---
    if (symbol) {
      const baseDir = rootStat.isDirectory() ? root : path.dirname(root);
      const listing = listTree(baseDir, 3000);
      const maxFilesToScan = 1500;
      const matches: string[] = [];
      let filesScanned = 0;
      for (const f of listing.files) {
        if (filesScanned >= maxFilesToScan) break;
        filesScanned += 1;
        const ms = grepOne(f, symbol, 5, 1_000_000);
        matches.push(...ms);
        if (matches.length >= 200) break;
      }
      const bytes = matches.join('\n');
      return {
        output: [
          `code_read grep "${symbol}" in ${baseDir}`,
          `files scanned: ${filesScanned}${listing.truncated ? ' (tree truncated)' : ''}`,
          `matches: ${matches.length}`,
          '',
          bytes.substring(0, maxBytes),
        ].join('\n'),
        parsed: {
          mode: 'grep',
          symbol,
          match_count: matches.length,
          files_scanned: filesScanned,
          truncated: bytes.length > maxBytes,
        },
      };
    }

    // --- Mode 1: tree listing ---
    if (rootStat.isFile()) {
      // Single file — treat as tree listing of just one entry
      return {
        output: [
          `code_read listing (single file)`,
          `${root}  size=${rootStat.size}`,
          '',
          'Use the `file` parameter to read its contents (if it is source), or binary_decompile if it is a binary.',
        ].join('\n'),
        parsed: { mode: 'list', files: [{ path: root, size: rootStat.size }] },
      };
    }
    const listing = listTree(root, 1000);
    const details = listing.files.slice(0, 500).map(f => {
      try { return { path: f, size: fs.statSync(f).size }; } catch { return { path: f, size: 0 }; }
    });
    return {
      output: [
        `code_read listing — ${root}`,
        `files: ${details.length}${listing.truncated ? ' (tree truncated at 1000)' : ''}`,
        '',
        ...details.slice(0, 120).map(d => `  ${d.path}  (${d.size} bytes)`),
        details.length > 120 ? `... and ${details.length - 120} more` : '',
      ].filter(Boolean).join('\n'),
      parsed: {
        mode: 'list',
        root,
        file_count: details.length,
        truncated: listing.truncated,
        files: details.slice(0, 200),
      },
    };
  },
};

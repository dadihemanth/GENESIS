import { ToolDefinition } from './types';
import { executor } from './executor';
import { ALL_TOOLS } from './tools/index';

// Maps tool registry key → actual binary name when they differ
const BINARY_MAP: Record<string, string> = {
  curl_probe:          'curl',
  openssl_check:       'openssl',
  harvester:           'theHarvester',
  enum4linux:          'enum4linux-ng',
  impacket:            'impacket-secretsdump',
  // Mythos intelligence tools — map to the binaries they actually use
  binary_analyzer:     'strings',
  code_pattern_search: 'grep',
  payload_crafter:     'node',
  // Novel vulnerability discovery tools — pure Node.js, no external binary
  oob_check:           'node',
  differential_probe:  'node',
  race_probe:          'node',
  session_memory:      'node',
  // HTTP vulnerability analysis tools — pure Node.js, no external binary
  idor_probe:                'node',
  cors_probe:                'node',
  jwt_probe:                 'node',
  graphql_probe:             'node',
  ssti_detect:               'node',
  nosql_probe:               'node',
  cache_probe:               'node',
  prototype_pollution_probe: 'node',
  oauth_probe:               'node',
  http_smuggling_probe:      'node',
};

function binaryName(toolKey: string): string {
  return BINARY_MAP[toolKey] ?? toolKey;
}

// Tools whose version is best read via a shell command (pip show, etc.)
// These override VERSION_FLAGS for the named tool.
const SHELL_VERSION_COMMANDS: Record<string, string> = {
  wafw00f: "pip3 show wafw00f 2>/dev/null | grep ^Version | awk '{print \"wafw00f \" $2}'",
  john:    "john 2>&1 | grep -i 'john the ripper' | head -1",
  kerbrute: "kerbrute version 2>&1 | grep -i 'version:' | head -1",
};

// Version flags that differ from the standard --version
const VERSION_FLAGS: Record<string, string> = {
  nikto:              '-Version',
  gobuster:           'version',    // subcommand, not a flag
  kerbrute:           'version',    // subcommand, not a flag
  masscan:            '-V',
  ffuf:               '-V',
  dnsrecon:           '--version',
  commix:             '--version',
  httpx:              '-version',
  binary_analyzer:    '--version',
  code_pattern_search:'--version',
  payload_crafter:    '--version',
  oob_check:                 '--version',
  differential_probe:        '--version',
  race_probe:                '--version',
  session_memory:            '--version',
  idor_probe:                '--version',
  cors_probe:                '--version',
  jwt_probe:                 '--version',
  graphql_probe:             '--version',
  ssti_detect:               '--version',
  nosql_probe:               '--version',
  cache_probe:               '--version',
  prototype_pollution_probe: '--version',
  oauth_probe:               '--version',
  http_smuggling_probe:      '--version',
};

export class ToolRegistry {
  private tools: Map<string, ToolDefinition> = new Map();

  async initialize(): Promise<void> {
    console.log('[registry] Initializing tools...');

    const initPromises = Object.entries(ALL_TOOLS).map(async ([name, tool]) => {
      const def: ToolDefinition = { ...tool.definition };
      const bin = binaryName(name);

      try {
        const isAvail = await executor.isAvailable(bin);
        if (isAvail) {
          let version: string | null;
          const shellCmd = SHELL_VERSION_COMMANDS[name];
          if (shellCmd) {
            const r = await executor.executeShell(shellCmd, 10000);
            version = (r.stdout + r.stderr).trim().split('\n').map(l => l.trim()).find(l => l.length > 0) ?? null;
          } else {
            const flag = VERSION_FLAGS[name] ?? '--version';
            version = await executor.getVersion(bin, flag);
          }
          def.status = 'available';
          def.version = version;
          console.log(`[registry] ${name} (${bin}): available (${version ?? 'unknown'})`);
        } else {
          def.status = 'missing';
          def.version = null;
          console.log(`[registry] ${name} (${bin}): missing`);
        }
      } catch (err) {
        def.status = 'error';
        def.version = null;
        console.error(`[registry] ${name}: error during init`, err);
      }

      this.tools.set(name, def);
    });

    await Promise.all(initPromises);
    console.log(`[registry] Initialized ${this.tools.size} tools.`);
  }

  async getAll(): Promise<ToolDefinition[]> {
    return Array.from(this.tools.values());
  }

  async getOne(name: string): Promise<ToolDefinition | null> {
    return this.tools.get(name) ?? null;
  }

  async refreshStatus(name: string): Promise<ToolDefinition> {
    const tool = ALL_TOOLS[name];
    if (!tool) throw new Error(`Unknown tool: ${name}`);

    const bin = binaryName(name);
    const def: ToolDefinition = { ...tool.definition };

    try {
      const isAvail = await executor.isAvailable(bin);
      if (isAvail) {
        const version = await executor.getVersion(bin);
        def.status = 'available';
        def.version = version;
      } else {
        def.status = 'missing';
        def.version = null;
      }
    } catch {
      def.status = 'error';
      def.version = null;
    }

    this.tools.set(name, def);
    return def;
  }

  async testTool(name: string): Promise<{
    name: string;
    status: string;
    version: string | null;
    path: string | null;
  }> {
    const bin = binaryName(name);
    const isWindows = process.platform === 'win32';
    const whichCmd = isWindows ? 'where' : 'which';

    const pathResult = await executor.execute(whichCmd, [bin], 5000);
    const path = pathResult.exitCode === 0 ? pathResult.stdout.trim().split('\n')[0] : null;

    const isAvail = pathResult.exitCode === 0;
    let version: string | null = null;
    let status = 'missing';

    if (isAvail) {
      try {
        version = await executor.getVersion(bin);
        status = 'available';
      } catch {
        status = 'error';
      }
    }

    const existing = this.tools.get(name);
    if (existing) {
      existing.status = status as ToolDefinition['status'];
      existing.version = version;
      this.tools.set(name, existing);
    }

    return { name, status, version, path };
  }
}

export const registry = new ToolRegistry();

import { spawn } from 'child_process';
import { CommandResult } from './types';

const isWindows = process.platform === 'win32';

export class CommandExecutor {
  async execute(cmd: string, args: string[], timeoutMs = 600000): Promise<CommandResult> {
    const startTime = Date.now();

    return new Promise((resolve) => {
      let stdout = '';
      let stderr = '';
      let timedOut = false;
      let settled = false;

      const child = spawn(cmd, args, {
        stdio: ['pipe', 'pipe', 'pipe'],
        shell: false,
        windowsHide: true,
      });

      child.stdout.on('data', (data: Buffer) => {
        stdout += data.toString();
      });

      child.stderr.on('data', (data: Buffer) => {
        stderr += data.toString();
      });

      const timer = setTimeout(() => {
        if (settled) return;
        timedOut = true;
        try {
          child.kill('SIGTERM');
          setTimeout(() => {
            try { child.kill('SIGKILL'); } catch { /* already dead */ }
          }, 3000);
        } catch { /* already dead */ }
      }, timeoutMs);

      child.on('close', (code) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        const duration = (Date.now() - startTime) / 1000;
        resolve({
          stdout,
          stderr,
          exitCode: timedOut ? -1 : (code ?? -1),
          duration,
          timedOut,
        });
      });

      child.on('error', (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        const duration = (Date.now() - startTime) / 1000;
        resolve({
          stdout,
          stderr: stderr + '\n' + err.message,
          exitCode: -1,
          duration,
          timedOut: false,
        });
      });
    });
  }

  async executeShell(command: string, timeoutMs = 600000): Promise<CommandResult> {
    if (isWindows) {
      return this.execute('cmd.exe', ['/c', command], timeoutMs);
    } else {
      return this.execute('sh', ['-c', command], timeoutMs);
    }
  }

  async isAvailable(toolName: string): Promise<boolean> {
    const checkCmd = isWindows ? 'where' : 'which';
    const result = await this.execute(checkCmd, [toolName], 10000);
    return result.exitCode === 0;
  }

  async getVersion(toolName: string, versionFlag = '--version'): Promise<string | null> {
    try {
      const result = await this.execute(toolName, [versionFlag], 10000);
      const combined = (result.stdout + result.stderr).trim();
      if (!combined) return null;
      // Return the first non-empty line (some tools emit a blank line before the version)
      const firstNonEmpty = combined.split('\n').map(l => l.trim()).find(l => l.length > 0);
      return firstNonEmpty ?? null;
    } catch {
      return null;
    }
  }
}

export const executor = new CommandExecutor();

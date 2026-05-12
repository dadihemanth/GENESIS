export interface ToolResult {
  output: string;
  parsed: Record<string, unknown>;
  success?: boolean;
  tool?: string;
  duration?: number;
  command?: string;
  error?: string | null;
}

export interface ToolDefinition {
  name: string;
  description: string;
  status: 'available' | 'missing' | 'error';
  version: string | null;
  parameters: ToolParameter[];
}

export interface ToolParameter {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'array';
  required: boolean;
  description: string;
  default?: unknown;
}

export interface ExecuteRequest {
  tool: string;
  params: Record<string, unknown>;
}

export interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  duration: number;
  timedOut: boolean;
}

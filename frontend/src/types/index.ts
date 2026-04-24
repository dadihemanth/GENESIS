export type SessionStatus = 'pending' | 'running' | 'paused' | 'completed' | 'failed' | 'stopped';
export type ErrorPhase = 'settings_load' | 'anthropic_api' | 'mcp_call' | 'tool_execute' | 'subagent_api' | 'celery_task' | 'unhandled' | string;

export interface SessionError {
  id: string;
  session_id: string;
  phase: ErrorPhase;
  error_type: string;
  error_message: string;
  traceback?: string;
  iteration?: number | null;
  tool?: string | null;
  context: Record<string, unknown>;
  timestamp: string;
}
export type SessionPhase = 'reconnaissance' | 'service_analysis' | 'vulnerability_scan' | 'exploitation' | 'reporting';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ScanProfile = 'fast' | 'deep' | 'stealth' | 'full' | 'apt_sim';
export type AgentMode = 'solo' | 'multi_agent';
export type VerificationStatus = 'unverified' | 'confirmed' | 'exploited' | 'disputed';
export type HypothesisStatus = 'active' | 'confirmed' | 'ruled_out';

export interface Hypothesis {
  hyp_id: string;
  session_id: string;
  statement: string;
  confidence: number;
  evidence_for: string[];
  evidence_against: string[];
  next_test: string;
  status: HypothesisStatus;
  updated_at: string;
}

export interface Session {
  id: string;
  target_ip: string;
  target_hostname?: string;
  status: SessionStatus;
  phase: string;
  iteration: number;
  started_at?: string;
  completed_at?: string;
  summary?: string;
  vulnerability_count: number;
  critical_count: number;
  high_count: number;
  config: Record<string, unknown>;
  scan_profile: ScanProfile;
  agent_mode: AgentMode;
  network_topology: NetworkTopology;
  created_at: string;
  updated_at: string;
}

export interface Vulnerability {
  id: string;
  session_id: string;
  title: string;
  description: string;
  severity: Severity;
  cvss_score?: number;
  cve_ids: string[];
  affected_service: string;
  port?: number;
  protocol?: string;
  exploit_available: boolean;
  exploit_code?: string;
  patch_code?: string;
  remediation: string;
  confidence: number;
  verification_output?: string;
  verification_status: VerificationStatus;
  attack_chain_id?: string;
  chain_position?: number;
  mitre_techniques: string[];
  is_zero_day: boolean;
  created_at: string;
}

export interface DeepThought {
  iteration: number;
  content: string;
  timestamp: string;
}

export interface AttackChainStep {
  vuln_id: string;
  title: string;
  severity: Severity;
  chain_position: number;
  verification_status: VerificationStatus;
  mitre_techniques: string[];
  exploit_available: boolean;
  cvss_score?: number;
}

export interface AttackChain {
  chain_id: string;
  steps: AttackChainStep[];
  entry_point: string;
  final_impact: string;
  max_severity: Severity;
  total_steps: number;
  fully_exploitable: boolean;
  all_mitre_techniques: string[];
}

export interface NetworkNode {
  id: string;
  type: 'host' | 'service' | 'vuln';
  label: string;
  severity?: Severity;
  services?: string[];
}

export interface NetworkEdge {
  from: string;
  to: string;
  label: string;
}

export interface NetworkTopology {
  nodes: NetworkNode[];
  edges: NetworkEdge[];
}

export interface IntelligencePattern {
  id: string;
  session_id: string;
  vuln_count: number;
  max_severity: string;
  max_cvss: number;
  services: string;
  mitre_techniques: string;
  document: string;
}

export interface AgentThought {
  id?: string;
  session_id: string;
  thought: string;
  phase: string;
  iteration: number;
  timestamp: string;
}

export interface ToolOutput {
  id?: string;
  session_id: string;
  tool_name: string;
  params: Record<string, unknown>;
  raw_output: string | null;
  parsed_output: Record<string, unknown> | null;
  duration_seconds: number | null;
  timestamp: string;
}

export interface AppSettings {
  llm_provider: string;
  llm_api_key: string;
  llm_model: string;
  llm_max_tokens: string;
  llm_temperature: string;
  azure_endpoint: string;
  mcp_host: string;
  mcp_port: string;
  max_iterations: string;
  scan_timeout: string;
  storage_path: string;
  setup_complete: string;
  [key: string]: string;
}

export interface ToolInfo {
  name: string;
  description: string;
  status: 'available' | 'missing' | 'error';
  version: string | null;
  parameters: Array<{name: string; type: string; required: boolean; description: string}>;
}

export interface TestConnectionResult {
  success: boolean;
  message: string;
  details?: Record<string, unknown>;
}

export interface WSMessage {
  type: 'agent_thought' | 'tool_execution' | 'vulnerability_found' | 'session_update' | 'session_complete' | 'error' | 'session_error' | 'deep_thought' | 'topology_update' | 'agent_start' | 'agent_complete' | 'multi_agent_start' | 'multi_agent_complete' | 'hypothesis_update';
  data: Record<string, unknown>;
  timestamp: string;
}

export interface HealthStatus {
  postgres: 'ok' | 'error';
  mongodb: 'ok' | 'error';
  redis: 'ok' | 'error';
  chroma: 'ok' | 'error';
  mcp: 'ok' | 'error';
}

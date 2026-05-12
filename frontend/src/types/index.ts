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
export type ScanProfile = 'fast' | 'deep' | 'stealth' | 'full' | 'apt_sim' | 'exhaustive';
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

// v7.x — adversarial-reasoning transcripts (red/blue dialectic + philosopher
//        + persona agents: insider-threat, nation-state APT)
export type AdversarialKind = 'red_blue' | 'philosopher' | 'insider' | 'nation_state';
export type AdversarialTrigger = 'seed' | 'confirmed_hypothesis' | 'anomaly_threshold';
export type AdversarialVerdict =
  | 'survives' | 'killed' | 'parse_failed' | 'blue_blocked'
  | 'no_response' | 'red_no_response';

export interface AdversarialAgentTurn {
  raw: string;
  parsed: Record<string, unknown>;
}

export interface PhilosopherParsed {
  bug_class?: string;
  explanation?: string;
  novel_hypotheses?: Array<{ text: string; confidence: number }>;
}

export interface AdversarialRound {
  _id: string;
  session_id: string;
  kind: AdversarialKind;
  trigger: AdversarialTrigger;
  trigger_hypothesis_id?: string | null;
  // red_blue-only
  round?: number;
  red?: AdversarialAgentTurn | null;
  blue?: AdversarialAgentTurn | null;
  verdict?: AdversarialVerdict;
  linked_hypothesis_id?: string | null;
  confidence?: number;
  // philosopher-only
  anomalies_summary?: string;
  raw?: string;
  parsed?: PhilosopherParsed | Record<string, unknown>;
  linked_hypothesis_ids?: string[];
  // common
  created_at: string;
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
  azure_oai_api_version: string;
  // v7.x — JSON-encoded {model: {input, output}} per-model rate card (USD per 1M tokens).
  model_pricing: string;
  // v7.x — JSON array of ModelProfile (see types below). Multi-model routing
  // when non-empty; legacy single-model fallback when empty.
  model_profiles: string;
  // v7.x — JSON object {RoleName: profile_id}. Only honoured when
  // model_profiles is non-empty.
  role_assignments: string;
  // v7.x — "single" (legacy single-model) or "multi" (role-based routing).
  // Defaults to "single" if unset.
  llm_mode: string;
  mcp_host: string;
  mcp_port: string;
  max_iterations: string;
  scan_timeout: string;
  storage_path: string;
  setup_complete: string;
  [key: string]: string;
}

// v7.x — multi-model role routing
export type ModelProfileProvider =
  | 'anthropic' | 'azure' | 'azure_openai' | 'foundry_serverless'
  | 'bedrock' | 'custom';

export interface ModelProfile {
  id: string;
  name: string;
  provider: ModelProfileProvider;
  model: string;
  api_key: string;
  endpoint?: string;
  api_version?: string;
  custom_headers?: string;
  rates: ModelPricingRate;
  supports_tools?: boolean;
}

export type RoleName =
  | 'primary' | 'critic' | 'compress' | 'brief' | 'reasoning'
  | 'payload' | 'red_blue' | 'philosopher' | 'subagent';

export interface ModelPricingRate {
  input: number;
  output: number;
}

// v7.x — session cost summary (matches backend routes/costs.py shape)
export interface SessionCostsResponse {
  session_id: string;
  total_usd: number;
  totals: { input: number; output: number; cache_create: number; cache_read: number };
  tokens: { input: number; output: number; cache_create: number; cache_read: number };
  by_iteration: Array<{ iteration: number; cost_usd: number; cumulative_usd: number }>;
  by_source: Record<string, number>;
  by_model: Record<string, number>;
  rates_used: Record<string, ModelPricingRate>;
  default_rates: Record<string, ModelPricingRate>;
  unknown_models: string[];
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
  type:
    | 'agent_thought' | 'tool_execution' | 'vulnerability_found'
    | 'session_update' | 'session_complete' | 'error' | 'session_error'
    | 'deep_thought' | 'topology_update'
    | 'agent_start' | 'agent_complete'
    | 'multi_agent_start' | 'multi_agent_complete' | 'phase_transition'
    | 'hypothesis_update'
    | 'plan_tree_seeded' | 'plan_replan'
    | 'loop_break' | 'chain_suggestion' | 'target_brief'
    // T27 — live attack-graph + evidence-flow panel
    | 'graph_delta'
    // v7.0 — reasoning-loop lifecycle events
    | 'loop_started' | 'loop_tick' | 'loop_finished'
    // v7.x — adversarial reasoning events (red/blue + philosopher)
    | 'adversarial_round_complete'
    // v7.x — multi-agent rounds-loop and orchestrator backstop
    | 'backstop_loop'
    // v7.x — per-LLM-call token usage (drives the Costs tab)
    | 'llm_usage_recorded'
    // operator-goal subtask progress
    | 'goal_progress';
  data: Record<string, unknown>;
  timestamp: string;
}

// T21/T27 — attack knowledge graph types
export type GraphNodeLabel = 'Host' | 'Service' | 'Finding' | 'Credential' | 'Token' | 'Privilege' | 'Target';
export type GraphEdgeType = 'LISTENS_ON' | 'AUTHENTICATES_TO' | 'GRANTS' | 'CHAINS_INTO' | 'AFFECTS' | 'AFFECTS_HOST' | 'ON_TARGET';

export interface GraphNode {
  id: string;
  labels: GraphNodeLabel[];
  session_id?: string;
  title?: string;
  ip?: string;
  hostname?: string;
  port?: number;
  protocol?: string;
  banner?: string;
  severity?: string;
  cvss?: number;
  verification_status?: string;
  attack_chain_id?: string;
  chain_position?: number;
  [k: string]: unknown;
}

export interface GraphEdge {
  source: string;
  target: string;
  type: GraphEdgeType;
  position?: number;
  [k: string]: unknown;
}

export interface GraphPayload {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

// T27 — evidence-flow endpoint response shape
export interface ToolOutputDoc {
  _id?: string;
  session_id: string;
  tool_name: string;
  params?: Record<string, unknown>;
  raw_output?: string | null;
  parsed_output?: Record<string, unknown> | null;
  duration_seconds?: number | null;
  timestamp: string;
}

export interface VulnerabilityEvidence {
  vuln_id: string;
  title: string;
  severity: string;
  verification_status: string;
  verification_output: string | null;
  evidence_for: string[];
  endpoint: string;
  technique_tag: string;
  tool_used: string;
  candidate_tool_outputs: ToolOutputDoc[];
}

export interface HealthStatus {
  postgres: 'ok' | 'error';
  mongodb: 'ok' | 'error';
  redis: 'ok' | 'error';
  chroma: 'ok' | 'error';
  mcp: 'ok' | 'error';
  neo4j: 'ok' | 'error';
  minio: 'ok' | 'error';
}

// ── v6.0 Tier-8 types ──────────────────────────────────────────────────────

export type UserRole = 'admin' | 'operator' | 'reviewer' | 'read_only';

export interface User {
  id: string;
  email: string;
  role: UserRole;
  tenant_id: string | null;
  is_active: boolean;
  created_at: string;
}

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  token_budget: number | null;
  created_at: string;
}

export interface AuthToken {
  access_token: string;
  token_type: string;
  user: User;
}

export interface AuditEntry {
  id: string;
  tenant_id: string | null;
  user_id: string;
  action: string;
  resource_type: string;
  resource_id: string | null;
  ip_address: string | null;
  ts: string;
}

export type GoalSubGoalStatus = 'pending' | 'in_progress' | 'done';

export interface GoalSubGoal {
  description: string;
  probe_hints: string[];
  status?: GoalSubGoalStatus;
  evidence_count?: number;
}

export interface GoalPhase {
  name: string;
  sub_goals: GoalSubGoal[];
}

export interface GoalTree {
  root: string;
  phases: GoalPhase[];
  open_questions: string[];
}

export interface Goal {
  id: string;
  session_id: string;
  goal_text: string;
  compiled_tree: GoalTree | null;
  status: string;
  created_at: string;
}

export interface ThreatIntelEntry {
  cve_id: string;
  source: string;
  severity: string;
  cvss_score: number;
  description: string;
  affected_components: string[];
  matched_targets: Array<{
    host: string;
    service: string;
    version: string;
    confidence: number;
  }>;
  poc_url: string | null;
}

export interface ComplianceFinding {
  finding_id: string;
  title: string;
  severity: string;
  attack_class: string;
  control_ids: string[];
  description: string;
}

export interface ComplianceReport {
  session_id: string;
  framework: string;
  total_findings: number;
  mapped_findings: ComplianceFinding[];
  controls_violated: string[];
  controls_violated_count: number;
  summary: {
    total_findings: number;
    mapped_findings: number;
    unmapped_findings: number;
    severity_breakdown: Record<string, number>;
    unique_controls_violated: number;
  };
}

export interface IntegrationConfig {
  id: string;
  type: 'slack' | 'jira' | 'pagerduty' | 'splunk' | 'teams';
  name: string;
  enabled: boolean;
  config: Record<string, string>;
}

export interface AgentState {
  agent_id: string;
  agent_type: string;
  current_action: string;
  last_thought: string;
  status: 'idle' | 'thinking' | 'executing';
  // v7.x — model name + tokens spent attributed via llm_usage_recorded events
  model?: string;
  total_input_tokens?: number;
  total_output_tokens?: number;
  last_active?: string;
}

export interface ExplanationEvent {
  tool_name: string;
  explanation: string;
  driving_hypothesis_id: string | null;
  timestamp: string;
}

export interface HypothesisNode {
  hyp_id: string;
  statement: string;
  confidence: number;
  status: HypothesisStatus;
  parent_id: string | null;
  persona: string | null;
  curiosity_score: number | null;
}

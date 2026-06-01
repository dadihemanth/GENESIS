import axios from 'axios';
import type {
  Session, Vulnerability, ToolInfo, AppSettings, TestConnectionResult,
  HealthStatus, AttackChain, NetworkTopology, IntelligencePattern,
  SessionError, AuthToken, User, Tenant, AuditEntry, Goal,
  ThreatIntelEntry, ComplianceReport, IntegrationConfig, CandidateFinding,
  ValidationVerdict, ProofRun, FindingCluster, BenchmarkReport, TargetSurfaceGraph,
  ConfirmFindingsResult, CompleteValidationResult, ValidationProofJob,
  PlainLanguageFinding,
} from '../types';

const api = axios.create({ baseURL: '/api/v1', timeout: 120000 });

api.interceptors.request.use((config) => {
  // JWT takes priority over legacy API key
  const jwt = localStorage.getItem('genesis_jwt');
  if (jwt) {
    config.headers['Authorization'] = `Bearer ${jwt}`;
  } else {
    const apiKey = localStorage.getItem('genesis_api_key');
    if (apiKey) {
      config.headers['X-API-Key'] = apiKey;
    }
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    const message =
      error.response?.data?.detail ||
      error.response?.data?.message ||
      error.message ||
      'An unexpected error occurred';
    return Promise.reject(new Error(message));
  }
);

export const healthApi = {
  check: (): Promise<HealthStatus> => api.get('/health/detailed').then(r => {
    const s = r.data?.services ?? {};
    const ok = (v: unknown): 'ok' | 'error' =>
      (v as { status?: string })?.status === 'ok' ? 'ok' : 'error';
    return {
      postgres: ok(s.postgres),
      mongodb: ok(s.mongodb),
      redis: ok(s.redis),
      chroma:  ok(s.chromadb),
      mcp:     ok(s.mcp_server),
      neo4j:   ok(s.neo4j),
      minio:   ok(s.minio),
    };
  }),
};

export const sessionsApi = {
  create: (data: { target_ip: string; scan_profile?: string; agent_mode?: string; config?: Record<string, unknown> }) =>
    api.post<Session>('/sessions', data).then(r => r.data),
  list: (params?: { page?: number; size?: number; status?: string }) =>
    api.get<{ items: Session[]; total: number }>('/sessions', { params }).then(r => r.data),
  get: (id: string) =>
    api.get<Session>(`/sessions/${id}`).then(r => r.data),
  start: (id: string) =>
    api.post(`/sessions/${id}/start`).then(r => r.data),
  pause: (id: string) =>
    api.post(`/sessions/${id}/pause`).then(r => r.data),
  resume: (id: string) =>
    api.post(`/sessions/${id}/resume`).then(r => r.data),
  stop: (id: string) =>
    api.post(`/sessions/${id}/stop`).then(r => r.data),
  getThoughts: (id: string, params?: { page?: number; size?: number }) =>
    api.get(`/sessions/${id}/thoughts`, { params }).then(r => r.data),
  getHypotheses: (id: string) =>
    api.get(`/sessions/${id}/hypotheses`).then(r => r.data),
  getToolOutputs: (id: string, params?: { page?: number; size?: number }) =>
    api.get(`/sessions/${id}/tool-outputs`, { params }).then(r => r.data),
  getAttackChains: (id: string) =>
    api.get<AttackChain[]>(`/sessions/${id}/attack-chains`).then(r => r.data),
  getNetworkTopology: (id: string) =>
    api.get<NetworkTopology>(`/sessions/${id}/network-topology`).then(r => r.data),
  getMitreMapping: (id: string) =>
    api.get<{ session_id: string; techniques: Record<string, number>; total_techniques: number; total_mappings: number }>(`/sessions/${id}/mitre-mapping`).then(r => r.data),
  getErrors: (id: string, params?: { page?: number; size?: number }) =>
    api.get<{ items: SessionError[]; total: number; page: number; size: number }>(`/sessions/${id}/errors`, { params }).then(r => r.data),
  // Markdown report download. Returns the raw text and a suggested filename
  // pulled from the Content-Disposition header so the caller can save-as.
  downloadReport: async (id: string): Promise<{ filename: string; body: string }> => {
    const res = await api.get<string>(`/sessions/${id}/report`, {
      responseType: 'text',
      transformResponse: (v) => v,
    });
    let filename = `genesis-session-${id.split('-')[0]}.md`;
    const disp = (res.headers as Record<string, string>)['content-disposition'] || '';
    const m = /filename="([^"]+)"/.exec(disp);
    if (m) filename = m[1];
    return { filename, body: res.data as string };
  },
  downloadHtmlReport: async (
    id: string,
    params?: { audience?: 'combined' | 'executive' | 'technical'; include_raw?: boolean; max_evidence_chars?: number },
  ): Promise<{ filename: string; body: string }> => {
    const res = await api.get<string>(`/sessions/${id}/report.html`, {
      params,
      responseType: 'text',
      transformResponse: (v) => v,
    });
    let filename = `genesis-session-${id.split('-')[0]}.html`;
    const disp = (res.headers as Record<string, string>)['content-disposition'] || '';
    const m = /filename="([^"]+)"/.exec(disp);
    if (m) filename = m[1];
    return { filename, body: res.data as string };
  },
  // v7.x — per-session reproducibility report (specialists, attack-class
  // coverage, first-time-target floors, intel reframing). 404 when not
  // yet written (in-progress or pre-v7.x sessions).
  getReproducibility: (id: string) =>
    api.get<{
      session_id: string;
      target_ip: string;
      agent_mode: string;
      scan_profile: string;
      first_time_target: boolean;
      first_time_floors_applied: boolean;
      min_iter_floor_used: number;
      specialists_inherited_from_memory: string[];
      specialists_baseline_used: string[];
      specialists_detected: string[];
      specialists_actually_ran: string[];
      attack_classes_attempted: string[];
      attack_classes_unmet: string[];
      attack_class_probe_counts: Record<string, number>;
      tool_call_total: number;
      tool_call_distinct: number;
      prior_intel_findings_injected: number;
      prior_not_achieved_subgoals_injected: number;
      deeper_than_last_time_targets: string[];
      target_high_water_findings?: number;
      target_high_water_duration_min?: number;
      target_high_water_session_id?: string | null;
      this_run_findings_count?: number;
      this_run_vs_high_water_pct?: number | null;
      this_run_beats_high_water?: boolean | null;
      created_at: string;
    }>(`/sessions/${id}/reproducibility`).then(r => r.data),

  // v7.x — explain which model serves which role for this session, with
  // actual call counts so it's obvious whether the routing fired or not.
  getRouting: (id: string) =>
    api.get<{
      session_id: string;
      llm_mode: string;
      profiles_configured: number;
      rows: Array<{
        role: string;
        purpose: string;
        fires_in: string;
        active_for_this_session_mode: boolean;
        good_models: string;
        assigned_profile_id: string | null;
        assigned_profile_name: string | null;
        assigned_provider: string | null;
        assigned_model: string | null;
        fallback_to_primary: boolean;
        calls_this_session: number;
        input_tokens_this_session: number;
        output_tokens_this_session: number;
        observed_models: string[];
        why_assigned: string;
        explanation: string;
      }>;
    }>(`/sessions/${id}/routing`).then(r => r.data),

  // v7.x — per-endpoint × per-attack-class coverage heatmap. Cells are
  // attempted (>=1 probe ran) / confirmed (a verified vuln landed).
  getCoverageMatrix: (id: string) =>
    api.get<{
      session_id: string;
      target_ip: string;
      endpoints: string[];
      classes: string[];
      cells: Record<string, Record<string, { attempted: number; confirmed: boolean; last_tool: string }>>;
      density: {
        total_cells: number;
        attempted_cells: number;
        confirmed_cells: number;
        coverage_pct: number;
      };
    }>(`/sessions/${id}/coverage-matrix`).then(r => r.data),
};

export const intelligenceApi = {
  getPatterns: (params?: { page?: number; size?: number }) =>
    api.get<{ items: IntelligencePattern[]; total: number; page: number; size: number }>('/intelligence/patterns', { params }).then(r => r.data),
  recall: (fingerprint: string, n = 5) =>
    api.get<{ fingerprint: string; results: unknown[]; count: number }>('/intelligence/recall', { params: { fingerprint, n } }).then(r => r.data),
  indexSession: (id: string) =>
    api.post(`/intelligence/${id}/index`).then(r => r.data),
};

export interface DrivingHypothesis {
  hyp_id: string;
  statement: string;
  confidence: number;
  status: string;
  evidence_for: string[];
  evidence_against: string[];
  next_test: string | null;
  falsification_criteria: string | null;
  attack_chain_id: string | null;
  updated_at: string;
}

export interface DrivingToolCall {
  id: string;
  tool_name: string;
  is_custom_script: boolean;
  timestamp: string;
  duration_seconds: number | null;
  params: Record<string, unknown>;
  raw_output: string;
  oracle_verdict: string | null;
  oracle_reasons: string[] | null;
  match_score: number;
}

export interface VulnIdentification {
  vuln_id: string;
  title: string;
  severity: string;
  verification_status: string;
  confidence: number;
  plain_language?: PlainLanguageFinding;
  cve_ids: string[];
  is_zero_day: boolean;
  is_known: boolean;
  known_explanation: string;
  mitre_techniques: string[];
  endpoint: string;
  technique_tag: string;
  tool_used: string;
  evidence_for: string[];
  driving_hypothesis: DrivingHypothesis | null;
  driving_tool_calls: DrivingToolCall[];
}

export const vulnerabilitiesApi = {
  list: (params?: { severity?: string; session_id?: string; page?: number; size?: number }) =>
    api.get<{ items: Vulnerability[]; total: number }>('/vulnerabilities', { params }).then(r => r.data),
  get: (id: string) =>
    api.get<Vulnerability>(`/vulnerabilities/${id}`).then(r => r.data),
  search: (q: string, n = 20) =>
    api.get<{ items: Vulnerability[] }>('/vulnerabilities/search', { params: { q, n } }).then(r => r.data),
  identification: (id: string) =>
    api.get<VulnIdentification>(`/vulnerabilities/${id}/identification`).then(r => r.data),
  exportCsv: (sessionId: string) =>
    api.get(`/vulnerabilities/export/csv`, {
      params: { session_id: sessionId },
      responseType: 'blob',
    }).then(r => r.data as Blob),
  listNovel: (sessionId: string) =>
    api.get<{
      session_id: string;
      total_findings: number;
      novel_count: number;
      items: Array<{
        id: string;
        title: string;
        severity: string;
        cvss_score: number | null;
        verification_status: string;
        is_zero_day: boolean;
        affected_service: string;
        port: number | null;
        endpoint: string;
        tool_used: string;
        exploit_code: string;
        remediation: string;
        cve_ids: string[];
        mitre_techniques: string[];
        created_at: string;
      }>;
    }>(`/vulnerabilities/novel`, { params: { session_id: sessionId } }).then(r => r.data),
};

export const validatedApi = {
  listCandidates: (sessionId: string, params?: { status?: string; limit?: number }) =>
    api.get<{ session_id: string; items: CandidateFinding[]; total: number }>(
      `/validated/sessions/${sessionId}/candidates`,
      { params },
    ).then(r => r.data),
  createCandidate: (sessionId: string, data: Partial<CandidateFinding>) =>
    api.post<CandidateFinding>(`/validated/sessions/${sessionId}/candidates`, data).then(r => r.data),
  listVerdicts: (sessionId: string, params?: { candidate_id?: string; limit?: number }) =>
    api.get<{ session_id: string; items: ValidationVerdict[]; total: number }>(
      `/validated/sessions/${sessionId}/verdicts`,
      { params },
    ).then(r => r.data),
  addVerdict: (
    sessionId: string,
    candidateId: string,
    data: Pick<ValidationVerdict, 'verdict' | 'validator' | 'reasoning'> & Partial<ValidationVerdict>,
  ) =>
    api.post<ValidationVerdict>(
      `/validated/sessions/${sessionId}/candidates/${candidateId}/verdicts`,
      data,
    ).then(r => r.data),
  listProofRuns: (sessionId: string, params?: { candidate_id?: string; limit?: number }) =>
    api.get<{ session_id: string; items: ProofRun[]; total: number }>(
      `/validated/sessions/${sessionId}/proof-runs`,
      { params },
    ).then(r => r.data),
  addProofRun: (sessionId: string, candidateId: string, data: Partial<ProofRun>) =>
    api.post<ProofRun>(
      `/validated/sessions/${sessionId}/candidates/${candidateId}/proof-runs`,
      data,
    ).then(r => r.data),
  confirmFindings: (
    sessionId: string,
    data?: { candidate_ids?: string[]; operator_validated?: boolean; reason?: string },
  ) =>
    api.post<ConfirmFindingsResult>(
      `/validated/sessions/${sessionId}/confirm`,
      data ?? {},
    ).then(r => r.data),
  completeValidation: (
    sessionId: string,
    data?: { candidate_ids?: string[]; max_candidates?: number; force_reproof?: boolean },
  ) =>
    api.post<CompleteValidationResult>(
      `/validated/sessions/${sessionId}/complete-validation`,
      data ?? {},
    ).then(r => r.data),
  getProofJob: (sessionId: string, jobId: string) =>
    api.get<ValidationProofJob>(
      `/validated/sessions/${sessionId}/proof-jobs/${jobId}`,
    ).then(r => r.data),
  listClusters: (sessionId: string, params?: { rebuild?: boolean; limit?: number }) =>
    api.get<{ session_id: string; items: FindingCluster[]; total: number }>(
      `/validated/sessions/${sessionId}/clusters`,
      { params },
    ).then(r => r.data),
  getSurfaceGraph: (sessionId: string, params?: { rebuild?: boolean }) =>
    api.get<TargetSurfaceGraph>(`/validated/sessions/${sessionId}/surface-graph`, { params }).then(r => r.data),
  createBenchmark: (sessionId: string, data?: { label?: string; lane?: string; ground_truth?: unknown[] }) =>
    api.post<BenchmarkReport>(`/validated/sessions/${sessionId}/benchmark`, data ?? {}).then(r => r.data),
  listBenchmarkReports: (sessionId: string, params?: { limit?: number }) =>
    api.get<{ session_id: string; items: BenchmarkReport[]; total: number }>(
      `/validated/sessions/${sessionId}/benchmark`,
      { params },
    ).then(r => r.data),
};

export const settingsApi = {
  get: () =>
    api.get<AppSettings>('/settings').then(r => r.data),
  update: (data: Partial<AppSettings>) =>
    api.put<AppSettings>('/settings', data).then(r => r.data),
  testLLM: (data?: Partial<AppSettings>) =>
    api.post<TestConnectionResult>('/settings/test-llm', data).then(r => r.data),
  testMCP: (data?: { host?: string; port?: string }) =>
    api.post<TestConnectionResult>('/settings/test-mcp', data).then(r => r.data),
};

export const toolsApi = {
  list: () =>
    api.get<ToolInfo[]>('/tools').then(r => r.data),
  testAll: () =>
    api.post<ToolInfo[]>('/tools/test-all').then(r => r.data),
};

export interface AgentInfo {
  name: string;
  kind: 'generalist' | 'specialist' | 'solo' | 'other';
  phase: string;
  description: string;
  tool_count: number;
  tools: string[];
}

export interface AgentRoster {
  agents: AgentInfo[];
  solo: AgentInfo;
  totals: {
    generalists: number;
    specialists: number;
    agents_total: number;
    tools_total: number;
  };
}

export const agentsApi = {
  list: () =>
    api.get<AgentRoster>('/agents').then(r => r.data),
};

export interface ContainerInfo {
  id: string;
  name: string;
  service: string;
  is_mcp_service: boolean;
  image: string;
  status: string;          // running | exited | created | restarting
  state: string | null;
  exit_code: number | null;
  health: string | null;   // starting | healthy | unhealthy | null
  started_at: string | null;
  uptime_seconds: number | null;
  restart_count: number;
  networks: string[];
  ports: string[];
}

export interface ContainerInventory {
  project: string;
  totals: {
    containers: number;
    running: number;
    stopped: number;
    healthy: number;
    unhealthy: number;
    mcp_total: number;
    mcp_running: number;
  };
  containers: ContainerInfo[];
}

export const containersApi = {
  list: () =>
    api.get<ContainerInventory>('/containers').then(r => r.data),
};

// ── v6.0 API wrappers ──────────────────────────────────────────────────────

export const authApi = {
  login: (email: string, password: string): Promise<AuthToken> =>
    api.post<AuthToken>('/auth/login', { email, password }).then(r => r.data),
  register: (email: string, password: string): Promise<AuthToken> =>
    api.post<AuthToken>('/auth/register', { email, password }).then(r => r.data),
  me: (): Promise<User> =>
    api.get<User>('/auth/me').then(r => r.data),
  listTenants: (): Promise<Tenant[]> =>
    api.get<Tenant[]>('/auth/tenants').then(r => r.data),
  createTenant: (name: string, slug: string): Promise<Tenant> =>
    api.post<Tenant>('/auth/tenants', { name, slug }).then(r => r.data),
  getAuditLog: (params?: { page?: number; size?: number }): Promise<{ items: AuditEntry[]; total: number }> =>
    api.get('/auth/audit', { params }).then(r => r.data),
};

export const goalsApi = {
  create: (sessionId: string, goal: string): Promise<Goal> =>
    api.post<Goal>(`/goals/sessions/${sessionId}`, { goal }).then(r => r.data),
  get: (sessionId: string): Promise<Goal | null> =>
    api.get<Goal>(`/goals/sessions/${sessionId}`).then(r => r.data).catch(() => null),
};

export const threatsApi = {
  list: (sessionId?: string): Promise<{ threats: ThreatIntelEntry[]; count: number }> =>
    api.get('/intelligence/threats', { params: sessionId ? { session_id: sessionId } : {} }).then(r => r.data),
  triggerIngest: (sinceDays = 1) =>
    api.post('/intelligence/threats/ingest', null, { params: { since_days: sinceDays } }).then(r => r.data),
  triggerReplay: (cveId: string, sessionId?: string) =>
    api.post(`/intelligence/threats/${cveId}/replay`, null, { params: sessionId ? { session_id: sessionId } : {} }).then(r => r.data),
};

export const complianceApi = {
  getReport: (sessionId: string, framework: string): Promise<ComplianceReport> =>
    api.get<ComplianceReport>(`/compliance/sessions/${sessionId}/${framework}`).then(r => r.data),
  listFrameworks: (): Promise<{ frameworks: string[] }> =>
    api.get('/compliance/frameworks').then(r => r.data),
};

export const integrationsApi = {
  list: (): Promise<IntegrationConfig[]> =>
    api.get<IntegrationConfig[]>('/integrations').then(r => r.data),
  create: (config: Omit<IntegrationConfig, 'id'>): Promise<IntegrationConfig> =>
    api.post<IntegrationConfig>('/integrations', config).then(r => r.data),
  test: (id: string) =>
    api.post(`/integrations/${id}/test`).then(r => r.data),
  delete: (id: string) =>
    api.delete(`/integrations/${id}`).then(r => r.data),
};

export const eventsApi = {
  getEvents: (sessionId: string, fromSeq = 0) =>
    api.get(`/events/sessions/${sessionId}`, { params: { from_seq: fromSeq } }).then(r => r.data),
  getAbResults: () =>
    api.get('/events/admin/ab-results').then(r => r.data),
};

export const budgetsApi = {
  create: (data: { target_ip: string; monthly_usd_cap?: number; token_budget?: number; tool_call_cap?: number }) =>
    api.post('/budgets', data).then(r => r.data),
  getStatus: (targetIp: string, sessionId?: string) =>
    api.get(`/budgets/${encodeURIComponent(targetIp)}`, { params: sessionId ? { session_id: sessionId } : {} }).then(r => r.data),
};

// ── v7.0 reasoning-loop API wrappers ──────────────────────────────────────

export interface ReasoningLoopTick {
  iteration: number;
  state_snapshot: Record<string, unknown>;
  branches: Array<Record<string, unknown>>;
  chosen: string | null;
  reasoning: string;
  tokens: number;
  ts: string;
}

export interface ReasoningLoop {
  loop_id: string;
  session_id: string;
  loop_type: string;
  status: 'running' | 'complete' | 'aborted';
  inputs: Record<string, unknown>;
  ticks?: ReasoningLoopTick[];
  result: unknown;
  tokens_spent: number;
  tick_count: number;
  created_at: string;
  updated_at: string;
}

export interface ReasoningLoopType {
  loop_type: string;
  max_tokens: number;
  max_ticks: number;
}

export const loopsApi = {
  listForSession: (sessionId: string, loopType?: string): Promise<{ loops: ReasoningLoop[]; count: number }> =>
    api.get(`/loops/${sessionId}`, { params: loopType ? { loop_type: loopType } : {} }).then(r => r.data),
  getDetail: (loopId: string): Promise<ReasoningLoop> =>
    api.get(`/loops/detail/${loopId}`).then(r => r.data),
  listTypes: (): Promise<{ types: ReasoningLoopType[]; count: number }> =>
    api.get('/loops/types').then(r => r.data),
};

// v7.x — session costs (token usage × per-model rates)
export const costsApi = {
  getForSession: (sessionId: string): Promise<import('../types').SessionCostsResponse> =>
    api.get(`/sessions/${sessionId}/costs`).then(r => r.data),
};

// v7.x — adversarial-reasoning transcripts (red/blue + philosopher)
export const adversarialApi = {
  listForSession: (
    sessionId: string,
    kind?: 'red_blue' | 'philosopher',
  ): Promise<{ session_id: string; items: import('../types').AdversarialRound[]; count: number }> =>
    api.get(`/adversarial/${sessionId}`, { params: kind ? { kind } : {} }).then(r => r.data),
  getDetail: (roundId: string): Promise<import('../types').AdversarialRound> =>
    api.get(`/adversarial/detail/${roundId}`).then(r => r.data),
};

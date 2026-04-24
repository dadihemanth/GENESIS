import axios from 'axios';
import type { Session, Vulnerability, ToolInfo, AppSettings, TestConnectionResult, HealthStatus, AttackChain, NetworkTopology, IntelligencePattern, SessionError } from '../types';

const api = axios.create({ baseURL: '/api/v1', timeout: 120000 });

api.interceptors.request.use((config) => {
  const apiKey = localStorage.getItem('genesis_api_key');
  if (apiKey) {
    config.headers['X-API-Key'] = apiKey;
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
};

export const intelligenceApi = {
  getPatterns: (params?: { page?: number; size?: number }) =>
    api.get<{ items: IntelligencePattern[]; total: number; page: number; size: number }>('/intelligence/patterns', { params }).then(r => r.data),
  recall: (fingerprint: string, n = 5) =>
    api.get<{ fingerprint: string; results: unknown[]; count: number }>('/intelligence/recall', { params: { fingerprint, n } }).then(r => r.data),
  indexSession: (id: string) =>
    api.post(`/intelligence/${id}/index`).then(r => r.data),
};

export const vulnerabilitiesApi = {
  list: (params?: { severity?: string; session_id?: string; page?: number; size?: number }) =>
    api.get<{ items: Vulnerability[]; total: number }>('/vulnerabilities', { params }).then(r => r.data),
  get: (id: string) =>
    api.get<Vulnerability>(`/vulnerabilities/${id}`).then(r => r.data),
  search: (q: string, n = 20) =>
    api.get<{ items: Vulnerability[] }>('/vulnerabilities/search', { params: { q, n } }).then(r => r.data),
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

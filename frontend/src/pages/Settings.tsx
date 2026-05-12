import React, { useEffect, useState, useCallback } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Tab,
  Tabs,
  TextField,
  Button,
  Grid,
  CircularProgress,
  Alert,
  Snackbar,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Slider,
  Divider,
  Skeleton,
  Chip,
  Autocomplete,
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import RadioButtonCheckedIcon from '@mui/icons-material/RadioButtonChecked';

import { settingsApi, toolsApi, healthApi, agentsApi, containersApi } from '../services/api';
import type { AgentRoster, ContainerInventory, ContainerInfo } from '../services/api';
import RefreshIcon from '@mui/icons-material/Refresh';
import { useStore } from '../store';
import type { AppSettings, ToolInfo, HealthStatus, ModelPricingRate } from '../types';
import StatusChip from '../components/StatusChip';
import ModelsTabContent from '../components/ModelsTabContent';

// v7.x — published list-price defaults shown as helper text under the rate
// fields. Mirrors backend `_DEFAULT_RATES` in routes/costs.py.
const DEFAULT_RATES: Record<string, ModelPricingRate> = {
  'claude-opus-4-7': { input: 15, output: 75 },
  'claude-sonnet-4-6': { input: 3, output: 15 },
  'claude-haiku-4-5': { input: 0.8, output: 4 },
  'claude-haiku-4-5-20251001': { input: 0.8, output: 4 },
  'gpt-5.5': { input: 1.25, output: 10 },
  'gpt-5': { input: 1.25, output: 10 },
  'gpt-4o': { input: 2.5, output: 10 },
  'gpt-4o-mini': { input: 0.15, output: 0.6 },
  'gpt-4.1': { input: 2.0, output: 8 },
  'o3': { input: 15, output: 60 },
  'o4-mini': { input: 3, output: 12 },
};

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel: React.FC<TabPanelProps> = ({ children, value, index }) => (
  <Box role="tabpanel" hidden={value !== index} sx={{ pt: 3 }}>
    {value === index && children}
  </Box>
);

function fmtUptime(secs: number | null): string {
  if (secs == null) return '—';
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
  return `${Math.floor(secs / 86400)}d ${Math.floor((secs % 86400) / 3600)}h`;
}

function statusColor(status: string, health: string | null): string {
  if (status !== 'running') return '#f44336';
  if (health === 'unhealthy') return '#ff9800';
  if (health === 'starting') return '#ffd54f';
  return '#4caf50';
}

const ContainerCard: React.FC<{ container: ContainerInfo }> = ({ container: c }) => {
  const dot = statusColor(c.status, c.health);
  const isRunning = c.status === 'running';
  const subStatus =
    c.status !== 'running'
      ? `${c.status}${c.exit_code != null ? ` (exit ${c.exit_code})` : ''}`
      : c.health
        ? c.health
        : 'running';
  return (
    <Card
      sx={{
        p: 2,
        position: 'relative',
        borderLeft: `3px solid ${c.is_mcp_service ? '#4e5ced' : 'rgba(30,41,60,0.10)'}`,
        opacity: isRunning ? 1 : 0.78,
      }}
    >
      <Box
        sx={{
          position: 'absolute', top: 12, right: 12,
          width: 10, height: 10, borderRadius: '50%',
          backgroundColor: dot,
          boxShadow: isRunning && c.health !== 'unhealthy' ? `0 0 8px ${dot}` : 'none',
        }}
      />
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5, flexWrap: 'wrap', pr: 3 }}>
        <Typography sx={{ fontWeight: 700, fontSize: '0.88rem', color: '#1a1f2e' }}>
          {c.service}
        </Typography>
        {c.is_mcp_service && (
          <Chip label="MCP" size="small"
            sx={{ height: 16, fontSize: '0.58rem', fontWeight: 700, backgroundColor: 'rgba(78,92,237,0.15)', color: '#4e5ced' }} />
        )}
      </Box>
      <Typography sx={{ fontSize: '0.7rem', color: '#8a93a6', fontFamily: 'monospace', mb: 0.75, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {c.name}
      </Typography>
      <Box sx={{ display: 'flex', gap: 0.75, alignItems: 'center', mb: 0.5, flexWrap: 'wrap' }}>
        <Chip label={subStatus} size="small"
          sx={{ height: 18, fontSize: '0.62rem', fontFamily: 'monospace',
                backgroundColor: `${dot}1f`, color: dot, fontWeight: 700 }} />
        <Typography sx={{ fontSize: '0.68rem', color: '#5a6478', fontFamily: 'monospace' }}>
          uptime {fmtUptime(c.uptime_seconds)}
        </Typography>
        {c.restart_count > 0 && (
          <Chip label={`restart ×${c.restart_count}`} size="small"
            sx={{ height: 16, fontSize: '0.58rem', backgroundColor: 'rgba(255,152,0,0.15)', color: '#ff9800' }} />
        )}
      </Box>
      {c.ports.length > 0 && (
        <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mb: 0.5 }}>
          {c.ports.slice(0, 4).map(p => (
            <Chip key={p} label={p} size="small"
              sx={{ height: 16, fontSize: '0.58rem', fontFamily: 'monospace',
                    backgroundColor: '#f4f6fb', color: '#1a1f2e' }} />
          ))}
          {c.ports.length > 4 && (
            <Typography sx={{ fontSize: '0.6rem', color: '#8a93a6' }}>+{c.ports.length - 4}</Typography>
          )}
        </Box>
      )}
      <Typography sx={{ fontSize: '0.65rem', color: '#8a93a6', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {c.image}
      </Typography>
    </Card>
  );
};

const Settings: React.FC = () => {
  const { setSettings: storeSetSettings } = useStore();
  const [tab, setTab] = useState(0);
  const [settings, setSettingsLocal] = useState<AppSettings | null>(null);
  const [loadingSettings, setLoadingSettings] = useState(true);

  const [tools, setTools] = useState<ToolInfo[]>([]);
  const [toolsLoading, setToolsLoading] = useState(false);
  const [toolsTesting, setToolsTesting] = useState(false);

  const [agents, setAgents] = useState<AgentRoster | null>(null);
  const [agentsLoading, setAgentsLoading] = useState(false);
  const [expandedAgent, setExpandedAgent] = useState<string | null>(null);

  const [containers, setContainers] = useState<ContainerInventory | null>(null);
  const [containersLoading, setContainersLoading] = useState(false);
  const [containersError, setContainersError] = useState<string | null>(null);
  const [showOnlyMcp, setShowOnlyMcp] = useState(false);

  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [healthLoading, setHealthLoading] = useState(false);

  const [savedSettings, setSavedSettings] = useState<AppSettings | null>(null);
  const [llmTesting, setLlmTesting] = useState(false);
  const [llmTestResult, setLlmTestResult] = useState<{ success: boolean; message: string } | null>(null);
  const [mcpTesting, setMcpTesting] = useState(false);
  const [mcpTestResult, setMcpTestResult] = useState<{ success: boolean; message: string } | null>(null);

  const [saving, setSaving] = useState(false);
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false, message: '', severity: 'success',
  });

  const loadSettings = useCallback(async () => {
    setLoadingSettings(true);
    try {
      const s = await settingsApi.get();
      setSettingsLocal(s);
      setSavedSettings(s);
      storeSetSettings(s);
    } catch {
      // ignore
    } finally {
      setLoadingSettings(false);
    }
  }, [storeSetSettings]);

  useEffect(() => { loadSettings(); }, [loadSettings]);

  useEffect(() => {
    if (tab === 2) {
      setToolsLoading(true);
      toolsApi.list().then(setTools).catch(() => {}).finally(() => setToolsLoading(false));
    }
    if (tab === 3) {
      setAgentsLoading(true);
      agentsApi.list().then(setAgents).catch(() => {}).finally(() => setAgentsLoading(false));
    }
    if (tab === 4) {
      setHealthLoading(true);
      healthApi.check().then(setHealth).catch(() => {}).finally(() => setHealthLoading(false));
    }
    if (tab === 6) {
      setContainersLoading(true);
      setContainersError(null);
      containersApi.list()
        .then(setContainers)
        .catch((err) => setContainersError(err instanceof Error ? err.message : String(err)))
        .finally(() => setContainersLoading(false));
    }
  }, [tab]);

  const refreshContainers = useCallback(() => {
    setContainersLoading(true);
    setContainersError(null);
    containersApi.list()
      .then(setContainers)
      .catch((err) => setContainersError(err instanceof Error ? err.message : String(err)))
      .finally(() => setContainersLoading(false));
  }, []);

  const update = (key: keyof AppSettings, value: string) => {
    setSettingsLocal(prev => prev ? { ...prev, [key]: value } : prev);
  };

  const handleSave = async (keys?: (keyof AppSettings)[]) => {
    if (!settings) return;
    setSaving(true);
    try {
      const payload = keys ? Object.fromEntries(keys.map(k => [k, settings[k]])) : settings;
      const saved = await settingsApi.update(payload as Partial<AppSettings>);
      // Rebase the form to what the server actually persisted (sensitive fields
      // come back redacted — the user now sees the masked value, matching what
      // a fresh page load would show).
      setSettingsLocal(saved);
      setSavedSettings(saved);
      storeSetSettings(saved);
      // Clear the last test result — once saved, the green banner is stale:
      // any subsequent change should re-test before claiming success.
      setLlmTestResult(null);
      setSnackbar({ open: true, message: 'Settings saved', severity: 'success' });
    } catch (err) {
      setSnackbar({ open: true, message: err instanceof Error ? err.message : 'Failed to save', severity: 'error' });
    } finally {
      setSaving(false);
    }
  };

  const handleTestLLM = async () => {
    if (!settings) return;
    setLlmTesting(true);
    setLlmTestResult(null);
    try {
      const result = await settingsApi.testLLM(settings);
      setLlmTestResult(result);
    } catch (err) {
      setLlmTestResult({ success: false, message: err instanceof Error ? err.message : 'Test failed' });
    } finally {
      setLlmTesting(false);
    }
  };

  const handleTestMCP = async () => {
    if (!settings) return;
    setMcpTesting(true);
    setMcpTestResult(null);
    try {
      const result = await settingsApi.testMCP({ host: settings.mcp_host, port: settings.mcp_port });
      setMcpTestResult(result);
    } catch (err) {
      setMcpTestResult({ success: false, message: err instanceof Error ? err.message : 'Test failed' });
    } finally {
      setMcpTesting(false);
    }
  };

  const handleTestAllTools = async () => {
    setToolsTesting(true);
    try {
      await toolsApi.testAll();
      const updated = await toolsApi.list();
      setTools(updated);
      setSnackbar({ open: true, message: 'Tool test complete', severity: 'success' });
    } catch (err) {
      setSnackbar({ open: true, message: err instanceof Error ? err.message : 'Tool test failed', severity: 'error' });
    } finally {
      setToolsTesting(false);
    }
  };

  if (loadingSettings) {
    return (
      <Box sx={{ p: 3 }}>
        <Skeleton variant="text" width={200} height={40} sx={{ mb: 3 }} />
        <Skeleton variant="rectangular" height={400} sx={{ borderRadius: 2 }} />
      </Box>
    );
  }

  if (!settings) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">Failed to load settings. Please try refreshing.</Alert>
      </Box>
    );
  }

  const dbEntries: Array<{ key: keyof HealthStatus; label: string }> = [
    { key: 'postgres', label: 'PostgreSQL' },
    { key: 'mongodb', label: 'MongoDB' },
    { key: 'redis', label: 'Redis' },
    { key: 'chroma', label: 'ChromaDB' },
    { key: 'neo4j', label: 'Neo4j' },
    { key: 'minio', label: 'MinIO' },
  ];

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" sx={{ mb: 3, color: '#1a1f2e' }}>
        Settings
      </Typography>

      <Card>
        <Box sx={{ borderBottom: '1px solid #dfe3ec' }}>
          <Tabs
            value={tab}
            onChange={(_, v) => setTab(v)}
            sx={{
              '& .MuiTab-root': { color: '#8a93a6', fontSize: '0.85rem' },
              '& .Mui-selected': { color: '#4e5ced' },
              '& .MuiTabs-indicator': { backgroundColor: '#4e5ced' },
              px: 2,
            }}
          >
            <Tab label="LLM" />
            <Tab label="MCP Server" />
            <Tab label="Tools" />
            <Tab label="Agents" />
            <Tab label="Database" />
            <Tab label="Storage" />
            <Tab label="Containers" />
          </Tabs>
        </Box>

        <CardContent sx={{ p: 3 }}>
          {/* Tab 0 – LLM */}
          <TabPanel value={tab} index={0}>
            {/* v7.x — Mode toggle: single (legacy) vs multi (role-based routing).
                Saves explicitly with the new value (not via state) to dodge the
                React stale-closure that flips the choice back to the old one. */}
            <Box sx={{ maxWidth: 720, mb: 3 }}>
              <Typography sx={{ fontSize: '0.85rem', fontWeight: 600, color: '#5a6478', mb: 1 }}>
                LLM mode
              </Typography>
              <FormControl size="small">
                <Select
                  value={(settings.llm_mode as string) || 'single'}
                  onChange={async e => {
                    const newMode = e.target.value as string;
                    update('llm_mode', newMode);  // optimistic UI flip
                    setSaving(true);
                    try {
                      const saved = await settingsApi.update({ llm_mode: newMode } as Partial<AppSettings>);
                      setSettingsLocal(saved);
                      setSavedSettings(saved);
                      storeSetSettings(saved);
                      setLlmTestResult(null);
                      setSnackbar({ open: true, message: `LLM mode → ${newMode}`, severity: 'success' });
                    } catch (err) {
                      // Roll back optimistic flip
                      update('llm_mode', (settings.llm_mode as string) || 'single');
                      setSnackbar({ open: true, message: err instanceof Error ? err.message : 'Failed to save', severity: 'error' });
                    } finally {
                      setSaving(false);
                    }
                  }}
                >
                  <MenuItem value="single">Single model (legacy fields below)</MenuItem>
                  <MenuItem value="multi">Multi-model (role-based routing)</MenuItem>
                </Select>
              </FormControl>
              <Typography sx={{ fontSize: '0.72rem', color: '#8a93a6', mt: 0.5 }}>
                {(settings.llm_mode || 'single') === 'multi'
                  ? 'Role-based routing: each call site (primary, critic, payload, …) uses an assigned profile.'
                  : 'Single model: every call uses the legacy fields below.'}
              </Typography>
            </Box>

            {((settings.llm_mode as string) || 'single') === 'multi' && (
              <Box sx={{ maxWidth: 720, mb: 3, p: 2, border: '1px solid rgba(30,41,60,0.08)', borderRadius: 1 }}>
                <ModelsTabContent
                  profiles={(() => {
                    try { return JSON.parse(settings.model_profiles || '[]'); } catch { return []; }
                  })()}
                  assignments={(() => {
                    try { return JSON.parse(settings.role_assignments || '{}'); } catch { return {}; }
                  })()}
                  onChange={(profs, assigns) => {
                    update('model_profiles', JSON.stringify(profs));
                    update('role_assignments', JSON.stringify(assigns));
                  }}
                />
                <Box sx={{ mt: 2, display: 'flex', justifyContent: 'flex-end' }}>
                  <Button
                    variant="contained"
                    onClick={() => handleSave(['model_profiles', 'role_assignments'])}
                    disabled={saving}
                    startIcon={saving ? <CircularProgress size={16} color="inherit" /> : undefined}
                  >
                    Save profiles & roles
                  </Button>
                </Box>
              </Box>
            )}

            {((settings.llm_mode as string) || 'single') === 'single' && (
              <>
                <Typography sx={{ fontSize: '0.85rem', fontWeight: 600, color: '#5a6478', mb: 1 }}>
                  Single-model settings
                </Typography>
                <Typography sx={{ fontSize: '0.75rem', color: '#8a93a6', mb: 2, maxWidth: 560 }}>
                  All orchestrator calls use this one model. Switch to multi-model above to enable per-role routing.
                </Typography>
              </>
            )}
            {((settings.llm_mode as string) || 'single') === 'single' && (
            <Grid container spacing={3} maxWidth={560}>
              <Grid item xs={12}>
                <FormControl fullWidth>
                  <InputLabel>Provider</InputLabel>
                  <Select
                    value={settings.llm_provider || 'anthropic'}
                    label="Provider"
                    onChange={e => update('llm_provider', e.target.value)}
                  >
                    <MenuItem value="anthropic">Anthropic</MenuItem>
                    <MenuItem value="azure">Azure AI Foundry (Anthropic)</MenuItem>
                    <MenuItem value="azure_openai">Azure OpenAI (GPT)</MenuItem>
                  </Select>
                </FormControl>
              </Grid>

              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="API Key"
                  type="password"
                  value={settings.llm_api_key || ''}
                  onChange={e => update('llm_api_key', e.target.value)}
                  helperText={
                    (savedSettings?.llm_api_key || '').startsWith('••••')
                      ? 'Stored key is masked for display. Clear the field and paste a new key to replace it — leave as-is to keep the current key.'
                      : ' '
                  }
                />
                {settings.llm_api_key !== (savedSettings?.llm_api_key ?? '') && (
                  <Box sx={{ mt: 0.5 }}>
                    <Chip
                      label="Unsaved changes — click Save to persist this key"
                      size="small"
                      sx={{
                        backgroundColor: 'rgba(255,152,0,0.12)',
                        color: '#ff9800',
                        border: '1px solid rgba(255,152,0,0.4)',
                        fontSize: '0.7rem',
                        height: 20,
                      }}
                    />
                  </Box>
                )}
              </Grid>

              <Grid item xs={12}>
                <Autocomplete
                  freeSolo
                  options={
                    settings.llm_provider === 'azure_openai'
                      ? ['gpt-5.5', 'gpt-4o', 'gpt-4o-mini', 'o3', 'o4-mini']
                      : ['claude-opus-4-7', 'claude-sonnet-4-6', 'claude-haiku-4-5']
                  }
                  value={settings.llm_model || 'claude-sonnet-4-6'}
                  onChange={(_, v) => update('llm_model', v || '')}
                  onInputChange={(_, v) => update('llm_model', v)}
                  renderInput={(params) => (
                    <TextField
                      {...params}
                      label="Model"
                      helperText="Select a preset or type a custom model name"
                    />
                  )}
                />
              </Grid>

              {(settings.llm_provider === 'azure' || settings.llm_provider === 'azure_openai') && (
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Endpoint URL"
                    placeholder={
                      settings.llm_provider === 'azure_openai'
                        ? 'https://your-resource.cognitiveservices.azure.com/'
                        : 'https://your-resource.services.ai.azure.com/anthropic'
                    }
                    value={settings.azure_endpoint || ''}
                    onChange={e => update('azure_endpoint', e.target.value)}
                    helperText={
                      settings.llm_provider === 'azure_openai'
                        ? 'Azure AI Foundry endpoint for your OpenAI deployment'
                        : 'Paste the base endpoint — /v1/messages is appended automatically'
                    }
                  />
                </Grid>
              )}

              {settings.llm_provider === 'azure_openai' && (
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="API Version"
                    placeholder="2024-12-01-preview"
                    value={settings.azure_oai_api_version || '2024-12-01-preview'}
                    onChange={e => update('azure_oai_api_version', e.target.value)}
                    helperText="Azure OpenAI API version"
                  />
                </Grid>
              )}

              <Grid item xs={12}>
                <Typography gutterBottom sx={{ color: '#5a6478', fontSize: '0.875rem' }}>
                  Temperature: {settings.llm_temperature || '0.7'}
                </Typography>
                <Slider
                  min={0}
                  max={2}
                  step={0.1}
                  value={parseFloat(settings.llm_temperature || '0.7')}
                  onChange={(_, v) => update('llm_temperature', String(v))}
                  color="primary"
                  valueLabelDisplay="auto"
                />
              </Grid>

              {/* v7.x — Per-model pricing for the session Costs tab. */}
              <Grid item xs={12}>
                <Box sx={{ mt: 1, p: 2, borderRadius: 1, border: '1px solid rgba(30,41,60,0.08)' }}>
                  <Typography sx={{ fontWeight: 600, fontSize: '0.875rem', mb: 0.5 }}>
                    Pricing for {settings.llm_model || '(no model selected)'}
                  </Typography>
                  <Typography sx={{ color: '#5a6478', fontSize: '0.75rem', mb: 1.5 }}>
                    USD per 1M tokens. Cache rates are auto-derived (cache_create = 1.25× input,
                    cache_read = 0.1× input). Defaults shown when blank.
                  </Typography>
                  {(() => {
                    let parsed: Record<string, ModelPricingRate> = {};
                    try { parsed = JSON.parse(settings.model_pricing || '{}'); } catch { parsed = {}; }
                    const m = settings.llm_model || '';
                    const current = (m && parsed[m]) || { input: 0, output: 0 };
                    const updateRate = (field: 'input' | 'output', v: string) => {
                      const num = v === '' ? 0 : Number(v);
                      const next = { ...parsed, [m]: { ...current, [field]: isNaN(num) ? 0 : num } };
                      update('model_pricing', JSON.stringify(next));
                    };
                    return (
                      <Grid container spacing={2}>
                        <Grid item xs={6}>
                          <TextField
                            fullWidth
                            type="number"
                            label="Input ($ / 1M tokens)"
                            value={current.input || ''}
                            onChange={e => updateRate('input', e.target.value)}
                            inputProps={{ min: 0, step: 0.01 }}
                            disabled={!m}
                            helperText={DEFAULT_RATES[m] ? `Default: $${DEFAULT_RATES[m].input}` : ' '}
                          />
                        </Grid>
                        <Grid item xs={6}>
                          <TextField
                            fullWidth
                            type="number"
                            label="Output ($ / 1M tokens)"
                            value={current.output || ''}
                            onChange={e => updateRate('output', e.target.value)}
                            inputProps={{ min: 0, step: 0.01 }}
                            disabled={!m}
                            helperText={DEFAULT_RATES[m] ? `Default: $${DEFAULT_RATES[m].output}` : ' '}
                          />
                        </Grid>
                      </Grid>
                    );
                  })()}
                </Box>
              </Grid>

              <Grid item xs={12}>
                <Box sx={{ display: 'flex', gap: 2 }}>
                  <Button
                    variant="contained"
                    color="primary"
                    onClick={() => handleSave(['llm_provider', 'llm_api_key', 'llm_model', 'llm_temperature', 'azure_endpoint', 'azure_oai_api_version', 'model_pricing'])}
                    disabled={saving}
                    startIcon={saving ? <CircularProgress size={16} color="inherit" /> : undefined}
                  >
                    Save
                  </Button>
                  <Button
                    variant="outlined"
                    color="primary"
                    onClick={handleTestLLM}
                    disabled={llmTesting}
                    startIcon={llmTesting ? <CircularProgress size={16} color="inherit" /> : undefined}
                  >
                    Test Connection
                  </Button>
                </Box>
                {llmTestResult && (
                  <Alert severity={llmTestResult.success ? 'success' : 'error'} sx={{ mt: 2 }}>
                    {llmTestResult.message}
                    {llmTestResult.success
                      && settings.llm_api_key !== (savedSettings?.llm_api_key ?? '')
                      && (
                        <Typography component="div" sx={{ mt: 0.5, fontSize: '0.8rem', fontWeight: 600 }}>
                          This key is not saved yet — click <b>Save</b> or scans will keep using the previously stored key.
                        </Typography>
                      )}
                  </Alert>
                )}
              </Grid>
            </Grid>
            )}
          </TabPanel>

          {/* Tab 1 – MCP */}
          <TabPanel value={tab} index={1}>
            <Grid container spacing={3} maxWidth={480}>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Host"
                  value={settings.mcp_host || 'localhost'}
                  onChange={e => update('mcp_host', e.target.value)}
                />
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Port"
                  type="number"
                  value={settings.mcp_port || '3001'}
                  onChange={e => update('mcp_port', e.target.value)}
                />
              </Grid>

              <Grid item xs={12}>
                <Card variant="outlined" sx={{ p: 2, border: '1px solid #dfe3ec' }}>
                  <Typography variant="body2" sx={{ color: '#5a6478', mb: 1 }}>
                    Server Status
                  </Typography>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <RadioButtonCheckedIcon
                      sx={{ color: health?.mcp === 'ok' ? '#4caf50' : '#f44336', fontSize: 16 }}
                    />
                    <Typography sx={{ fontFamily: 'monospace', fontSize: '0.85rem', color: '#1a1f2e' }}>
                      {settings.mcp_host}:{settings.mcp_port}
                    </Typography>
                  </Box>
                </Card>
              </Grid>

              <Grid item xs={12}>
                <Box sx={{ display: 'flex', gap: 2 }}>
                  <Button
                    variant="contained"
                    color="primary"
                    onClick={() => handleSave(['mcp_host', 'mcp_port'])}
                    disabled={saving}
                    startIcon={saving ? <CircularProgress size={16} color="inherit" /> : undefined}
                  >
                    Save
                  </Button>
                  <Button
                    variant="outlined"
                    color="primary"
                    onClick={handleTestMCP}
                    disabled={mcpTesting}
                    startIcon={mcpTesting ? <CircularProgress size={16} color="inherit" /> : undefined}
                  >
                    Test Connection
                  </Button>
                </Box>
                {mcpTestResult && (
                  <Alert severity={mcpTestResult.success ? 'success' : 'error'} sx={{ mt: 2 }}>
                    {mcpTestResult.message}
                  </Alert>
                )}
              </Grid>
            </Grid>
          </TabPanel>

          {/* Tab 2 – Tools */}
          <TabPanel value={tab} index={2}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
              <Typography variant="body2" sx={{ color: '#5a6478' }}>
                Security tools available on the MCP server
              </Typography>
              <Button
                variant="outlined"
                color="primary"
                onClick={handleTestAllTools}
                disabled={toolsTesting}
                startIcon={toolsTesting ? <CircularProgress size={14} color="inherit" /> : undefined}
              >
                {toolsTesting ? 'Testing...' : 'Test All'}
              </Button>
            </Box>

            <Grid container spacing={2}>
              {toolsLoading
                ? [...Array(9)].map((_, i) => (
                    <Grid item xs={12} sm={6} md={4} key={i}>
                      <Skeleton variant="rectangular" height={100} sx={{ borderRadius: 2 }} />
                    </Grid>
                  ))
                : tools.map(tool => (
                    <Grid item xs={12} sm={6} md={4} key={tool.name}>
                      <Card sx={{ p: 2, position: 'relative' }}>
                        <Box
                          sx={{
                            position: 'absolute',
                            top: 12,
                            right: 12,
                            width: 10,
                            height: 10,
                            borderRadius: '50%',
                            backgroundColor:
                              tool.status === 'available'
                                ? '#4caf50'
                                : tool.status === 'missing'
                                ? '#f44336'
                                : '#ffab00',
                            boxShadow: tool.status === 'available' ? '0 0 6px #4caf50' : 'none',
                          }}
                        />
                        <Typography sx={{ fontWeight: 700, fontSize: '0.875rem', color: '#1a1f2e', mb: 0.5 }}>
                          {tool.name}
                        </Typography>
                        {tool.version && (
                          <Chip
                            label={`v${tool.version}`}
                            size="small"
                            sx={{ mb: 1, backgroundColor: 'rgba(78,92,237,0.10)', color: '#4e5ced', height: 18, fontSize: '0.65rem' }}
                          />
                        )}
                        <Typography sx={{ fontSize: '0.75rem', color: '#8a93a6', mb: 1.5 }}>
                          {tool.description}
                        </Typography>
                        <StatusChip status={tool.status} />
                      </Card>
                    </Grid>
                  ))}
            </Grid>
          </TabPanel>

          {/* Tab 3 – Agents */}
          <TabPanel value={tab} index={3}>
            {!agents && agentsLoading ? (
              <Grid container spacing={2}>
                {[...Array(6)].map((_, i) => (
                  <Grid item xs={12} sm={6} md={4} key={i}>
                    <Skeleton variant="rectangular" height={150} sx={{ borderRadius: 2 }} />
                  </Grid>
                ))}
              </Grid>
            ) : agents ? (
              <>
                {/* Roster summary */}
                <Box sx={{ display: 'flex', gap: 3, mb: 3, flexWrap: 'wrap' }}>
                  {[
                    { label: 'Generalists', value: agents.totals.generalists, color: '#4e5ced',
                      hint: 'Phase-1/2 always-on agents (recon, analyst, exploit, code).' },
                    { label: 'Specialists', value: agents.totals.specialists, color: '#26a69a',
                      hint: 'T22 conditional agents — activated when Phase-1 finds matching surface.' },
                    { label: 'Agents total', value: agents.totals.agents_total, color: '#1a1f2e' },
                    { label: 'Tools total', value: agents.totals.tools_total, color: '#5a6478',
                      hint: 'Distinct tools available across all agents.' },
                  ].map(s => (
                    <Box key={s.label} sx={{ minWidth: 130 }}>
                      <Typography sx={{ fontSize: '0.7rem', color: '#8a93a6', textTransform: 'uppercase', letterSpacing: 0.5 }}>
                        {s.label}
                      </Typography>
                      <Typography sx={{ fontSize: '1.6rem', color: s.color, fontWeight: 700, lineHeight: 1.1 }}>
                        {s.value}
                      </Typography>
                      {s.hint && (
                        <Typography sx={{ fontSize: '0.68rem', color: '#8a93a6', mt: 0.25 }}>{s.hint}</Typography>
                      )}
                    </Box>
                  ))}
                </Box>

                <Typography variant="body2" sx={{ color: '#5a6478', mb: 2 }}>
                  Click any agent to see the exact tools it can call.
                </Typography>

                <Grid container spacing={2}>
                  {agents.agents.map(a => {
                    const isOpen = expandedAgent === a.name;
                    const accent = a.kind === 'generalist' ? '#4e5ced' : a.kind === 'specialist' ? '#26a69a' : '#5a6478';
                    return (
                      <Grid item xs={12} sm={6} md={4} key={a.name}>
                        <Card
                          onClick={() => setExpandedAgent(isOpen ? null : a.name)}
                          sx={{
                            p: 2,
                            cursor: 'pointer',
                            borderLeft: `3px solid ${accent}`,
                            transition: 'box-shadow 120ms ease',
                            boxShadow: isOpen ? '0 4px 14px rgba(26,31,46,0.10)' : undefined,
                          }}
                        >
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5, flexWrap: 'wrap' }}>
                            <Typography sx={{ fontWeight: 700, fontSize: '0.95rem', color: '#1a1f2e' }}>
                              {a.name}
                            </Typography>
                            <Chip label={a.kind} size="small"
                              sx={{ height: 18, fontSize: '0.6rem', fontWeight: 700, backgroundColor: `${accent}1a`, color: accent }} />
                            <Chip label={a.phase} size="small"
                              sx={{ height: 18, fontSize: '0.6rem', backgroundColor: 'rgba(90,100,120,0.10)', color: '#5a6478' }} />
                            <Box sx={{ flexGrow: 1 }} />
                            <Chip label={`${a.tool_count} tools`} size="small"
                              sx={{ height: 18, fontSize: '0.62rem', fontFamily: 'monospace',
                                    backgroundColor: 'rgba(78,92,237,0.10)', color: '#4e5ced' }} />
                          </Box>
                          <Typography sx={{ fontSize: '0.78rem', color: '#5a6478', mb: isOpen ? 1.5 : 0 }}>
                            {a.description}
                          </Typography>
                          {isOpen && (
                            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 1 }}>
                              {a.tools.map(t => (
                                <Chip
                                  key={t}
                                  label={t}
                                  size="small"
                                  sx={{
                                    height: 20,
                                    fontSize: '0.65rem',
                                    fontFamily: 'monospace',
                                    backgroundColor: '#f4f6fb',
                                    color: '#1a1f2e',
                                    border: '1px solid rgba(30,41,60,0.08)',
                                  }}
                                />
                              ))}
                            </Box>
                          )}
                        </Card>
                      </Grid>
                    );
                  })}
                </Grid>

                <Divider sx={{ my: 3 }} />

                <Typography variant="body2" sx={{ color: '#5a6478', mb: 1.5 }}>
                  Solo (single-agent) mode runs one orchestrator with the full tool union:
                </Typography>
                <Card sx={{ p: 2, borderLeft: '3px solid #ff9800' }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5, flexWrap: 'wrap' }}>
                    <Typography sx={{ fontWeight: 700, fontSize: '0.95rem', color: '#1a1f2e' }}>
                      {agents.solo.name}
                    </Typography>
                    <Chip label="solo" size="small"
                      sx={{ height: 18, fontSize: '0.6rem', fontWeight: 700, backgroundColor: 'rgba(255,152,0,0.15)', color: '#ff9800' }} />
                    <Box sx={{ flexGrow: 1 }} />
                    <Chip label={`${agents.solo.tool_count} tools`} size="small"
                      sx={{ height: 18, fontSize: '0.62rem', fontFamily: 'monospace',
                            backgroundColor: 'rgba(78,92,237,0.10)', color: '#4e5ced' }} />
                  </Box>
                  <Typography sx={{ fontSize: '0.78rem', color: '#5a6478' }}>
                    {agents.solo.description}
                  </Typography>
                </Card>
              </>
            ) : (
              <Alert severity="warning">Failed to load agent roster.</Alert>
            )}
          </TabPanel>

          {/* Tab 4 – Database */}
          <TabPanel value={tab} index={4}>
            <Grid container spacing={2} maxWidth={600}>
              {dbEntries.map(db => (
                <Grid item xs={12} sm={6} key={db.key}>
                  <Card sx={{ p: 2 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 1 }}>
                      {healthLoading ? (
                        <CircularProgress size={20} />
                      ) : health?.[db.key] === 'ok' ? (
                        <CheckCircleIcon sx={{ color: '#4caf50', fontSize: 20 }} />
                      ) : (
                        <ErrorIcon sx={{ color: '#f44336', fontSize: 20 }} />
                      )}
                      <Typography sx={{ fontWeight: 600, color: '#1a1f2e', fontSize: '0.875rem' }}>
                        {db.label}
                      </Typography>
                      <Box sx={{ ml: 'auto' }}>
                        <Chip
                          label={healthLoading ? '...' : health?.[db.key] ?? 'unknown'}
                          size="small"
                          sx={{
                            backgroundColor:
                              !healthLoading && health?.[db.key] === 'ok'
                                ? 'rgba(76,175,80,0.15)'
                                : 'rgba(244,67,54,0.15)',
                            color:
                              !healthLoading && health?.[db.key] === 'ok' ? '#4caf50' : '#f44336',
                            fontFamily: 'monospace',
                          }}
                        />
                      </Box>
                    </Box>
                    <Typography sx={{ fontSize: '0.75rem', color: '#8a93a6', fontFamily: 'monospace' }}>
                      Connection via environment variables
                    </Typography>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </TabPanel>

          {/* Tab 5 – Storage */}
          <TabPanel value={tab} index={5}>
            <Grid container spacing={3} maxWidth={480}>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Storage Path"
                  value={settings.storage_path || '/data/security'}
                  onChange={e => update('storage_path', e.target.value)}
                  helperText="Base directory for session artifacts"
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  fullWidth
                  label="Scan Timeout (seconds)"
                  type="number"
                  value={settings.scan_timeout || '3600'}
                  onChange={e => update('scan_timeout', e.target.value)}
                  helperText="Max duration per tool execution"
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  fullWidth
                  label="Max Iterations"
                  type="number"
                  value={settings.max_iterations || '20'}
                  onChange={e => update('max_iterations', e.target.value)}
                  helperText="Max agent reasoning loops per session"
                />
              </Grid>
              <Grid item xs={12}>
                <Button
                  variant="contained"
                  color="primary"
                  onClick={() => handleSave(['storage_path', 'scan_timeout', 'max_iterations'])}
                  disabled={saving}
                  startIcon={saving ? <CircularProgress size={16} color="inherit" /> : undefined}
                >
                  Save Storage Settings
                </Button>
              </Grid>
            </Grid>
          </TabPanel>

          {/* Tab 6 – Containers */}
          <TabPanel value={tab} index={6}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2, gap: 2, flexWrap: 'wrap' }}>
              <Typography variant="body2" sx={{ color: '#5a6478' }}>
                GENESIS containers — MCP service surface and supporting infrastructure.
              </Typography>
              <Box sx={{ display: 'flex', gap: 1 }}>
                <Button
                  size="small"
                  variant={showOnlyMcp ? 'contained' : 'outlined'}
                  onClick={() => setShowOnlyMcp(v => !v)}
                  sx={{ textTransform: 'none', fontSize: '0.7rem', py: 0.25 }}
                >
                  {showOnlyMcp ? 'MCP only ✓' : 'MCP only'}
                </Button>
                <Button
                  size="small"
                  variant="outlined"
                  startIcon={containersLoading ? <CircularProgress size={12} /> : <RefreshIcon sx={{ fontSize: 14 }} />}
                  onClick={refreshContainers}
                  disabled={containersLoading}
                  sx={{ textTransform: 'none', fontSize: '0.7rem', py: 0.25 }}
                >
                  Refresh
                </Button>
              </Box>
            </Box>

            {containersError && (
              <Alert severity="error" sx={{ mb: 2 }}>
                {containersError.includes('docker') || containersError.includes('503')
                  ? 'Backend cannot reach the docker engine. Confirm /var/run/docker.sock is mounted into the backend container.'
                  : containersError}
              </Alert>
            )}

            {!containers && containersLoading && (
              <Grid container spacing={2}>
                {[...Array(6)].map((_, i) => (
                  <Grid item xs={12} sm={6} md={4} key={i}>
                    <Skeleton variant="rectangular" height={130} sx={{ borderRadius: 2 }} />
                  </Grid>
                ))}
              </Grid>
            )}

            {containers && (
              <>
                {/* Roster summary */}
                <Box sx={{ display: 'flex', gap: 3, mb: 3, flexWrap: 'wrap' }}>
                  {[
                    { label: 'Total', value: containers.totals.containers, color: '#1a1f2e' },
                    { label: 'Running', value: containers.totals.running, color: '#4caf50' },
                    { label: 'Stopped', value: containers.totals.stopped, color: '#f44336' },
                    { label: 'Healthy', value: containers.totals.healthy, color: '#4caf50' },
                    { label: 'Unhealthy', value: containers.totals.unhealthy, color: '#ff9800' },
                    { label: 'MCP surface', value: `${containers.totals.mcp_running}/${containers.totals.mcp_total}`, color: '#4e5ced',
                      hint: 'Running / total. Includes mcp_server + sandbox pool + sibling tool containers.' },
                  ].map(s => (
                    <Box key={s.label} sx={{ minWidth: 110 }}>
                      <Typography sx={{ fontSize: '0.7rem', color: '#8a93a6', textTransform: 'uppercase', letterSpacing: 0.5 }}>
                        {s.label}
                      </Typography>
                      <Typography sx={{ fontSize: '1.6rem', color: s.color, fontWeight: 700, lineHeight: 1.1 }}>
                        {s.value}
                      </Typography>
                      {(s as { hint?: string }).hint && (
                        <Typography sx={{ fontSize: '0.65rem', color: '#8a93a6', mt: 0.25 }}>
                          {(s as { hint?: string }).hint}
                        </Typography>
                      )}
                    </Box>
                  ))}
                </Box>

                <Grid container spacing={2}>
                  {(showOnlyMcp ? containers.containers.filter(c => c.is_mcp_service) : containers.containers).map(c => (
                    <Grid item xs={12} sm={6} md={4} key={c.id || c.name}>
                      <ContainerCard container={c} />
                    </Grid>
                  ))}
                </Grid>

                {showOnlyMcp && containers.containers.filter(c => c.is_mcp_service).length === 0 && (
                  <Alert severity="info">No MCP-surface containers found.</Alert>
                )}
              </>
            )}
          </TabPanel>
        </CardContent>
      </Card>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar(s => ({ ...s, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert severity={snackbar.severity} onClose={() => setSnackbar(s => ({ ...s, open: false }))}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default Settings;

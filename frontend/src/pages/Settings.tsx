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

import { settingsApi, toolsApi, healthApi } from '../services/api';
import { useStore } from '../store';
import type { AppSettings, ToolInfo, HealthStatus } from '../types';
import StatusChip from '../components/StatusChip';

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

const Settings: React.FC = () => {
  const { setSettings: storeSetSettings } = useStore();
  const [tab, setTab] = useState(0);
  const [settings, setSettingsLocal] = useState<AppSettings | null>(null);
  const [loadingSettings, setLoadingSettings] = useState(true);

  const [tools, setTools] = useState<ToolInfo[]>([]);
  const [toolsLoading, setToolsLoading] = useState(false);
  const [toolsTesting, setToolsTesting] = useState(false);

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
      setHealthLoading(true);
      healthApi.check().then(setHealth).catch(() => {}).finally(() => setHealthLoading(false));
    }
  }, [tab]);

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
    } catch {
      // ignore
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
  ];

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" sx={{ mb: 3, color: '#f0f0f0' }}>
        Settings
      </Typography>

      <Card>
        <Box sx={{ borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
          <Tabs
            value={tab}
            onChange={(_, v) => setTab(v)}
            sx={{
              '& .MuiTab-root': { color: '#616161', fontSize: '0.85rem' },
              '& .Mui-selected': { color: '#86BC25' },
              '& .MuiTabs-indicator': { backgroundColor: '#86BC25' },
              px: 2,
            }}
          >
            <Tab label="LLM" />
            <Tab label="MCP Server" />
            <Tab label="Tools" />
            <Tab label="Database" />
            <Tab label="Storage" />
          </Tabs>
        </Box>

        <CardContent sx={{ p: 3 }}>
          {/* Tab 0 – LLM */}
          <TabPanel value={tab} index={0}>
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
                    <MenuItem value="azure">Azure AI Foundry</MenuItem>
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
                  options={['claude-opus-4-7', 'claude-sonnet-4-6', 'claude-haiku-4-5']}
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

              {settings.llm_provider === 'azure' && (
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    label="Endpoint URL"
                    placeholder="https://your-resource.services.ai.azure.com/anthropic"
                    value={settings.azure_endpoint || ''}
                    onChange={e => update('azure_endpoint', e.target.value)}
                    helperText="Paste the base endpoint — /v1/messages is appended automatically"
                  />
                </Grid>
              )}

              <Grid item xs={12}>
                <Typography gutterBottom sx={{ color: '#9e9e9e', fontSize: '0.875rem' }}>
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

              <Grid item xs={12}>
                <Box sx={{ display: 'flex', gap: 2 }}>
                  <Button
                    variant="contained"
                    color="primary"
                    onClick={() => handleSave(['llm_provider', 'llm_api_key', 'llm_model', 'llm_temperature', 'azure_endpoint'])}
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
                <Card variant="outlined" sx={{ p: 2, border: '1px solid rgba(255,255,255,0.08)' }}>
                  <Typography variant="body2" sx={{ color: '#9e9e9e', mb: 1 }}>
                    Server Status
                  </Typography>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <RadioButtonCheckedIcon
                      sx={{ color: health?.mcp === 'ok' ? '#4caf50' : '#f44336', fontSize: 16 }}
                    />
                    <Typography sx={{ fontFamily: 'monospace', fontSize: '0.85rem', color: '#f0f0f0' }}>
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
              <Typography variant="body2" sx={{ color: '#9e9e9e' }}>
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
                        <Typography sx={{ fontWeight: 700, fontSize: '0.875rem', color: '#f0f0f0', mb: 0.5 }}>
                          {tool.name}
                        </Typography>
                        {tool.version && (
                          <Chip
                            label={`v${tool.version}`}
                            size="small"
                            sx={{ mb: 1, backgroundColor: 'rgba(134,188,37,0.10)', color: '#86BC25', height: 18, fontSize: '0.65rem' }}
                          />
                        )}
                        <Typography sx={{ fontSize: '0.75rem', color: '#616161', mb: 1.5 }}>
                          {tool.description}
                        </Typography>
                        <StatusChip status={tool.status} />
                      </Card>
                    </Grid>
                  ))}
            </Grid>
          </TabPanel>

          {/* Tab 3 – Database */}
          <TabPanel value={tab} index={3}>
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
                      <Typography sx={{ fontWeight: 600, color: '#f0f0f0', fontSize: '0.875rem' }}>
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
                    <Typography sx={{ fontSize: '0.75rem', color: '#616161', fontFamily: 'monospace' }}>
                      Connection via environment variables
                    </Typography>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </TabPanel>

          {/* Tab 4 – Storage */}
          <TabPanel value={tab} index={4}>
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

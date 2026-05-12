import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  TextField,
  Stepper,
  Step,
  StepLabel,
  Radio,
  RadioGroup,
  FormControlLabel,
  FormControl,
  FormLabel,
  Slider,
  Grid,
  CircularProgress,
  Alert,
  Divider,
  Skeleton,
  Autocomplete,
} from '@mui/material';
import ShieldIcon from '@mui/icons-material/Shield';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorIcon from '@mui/icons-material/Error';
import { useNavigate } from 'react-router-dom';

import { healthApi, settingsApi, toolsApi } from '../services/api';
import { useStore } from '../store';
import type { HealthStatus, ToolInfo, AppSettings } from '../types';

const STEPS = ['Welcome', 'LLM Config', 'MCP Server', 'Tools', 'Database', 'Complete'];

interface FormData {
  llm_provider: string;
  llm_api_key: string;
  llm_model: string;
  llm_max_tokens: string;
  llm_temperature: string;
  azure_endpoint: string;
  azure_oai_api_version: string;
  mcp_host: string;
  mcp_port: string;
}

const initialForm: FormData = {
  llm_provider: 'anthropic',
  llm_api_key: '',
  llm_model: 'claude-sonnet-4-6',
  llm_max_tokens: '4096',
  llm_temperature: '0.7',
  azure_endpoint: '',
  azure_oai_api_version: '2024-12-01-preview',
  mcp_host: 'mcp_server',
  mcp_port: '3001',
};

// ────────────────────────────────────────────────────────────────
// Step 1 – Welcome
// ────────────────────────────────────────────────────────────────
const StepWelcome: React.FC<{ health: HealthStatus | null; healthLoading: boolean }> = ({
  health,
  healthLoading,
}) => {
  const dbs: Array<{ key: keyof HealthStatus; label: string }> = [
    { key: 'postgres', label: 'PostgreSQL' },
    { key: 'mongodb', label: 'MongoDB' },
    { key: 'redis', label: 'Redis' },
    { key: 'chroma', label: 'ChromaDB' },
    { key: 'neo4j', label: 'Neo4j' },
    { key: 'minio', label: 'MinIO' },
  ];

  return (
    <Box sx={{ textAlign: 'center', py: 2 }}>
      <ShieldIcon sx={{ fontSize: 72, color: '#4e5ced', mb: 2 }} />
      <Typography variant="h4" sx={{ mb: 1, color: '#1a1f2e' }}>
        Autonomous Security Research Platform
      </Typography>
      <Typography variant="body1" sx={{ color: '#5a6478', mb: 4, maxWidth: 520, mx: 'auto' }}>
        This platform automates security reconnaissance, vulnerability discovery, and exploit verification
        using AI agents. Configure your environment to get started.
      </Typography>

      <Typography variant="h6" sx={{ mb: 2, color: '#5a6478', textAlign: 'left' }}>
        Database Status
      </Typography>
      <Grid container spacing={2}>
        {dbs.map(db => (
          <Grid item xs={6} sm={3} key={db.key}>
            <Box
              sx={{
                p: 2,
                borderRadius: 2,
                border: '1px solid #dfe3ec',
                textAlign: 'center',
              }}
            >
              {healthLoading ? (
                <Skeleton variant="circular" width={24} height={24} sx={{ mx: 'auto', mb: 1 }} />
              ) : health?.[db.key] === 'ok' ? (
                <CheckCircleIcon sx={{ color: '#4caf50', fontSize: 24 }} />
              ) : (
                <ErrorIcon sx={{ color: '#f44336', fontSize: 24 }} />
              )}
              <Typography variant="caption" sx={{ color: '#5a6478', display: 'block', mt: 0.5 }}>
                {db.label}
              </Typography>
              <Typography
                variant="caption"
                sx={{
                  color: healthLoading ? '#8a93a6' : health?.[db.key] === 'ok' ? '#4caf50' : '#f44336',
                  fontFamily: 'monospace',
                  fontWeight: 600,
                }}
              >
                {healthLoading ? 'checking...' : health?.[db.key] ?? 'unknown'}
              </Typography>
            </Box>
          </Grid>
        ))}
      </Grid>
    </Box>
  );
};

// ────────────────────────────────────────────────────────────────
// Step 2 – LLM Config
// ────────────────────────────────────────────────────────────────
const StepLLM: React.FC<{
  form: FormData;
  onChange: (k: keyof FormData, v: string) => void;
  testResult: { success: boolean; message: string } | null;
  testing: boolean;
  onTest: () => void;
}> = ({ form, onChange, testResult, testing, onTest }) => (
  <Box>
    <FormControl component="fieldset" sx={{ mb: 3, width: '100%' }}>
      <FormLabel sx={{ color: '#5a6478', mb: 1 }}>LLM Provider</FormLabel>
      <RadioGroup
        row
        value={form.llm_provider}
        onChange={e => onChange('llm_provider', e.target.value)}
      >
        <FormControlLabel value="anthropic" control={<Radio color="primary" />} label="Anthropic" />
        <FormControlLabel value="azure" control={<Radio color="primary" />} label="Azure AI Foundry (Anthropic)" />
        <FormControlLabel value="azure_openai" control={<Radio color="primary" />} label="Azure OpenAI (GPT)" />
      </RadioGroup>
    </FormControl>

    <TextField
      fullWidth
      label="API Key"
      type="password"
      value={form.llm_api_key}
      onChange={e => onChange('llm_api_key', e.target.value)}
      sx={{ mb: 2 }}
    />

    <Autocomplete
      freeSolo
      options={
        form.llm_provider === 'azure_openai'
          ? ['gpt-5.5', 'gpt-4o', 'gpt-4o-mini', 'o3', 'o4-mini']
          : ['claude-opus-4-7', 'claude-sonnet-4-6', 'claude-haiku-4-5']
      }
      value={form.llm_model}
      onChange={(_, v) => onChange('llm_model', v || '')}
      onInputChange={(_, v) => onChange('llm_model', v)}
      sx={{ mb: 2 }}
      renderInput={(params) => (
        <TextField
          {...params}
          label="Model"
          helperText="Select a preset or type a custom model name (e.g. for Azure deployments)"
        />
      )}
    />

    {(form.llm_provider === 'azure' || form.llm_provider === 'azure_openai') && (
      <TextField
        fullWidth
        label="Endpoint URL"
        placeholder={
          form.llm_provider === 'azure_openai'
            ? 'https://your-resource.cognitiveservices.azure.com/'
            : 'https://your-resource.services.ai.azure.com/anthropic'
        }
        value={form.azure_endpoint}
        onChange={e => onChange('azure_endpoint', e.target.value)}
        helperText={
          form.llm_provider === 'azure_openai'
            ? 'Azure AI Foundry endpoint for your OpenAI deployment'
            : 'Paste the base endpoint — /v1/messages is appended automatically'
        }
        sx={{ mb: 2 }}
      />
    )}

    {form.llm_provider === 'azure_openai' && (
      <TextField
        fullWidth
        label="API Version"
        placeholder="2024-12-01-preview"
        value={form.azure_oai_api_version || '2024-12-01-preview'}
        onChange={e => onChange('azure_oai_api_version', e.target.value)}
        helperText="Azure OpenAI API version"
        sx={{ mb: 2 }}
      />
    )}

    <Box sx={{ mb: 3 }}>
      <Typography gutterBottom sx={{ color: '#5a6478', fontSize: '0.875rem' }}>
        Temperature: {form.llm_temperature}
      </Typography>
      <Slider
        min={0}
        max={2}
        step={0.1}
        value={parseFloat(form.llm_temperature)}
        onChange={(_, v) => onChange('llm_temperature', String(v))}
        color="primary"
        valueLabelDisplay="auto"
      />
    </Box>

    <Button
      variant="outlined"
      color="primary"
      onClick={onTest}
      disabled={testing || !form.llm_api_key}
      startIcon={testing ? <CircularProgress size={16} color="inherit" /> : undefined}
      sx={{ mb: 2 }}
    >
      {testing ? 'Testing...' : 'Test Connection'}
    </Button>

    {testResult && (
      <Alert severity={testResult.success ? 'success' : 'error'} sx={{ mt: 1 }}>
        {testResult.message}
      </Alert>
    )}
  </Box>
);

// ────────────────────────────────────────────────────────────────
// Step 3 – MCP Server
// ────────────────────────────────────────────────────────────────
const StepMCP: React.FC<{
  form: FormData;
  onChange: (k: keyof FormData, v: string) => void;
  testResult: { success: boolean; message: string } | null;
  testing: boolean;
  onTest: () => void;
}> = ({ form, onChange, testResult, testing, onTest }) => (
  <Box>
    <Typography variant="body2" sx={{ color: '#5a6478', mb: 3 }}>
      Configure the MCP (Model Context Protocol) server that provides security tools to the AI agent.
    </Typography>

    <TextField
      fullWidth
      label="Host"
      value={form.mcp_host}
      onChange={e => onChange('mcp_host', e.target.value)}
      sx={{ mb: 2 }}
    />
    <TextField
      fullWidth
      label="Port"
      type="number"
      value={form.mcp_port}
      onChange={e => onChange('mcp_port', e.target.value)}
      sx={{ mb: 3 }}
    />

    <Button
      variant="outlined"
      color="primary"
      onClick={onTest}
      disabled={testing}
      startIcon={testing ? <CircularProgress size={16} color="inherit" /> : undefined}
      sx={{ mb: 2 }}
    >
      {testing ? 'Testing...' : 'Test Connection'}
    </Button>

    {testResult && (
      <Alert severity={testResult.success ? 'success' : 'error'} sx={{ mt: 1 }}>
        {testResult.message}
      </Alert>
    )}
  </Box>
);

// ────────────────────────────────────────────────────────────────
// Step 4 – Tools
// ────────────────────────────────────────────────────────────────
const StepTools: React.FC<{
  tools: ToolInfo[];
  loading: boolean;
  onTestAll: () => void;
  testing: boolean;
}> = ({ tools, loading, onTestAll, testing }) => (
  <Box>
    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
      <Typography variant="body2" sx={{ color: '#5a6478' }}>
        Security tools available on the MCP server.
      </Typography>
      <Button
        variant="outlined"
        color="primary"
        size="small"
        onClick={onTestAll}
        disabled={testing}
        startIcon={testing ? <CircularProgress size={14} color="inherit" /> : undefined}
      >
        {testing ? 'Testing...' : 'Test All Tools'}
      </Button>
    </Box>

    <Grid container spacing={1.5}>
      {loading
        ? [...Array(9)].map((_, i) => (
            <Grid item xs={6} sm={4} key={i}>
              <Skeleton variant="rectangular" height={64} sx={{ borderRadius: 1 }} />
            </Grid>
          ))
        : tools.map(tool => (
            <Grid item xs={6} sm={4} key={tool.name}>
              <Box
                sx={{
                  p: 1.5,
                  borderRadius: 1.5,
                  border: '1px solid #dfe3ec',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 1.5,
                }}
              >
                <Box
                  sx={{
                    width: 8,
                    height: 8,
                    borderRadius: '50%',
                    flexShrink: 0,
                    backgroundColor:
                      tool.status === 'available'
                        ? '#4caf50'
                        : tool.status === 'missing'
                        ? '#f44336'
                        : '#ffab00',
                  }}
                />
                <Box>
                  <Typography sx={{ fontSize: '0.8rem', color: '#1a1f2e', fontWeight: 600 }}>
                    {tool.name}
                  </Typography>
                  <Typography sx={{ fontSize: '0.7rem', color: '#8a93a6' }}>
                    {tool.status}
                  </Typography>
                </Box>
              </Box>
            </Grid>
          ))}
    </Grid>
  </Box>
);

// ────────────────────────────────────────────────────────────────
// Step 5 – Database
// ────────────────────────────────────────────────────────────────
const StepDatabase: React.FC<{ health: HealthStatus | null; loading: boolean }> = ({ health, loading }) => {
  const dbs: Array<{ key: keyof HealthStatus; label: string; desc: string }> = [
    { key: 'postgres', label: 'PostgreSQL', desc: 'Session and vulnerability storage' },
    { key: 'mongodb', label: 'MongoDB', desc: 'Tool outputs and agent thoughts' },
    { key: 'redis', label: 'Redis', desc: 'Session state and pub/sub' },
    { key: 'chroma', label: 'ChromaDB', desc: 'Vector embeddings for RAG' },
    { key: 'neo4j', label: 'Neo4j', desc: 'Attack knowledge graph' },
    { key: 'minio', label: 'MinIO', desc: 'Artifact and source archive store' },
  ];

  return (
    <Box>
      <Typography variant="body2" sx={{ color: '#5a6478', mb: 3 }}>
        Database connection status. These are read-only — configure via environment variables.
      </Typography>
      <Grid container spacing={2}>
        {dbs.map(db => (
          <Grid item xs={12} sm={6} key={db.key}>
            <Box
              sx={{
                p: 2,
                borderRadius: 2,
                border: '1px solid #dfe3ec',
                display: 'flex',
                alignItems: 'center',
                gap: 2,
              }}
            >
              {loading ? (
                <Skeleton variant="circular" width={20} height={20} />
              ) : health?.[db.key] === 'ok' ? (
                <CheckCircleIcon sx={{ color: '#4caf50' }} />
              ) : (
                <ErrorIcon sx={{ color: '#f44336' }} />
              )}
              <Box>
                <Typography sx={{ fontWeight: 600, fontSize: '0.875rem', color: '#1a1f2e' }}>
                  {db.label}
                </Typography>
                <Typography sx={{ fontSize: '0.75rem', color: '#8a93a6' }}>
                  {db.desc}
                </Typography>
              </Box>
              <Box sx={{ ml: 'auto' }}>
                <Typography
                  sx={{
                    fontFamily: 'monospace',
                    fontSize: '0.75rem',
                    color: loading ? '#8a93a6' : health?.[db.key] === 'ok' ? '#4caf50' : '#f44336',
                  }}
                >
                  {loading ? 'checking...' : health?.[db.key] ?? 'unknown'}
                </Typography>
              </Box>
            </Box>
          </Grid>
        ))}
      </Grid>
    </Box>
  );
};

// ────────────────────────────────────────────────────────────────
// Step 6 – Complete
// ────────────────────────────────────────────────────────────────
const StepComplete: React.FC<{ form: FormData }> = ({ form }) => (
  <Box sx={{ textAlign: 'center' }}>
    <CheckCircleIcon sx={{ fontSize: 64, color: '#4caf50', mb: 2 }} />
    <Typography variant="h5" sx={{ mb: 2, color: '#1a1f2e' }}>
      Configuration Complete
    </Typography>
    <Typography variant="body2" sx={{ color: '#5a6478', mb: 4 }}>
      Your platform is configured and ready to use.
    </Typography>
    <Box sx={{ textAlign: 'left', maxWidth: 400, mx: 'auto' }}>
      {[
        { label: 'Provider', value: form.llm_provider },
        { label: 'Model', value: form.llm_model },
        { label: 'MCP Server', value: `${form.mcp_host}:${form.mcp_port}` },
      ].map(item => (
        <Box key={item.label} sx={{ display: 'flex', justifyContent: 'space-between', py: 1, borderBottom: '1px solid #dfe3ec' }}>
          <Typography sx={{ color: '#5a6478', fontSize: '0.875rem' }}>{item.label}</Typography>
          <Typography sx={{ color: '#1a1f2e', fontFamily: 'monospace', fontSize: '0.875rem' }}>{item.value}</Typography>
        </Box>
      ))}
    </Box>
  </Box>
);

// ────────────────────────────────────────────────────────────────
// Main SetupWizard
// ────────────────────────────────────────────────────────────────
const SetupWizard: React.FC = () => {
  const navigate = useNavigate();
  const { setSettings } = useStore();

  const [activeStep, setActiveStep] = useState(0);
  const [form, setForm] = useState<FormData>(initialForm);

  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [healthLoading, setHealthLoading] = useState(true);
  const [tools, setTools] = useState<ToolInfo[]>([]);
  const [toolsLoading, setToolsLoading] = useState(false);

  const [llmTest, setLlmTest] = useState<{ success: boolean; message: string } | null>(null);
  const [llmTesting, setLlmTesting] = useState(false);
  const [mcpTest, setMcpTest] = useState<{ success: boolean; message: string } | null>(null);
  const [mcpTesting, setMcpTesting] = useState(false);
  const [toolsTesting, setToolsTesting] = useState(false);

  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState('');

  useEffect(() => {
    const load = async () => {
      setHealthLoading(true);
      try {
        const h = await healthApi.check();
        setHealth(h);
      } catch {
        // ignore
      } finally {
        setHealthLoading(false);
      }
    };
    load();
  }, []);

  // Fetch tools when entering step 3 (index 3)
  useEffect(() => {
    if (activeStep === 3) {
      setToolsLoading(true);
      toolsApi.list()
        .then(setTools)
        .catch(() => {})
        .finally(() => setToolsLoading(false));
    }
  }, [activeStep]);

  // Refresh health when entering step 4 (index 4)
  useEffect(() => {
    if (activeStep === 4) {
      setHealthLoading(true);
      healthApi.check()
        .then(setHealth)
        .catch(() => {})
        .finally(() => setHealthLoading(false));
    }
  }, [activeStep]);

  const updateForm = (k: keyof FormData, v: string) => setForm(f => ({ ...f, [k]: v }));

  const handleTestLLM = async () => {
    setLlmTesting(true);
    setLlmTest(null);
    try {
      const result = await settingsApi.testLLM(form as unknown as Partial<AppSettings>);
      setLlmTest(result);
    } catch (err) {
      setLlmTest({ success: false, message: err instanceof Error ? err.message : 'Test failed' });
    } finally {
      setLlmTesting(false);
    }
  };

  const handleTestMCP = async () => {
    setMcpTesting(true);
    setMcpTest(null);
    try {
      const result = await settingsApi.testMCP({ host: form.mcp_host, port: form.mcp_port });
      setMcpTest(result);
    } catch (err) {
      setMcpTest({ success: false, message: err instanceof Error ? err.message : 'Test failed' });
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
    } catch {
      // ignore
    } finally {
      setToolsTesting(false);
    }
  };

  const canProceed = (): boolean => {
    if (activeStep === 1) return !!form.llm_api_key;
    if (activeStep === 2) return !!form.mcp_host && !!form.mcp_port;
    return true;
  };

  const handleNext = () => setActiveStep(s => s + 1);
  const handleBack = () => setActiveStep(s => s - 1);

  const handleComplete = async () => {
    setSaving(true);
    setSaveError('');
    try {
      const payload: Partial<AppSettings> = {
        ...form,
        setup_complete: 'true',
      };
      const saved = await settingsApi.update(payload);
      setSettings(saved);
      navigate('/');
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  const renderStep = () => {
    switch (activeStep) {
      case 0:
        return <StepWelcome health={health} healthLoading={healthLoading} />;
      case 1:
        return (
          <StepLLM
            form={form}
            onChange={updateForm}
            testResult={llmTest}
            testing={llmTesting}
            onTest={handleTestLLM}
          />
        );
      case 2:
        return (
          <StepMCP
            form={form}
            onChange={updateForm}
            testResult={mcpTest}
            testing={mcpTesting}
            onTest={handleTestMCP}
          />
        );
      case 3:
        return (
          <StepTools
            tools={tools}
            loading={toolsLoading}
            onTestAll={handleTestAllTools}
            testing={toolsTesting}
          />
        );
      case 4:
        return <StepDatabase health={health} loading={healthLoading} />;
      case 5:
        return <StepComplete form={form} />;
      default:
        return null;
    }
  };

  return (
    <Box
      sx={{
        minHeight: '100vh',
        backgroundColor: '#fafbfd',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        p: 3,
      }}
    >
      <Box sx={{ width: '100%', maxWidth: 720 }}>
        <Typography variant="h5" sx={{ mb: 4, textAlign: 'center', color: '#4e5ced', letterSpacing: '0.08em' }}>
          Platform Setup
        </Typography>

        <Stepper
          activeStep={activeStep}
          alternativeLabel
          sx={{
            mb: 4,
            '& .MuiStepLabel-label': { color: '#8a93a6', fontSize: '0.75rem' },
            '& .MuiStepLabel-label.Mui-active': { color: '#4e5ced' },
            '& .MuiStepLabel-label.Mui-completed': { color: '#4caf50' },
            '& .MuiStepConnector-line': { borderColor: '#dfe3ec' },
          }}
        >
          {STEPS.map(label => (
            <Step key={label}>
              <StepLabel>{label}</StepLabel>
            </Step>
          ))}
        </Stepper>

        <Card>
          <CardContent sx={{ p: 4 }}>
            {renderStep()}
          </CardContent>
        </Card>

        {saveError && (
          <Alert severity="error" sx={{ mt: 2 }}>
            {saveError}
          </Alert>
        )}

        <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 3 }}>
          <Button
            variant="outlined"
            color="inherit"
            onClick={handleBack}
            disabled={activeStep === 0}
            sx={{ color: '#5a6478', borderColor: '#dfe3ec' }}
          >
            Back
          </Button>

          {activeStep < STEPS.length - 1 ? (
            <Button
              variant="contained"
              color="primary"
              onClick={handleNext}
              disabled={!canProceed()}
              sx={{ fontWeight: 600 }}
            >
              Next
            </Button>
          ) : (
            <Button
              variant="contained"
              color="success"
              onClick={handleComplete}
              disabled={saving}
              startIcon={saving ? <CircularProgress size={16} color="inherit" /> : <CheckCircleIcon />}
              sx={{ fontWeight: 600 }}
            >
              {saving ? 'Saving...' : 'Complete Setup'}
            </Button>
          )}
        </Box>
      </Box>
    </Box>
  );
};

export default SetupWizard;

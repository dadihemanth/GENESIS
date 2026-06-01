/**
 * v7.x — Multi-model routing Settings UI.
 *
 * Renders inside the Settings page LLM tab. Two sections:
 *   1. Model Profiles — Add / Edit / Delete cards, Auto-seed defaults.
 *   2. Role Assignments — one dropdown per role.
 *
 * Persists `model_profiles` + `role_assignments` as JSON strings via the
 * existing settingsApi.update() flow. Legacy single-model settings are kept
 * intact for backward compat — when profiles is empty, the backend falls
 * back to llm_provider/llm_model/llm_api_key/etc.
 */
import React, { useCallback, useMemo, useState } from 'react';
import {
  Alert,
  Box, Button, Card, CardContent, Chip, CircularProgress, Dialog, DialogActions, DialogContent,
  DialogTitle, FormControl, Grid, IconButton, InputLabel, MenuItem,
  Paper, Select, TextField, Tooltip, Typography,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import EditIcon from '@mui/icons-material/Edit';
import DeleteIcon from '@mui/icons-material/Delete';
import AutoFixHighIcon from '@mui/icons-material/AutoFixHigh';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import { settingsApi } from '../services/api';
import type { ModelProfile, ModelProfileProvider, RoleName } from '../types';

const ROLES: { name: RoleName; description: string; warn?: string }[] = [
  {
    name: 'primary',
    description: 'Main orchestrator loop — fires ONLY in solo agent_mode.',
    warn: 'In multi-agent mode this is NOT the model that runs the scan. Use `subagent` instead.',
  },
  {
    name: 'subagent',
    description: 'Used by EVERY multi-agent sub-agent (recon, analyst, exploit, code, crypto, auth, …). This is what drives the scan in multi-agent mode.',
  },
  {
    name: 'critic',
    description: 'Adversarial critic — confirms/disputes finding evidence. High volume, short prompts. Cheap models excel.',
  },
  {
    name: 'compress',
    description: 'History compression every 15 iterations (solo mode). Pure summarisation.',
  },
  {
    name: 'brief',
    description: 'Pre-scan target intent brief (once per session).',
  },
  {
    name: 'reasoning',
    description: 'v7 deliberate loops + orchestrator-side backstop. Multi-step structured reasoning.',
  },
  {
    name: 'payload',
    description: 'Dedicated payload SubAgent in Phase 2. Generates aggressive non-obvious payload candidates (WAF-bypass encodings, parser-differential, polyglots, second-order). Best with Llama 4 / DeepSeek-R1 — less guardrail friction on offensive payloads. The exploit agent picks up its candidates and runs them.',
  },
  {
    name: 'red_blue',
    description: 'Red/blue adversarial dialectic — red proposes, blue challenges (two short LLM calls per round).',
  },
  {
    name: 'philosopher',
    description: 'Bug-class hypothesis generator. Also drives the new insider-threat and nation-state APT personas.',
  },
  {
    name: 'validator',
    description: 'Optional Validation Lab reviewer for candidate evidence before manual proof follow-up.',
  },
  {
    name: 'endpoint_validator',
    description: 'Checks live endpoint reachability, auth/session assumptions, and dynamic proof needs.',
  },
  {
    name: 'source_validator',
    description: 'Checks source, taint, invariant, and cross-file evidence for hybrid candidates.',
  },
  {
    name: 'counter_validator',
    description: 'Refutes weak candidates and records missing proof conditions.',
  },
  {
    name: 'proof_planner',
    description: 'Turns candidate leads into concrete safe proof-tool parameters for optional Complete Validation.',
  },
];

const PROVIDER_OPTIONS: { value: ModelProfileProvider; label: string }[] = [
  { value: 'anthropic', label: 'Anthropic' },
  { value: 'azure', label: 'Azure (Anthropic on Azure)' },
  { value: 'azure_openai', label: 'Azure OpenAI (GPT-5 / o-series)' },
  { value: 'foundry_serverless', label: 'Azure AI Foundry (Llama 4 / DeepSeek)' },
  { value: 'bedrock', label: 'AWS Bedrock' },
  { value: 'custom', label: 'Custom OpenAI-compatible' },
];

const MODEL_PRESETS: Record<ModelProfileProvider, string[]> = {
  anthropic: ['claude-opus-4-7', 'claude-sonnet-4-6', 'claude-haiku-4-5'],
  azure: ['claude-opus-4-7', 'claude-sonnet-4-6'],
  azure_openai: ['gpt-5.5', 'gpt-5', 'gpt-4o', 'gpt-4o-mini', 'o3', 'o4-mini'],
  foundry_serverless: [
    'Llama-4-Maverick-17B-128E-Instruct-FP8',
    'Llama-4-Scout-17B-16E-Instruct',
    'DeepSeek-R1',
    'Qwen2.5-Coder-32B-Instruct',
    'Mistral-Large-2411',
  ],
  bedrock: ['anthropic.claude-opus-4-7-v1:0', 'anthropic.claude-sonnet-4-6-v1:0'],
  custom: [],
};

const RATE_DEFAULTS: Record<string, { input: number; output: number }> = {
  'claude-opus-4-7': { input: 15, output: 75 },
  'claude-sonnet-4-6': { input: 3, output: 15 },
  'claude-haiku-4-5': { input: 0.8, output: 4 },
  'gpt-5.5': { input: 1.25, output: 10 },
  'gpt-5': { input: 1.25, output: 10 },
  'gpt-4o': { input: 2.5, output: 10 },
  'gpt-4o-mini': { input: 0.15, output: 0.6 },
  'o3': { input: 15, output: 60 },
  'o4-mini': { input: 3, output: 12 },
  'Llama-4-Maverick-17B-128E-Instruct-FP8': { input: 0.4, output: 0.6 },
  'Llama-4-Scout-17B-16E-Instruct': { input: 0.4, output: 0.6 },
  'DeepSeek-R1': { input: 0.55, output: 2.19 },
};

function newId(): string {
  return 'p-' + Math.random().toString(36).slice(2, 10);
}

// Defaults seeded by "Auto-seed defaults" button. Includes the user's Llama 4
// Foundry endpoint pre-filled so they only need to paste the API key.
const DEFAULT_LLAMA_FOUNDRY_ENDPOINT =
  'https://ai-security-service-tes-resource.services.ai.azure.com/openai/v1/';

function defaultProfiles(): ModelProfile[] {
  return [
    {
      id: newId(),
      name: 'Opus 4.7 (primary)',
      provider: 'anthropic',
      model: 'claude-opus-4-7',
      api_key: '',
      rates: { input: 15, output: 75 },
    },
    {
      id: newId(),
      name: 'Sonnet 4.6',
      provider: 'anthropic',
      model: 'claude-sonnet-4-6',
      api_key: '',
      rates: { input: 3, output: 15 },
    },
    {
      id: newId(),
      name: 'Haiku 4.5 (cheap critic)',
      provider: 'anthropic',
      model: 'claude-haiku-4-5',
      api_key: '',
      rates: { input: 0.8, output: 4 },
    },
    {
      id: newId(),
      name: 'GPT-5.5 (Azure OpenAI)',
      provider: 'azure_openai',
      model: 'gpt-5.5',
      api_key: '',
      endpoint: '',
      api_version: '2024-12-01-preview',
      rates: { input: 1.25, output: 10 },
    },
    {
      id: newId(),
      name: 'Llama 4 Maverick (Foundry)',
      provider: 'foundry_serverless',
      model: 'Llama-4-Maverick-17B-128E-Instruct-FP8',
      api_key: '',
      endpoint: DEFAULT_LLAMA_FOUNDRY_ENDPOINT,
      rates: { input: 0.4, output: 0.6 },
      supports_tools: true,
    },
  ];
}

interface Props {
  profiles: ModelProfile[];
  assignments: Partial<Record<RoleName, string>>;
  onChange: (profiles: ModelProfile[], assignments: Partial<Record<RoleName, string>>) => void;
}

type TestStatus = { status: 'idle' } | { status: 'running' } | { status: 'ok'; message: string } | { status: 'fail'; message: string };

function profileToTestBody(p: ModelProfile): Partial<Record<string, string>> {
  // Maps a profile onto the same key shape /settings/test-llm consumes (the
  // existing _load_all_settings shape).
  return {
    llm_provider: p.provider,
    llm_model: p.model,
    llm_api_key: p.api_key,
    azure_endpoint: p.endpoint || '',
    azure_oai_api_version: p.api_version || '2024-12-01-preview',
    foundry_endpoint: p.endpoint || '',
    foundry_api_version: p.api_version || '2024-05-01-preview',
    // Anthropic provider: optional base-URL override (proxies / regional gateways).
    anthropic_endpoint: p.provider === 'anthropic' ? (p.endpoint || '') : '',
    custom_endpoint: p.endpoint || '',
    custom_headers: p.custom_headers || '',
  };
}

const ModelsTabContent: React.FC<Props> = ({ profiles, assignments, onChange }) => {
  const [editing, setEditing] = useState<ModelProfile | null>(null);
  const [tests, setTests] = useState<Record<string, TestStatus>>({});

  const runTest = useCallback(async (p: ModelProfile) => {
    setTests(prev => ({ ...prev, [p.id]: { status: 'running' } }));
    try {
      const result = await settingsApi.testLLM(profileToTestBody(p) as any);
      setTests(prev => ({
        ...prev,
        [p.id]: result.success
          ? { status: 'ok', message: result.message }
          : { status: 'fail', message: result.message },
      }));
    } catch (exc: any) {
      setTests(prev => ({
        ...prev,
        [p.id]: { status: 'fail', message: String(exc?.message ?? exc) },
      }));
    }
  }, []);

  const setProfiles = useCallback((next: ModelProfile[]) => {
    onChange(next, assignments);
  }, [assignments, onChange]);

  const setAssignments = useCallback((next: Partial<Record<RoleName, string>>) => {
    onChange(profiles, next);
  }, [profiles, onChange]);

  const handleAdd = () => {
    setEditing({
      id: newId(), name: 'New profile', provider: 'anthropic',
      model: '', api_key: '', rates: { input: 0, output: 0 },
    });
  };

  const handleSeedDefaults = () => {
    if (profiles.length > 0) {
      const ok = window.confirm(
        'Replace existing profiles with the default seed (Opus / Sonnet / Haiku / GPT-5.5 / Llama 4)?',
      );
      if (!ok) return;
    }
    const seeded = defaultProfiles();
    const newAssignments: Partial<Record<RoleName, string>> = {
      primary: seeded[0].id,
      critic: seeded[2].id,
      compress: seeded[2].id,
      brief: seeded[1].id,
      reasoning: seeded[0].id,
      payload: seeded[4].id,
      red_blue: seeded[1].id,
      philosopher: seeded[0].id,
      subagent: seeded[0].id,
    };
    onChange(seeded, newAssignments);
  };

  const handleSaveProfile = (p: ModelProfile) => {
    const idx = profiles.findIndex(x => x.id === p.id);
    if (idx >= 0) {
      const next = [...profiles];
      next[idx] = p;
      setProfiles(next);
    } else {
      setProfiles([...profiles, p]);
    }
    setEditing(null);
  };

  const handleDelete = (id: string) => {
    if (!window.confirm('Delete this profile?')) return;
    setProfiles(profiles.filter(p => p.id !== id));
    // Remove any role assignments pointing at the deleted profile
    const cleaned = { ...assignments };
    (Object.keys(cleaned) as RoleName[]).forEach(role => {
      if (cleaned[role] === id) delete cleaned[role];
    });
    setAssignments(cleaned);
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
        <Typography sx={{ fontSize: '1rem', fontWeight: 600 }}>Model Profiles</Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button
            size="small"
            startIcon={<AutoFixHighIcon fontSize="small" />}
            onClick={handleSeedDefaults}
          >
            Auto-seed defaults
          </Button>
          <Button
            size="small"
            variant="contained"
            startIcon={<AddIcon fontSize="small" />}
            onClick={handleAdd}
          >
            Add profile
          </Button>
        </Box>
      </Box>

      {profiles.length === 0 ? (
        <Paper variant="outlined" sx={{ p: 3, textAlign: 'center', mb: 3 }}>
          <Typography sx={{ fontSize: '0.9rem', color: '#5a6478', mb: 1 }}>
            No profiles configured.
          </Typography>
          <Typography sx={{ fontSize: '0.8rem', color: '#8a93a6', mb: 2 }}>
            The orchestrator will fall back to the legacy single-model settings below.
            Click <strong>Auto-seed defaults</strong> to create profiles for Opus 4.7,
            Sonnet 4.6, Haiku 4.5, GPT-5.5, and Llama 4 Maverick (Foundry endpoint
            pre-filled).
          </Typography>
        </Paper>
      ) : (
        <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', md: '1fr 1fr' }, gap: 2, mb: 3 }}>
          {profiles.map(p => {
            const t = tests[p.id] ?? { status: 'idle' };
            return (
              <Card key={p.id} variant="outlined">
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
                    <Box sx={{ flex: 1, minWidth: 0 }}>
                      <Typography sx={{ fontWeight: 600, fontSize: '0.95rem' }}>{p.name}</Typography>
                      <Box sx={{ display: 'flex', gap: 0.5, mt: 0.5, flexWrap: 'wrap' }}>
                        <Chip size="small" label={p.provider} sx={{ fontSize: '0.7rem' }} />
                        <Chip size="small" variant="outlined" label={p.model || '(no model)'} sx={{ fontSize: '0.7rem' }} />
                      </Box>
                      <Typography sx={{ fontSize: '0.75rem', color: '#5a6478', mt: 0.5 }}>
                        ${p.rates?.input ?? 0} in / ${p.rates?.output ?? 0} out per 1M tokens
                      </Typography>
                      {p.api_key ? null : (
                        <Chip size="small" color="warning" label="No API key" sx={{ mt: 0.5, fontSize: '0.65rem' }} />
                      )}
                    </Box>
                    <Box sx={{ display: 'flex', gap: 0.5 }}>
                      <Tooltip title="Test connection">
                        <span>
                          <IconButton
                            size="small"
                            onClick={() => runTest(p)}
                            disabled={t.status === 'running' || !p.api_key || !p.model}
                          >
                            {t.status === 'running'
                              ? <CircularProgress size={14} />
                              : <PlayArrowIcon fontSize="small" />}
                          </IconButton>
                        </span>
                      </Tooltip>
                      <Tooltip title="Edit">
                        <IconButton size="small" onClick={() => setEditing(p)}>
                          <EditIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Delete">
                        <IconButton size="small" onClick={() => handleDelete(p.id)}>
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </Box>
                  </Box>
                  {t.status === 'ok' && (
                    <Alert severity="success" icon={<CheckCircleIcon fontSize="small" />}
                      sx={{ mt: 1, py: 0, fontSize: '0.75rem' }}>
                      {t.message}
                    </Alert>
                  )}
                  {t.status === 'fail' && (
                    <Alert severity="error" icon={<ErrorOutlineIcon fontSize="small" />}
                      sx={{ mt: 1, py: 0, fontSize: '0.75rem' }}>
                      {t.message}
                    </Alert>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </Box>
      )}

      <Typography sx={{ fontSize: '1rem', fontWeight: 600, mb: 1 }}>Role Assignments</Typography>
      <Typography sx={{ fontSize: '0.8rem', color: '#5a6478', mb: 2 }}>
        Each role uses the assigned profile. Unset roles fall back to the <strong>primary</strong> assignment.
      </Typography>
      {profiles.length === 0 ? (
        <Typography sx={{ fontSize: '0.8rem', color: '#8a93a6', fontStyle: 'italic', mb: 2 }}>
          Add at least one profile to enable role assignments.
        </Typography>
      ) : (
        <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr' }, gap: 1.5, mb: 3 }}>
          {ROLES.map(role => (
            <Box key={role.name} sx={{ p: 1.25, border: '1px solid #e5e9f0', borderRadius: 1 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                <Box sx={{ minWidth: 110 }}>
                  <Typography sx={{ fontSize: '0.85rem', fontWeight: 600, fontFamily: 'monospace', color: '#1a1f2c' }}>
                    {role.name}
                  </Typography>
                </Box>
                <FormControl size="small" sx={{ flex: 1 }}>
                  <Select
                    value={assignments[role.name] || ''}
                    onChange={e => setAssignments({ ...assignments, [role.name]: e.target.value as string })}
                    displayEmpty
                  >
                    <MenuItem value="">
                      <em>(use primary fallback)</em>
                    </MenuItem>
                    {profiles.map(p => (
                      <MenuItem key={p.id} value={p.id}>{p.name}</MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Box>
              <Typography sx={{ fontSize: '0.72rem', color: '#5a6478', mt: 0.5, ml: 0.5 }}>
                {role.description}
              </Typography>
              {role.warn && (
                <Typography sx={{ fontSize: '0.7rem', color: '#b8740c', mt: 0.25, ml: 0.5, fontWeight: 500 }}>
                  ⚠ {role.warn}
                </Typography>
              )}
            </Box>
          ))}
        </Box>
      )}

      {editing && (
        <ProfileEditor
          profile={editing}
          onCancel={() => setEditing(null)}
          onSave={handleSaveProfile}
        />
      )}
    </Box>
  );
};


interface EditorProps {
  profile: ModelProfile;
  onSave: (p: ModelProfile) => void;
  onCancel: () => void;
}

const ProfileEditor: React.FC<EditorProps> = ({ profile, onSave, onCancel }) => {
  const [draft, setDraft] = useState<ModelProfile>({ ...profile, rates: { ...profile.rates } });
  const set = (k: keyof ModelProfile, v: any) => setDraft(d => ({ ...d, [k]: v }));
  const setRate = (k: 'input' | 'output', v: number) =>
    setDraft(d => ({ ...d, rates: { ...d.rates, [k]: v } }));

  const presets = MODEL_PRESETS[draft.provider] || [];

  // Auto-fill rates when model changes to a known preset
  const handleModelChange = (m: string) => {
    set('model', m);
    const def = RATE_DEFAULTS[m];
    if (def && (!draft.rates?.input || !draft.rates?.output)) {
      setDraft(d => ({ ...d, model: m, rates: { ...def } }));
    }
  };

  const showEndpoint = ['anthropic', 'azure', 'azure_openai', 'foundry_serverless', 'custom'].includes(draft.provider);
  const showApiVersion = ['azure_openai', 'foundry_serverless'].includes(draft.provider);
  const endpointIsOptional = draft.provider === 'anthropic';

  return (
    <Dialog open onClose={onCancel} maxWidth="sm" fullWidth>
      <DialogTitle>Edit Model Profile</DialogTitle>
      <DialogContent>
        <Grid container spacing={2} sx={{ mt: 0.5 }}>
          <Grid item xs={12}>
            <TextField fullWidth label="Profile name" value={draft.name}
              onChange={e => set('name', e.target.value)} size="small" />
          </Grid>
          <Grid item xs={12}>
            <FormControl fullWidth size="small">
              <InputLabel>Provider</InputLabel>
              <Select label="Provider" value={draft.provider}
                onChange={e => set('provider', e.target.value)}>
                {PROVIDER_OPTIONS.map(o => (
                  <MenuItem key={o.value} value={o.value}>{o.label}</MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12}>
            <TextField fullWidth label="Model / deployment" value={draft.model}
              onChange={e => handleModelChange(e.target.value)} size="small"
              helperText={presets.length ? `Presets: ${presets.slice(0, 3).join(', ')}…` : ' '} />
          </Grid>
          <Grid item xs={12}>
            <TextField fullWidth label="API key" value={draft.api_key} type="password"
              onChange={e => set('api_key', e.target.value)} size="small" />
          </Grid>
          {showEndpoint && (
            <Grid item xs={12}>
              <TextField fullWidth
                label={endpointIsOptional ? 'Endpoint URL (optional)' : 'Endpoint URL'}
                value={draft.endpoint || ''}
                onChange={e => set('endpoint', e.target.value)} size="small"
                placeholder={
                  draft.provider === 'foundry_serverless'
                    ? 'https://your-resource.services.ai.azure.com/openai/v1/'
                    : draft.provider === 'azure_openai'
                      ? 'https://your-resource.cognitiveservices.azure.com/'
                      : draft.provider === 'anthropic'
                        ? 'leave blank for api.anthropic.com — set for proxies / regional gateways'
                        : ''
                }
                helperText={
                  draft.provider === 'anthropic'
                    ? 'Optional. If your API key is for a non-default Anthropic-compatible endpoint, paste the base URL here.'
                    : ' '
                } />
            </Grid>
          )}
          {showApiVersion && (
            <Grid item xs={12}>
              <TextField fullWidth label="API version" value={draft.api_version || ''}
                onChange={e => set('api_version', e.target.value)} size="small"
                placeholder="2024-12-01-preview" />
            </Grid>
          )}
          <Grid item xs={6}>
            <TextField fullWidth type="number" label="Input $/M tokens"
              value={draft.rates?.input ?? 0}
              onChange={e => setRate('input', Number(e.target.value) || 0)}
              size="small" inputProps={{ step: 0.01, min: 0 }} />
          </Grid>
          <Grid item xs={6}>
            <TextField fullWidth type="number" label="Output $/M tokens"
              value={draft.rates?.output ?? 0}
              onChange={e => setRate('output', Number(e.target.value) || 0)}
              size="small" inputProps={{ step: 0.01, min: 0 }} />
          </Grid>
        </Grid>
      </DialogContent>
      <DialogActions>
        <Button onClick={onCancel}>Cancel</Button>
        <Button variant="contained" onClick={() => onSave(draft)}>Save</Button>
      </DialogActions>
    </Dialog>
  );
};

export default ModelsTabContent;

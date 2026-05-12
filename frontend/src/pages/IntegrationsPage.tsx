import React, { useEffect, useState } from 'react';
import {
  Box, Button, Card, CardContent, CardActions, Chip, CircularProgress,
  Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel,
  Grid, IconButton, MenuItem, Select, Switch, TextField, Typography, Alert,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import { integrationsApi } from '../services/api';
import type { IntegrationConfig } from '../types';

const INTEGRATION_TYPES = ['slack', 'jira', 'pagerduty', 'splunk', 'teams'] as const;
const INTEGRATION_LABELS: Record<string, string> = {
  slack: 'Slack',
  jira: 'Jira',
  pagerduty: 'PagerDuty',
  splunk: 'Splunk HEC',
  teams: 'Microsoft Teams',
};

const CONFIG_FIELDS: Record<string, { field: string; label: string; type?: string }[]> = {
  slack:      [{ field: 'webhook_url', label: 'Webhook URL', type: 'url' }],
  teams:      [{ field: 'webhook_url', label: 'Webhook URL', type: 'url' }],
  pagerduty:  [{ field: 'routing_key', label: 'Routing Key (Integration Key)' }],
  jira:       [
    { field: 'base_url', label: 'Jira Base URL', type: 'url' },
    { field: 'project_key', label: 'Project Key' },
    { field: 'email', label: 'Email', type: 'email' },
    { field: 'api_token', label: 'API Token', type: 'password' },
  ],
  splunk:     [
    { field: 'hec_url', label: 'HEC URL', type: 'url' },
    { field: 'hec_token', label: 'HEC Token', type: 'password' },
    { field: 'index', label: 'Index (default: genesis_findings)' },
  ],
};

export default function IntegrationsPage() {
  const [integrations, setIntegrations] = useState<IntegrationConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [selectedType, setSelectedType] = useState<string>('slack');
  const [configValues, setConfigValues] = useState<Record<string, string>>({});
  const [integrationName, setIntegrationName] = useState('');
  const [saving, setSaving] = useState(false);
  const [testResult, setTestResult] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);

  const loadIntegrations = async () => {
    try {
      const data = await integrationsApi.list();
      setIntegrations(data);
    } catch { /* ignore */ }
    setLoading(false);
  };

  useEffect(() => { loadIntegrations(); }, []);

  const handleCreate = async () => {
    setSaving(true);
    try {
      await integrationsApi.create({
        type: selectedType as IntegrationConfig['type'],
        name: integrationName || INTEGRATION_LABELS[selectedType],
        enabled: true,
        config: configValues,
      });
      setDialogOpen(false);
      setConfigValues({});
      setIntegrationName('');
      await loadIntegrations();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to save integration');
    }
    setSaving(false);
  };

  const handleTest = async (id: string) => {
    try {
      const result = await integrationsApi.test(id);
      setTestResult(prev => ({ ...prev, [id]: result?.ok ? '✓ Success' : `✗ ${result?.error || 'failed'}` }));
    } catch (err: unknown) {
      setTestResult(prev => ({ ...prev, [id]: `✗ ${err instanceof Error ? err.message : 'error'}` }));
    }
  };

  const handleDelete = async (id: string) => {
    await integrationsApi.delete(id);
    await loadIntegrations();
  };

  if (loading) return <Box sx={{ p: 4, display: 'flex', justifyContent: 'center' }}><CircularProgress /></Box>;

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h5" fontWeight={700}>SOC Integrations</Typography>
        <Button startIcon={<AddIcon />} variant="contained" onClick={() => setDialogOpen(true)}>Add Integration</Button>
      </Box>

      {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>{error}</Alert>}

      {integrations.length === 0 && (
        <Typography color="text.secondary">No integrations configured. Add Slack, Jira, PagerDuty, Splunk, or Teams.</Typography>
      )}

      <Grid container spacing={2}>
        {integrations.map(integration => (
          <Grid item xs={12} sm={6} md={4} key={integration.id}>
            <Card variant="outlined">
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <Typography variant="subtitle1" fontWeight={600}>{integration.name}</Typography>
                  <Chip label={INTEGRATION_LABELS[integration.type]} size="small" />
                </Box>
                <Chip
                  label={integration.enabled ? 'Enabled' : 'Disabled'}
                  color={integration.enabled ? 'success' : 'default'}
                  size="small" sx={{ mt: 1 }}
                />
                {testResult[integration.id] && (
                  <Typography variant="caption" display="block" sx={{ mt: 1 }}
                    color={testResult[integration.id].startsWith('✓') ? 'success.main' : 'error.main'}>
                    {testResult[integration.id]}
                  </Typography>
                )}
              </CardContent>
              <CardActions>
                <Button size="small" startIcon={<PlayArrowIcon />} onClick={() => handleTest(integration.id)}>Test</Button>
                <IconButton size="small" color="error" onClick={() => handleDelete(integration.id)}><DeleteIcon fontSize="small" /></IconButton>
              </CardActions>
            </Card>
          </Grid>
        ))}
      </Grid>

      <Dialog open={dialogOpen} onClose={() => setDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Add Integration</DialogTitle>
        <DialogContent>
          <Select
            fullWidth value={selectedType}
            onChange={e => { setSelectedType(e.target.value); setConfigValues({}); }}
            sx={{ mb: 2, mt: 1 }}
          >
            {INTEGRATION_TYPES.map(t => (
              <MenuItem key={t} value={t}>{INTEGRATION_LABELS[t]}</MenuItem>
            ))}
          </Select>
          <TextField
            fullWidth label="Name" value={integrationName}
            onChange={e => setIntegrationName(e.target.value)}
            placeholder={INTEGRATION_LABELS[selectedType]}
            sx={{ mb: 2 }}
          />
          {(CONFIG_FIELDS[selectedType] || []).map(({ field, label, type }) => (
            <TextField
              key={field} fullWidth label={label} type={type || 'text'}
              value={configValues[field] || ''}
              onChange={e => setConfigValues(prev => ({ ...prev, [field]: e.target.value }))}
              sx={{ mb: 2 }}
            />
          ))}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDialogOpen(false)}>Cancel</Button>
          <Button onClick={handleCreate} variant="contained" disabled={saving}>
            {saving ? <CircularProgress size={20} /> : 'Save'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}

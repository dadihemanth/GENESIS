import React, { useEffect, useState, useCallback } from 'react';
import {
  Box,
  Grid,
  Card,
  CardContent,
  Typography,
  Button,
  TextField,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Skeleton,
  CircularProgress,
  Snackbar,
  Alert,
  IconButton,
  ToggleButton,
  ToggleButtonGroup,
  Tooltip,
} from '@mui/material';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import VisibilityIcon from '@mui/icons-material/Visibility';
import ComputerIcon from '@mui/icons-material/Computer';
import BugReportIcon from '@mui/icons-material/BugReport';
import ErrorIcon from '@mui/icons-material/Error';
import BuildIcon from '@mui/icons-material/Build';
import { useNavigate } from 'react-router-dom';
import { format } from 'date-fns';

import { healthApi, sessionsApi, vulnerabilitiesApi, toolsApi, goalsApi } from '../services/api';
import { useStore } from '../store';
import StatusChip from '../components/StatusChip';
import SeverityBadge from '../components/SeverityBadge';
import type { Session, Vulnerability, ToolInfo } from '../types';

interface StatCardProps {
  title: string;
  value: number | string;
  icon: React.ReactNode;
  color: string;
  loading: boolean;
}

const StatCard: React.FC<StatCardProps> = ({ title, value, icon, color, loading }) => (
  <Card sx={{ height: '100%' }}>
    <CardContent sx={{ p: 3 }}>
      {loading ? (
        <>
          <Skeleton variant="text" width="60%" height={20} />
          <Skeleton variant="text" width="40%" height={48} sx={{ mt: 1 }} />
        </>
      ) : (
        <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
          <Box>
            <Typography variant="body2" sx={{ color: '#5a6478', mb: 1 }}>
              {title}
            </Typography>
            <Typography variant="h4" sx={{ color, fontWeight: 700 }}>
              {value}
            </Typography>
          </Box>
          <Box
            sx={{
              p: 1.5,
              borderRadius: 2,
              backgroundColor: `${color}20`,
              color,
              display: 'flex',
            }}
          >
            {icon}
          </Box>
        </Box>
      )}
    </CardContent>
  </Card>
);

const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const { setSessions, setHealth } = useStore();

  const [sessions, setSessLocal] = useState<Session[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [tools, setTools] = useState<ToolInfo[]>([]);
  const [loading, setLoading] = useState(true);

  const [targetIp, setTargetIp] = useState('');
  // v7.x — scan profile is now operator-selectable. exhaustive (default,
  // 1h floor) for normal use; deep_research (6h floor, 10 multi-agent
  // rounds, mandatory PoC verification) for thorough scans that match the
  // 8-11h sessions which historically produced 200-450 findings.
  const [scanProfile, setScanProfile] = useState<'exhaustive' | 'deep_research' | 'validated_dynamic'>('exhaustive');
  // Solo mode is no longer operator-selectable. Every scan runs in
  // multi-agent mode (recon + analyst + exploit + code generalists, plus
  // any specialists Phase-1 detection activates).
  const agentMode = 'multi_agent';
  const [operatorContext, setOperatorContext] = useState('');
  const [operatorGoal, setOperatorGoal] = useState('');
  const [starting, setStarting] = useState(false);
  const [ipError, setIpError] = useState('');

  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false,
    message: '',
    severity: 'success',
  });

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [healthData, sessionsData, vulnsData, toolsData] = await Promise.allSettled([
        healthApi.check(),
        sessionsApi.list({ size: 10 }),
        vulnerabilitiesApi.list({ size: 10 }),
        toolsApi.list(),
      ]);

      if (healthData.status === 'fulfilled') {
        setHealth(healthData.value);
      }
      if (sessionsData.status === 'fulfilled') {
        setSessLocal(sessionsData.value.items);
        setSessions(sessionsData.value.items);
      }
      if (vulnsData.status === 'fulfilled') {
        setVulnerabilities(vulnsData.value.items);
      }
      if (toolsData.status === 'fulfilled') {
        setTools(toolsData.value);
      }
    } finally {
      setLoading(false);
    }
  }, [setSessions, setHealth]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const validateIp = (value: string): boolean => {
    const v = value.trim();
    if (!v) return false;
    try {
      const parsed = new URL(v.includes('://') ? v : `http://${v}`);
      const host = parsed.hostname.toLowerCase();
      if (host === 'localhost' || host === '127.0.0.1' || host.startsWith('127.')) return false;
      if (parsed.port && !/^\d{1,5}$/.test(parsed.port)) return false;
      if (parsed.port && Number(parsed.port) > 65535) return false;
      const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
      const hostRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      if (ipRegex.test(host)) {
        return host.split('.').every(part => Number(part) >= 0 && Number(part) <= 255);
      }
      return hostRegex.test(host);
    } catch {
      return false;
    }
  };

  const handleStartResearch = async () => {
    if (!targetIp.trim()) {
      setIpError('Target IP or hostname is required');
      return;
    }
    if (!validateIp(targetIp)) {
      setIpError('Enter a valid IP address or hostname');
      return;
    }
    setIpError('');
    setStarting(true);
    try {
      const trimmedContext = operatorContext.trim();
      const session = await sessionsApi.create({
        target_ip: targetIp.trim(),
        scan_profile: scanProfile,
        agent_mode: agentMode,
        // operator_context is stored inside the existing Session.config JSON
        // column (no schema migration). The orchestrator reads it at session
        // start and threads it into the pre-scan brief AND the seed prompt.
        ...(trimmedContext ? { config: { operator_context: trimmedContext } } : {}),
      });
      // Compile operator goal before starting so the orchestrator injects it at session launch
      const trimmedGoal = operatorGoal.trim();
      if (trimmedGoal) {
        try { await goalsApi.create(session.id, trimmedGoal); } catch { /* non-fatal */ }
      }
      await sessionsApi.start(session.id);
      navigate(`/sessions/${session.id}`);
    } catch (err) {
      setSnackbar({
        open: true,
        message: err instanceof Error ? err.message : 'Failed to start research session',
        severity: 'error',
      });
    } finally {
      setStarting(false);
    }
  };

  const activeSessions = sessions.filter(s => s.status === 'running').length;
  const totalVulns = sessions.reduce((sum, s) => sum + s.vulnerability_count, 0);
  const criticalFindings = sessions.reduce((sum, s) => sum + s.critical_count, 0);
  const availableTools = tools.filter(t => t.status === 'available').length;

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" sx={{ mb: 3, color: '#1a1f2e' }}>
        Dashboard
      </Typography>

      {/* Stats row */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} lg={3}>
          <StatCard
            title="Active Sessions"
            value={activeSessions}
            icon={<ComputerIcon />}
            color="#4e5ced"
            loading={loading}
          />
        </Grid>
        <Grid item xs={12} sm={6} lg={3}>
          <StatCard
            title="Total Vulnerabilities"
            value={totalVulns}
            icon={<BugReportIcon />}
            color="#f44336"
            loading={loading}
          />
        </Grid>
        <Grid item xs={12} sm={6} lg={3}>
          <StatCard
            title="Critical Findings"
            value={criticalFindings}
            icon={<ErrorIcon />}
            color="#b71c1c"
            loading={loading}
          />
        </Grid>
        <Grid item xs={12} sm={6} lg={3}>
          <StatCard
            title="Tools Available"
            value={availableTools}
            icon={<BuildIcon />}
            color="#4caf50"
            loading={loading}
          />
        </Grid>
      </Grid>

      <Grid container spacing={3}>
        {/* Quick Start */}
        <Grid item xs={12} md={4}>
          <Card sx={{ height: '100%' }}>
            <CardContent sx={{ p: 3 }}>
              <Typography variant="h5" sx={{ mb: 2, color: '#1a1f2e', display: 'flex', alignItems: 'center', gap: 1 }}>
                <PlayArrowIcon sx={{ color: '#4e5ced' }} />
                Start New Research
              </Typography>
              <Typography variant="body2" sx={{ color: '#5a6478', mb: 3 }}>
                Enter a target IP address or hostname to begin an autonomous security assessment.
              </Typography>
              <TextField
                fullWidth
                label="Target IP / Hostname"
                placeholder="192.168.1.1, example.com, or http://target.local:8080"
                value={targetIp}
                onChange={e => {
                  setTargetIp(e.target.value);
                  setIpError('');
                }}
                error={!!ipError}
                helperText={ipError}
                onKeyDown={e => e.key === 'Enter' && handleStartResearch()}
                sx={{ mb: 2 }}
              />
              <TextField
                fullWidth
                label="Operator Goal (optional)"
                placeholder="compromise admin@target.com · find RCE · enumerate all PII endpoints"
                value={operatorGoal}
                onChange={e => setOperatorGoal(e.target.value)}
                helperText="Compiled into an attack tree (T132) and injected into the agent's system prompt. Leave blank for a default comprehensive pentest."
                inputProps={{ maxLength: 500 }}
                sx={{ mb: 2 }}
              />
              <TextField
                fullWidth
                multiline
                rows={5}
                label="Additional context (optional)"
                placeholder={
                  "Known tech stack. Credentials for authenticated testing. In-scope paths. Out-of-scope paths. Hostname aliases. Anything the agent should know."
                }
                value={operatorContext}
                onChange={e => setOperatorContext(e.target.value)}
                helperText={`${operatorContext.length} / 4000 chars — fed into the pre-scan brief and the agent's seed prompt`}
                inputProps={{ maxLength: 4000 }}
                sx={{ mb: 2 }}
              />
              <Box sx={{ mb: 2 }}>
                <Typography sx={{ fontSize: '0.78rem', fontWeight: 600, color: '#5a6478', mb: 0.5 }}>
                  Scan profile
                </Typography>
                <ToggleButtonGroup
                  value={scanProfile}
                  exclusive
                  size="small"
                  onChange={(_, v) => { if (v) setScanProfile(v); }}
                  sx={{ width: '100%', '& .MuiToggleButton-root': { textTransform: 'none', fontSize: '0.75rem', flex: 1 } }}
                >
                  <Tooltip title="Default discovery depth with evidence checks and critic validation. Findings appear directly as confirmed, disputed, or unverified.">
                    <ToggleButton value="exhaustive">Exhaustive</ToggleButton>
                  </Tooltip>
                  <Tooltip title="Long-horizon. 6h wallclock floor, 10 multi-agent rounds, 16/16 attack-class checklist, mandatory PoC re-verification. Best for thorough audits — empirically produces 200-450 findings vs 50-150 for exhaustive.">
                    <ToggleButton value="deep_research">Deep Research (6h+)</ToggleButton>
                  </Tooltip>
                  <Tooltip title="Hybrid discovery with optional validation-lab artifacts, proof runs, scorecards, and source/runtime correlation.">
                    <ToggleButton value="validated_dynamic">Validated</ToggleButton>
                  </Tooltip>
                </ToggleButtonGroup>
                <Typography sx={{ fontSize: '0.7rem', color: '#1565c0', mt: 0.5 }}>
                  Findings are saved through GENESIS evidence checks and critic review. The Validation Lab is optional follow-up for extra proof, scorecards, and CISO demo evidence.
                </Typography>
                {scanProfile === 'validated_dynamic' && (
                  <Typography sx={{ fontSize: '0.7rem', color: '#1565c0', mt: 0.5 }}>
                    Validated mode spends more effort on hybrid source/runtime mapping, proof artifacts, and benchmark-ready reporting without delaying normal findings.
                  </Typography>
                )}
                {scanProfile === 'deep_research' && (
                  <Typography sx={{ fontSize: '0.7rem', color: '#b8740c', mt: 0.5 }}>
                    ⚠ Will run for at least 6 hours and use 5–10× the tokens of an exhaustive scan.
                  </Typography>
                )}
              </Box>
              <Button
                variant="contained"
                color="primary"
                size="large"
                fullWidth
                onClick={handleStartResearch}
                disabled={starting}
                startIcon={starting ? <CircularProgress size={18} color="inherit" /> : <PlayArrowIcon />}
                sx={{ fontWeight: 600, py: 1.5 }}
              >
                {starting ? 'Starting...' : 'Start Research'}
              </Button>
            </CardContent>
          </Card>
        </Grid>

        {/* Recent Sessions */}
        <Grid item xs={12} md={8}>
          <Card>
            <CardContent sx={{ p: 3 }}>
              <Typography variant="h5" sx={{ mb: 2, color: '#1a1f2e' }}>
                Recent Sessions
              </Typography>
              {loading ? (
                <Box>
                  {[...Array(4)].map((_, i) => (
                    <Skeleton key={i} variant="rectangular" height={52} sx={{ mb: 1, borderRadius: 1 }} />
                  ))}
                </Box>
              ) : sessions.length === 0 ? (
                <Box sx={{ textAlign: 'center', py: 6 }}>
                  <ComputerIcon sx={{ fontSize: 48, color: '#c3cad7', mb: 2 }} />
                  <Typography sx={{ color: '#8a93a6' }}>
                    No sessions yet. Start your first research scan above.
                  </Typography>
                </Box>
              ) : (
                <TableContainer component={Box}>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        {['Target IP', 'Status', 'Vulns', 'Critical', 'Phase', 'Started', ''].map(h => (
                          <TableCell
                            key={h}
                            sx={{ color: '#8a93a6', fontSize: '0.75rem', py: 1 }}
                          >
                            {h}
                          </TableCell>
                        ))}
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {sessions.map(session => (
                        <TableRow
                          key={session.id}
                          sx={{
                            '&:hover': { backgroundColor: 'rgba(78,92,237,0.04)' },
                            cursor: 'pointer',
                          }}
                          onClick={() => navigate(`/sessions/${session.id}`)}
                        >
                          <TableCell sx={{ color: '#1a1f2e', fontFamily: 'monospace', fontSize: '0.85rem', borderBottom: '1px solid rgba(30,41,60,0.05)' }}>
                            {session.target_ip}
                          </TableCell>
                          <TableCell sx={{ borderBottom: '1px solid rgba(30,41,60,0.05)' }}>
                            <StatusChip status={session.status} />
                          </TableCell>
                          <TableCell sx={{ color: '#1a1f2e', borderBottom: '1px solid rgba(30,41,60,0.05)' }}>
                            {session.vulnerability_count}
                          </TableCell>
                          <TableCell sx={{ borderBottom: '1px solid rgba(30,41,60,0.05)' }}>
                            {session.critical_count > 0 ? (
                              <Typography sx={{ color: '#f44336', fontWeight: 700 }}>
                                {session.critical_count}
                              </Typography>
                            ) : (
                              <Typography sx={{ color: '#8a93a6' }}>0</Typography>
                            )}
                          </TableCell>
                          <TableCell sx={{ color: '#5a6478', fontSize: '0.8rem', borderBottom: '1px solid rgba(30,41,60,0.05)', textTransform: 'capitalize' }}>
                            {session.phase.replace(/_/g, ' ')}
                          </TableCell>
                          <TableCell sx={{ color: '#8a93a6', fontSize: '0.75rem', borderBottom: '1px solid rgba(30,41,60,0.05)' }}>
                            {session.started_at
                              ? format(new Date(session.started_at), 'MMM dd HH:mm')
                              : '—'}
                          </TableCell>
                          <TableCell sx={{ borderBottom: '1px solid rgba(30,41,60,0.05)' }}>
                            <IconButton
                              size="small"
                              onClick={e => { e.stopPropagation(); navigate(`/sessions/${session.id}`); }}
                              sx={{ color: '#4e5ced' }}
                            >
                              <VisibilityIcon fontSize="small" />
                            </IconButton>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Recent Vulnerabilities */}
        <Grid item xs={12}>
          <Card>
            <CardContent sx={{ p: 3 }}>
              <Typography variant="h5" sx={{ mb: 2, color: '#1a1f2e' }}>
                Recent Vulnerabilities
              </Typography>
              {loading ? (
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                  {[...Array(8)].map((_, i) => (
                    <Skeleton key={i} variant="rectangular" width={160} height={32} sx={{ borderRadius: 4 }} />
                  ))}
                </Box>
              ) : vulnerabilities.length === 0 ? (
                <Typography sx={{ color: '#8a93a6', textAlign: 'center', py: 3 }}>
                  No vulnerabilities found yet.
                </Typography>
              ) : (
                <Box sx={{ overflowX: 'auto', pb: 1 }}>
                  <Box sx={{ display: 'flex', gap: 1.5, minWidth: 'max-content' }}>
                    {vulnerabilities.map(vuln => (
                      <Box
                        key={vuln.id}
                        onClick={() => navigate('/vulnerabilities')}
                        sx={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 1,
                          p: 1,
                          px: 1.5,
                          borderRadius: 2,
                          border: '1px solid #dfe3ec',
                          cursor: 'pointer',
                          backgroundColor: 'rgba(78,92,237,0.03)',
                          '&:hover': { backgroundColor: 'rgba(78,92,237,0.08)', borderColor: 'rgba(78,92,237,0.3)' },
                          transition: 'all 0.15s ease',
                          maxWidth: 260,
                        }}
                      >
                        <SeverityBadge severity={vuln.severity} />
                        <Typography
                          variant="body2"
                          sx={{
                            color: '#1a1f2e',
                            fontSize: '0.8rem',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          {vuln.title}
                        </Typography>
                      </Box>
                    ))}
                  </Box>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={5000}
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

export default Dashboard;

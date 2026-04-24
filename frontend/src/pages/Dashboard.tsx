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
} from '@mui/material';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import VisibilityIcon from '@mui/icons-material/Visibility';
import ComputerIcon from '@mui/icons-material/Computer';
import BugReportIcon from '@mui/icons-material/BugReport';
import ErrorIcon from '@mui/icons-material/Error';
import BuildIcon from '@mui/icons-material/Build';
import { useNavigate } from 'react-router-dom';
import { format } from 'date-fns';

import { healthApi, sessionsApi, vulnerabilitiesApi, toolsApi } from '../services/api';
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
            <Typography variant="body2" sx={{ color: '#9e9e9e', mb: 1 }}>
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
  const [scanProfile, setScanProfile] = useState<string>('deep');
  const [agentMode, setAgentMode] = useState<string>('solo');
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
    if (v === 'localhost' || v === '127.0.0.1' || v.startsWith('127.')) return false;
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$|^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return ipRegex.test(v);
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
      const session = await sessionsApi.create({ target_ip: targetIp.trim(), scan_profile: scanProfile, agent_mode: agentMode });
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
      <Typography variant="h4" sx={{ mb: 3, color: '#f0f0f0' }}>
        Dashboard
      </Typography>

      {/* Stats row */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} lg={3}>
          <StatCard
            title="Active Sessions"
            value={activeSessions}
            icon={<ComputerIcon />}
            color="#86BC25"
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
              <Typography variant="h5" sx={{ mb: 2, color: '#f0f0f0', display: 'flex', alignItems: 'center', gap: 1 }}>
                <PlayArrowIcon sx={{ color: '#86BC25' }} />
                Start New Research
              </Typography>
              <Typography variant="body2" sx={{ color: '#9e9e9e', mb: 3 }}>
                Enter a target IP address or hostname to begin an autonomous security assessment.
              </Typography>
              <TextField
                fullWidth
                label="Target IP / Hostname"
                placeholder="192.168.1.1 or example.com"
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
              <Typography variant="caption" sx={{ color: '#9e9e9e', display: 'block', mb: 0.5 }}>Scan Profile</Typography>
              <ToggleButtonGroup
                value={scanProfile}
                exclusive
                onChange={(_, v) => v && setScanProfile(v)}
                size="small"
                sx={{ mb: 2, '& .MuiToggleButton-root': { fontSize: '0.7rem', py: 0.5, px: 1.5, borderColor: 'rgba(255,255,255,0.1)', color: '#9e9e9e', textTransform: 'none' }, '& .Mui-selected': { backgroundColor: 'rgba(134,188,37,0.12) !important', color: '#86BC25 !important', borderColor: 'rgba(134,188,37,0.3) !important' } }}
              >
                {['fast', 'deep', 'stealth', 'full', 'apt_sim'].map(p => (
                  <ToggleButton key={p} value={p}>{p}</ToggleButton>
                ))}
              </ToggleButtonGroup>
              <Typography variant="caption" sx={{ color: '#9e9e9e', display: 'block', mb: 0.5 }}>Agent Mode</Typography>
              <ToggleButtonGroup
                value={agentMode}
                exclusive
                onChange={(_, v) => v && setAgentMode(v)}
                size="small"
                sx={{ mb: 2, '& .MuiToggleButton-root': { fontSize: '0.7rem', py: 0.5, px: 1.5, borderColor: 'rgba(255,255,255,0.1)', color: '#9e9e9e', textTransform: 'none' }, '& .Mui-selected': { backgroundColor: 'rgba(134,188,37,0.12) !important', color: '#86BC25 !important', borderColor: 'rgba(134,188,37,0.3) !important' } }}
              >
                <ToggleButton value="solo">Solo</ToggleButton>
                <ToggleButton value="multi_agent">Multi-Agent</ToggleButton>
              </ToggleButtonGroup>
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
              <Typography variant="h5" sx={{ mb: 2, color: '#f0f0f0' }}>
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
                  <ComputerIcon sx={{ fontSize: 48, color: '#424242', mb: 2 }} />
                  <Typography sx={{ color: '#616161' }}>
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
                            sx={{ color: '#616161', fontSize: '0.75rem', py: 1 }}
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
                            '&:hover': { backgroundColor: 'rgba(134,188,37,0.04)' },
                            cursor: 'pointer',
                          }}
                          onClick={() => navigate(`/sessions/${session.id}`)}
                        >
                          <TableCell sx={{ color: '#f0f0f0', fontFamily: 'monospace', fontSize: '0.85rem', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                            {session.target_ip}
                          </TableCell>
                          <TableCell sx={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                            <StatusChip status={session.status} />
                          </TableCell>
                          <TableCell sx={{ color: '#f0f0f0', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                            {session.vulnerability_count}
                          </TableCell>
                          <TableCell sx={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                            {session.critical_count > 0 ? (
                              <Typography sx={{ color: '#f44336', fontWeight: 700 }}>
                                {session.critical_count}
                              </Typography>
                            ) : (
                              <Typography sx={{ color: '#616161' }}>0</Typography>
                            )}
                          </TableCell>
                          <TableCell sx={{ color: '#9e9e9e', fontSize: '0.8rem', borderBottom: '1px solid rgba(255,255,255,0.05)', textTransform: 'capitalize' }}>
                            {session.phase.replace(/_/g, ' ')}
                          </TableCell>
                          <TableCell sx={{ color: '#616161', fontSize: '0.75rem', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                            {session.started_at
                              ? format(new Date(session.started_at), 'MMM dd HH:mm')
                              : '—'}
                          </TableCell>
                          <TableCell sx={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                            <IconButton
                              size="small"
                              onClick={e => { e.stopPropagation(); navigate(`/sessions/${session.id}`); }}
                              sx={{ color: '#86BC25' }}
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
              <Typography variant="h5" sx={{ mb: 2, color: '#f0f0f0' }}>
                Recent Vulnerabilities
              </Typography>
              {loading ? (
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                  {[...Array(8)].map((_, i) => (
                    <Skeleton key={i} variant="rectangular" width={160} height={32} sx={{ borderRadius: 4 }} />
                  ))}
                </Box>
              ) : vulnerabilities.length === 0 ? (
                <Typography sx={{ color: '#616161', textAlign: 'center', py: 3 }}>
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
                          border: '1px solid rgba(255,255,255,0.08)',
                          cursor: 'pointer',
                          backgroundColor: 'rgba(134,188,37,0.03)',
                          '&:hover': { backgroundColor: 'rgba(134,188,37,0.08)', borderColor: 'rgba(134,188,37,0.3)' },
                          transition: 'all 0.15s ease',
                          maxWidth: 260,
                        }}
                      >
                        <SeverityBadge severity={vuln.severity} />
                        <Typography
                          variant="body2"
                          sx={{
                            color: '#f0f0f0',
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

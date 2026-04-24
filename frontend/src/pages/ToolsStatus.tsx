import React, { useEffect, useState, useCallback } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  Button,
  Chip,
  CircularProgress,
  Skeleton,
  Tooltip,
  Snackbar,
  Alert,
  Divider,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import RadarIcon from '@mui/icons-material/Radar';
import LanguageIcon from '@mui/icons-material/Language';
import LockIcon from '@mui/icons-material/Lock';
import KeyIcon from '@mui/icons-material/Key';
import WindowIcon from '@mui/icons-material/Window';
import CodeIcon from '@mui/icons-material/Code';

import { toolsApi } from '../services/api';
import StatusChip from '../components/StatusChip';
import type { ToolInfo } from '../types';

// ── Category definitions ─────────────────────────────────────────────────────

interface Category {
  id: string;
  label: string;
  icon: React.ReactNode;
  tools: string[];
}

const CATEGORIES: Category[] = [
  {
    id: 'recon',
    label: 'Reconnaissance',
    icon: <RadarIcon />,
    tools: ['nmap', 'masscan', 'amass', 'subfinder', 'dnsrecon', 'harvester', 'httpx'],
  },
  {
    id: 'web',
    label: 'Web Scanning',
    icon: <LanguageIcon />,
    tools: ['nikto', 'nuclei', 'whatweb', 'wafw00f', 'gobuster', 'feroxbuster', 'ffuf',
            'wpscan', 'xsstrike', 'sqlmap', 'commix', 'arjun', 'curl_probe'],
  },
  {
    id: 'ssl',
    label: 'SSL / TLS',
    icon: <LockIcon />,
    tools: ['sslscan', 'openssl_check'],
  },
  {
    id: 'auth',
    label: 'Authentication',
    icon: <KeyIcon />,
    tools: ['hydra', 'john'],
  },
  {
    id: 'windows',
    label: 'Windows / Active Directory',
    icon: <WindowIcon />,
    tools: ['enum4linux', 'netexec', 'impacket', 'kerbrute'],
  },
  {
    id: 'static',
    label: 'Static Analysis',
    icon: <CodeIcon />,
    tools: ['semgrep', 'bandit'],
  },
];

// ── Status dot colour ─────────────────────────────────────────────────────────

const statusDotColor = (status: string): string => {
  if (status === 'available') return '#4caf50';
  if (status === 'missing') return '#f44336';
  return '#ff9800';
};

// ── Tool card ─────────────────────────────────────────────────────────────────

const ToolCard: React.FC<{ tool: ToolInfo }> = ({ tool }) => (
  <Card sx={{ height: '100%', position: 'relative' }}>
    <Box
      sx={{
        position: 'absolute',
        top: 12,
        right: 12,
        width: 9,
        height: 9,
        borderRadius: '50%',
        backgroundColor: statusDotColor(tool.status),
        boxShadow: tool.status === 'available' ? `0 0 7px ${statusDotColor(tool.status)}` : 'none',
      }}
    />

    <CardContent sx={{ p: 2.5 }}>
      <Typography
        variant="subtitle1"
        sx={{
          fontWeight: 700,
          color: '#f0f0f0',
          mb: 0.5,
          fontFamily: 'monospace',
          pr: 2,
          fontSize: '0.9rem',
        }}
      >
        {tool.name}
      </Typography>

      {tool.version && (
        <Chip
          label={tool.version.split('\n')[0].substring(0, 30)}
          size="small"
          sx={{
            backgroundColor: 'rgba(134,188,37,0.10)',
            color: '#86BC25',
            fontFamily: 'monospace',
            fontSize: '0.6rem',
            height: 18,
            mb: 1,
            maxWidth: '100%',
          }}
        />
      )}

      <Typography
        variant="body2"
        sx={{
          color: '#616161',
          fontSize: '0.78rem',
          lineHeight: 1.5,
          mb: 2,
          minHeight: 36,
          display: '-webkit-box',
          WebkitLineClamp: 2,
          WebkitBoxOrient: 'vertical',
          overflow: 'hidden',
        }}
      >
        {tool.description || 'Security assessment tool'}
      </Typography>

      <StatusChip status={tool.status} />
    </CardContent>
  </Card>
);

const ToolCardSkeleton: React.FC = () => (
  <Card>
    <CardContent sx={{ p: 2.5 }}>
      <Skeleton variant="text" width="60%" height={22} sx={{ mb: 0.5 }} />
      <Skeleton variant="text" width="35%" height={18} sx={{ mb: 1 }} />
      <Skeleton variant="text" width="90%" height={15} />
      <Skeleton variant="text" width="75%" height={15} sx={{ mb: 2 }} />
      <Skeleton variant="rectangular" width={80} height={22} sx={{ borderRadius: 4 }} />
    </CardContent>
  </Card>
);

// ── Main page ─────────────────────────────────────────────────────────────────

const ToolsStatus: React.FC = () => {
  const [tools, setTools] = useState<ToolInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [testing, setTesting] = useState(false);
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false, message: '', severity: 'success',
  });

  const fetchTools = useCallback(async () => {
    setLoading(true);
    try {
      const result = await toolsApi.list();
      setTools(result);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchTools(); }, [fetchTools]);

  const handleTestAll = async () => {
    setTesting(true);
    try {
      const result = await toolsApi.testAll();
      setTools(result);
      setSnackbar({ open: true, message: 'All tools tested', severity: 'success' });
    } catch (err) {
      setSnackbar({ open: true, message: err instanceof Error ? err.message : 'Test failed', severity: 'error' });
    } finally {
      setTesting(false);
    }
  };

  const toolMap = Object.fromEntries(tools.map(t => [t.name, t]));
  const available = tools.filter(t => t.status === 'available').length;
  const missing = tools.filter(t => t.status === 'missing').length;
  const errored = tools.filter(t => t.status === 'error').length;

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', mb: 3, flexWrap: 'wrap', gap: 2 }}>
        <Box>
          <Typography variant="h4" sx={{ mb: 1, color: '#f0f0f0' }}>
            Tools Status
          </Typography>
          {!loading && tools.length > 0 && (
            <Box sx={{ display: 'flex', gap: 2.5, flexWrap: 'wrap' }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
                <CheckCircleIcon sx={{ color: '#4caf50', fontSize: 17 }} />
                <Typography sx={{ color: '#4caf50', fontWeight: 700, fontFamily: 'monospace', fontSize: '0.9rem' }}>
                  {available}
                </Typography>
                <Typography sx={{ color: '#616161', fontSize: '0.82rem' }}>Operational</Typography>
              </Box>
              {missing > 0 && (
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
                  <Box sx={{ width: 9, height: 9, borderRadius: '50%', backgroundColor: '#f44336' }} />
                  <Typography sx={{ color: '#f44336', fontWeight: 700, fontFamily: 'monospace', fontSize: '0.9rem' }}>
                    {missing}
                  </Typography>
                  <Typography sx={{ color: '#616161', fontSize: '0.82rem' }}>Missing</Typography>
                </Box>
              )}
              {errored > 0 && (
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
                  <Box sx={{ width: 9, height: 9, borderRadius: '50%', backgroundColor: '#ff9800' }} />
                  <Typography sx={{ color: '#ff9800', fontWeight: 700, fontFamily: 'monospace', fontSize: '0.9rem' }}>
                    {errored}
                  </Typography>
                  <Typography sx={{ color: '#616161', fontSize: '0.82rem' }}>Error</Typography>
                </Box>
              )}
              <Typography sx={{ color: '#424242', fontSize: '0.82rem', ml: 'auto' }}>
                {tools.length} total
              </Typography>
            </Box>
          )}
        </Box>

        <Box sx={{ display: 'flex', gap: 1.5 }}>
          <Tooltip title="Refresh tool list">
            <Button
              variant="outlined"
              color="inherit"
              size="small"
              onClick={fetchTools}
              disabled={loading}
              startIcon={<RefreshIcon />}
              sx={{ color: '#616161', borderColor: 'rgba(255,255,255,0.12)', fontSize: '0.8rem' }}
            >
              Refresh
            </Button>
          </Tooltip>
          <Button
            variant="contained"
            color="primary"
            size="small"
            onClick={handleTestAll}
            disabled={testing || loading}
            startIcon={testing ? <CircularProgress size={14} color="inherit" /> : undefined}
            sx={{ fontSize: '0.8rem' }}
          >
            {testing ? 'Testing...' : 'Test All Tools'}
          </Button>
        </Box>
      </Box>

      {/* Categories */}
      {loading ? (
        <Box>
          {CATEGORIES.map(cat => (
            <Box key={cat.id} sx={{ mb: 4 }}>
              <Skeleton variant="text" width={180} height={28} sx={{ mb: 2 }} />
              <Grid container spacing={2}>
                {[...Array(cat.tools.length > 4 ? 4 : cat.tools.length)].map((_, i) => (
                  <Grid item xs={12} sm={6} md={4} lg={3} key={i}>
                    <ToolCardSkeleton />
                  </Grid>
                ))}
              </Grid>
            </Box>
          ))}
        </Box>
      ) : tools.length === 0 ? (
        <Box sx={{ textAlign: 'center', py: 8 }}>
          <Typography variant="h6" sx={{ color: '#424242', mb: 1 }}>No tools available</Typography>
          <Typography sx={{ color: '#616161', fontSize: '0.875rem' }}>
            Make sure the MCP server is running and configured correctly.
          </Typography>
        </Box>
      ) : (
        CATEGORIES.map((cat, idx) => {
          const catTools = cat.tools
            .map(name => toolMap[name])
            .filter(Boolean) as ToolInfo[];

          if (catTools.length === 0) return null;

          const catAvailable = catTools.filter(t => t.status === 'available').length;
          const catMissing = catTools.filter(t => t.status === 'missing').length;

          return (
            <Box key={cat.id} sx={{ mb: idx < CATEGORIES.length - 1 ? 5 : 0 }}>
              {/* Category header */}
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
                <Box sx={{ color: '#86BC25', display: 'flex', alignItems: 'center' }}>
                  {cat.icon}
                </Box>
                <Typography variant="h6" sx={{ color: '#f0f0f0', fontWeight: 600, fontSize: '0.95rem' }}>
                  {cat.label}
                </Typography>
                <Chip
                  label={`${catAvailable}/${catTools.length}`}
                  size="small"
                  sx={{
                    backgroundColor: catMissing === 0 ? 'rgba(76,175,80,0.12)' : 'rgba(255,255,255,0.06)',
                    color: catMissing === 0 ? '#4caf50' : '#9e9e9e',
                    fontFamily: 'monospace',
                    fontSize: '0.7rem',
                    height: 20,
                  }}
                />
              </Box>
              <Divider sx={{ mb: 2 }} />

              <Grid container spacing={2}>
                {catTools.map(tool => (
                  <Grid item xs={12} sm={6} md={4} lg={3} key={tool.name}>
                    <ToolCard tool={tool} />
                  </Grid>
                ))}
              </Grid>
            </Box>
          );
        })
      )}

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

export default ToolsStatus;

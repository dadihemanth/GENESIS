// Sessions — list every scan ever run, with status, target, finding count,
// and a per-row "Download report" button that saves a Markdown report
// (Findings + chains + hypotheses + tool histogram). Clicking a row opens
// the SessionViewer.
import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  IconButton,
  MenuItem,
  Select,
  Snackbar,
  Alert,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TablePagination,
  TableRow,
  Tooltip,
  Typography,
} from '@mui/material';
import DownloadIcon from '@mui/icons-material/Download';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import RefreshIcon from '@mui/icons-material/Refresh';

import { sessionsApi } from '../services/api';
import type { Session } from '../types';

const STATUS_COLOURS: Record<string, string> = {
  running: '#4caf50',
  completed: '#4e5ced',
  paused: '#ff9800',
  stopped: '#f44336',
  failed: '#f44336',
  pending: '#5a6478',
};

function fmtTime(ts: string | null | undefined): string {
  if (!ts) return '—';
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

function fmtDuration(start: string | null | undefined, end: string | null | undefined): string {
  if (!start) return '—';
  const s = new Date(start).getTime();
  const e = end ? new Date(end).getTime() : Date.now();
  if (isNaN(s) || isNaN(e)) return '—';
  const secs = Math.max(0, Math.round((e - s) / 1000));
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  return `${h}h ${m}m`;
}

const Sessions: React.FC = () => {
  const navigate = useNavigate();
  const [sessions, setSessions] = useState<Session[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);          // 0-indexed for MUI
  const [size, setSize] = useState(25);
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [snack, setSnack] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false, message: '', severity: 'success',
  });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await sessionsApi.list({
        page: page + 1,    // backend is 1-indexed
        size,
        status: statusFilter || undefined,
      });
      setSessions(data.items);
      setTotal(data.total);
    } catch (err) {
      setSnack({ open: true, message: err instanceof Error ? err.message : String(err), severity: 'error' });
    } finally {
      setLoading(false);
    }
  }, [page, size, statusFilter]);

  useEffect(() => { load(); }, [load]);

  const downloadReport = useCallback(async (id: string) => {
    setDownloadingId(id);
    try {
      const { filename, body } = await sessionsApi.downloadReport(id);
      // Save-as via a temporary anchor; works in every browser without
      // an extra package.
      const blob = new Blob([body], { type: 'text/markdown;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setSnack({ open: true, message: `Downloaded ${filename}`, severity: 'success' });
    } catch (err) {
      setSnack({ open: true, message: err instanceof Error ? err.message : String(err), severity: 'error' });
    } finally {
      setDownloadingId(null);
    }
  }, []);

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3, flexWrap: 'wrap' }}>
        <Typography variant="h4" sx={{ color: '#1a1f2e', flexGrow: 1 }}>
          Sessions
        </Typography>
        <Select
          size="small"
          value={statusFilter}
          displayEmpty
          onChange={(e) => { setStatusFilter(e.target.value); setPage(0); }}
          sx={{ minWidth: 160, fontSize: '0.85rem' }}
        >
          <MenuItem value="">All statuses</MenuItem>
          {['pending', 'running', 'paused', 'completed', 'stopped', 'failed'].map(s => (
            <MenuItem key={s} value={s}>{s}</MenuItem>
          ))}
        </Select>
        <Button
          size="small"
          variant="outlined"
          startIcon={loading ? <CircularProgress size={14} /> : <RefreshIcon sx={{ fontSize: 16 }} />}
          onClick={load}
          disabled={loading}
          sx={{ textTransform: 'none' }}
        >
          Refresh
        </Button>
      </Box>

      <Card>
        <CardContent sx={{ p: 0, '&:last-child': { pb: 0 } }}>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ backgroundColor: '#f4f6fb' }}>
                  <TableCell sx={{ fontWeight: 700, fontSize: '0.75rem' }}>Target</TableCell>
                  <TableCell sx={{ fontWeight: 700, fontSize: '0.75rem' }}>Status</TableCell>
                  <TableCell sx={{ fontWeight: 700, fontSize: '0.75rem' }}>Mode</TableCell>
                  <TableCell sx={{ fontWeight: 700, fontSize: '0.75rem' }} align="right">Findings</TableCell>
                  <TableCell sx={{ fontWeight: 700, fontSize: '0.75rem' }} align="right">Iterations</TableCell>
                  <TableCell sx={{ fontWeight: 700, fontSize: '0.75rem' }}>Started</TableCell>
                  <TableCell sx={{ fontWeight: 700, fontSize: '0.75rem' }}>Duration</TableCell>
                  <TableCell sx={{ fontWeight: 700, fontSize: '0.75rem' }} align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {!loading && sessions.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={8} align="center" sx={{ py: 5, color: '#8a93a6', fontSize: '0.85rem' }}>
                      No sessions match the current filter.
                    </TableCell>
                  </TableRow>
                )}
                {sessions.map(s => {
                  const sevColor = STATUS_COLOURS[s.status] ?? '#5a6478';
                  return (
                    <TableRow
                      key={s.id}
                      hover
                      onClick={() => navigate(`/sessions/${s.id}`)}
                      sx={{ cursor: 'pointer' }}
                    >
                      <TableCell>
                        <Typography sx={{ fontFamily: 'monospace', fontSize: '0.78rem', color: '#1a1f2e', fontWeight: 600 }}>
                          {s.target_hostname || s.target_ip || '—'}
                        </Typography>
                        <Typography sx={{ fontFamily: 'monospace', fontSize: '0.65rem', color: '#8a93a6' }}>
                          {String(s.id).split('-')[0]}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={s.status}
                          size="small"
                          sx={{
                            height: 20, fontSize: '0.65rem', fontFamily: 'monospace', fontWeight: 700,
                            backgroundColor: `${sevColor}20`, color: sevColor,
                            border: `1px solid ${sevColor}55`,
                          }}
                        />
                      </TableCell>
                      <TableCell sx={{ fontSize: '0.75rem', color: '#5a6478', fontFamily: 'monospace' }}>
                        {s.agent_mode || '—'}
                      </TableCell>
                      <TableCell align="right" sx={{ fontSize: '0.78rem', fontWeight: 700, color: '#1a1f2e' }}>
                        {s.vulnerability_count ?? 0}
                      </TableCell>
                      <TableCell align="right" sx={{ fontSize: '0.78rem', fontFamily: 'monospace', color: '#5a6478' }}>
                        {s.iteration ?? 0}
                      </TableCell>
                      <TableCell sx={{ fontSize: '0.7rem', color: '#5a6478', fontFamily: 'monospace' }}>
                        {fmtTime(s.started_at)}
                      </TableCell>
                      <TableCell sx={{ fontSize: '0.7rem', color: '#5a6478', fontFamily: 'monospace' }}>
                        {fmtDuration(s.started_at, s.completed_at)}
                      </TableCell>
                      <TableCell align="right" onClick={(e) => e.stopPropagation()}>
                        <Tooltip title="Download Markdown report">
                          <span>
                            <IconButton
                              size="small"
                              onClick={() => downloadReport(s.id)}
                              disabled={downloadingId === s.id}
                              sx={{ color: '#4e5ced' }}
                            >
                              {downloadingId === s.id
                                ? <CircularProgress size={14} />
                                : <DownloadIcon sx={{ fontSize: 18 }} />}
                            </IconButton>
                          </span>
                        </Tooltip>
                        <Tooltip title="Open session viewer">
                          <IconButton
                            size="small"
                            onClick={() => navigate(`/sessions/${s.id}`)}
                            sx={{ color: '#5a6478' }}
                          >
                            <OpenInNewIcon sx={{ fontSize: 18 }} />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
          <TablePagination
            component="div"
            count={total}
            page={page}
            onPageChange={(_, p) => setPage(p)}
            rowsPerPage={size}
            onRowsPerPageChange={(e) => { setSize(parseInt(e.target.value, 10)); setPage(0); }}
            rowsPerPageOptions={[10, 25, 50, 100]}
          />
        </CardContent>
      </Card>

      <Snackbar
        open={snack.open}
        autoHideDuration={4000}
        onClose={() => setSnack(s => ({ ...s, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert severity={snack.severity} onClose={() => setSnack(s => ({ ...s, open: false }))}>
          {snack.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default Sessions;

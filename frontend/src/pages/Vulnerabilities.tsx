import React, { useEffect, useState, useCallback, useRef } from 'react';
import {
  Box,
  Typography,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TablePagination,
  Chip,
  LinearProgress,
  Divider,
  IconButton,
  InputAdornment,
  Skeleton,
  Alert,
} from '@mui/material';
import SearchIcon from '@mui/icons-material/Search';
import ClearIcon from '@mui/icons-material/Clear';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import { format } from 'date-fns';

import { vulnerabilitiesApi, sessionsApi } from '../services/api';
import SeverityBadge from '../components/SeverityBadge';
import type { Vulnerability, Session } from '../types';

const SEVERITIES: Array<{ value: string; label: string }> = [
  { value: '', label: 'All Severities' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'info', label: 'Info' },
];

const Vulnerabilities: React.FC = () => {
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [total, setTotal] = useState(0);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState('');
  const [selected, setSelected] = useState<Vulnerability | null>(null);

  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [sessionFilter, setSessionFilter] = useState('');
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(20);

  const searchTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const fetchVulns = useCallback(async (q: string, severity: string, sessionId: string, p: number, rpp: number) => {
    setLoading(true);
    setFetchError('');
    try {
      if (q.trim()) {
        const result = await vulnerabilitiesApi.search(q.trim(), rpp);
        setVulnerabilities(result.items);
        setTotal(result.items.length);
      } else {
        const result = await vulnerabilitiesApi.list({
          severity: severity || undefined,
          session_id: sessionId || undefined,
          page: p + 1,
          size: rpp,
        });
        setVulnerabilities(result.items);
        setTotal(result.total);
      }
    } catch (err) {
      setFetchError(err instanceof Error ? err.message : 'Failed to load vulnerabilities');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    sessionsApi.list({ size: 100 }).then(r => setSessions(r.items)).catch(() => {});
  }, []);

  useEffect(() => {
    if (searchTimer.current) clearTimeout(searchTimer.current);
    searchTimer.current = setTimeout(() => {
      fetchVulns(search, severityFilter, sessionFilter, page, rowsPerPage);
    }, 300);
    return () => { if (searchTimer.current) clearTimeout(searchTimer.current); };
  }, [search, severityFilter, sessionFilter, page, rowsPerPage, fetchVulns]);

  const handleSearchChange = (value: string) => {
    setSearch(value);
    setPage(0);
  };

  return (
    <Box sx={{ display: 'flex', height: 'calc(100vh - 64px)', overflow: 'hidden' }}>
      {/* Left panel – list */}
      <Box
        sx={{
          width: '60%',
          display: 'flex',
          flexDirection: 'column',
          borderRight: '1px solid #dfe3ec',
          overflow: 'hidden',
        }}
      >
        {/* Header + filters */}
        <Box sx={{ p: 2.5, borderBottom: '1px solid #dfe3ec', flexShrink: 0 }}>
          <Typography variant="h5" sx={{ mb: 2, color: '#1a1f2e' }}>
            Vulnerabilities
          </Typography>

          <TextField
            fullWidth
            placeholder="Search vulnerabilities..."
            value={search}
            onChange={e => handleSearchChange(e.target.value)}
            sx={{ mb: 1.5 }}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon sx={{ color: '#8a93a6', fontSize: 18 }} />
                </InputAdornment>
              ),
              endAdornment: search ? (
                <InputAdornment position="end">
                  <IconButton size="small" onClick={() => handleSearchChange('')} sx={{ color: '#8a93a6' }}>
                    <ClearIcon fontSize="small" />
                  </IconButton>
                </InputAdornment>
              ) : null,
            }}
          />

          <Box sx={{ display: 'flex', gap: 1.5 }}>
            <FormControl size="small" sx={{ minWidth: 140 }}>
              <InputLabel>Severity</InputLabel>
              <Select
                value={severityFilter}
                label="Severity"
                onChange={e => { setSeverityFilter(e.target.value); setPage(0); }}
              >
                {SEVERITIES.map(s => (
                  <MenuItem key={s.value} value={s.value}>{s.label}</MenuItem>
                ))}
              </Select>
            </FormControl>

            <FormControl size="small" sx={{ minWidth: 160 }}>
              <InputLabel>Session</InputLabel>
              <Select
                value={sessionFilter}
                label="Session"
                onChange={e => { setSessionFilter(e.target.value); setPage(0); }}
              >
                <MenuItem value="">All Sessions</MenuItem>
                {sessions.map(s => (
                  <MenuItem key={s.id} value={s.id}>{s.target_ip}</MenuItem>
                ))}
              </Select>
            </FormControl>
          </Box>
        </Box>

        {fetchError && (
          <Box sx={{ px: 2.5, pt: 1 }}>
            <Alert severity="error" onClose={() => setFetchError('')}>{fetchError}</Alert>
          </Box>
        )}

        {/* Table */}
        <Box sx={{ flexGrow: 1, overflowY: 'auto', '&::-webkit-scrollbar': { width: 4 }, '&::-webkit-scrollbar-thumb': { background: '#dfe3ec', borderRadius: 2 } }}>
          <Table stickyHeader size="small">
            <TableHead>
              <TableRow>
                {['Severity', 'Title', 'Service:Port', 'Session', 'CVEs', 'Confidence', 'Date'].map(h => (
                  <TableCell
                    key={h}
                    sx={{
                      backgroundColor: '#ffffff',
                      py: 1,
                    }}
                  >
                    {h}
                  </TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {loading ? (
                [...Array(8)].map((_, i) => (
                  <TableRow key={i}>
                    {[...Array(7)].map((__, j) => (
                      <TableCell key={j}>
                        <Skeleton variant="text" height={20} />
                      </TableCell>
                    ))}
                  </TableRow>
                ))
              ) : vulnerabilities.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} sx={{ textAlign: 'center', py: 6, borderBottom: 'none' }}>
                    <Typography sx={{ color: '#c3cad7' }}>
                      {search ? `No results for "${search}"` : 'No vulnerabilities found'}
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                vulnerabilities.map(vuln => (
                  <TableRow
                    key={vuln.id}
                    selected={selected?.id === vuln.id}
                    onClick={() => setSelected(vuln)}
                    sx={{
                      cursor: 'pointer',
                      backgroundColor: selected?.id === vuln.id ? 'rgba(78,92,237,0.06)' : 'transparent',
                      '&:hover': { backgroundColor: 'rgba(78,92,237,0.04)' },
                      '&.Mui-selected': { backgroundColor: 'rgba(78,92,237,0.08)' },
                    }}
                  >
                    <TableCell sx={{ py: 1 }}>
                      <SeverityBadge severity={vuln.severity} />
                    </TableCell>
                    <TableCell sx={{ py: 1, maxWidth: 200 }}>
                      <Typography sx={{ color: '#1a1f2e', fontSize: '0.8rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {vuln.title}
                      </Typography>
                    </TableCell>
                    <TableCell sx={{ py: 1 }}>
                      <Typography sx={{ color: '#4e5ced', fontFamily: 'monospace', fontSize: '0.72rem' }}>
                        {vuln.affected_service}{vuln.port ? `:${vuln.port}` : ''}
                      </Typography>
                    </TableCell>
                    <TableCell sx={{ py: 1 }}>
                      <Typography sx={{ color: '#8a93a6', fontFamily: 'monospace', fontSize: '0.7rem' }}>
                        {sessions.find(s => s.id === vuln.session_id)?.target_ip ?? vuln.session_id.slice(0, 8)}
                      </Typography>
                    </TableCell>
                    <TableCell sx={{ py: 1 }}>
                      <Typography sx={{ color: '#c3cad7', fontSize: '0.72rem', fontFamily: 'monospace' }}>
                        {(vuln.cve_ids ?? []).length > 0 ? vuln.cve_ids.length : '—'}
                      </Typography>
                    </TableCell>
                    <TableCell sx={{ py: 1 }}>
                      <Typography sx={{ color: '#5a6478', fontFamily: 'monospace', fontSize: '0.72rem' }}>
                        {Math.round((vuln.confidence ?? 0) * 100)}%
                      </Typography>
                    </TableCell>
                    <TableCell sx={{ py: 1 }}>
                      <Typography sx={{ color: '#8a93a6', fontSize: '0.7rem' }}>
                        {vuln.created_at ? format(new Date(vuln.created_at), 'MMM dd') : '—'}
                      </Typography>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </Box>

        <TablePagination
          component="div"
          count={total}
          page={page}
          onPageChange={(_, p) => setPage(p)}
          rowsPerPage={rowsPerPage}
          onRowsPerPageChange={e => { setRowsPerPage(parseInt(e.target.value)); setPage(0); }}
          rowsPerPageOptions={[10, 20, 50]}
          sx={{
            borderTop: '1px solid #dfe3ec',
            color: '#8a93a6',
            flexShrink: 0,
            '& .MuiTablePagination-select': { color: '#5a6478' },
            '& .MuiIconButton-root': { color: '#8a93a6' },
            '& .MuiIconButton-root.Mui-disabled': { color: '#333' },
          }}
        />
      </Box>

      {/* Right panel – detail */}
      <Box
        sx={{
          width: '40%',
          overflowY: 'auto',
          p: 3,
          '&::-webkit-scrollbar': { width: 4 },
          '&::-webkit-scrollbar-thumb': { background: '#dfe3ec', borderRadius: 2 },
        }}
      >
        {!selected ? (
          <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <SearchIcon sx={{ fontSize: 48, color: '#f6f8fc', mb: 2 }} />
            <Typography sx={{ color: '#c3cad7', textAlign: 'center' }}>
              Select a vulnerability to view details
            </Typography>
          </Box>
        ) : (
          <Box>
            {/* Title row */}
            <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2, mb: 2 }}>
              <SeverityBadge severity={selected.severity} size="medium" />
              {selected.cvss_score !== undefined && (
                <Chip
                  label={`CVSS ${selected.cvss_score.toFixed(1)}`}
                  size="small"
                  sx={{ backgroundColor: 'rgba(255,152,0,0.15)', color: '#ff9800', fontFamily: 'monospace', fontWeight: 700 }}
                />
              )}
              {selected.exploit_available && (
                <Chip
                  label="EXPLOIT"
                  size="small"
                  sx={{ backgroundColor: 'rgba(244,67,54,0.15)', color: '#f44336', fontFamily: 'monospace', fontWeight: 700 }}
                />
              )}
            </Box>

            <Typography variant="h5" sx={{ color: '#1a1f2e', mb: 2, lineHeight: 1.3 }}>
              {selected.title}
            </Typography>

            <Typography variant="body2" sx={{ color: '#5a6478', mb: 3, lineHeight: 1.7 }}>
              {selected.description}
            </Typography>

            <Divider sx={{ mb: 2 }} />

            {/* Meta */}
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, mb: 3 }}>
              <Box>
                <Typography variant="caption" sx={{ color: '#8a93a6', display: 'block' }}>Service</Typography>
                <Typography sx={{ color: '#1a1f2e', fontFamily: 'monospace', fontSize: '0.85rem' }}>
                  {selected.affected_service}
                </Typography>
              </Box>
              {selected.port && (
                <Box>
                  <Typography variant="caption" sx={{ color: '#8a93a6', display: 'block' }}>Port</Typography>
                  <Typography sx={{ color: '#4e5ced', fontFamily: 'monospace', fontSize: '0.85rem' }}>
                    {selected.port}
                  </Typography>
                </Box>
              )}
              {selected.protocol && (
                <Box>
                  <Typography variant="caption" sx={{ color: '#8a93a6', display: 'block' }}>Protocol</Typography>
                  <Typography sx={{ color: '#1a1f2e', fontFamily: 'monospace', fontSize: '0.85rem', textTransform: 'uppercase' }}>
                    {selected.protocol}
                  </Typography>
                </Box>
              )}
            </Box>

            {/* CVEs */}
            {(selected.cve_ids ?? []).length > 0 && (
              <Box sx={{ mb: 3 }}>
                <Typography variant="caption" sx={{ color: '#8a93a6', display: 'block', mb: 1 }}>
                  CVE IDs
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.75 }}>
                  {(selected.cve_ids ?? []).map(cve => (
                    <Chip
                      key={cve}
                      label={cve}
                      size="small"
                      icon={<OpenInNewIcon sx={{ fontSize: '12px !important' }} />}
                      component="a"
                      href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      clickable
                      sx={{
                        backgroundColor: 'rgba(78,92,237,0.10)',
                        color: '#4e5ced',
                        fontFamily: 'monospace',
                        fontSize: '0.72rem',
                        '&:hover': { backgroundColor: 'rgba(78,92,237,0.18)' },
                      }}
                    />
                  ))}
                </Box>
              </Box>
            )}

            {/* Confidence */}
            <Box sx={{ mb: 3 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                <Typography variant="caption" sx={{ color: '#8a93a6' }}>Confidence</Typography>
                <Typography variant="caption" sx={{ color: '#5a6478', fontFamily: 'monospace' }}>
                  {Math.round((selected.confidence ?? 0) * 100)}%
                </Typography>
              </Box>
              <LinearProgress
                variant="determinate"
                value={(selected.confidence ?? 0) * 100}
                sx={{
                  height: 6,
                  borderRadius: 3,
                  backgroundColor: '#dfe3ec',
                  '& .MuiLinearProgress-bar': {
                    backgroundColor:
                      (selected.confidence ?? 0) >= 0.8 ? '#4caf50' : (selected.confidence ?? 0) >= 0.5 ? '#ff9800' : '#f44336',
                    borderRadius: 3,
                  },
                }}
              />
            </Box>

            <Divider sx={{ mb: 2 }} />

            {/* Exploit */}
            <Box sx={{ mb: 3 }}>
              <Typography variant="subtitle2" sx={{ color: '#5a6478', mb: 1, textTransform: 'uppercase', letterSpacing: '0.08em', fontSize: '0.72rem' }}>
                Exploit
              </Typography>
              <Chip
                label={selected.exploit_available ? 'Available' : 'Not Available'}
                size="small"
                sx={{
                  backgroundColor: selected.exploit_available ? 'rgba(244,67,54,0.15)' : 'rgba(97,97,97,0.2)',
                  color: selected.exploit_available ? '#f44336' : '#8a93a6',
                  mb: selected.exploit_code ? 1.5 : 0,
                  fontFamily: 'monospace',
                }}
              />
              {selected.exploit_code && (
                <Box
                  component="pre"
                  sx={{
                    backgroundColor: '#0a0a0a',
                    border: '1px solid rgba(244,67,54,0.2)',
                    borderRadius: 1,
                    p: 1.5,
                    fontSize: '0.72rem',
                    fontFamily: 'monospace',
                    color: '#ef9a9a',
                    overflowX: 'auto',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-all',
                    maxHeight: 200,
                    overflowY: 'auto',
                    margin: 0,
                  }}
                >
                  {selected.exploit_code}
                </Box>
              )}
            </Box>

            <Divider sx={{ mb: 2 }} />

            {/* Remediation */}
            <Box sx={{ mb: 3 }}>
              <Typography variant="subtitle2" sx={{ color: '#5a6478', mb: 1, textTransform: 'uppercase', letterSpacing: '0.08em', fontSize: '0.72rem' }}>
                Remediation
              </Typography>
              <Typography variant="body2" sx={{ color: '#c8e6c9', lineHeight: 1.7, fontSize: '0.85rem' }}>
                {selected.remediation}
              </Typography>
            </Box>

            {/* Verification Output */}
            {selected.verification_output && (
              <>
                <Divider sx={{ mb: 2 }} />
                <Box>
                  <Typography variant="subtitle2" sx={{ color: '#5a6478', mb: 1, textTransform: 'uppercase', letterSpacing: '0.08em', fontSize: '0.72rem' }}>
                    Verification Output
                  </Typography>
                  <Box
                    component="pre"
                    sx={{
                      backgroundColor: '#0a0a0a',
                      border: '1px solid #dfe3ec',
                      borderRadius: 1,
                      p: 1.5,
                      fontSize: '0.72rem',
                      fontFamily: 'monospace',
                      color: '#5a6478',
                      overflowX: 'auto',
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-all',
                      maxHeight: 200,
                      overflowY: 'auto',
                      margin: 0,
                    }}
                  >
                    {selected.verification_output}
                  </Box>
                </Box>
              </>
            )}
          </Box>
        )}
      </Box>
    </Box>
  );
};

export default Vulnerabilities;

import React, { useEffect, useState, useCallback } from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  TextField,
  Button,
  CircularProgress,
  Alert,
  Grid,
  Skeleton,
} from '@mui/material';
import PsychologyIcon from '@mui/icons-material/Psychology';
import SearchIcon from '@mui/icons-material/Search';

import { intelligenceApi } from '../services/api';
import type { IntelligencePattern } from '../types';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#f44336', high: '#ff6d00', medium: '#ff9800', low: '#2979ff', info: '#5a6478',
};

const IntelligenceDashboard: React.FC = () => {
  const [patterns, setPatterns] = useState<IntelligencePattern[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [recallQuery, setRecallQuery] = useState('');
  const [recallResults, setRecallResults] = useState<unknown[]>([]);
  const [recalling, setRecalling] = useState(false);
  const [recallDone, setRecallDone] = useState(false);
  const [recallError, setRecallError] = useState('');

  const loadPatterns = useCallback(async () => {
    setLoading(true);
    try {
      const data = await intelligenceApi.getPatterns({ page: 1, size: 50 });
      setPatterns(data.items);
      setTotal(data.total);
    } catch {
      setPatterns([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadPatterns();
  }, [loadPatterns]);

  const handleRecall = async () => {
    if (!recallQuery.trim()) return;
    setRecalling(true);
    setRecallDone(false);
    setRecallError('');
    try {
      const data = await intelligenceApi.recall(recallQuery.trim(), 5);
      setRecallResults(data.results);
      setRecallDone(true);
    } catch (err) {
      setRecallError(err instanceof Error ? err.message : 'Recall failed');
    } finally {
      setRecalling(false);
    }
  };

  return (
    <Box sx={{ p: 3, maxWidth: 1200 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
        <PsychologyIcon sx={{ color: '#4e5ced', fontSize: 28 }} />
        <Typography variant="h4" sx={{ color: '#1a1f2e', fontSize: '1.4rem', fontWeight: 700 }}>
          Intelligence Library
        </Typography>
        <Chip label={`${total} patterns`} size="small" sx={{ backgroundColor: 'rgba(78,92,237,0.1)', color: '#4e5ced' }} />
      </Box>

      <Grid container spacing={3}>
        {/* Pattern Library */}
        <Grid item xs={12}>
          <Card>
            <CardContent sx={{ p: 3 }}>
              <Typography variant="h6" sx={{ color: '#1a1f2e', mb: 2, fontSize: '1rem' }}>
                Attack Pattern Library
              </Typography>
              {loading ? (
                <Box>{[...Array(5)].map((_, i) => <Skeleton key={i} variant="rectangular" height={42} sx={{ mb: 1, borderRadius: 1 }} />)}</Box>
              ) : patterns.length === 0 ? (
                <Alert severity="info" sx={{ backgroundColor: 'rgba(30,41,60,0.04)', color: '#5a6478' }}>
                  No patterns indexed yet. Complete a session to populate the intelligence library.
                </Alert>
              ) : (
                <TableContainer sx={{ '& .MuiTableCell-root': { borderColor: '#dfe3ec', color: '#2a3045', fontSize: '0.82rem' } }}>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: '#4e5ced !important', fontWeight: 600 }}>Session</TableCell>
                        <TableCell sx={{ color: '#4e5ced !important', fontWeight: 600 }}>Max Severity</TableCell>
                        <TableCell sx={{ color: '#4e5ced !important', fontWeight: 600 }}>Vulns</TableCell>
                        <TableCell sx={{ color: '#4e5ced !important', fontWeight: 600 }}>Services</TableCell>
                        <TableCell sx={{ color: '#4e5ced !important', fontWeight: 600 }}>MITRE Techniques</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {patterns.map((p) => (
                        <TableRow key={p.id} sx={{ '&:hover': { backgroundColor: 'rgba(78,92,237,0.03)' } }}>
                          <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.72rem !important' }}>
                            {p.session_id.substring(0, 12)}…
                          </TableCell>
                          <TableCell>
                            {p.max_severity && (
                              <Chip label={p.max_severity.toUpperCase()} size="small"
                                sx={{ backgroundColor: `${SEVERITY_COLORS[p.max_severity] ?? '#5a6478'}20`, color: SEVERITY_COLORS[p.max_severity] ?? '#5a6478', fontSize: '0.6rem', height: 18 }} />
                            )}
                          </TableCell>
                          <TableCell>{p.vuln_count}</TableCell>
                          <TableCell sx={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.services}</TableCell>
                          <TableCell sx={{ maxWidth: 200 }}>
                            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                              {p.mitre_techniques.split(',').slice(0, 4).map(t => t.trim()).filter(Boolean).map(t => (
                                <Chip key={t} label={t} size="small" sx={{ backgroundColor: 'rgba(79,195,247,0.08)', color: '#4fc3f7', fontSize: '0.6rem', height: 16 }} />
                              ))}
                            </Box>
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

        {/* Recall / Search */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent sx={{ p: 3 }}>
              <Typography variant="h6" sx={{ color: '#1a1f2e', mb: 2, fontSize: '1rem' }}>
                Recall Similar Targets
              </Typography>
              <Typography variant="body2" sx={{ color: '#5a6478', mb: 2 }}>
                Enter a target fingerprint (tech stack + services) to find similar past assessments.
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
                <TextField
                  fullWidth
                  size="small"
                  placeholder="e.g. Apache/2.4 PHP/7.4 MySQL port 80 443"
                  value={recallQuery}
                  onChange={e => setRecallQuery(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && handleRecall()}
                />
                <Button
                  variant="outlined"
                  onClick={handleRecall}
                  disabled={recalling}
                  startIcon={recalling ? <CircularProgress size={14} color="inherit" /> : <SearchIcon />}
                  sx={{ color: '#4e5ced', borderColor: 'rgba(78,92,237,0.3)', whiteSpace: 'nowrap' }}
                >
                  Recall
                </Button>
              </Box>
              {recallError && (
                <Alert severity="error" sx={{ mb: 1 }}>{recallError}</Alert>
              )}
              {recallDone && (
                recallResults.length === 0 ? (
                  <Alert severity="info" sx={{ backgroundColor: 'rgba(30,41,60,0.04)', color: '#5a6478' }}>No similar patterns found.</Alert>
                ) : (
                  <Box>
                    {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
                    {recallResults.map((r: any, i: number) => (
                      <Box key={i} sx={{ mb: 1.5, p: 1.5, backgroundColor: 'rgba(78,92,237,0.04)', borderRadius: 1, border: '1px solid rgba(78,92,237,0.1)' }}>
                        <Typography sx={{ color: '#4e5ced', fontSize: '0.75rem', fontFamily: 'monospace', mb: 0.5 }}>
                          Similarity: {((r.similarity ?? 0) * 100).toFixed(0)}%
                        </Typography>
                        <Typography sx={{ color: '#2a3045', fontSize: '0.78rem' }}>
                          {r.document?.substring(0, 200) ?? JSON.stringify(r.metadata)}
                        </Typography>
                      </Box>
                    ))}
                  </Box>
                )
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Statistics placeholder */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent sx={{ p: 3 }}>
              <Typography variant="h6" sx={{ color: '#1a1f2e', mb: 2, fontSize: '1rem' }}>
                Statistics
              </Typography>
              {patterns.length === 0 ? (
                <Alert severity="info" sx={{ backgroundColor: 'rgba(30,41,60,0.04)', color: '#5a6478' }}>
                  Statistics will populate as patterns are indexed.
                </Alert>
              ) : (
                <Box>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography variant="h4" sx={{ color: '#4e5ced', fontWeight: 700 }}>{total}</Typography>
                      <Typography variant="caption" sx={{ color: '#8a93a6' }}>Sessions Indexed</Typography>
                    </Box>
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography variant="h4" sx={{ color: '#f44336', fontWeight: 700 }}>
                        {patterns.filter(p => p.max_severity === 'critical').length}
                      </Typography>
                      <Typography variant="caption" sx={{ color: '#8a93a6' }}>Critical Severity</Typography>
                    </Box>
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography variant="h4" sx={{ color: '#ff9800', fontWeight: 700 }}>
                        {patterns.reduce((sum, p) => sum + (p.vuln_count ?? 0), 0)}
                      </Typography>
                      <Typography variant="caption" sx={{ color: '#8a93a6' }}>Total Vulnerabilities</Typography>
                    </Box>
                  </Box>
                  <Typography variant="body2" sx={{ color: '#5a6478', mb: 1 }}>Top Services Seen</Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                    {[...new Set(patterns.flatMap(p => p.services.split(',').map(s => s.trim())).filter(Boolean))].slice(0, 10).map(s => (
                      <Chip key={s} label={s} size="small" sx={{ backgroundColor: '#dfe3ec', color: '#5a6478', fontSize: '0.65rem' }} />
                    ))}
                  </Box>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default IntelligenceDashboard;

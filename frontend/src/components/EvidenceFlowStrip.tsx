// T27 — Evidence-flow view.
//
// Horizontal strip of confirmed findings. Click a card → fetch
// /api/v1/vulnerabilities/{id}/evidence → modal showing the evidence_for
// strings, verification_output audit trail, and candidate tool_output rows
// from Mongo. Makes the "which tool call produced this finding?" answer one
// click away instead of a grep through agent_thoughts.
import React, { useCallback, useEffect, useState } from 'react';
import {
  Box, Button, Chip, CircularProgress, Dialog, DialogActions, DialogContent,
  DialogTitle, Typography,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import TimelineIcon from '@mui/icons-material/Timeline';

import type { Vulnerability, VulnerabilityEvidence } from '../types';
import EmptyTabState from './EmptyTabState';

const API_KEY_STORAGE = 'genesis_api_key';
const apiHeaders = (): HeadersInit => {
  const key = localStorage.getItem(API_KEY_STORAGE);
  return key ? { 'X-API-Key': key } : {};
};

const SEVERITY_COLOURS: Record<string, string> = {
  critical: '#f44336', high: '#ff6d00', medium: '#ff9800', low: '#2979ff', info: '#5a6478',
};
const STATUS_COLOURS: Record<string, string> = {
  confirmed: '#4caf50', exploited: '#f44336', unverified: '#8a93a6', disputed: '#ff9800',
};

interface Props {
  vulns: Vulnerability[];
  sessionStatus?: string | null;
  iterationCount?: number;
  hypothesisCount?: number;
  toolCallCount?: number;
}

const EvidenceFlowStrip: React.FC<Props> = ({
  vulns, sessionStatus, iterationCount, hypothesisCount, toolCallCount,
}) => {
  const [openId, setOpenId] = useState<string | null>(null);
  const [evidence, setEvidence] = useState<VulnerabilityEvidence | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const ordered = [...vulns].sort((a, b) => {
    // Confirmed/exploited first, then by severity, then newest
    const rank: Record<string, number> = { exploited: 0, confirmed: 1, disputed: 2, unverified: 3 };
    const r = (rank[a.verification_status] ?? 9) - (rank[b.verification_status] ?? 9);
    if (r !== 0) return r;
    const severityRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const sv = (severityRank[a.severity] ?? 9) - (severityRank[b.severity] ?? 9);
    if (sv !== 0) return sv;
    return (b.created_at ?? '').localeCompare(a.created_at ?? '');
  });

  const openEvidence = useCallback(async (vulnId: string) => {
    setOpenId(vulnId);
    setLoading(true);
    setError(null);
    setEvidence(null);
    try {
      const res = await fetch(`/api/v1/vulnerabilities/${vulnId}/evidence`, {
        headers: apiHeaders(),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setEvidence(body as VulnerabilityEvidence);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  const close = () => {
    setOpenId(null);
    setEvidence(null);
    setError(null);
  };

  useEffect(() => {
    if (openId && !evidence && !loading && !error) {
      openEvidence(openId);
    }
  }, [openId, evidence, loading, error, openEvidence]);

  if (vulns.length === 0) {
    return (
      <EmptyTabState
        icon={<TimelineIcon sx={{ fontSize: 36 }} />}
        title="No evidence trail yet."
        trigger="Each finding card here links to the exact tool output that produced its evidence (cited evidence_for strings, candidate tool_outputs, audit trail). Cards appear once the agent confirms a finding."
        sessionStatus={sessionStatus}
        counters={[
          { label: 'iterations', value: iterationCount ?? 0 },
          { label: 'hypotheses', value: hypothesisCount ?? 0 },
          { label: 'tool calls', value: toolCallCount ?? 0 },
        ]}
      />
    );
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <Box sx={{ px: 2, py: 1, borderBottom: '1px solid rgba(30,41,60,0.04)', flexShrink: 0 }}>
        <Typography variant="caption" sx={{ color: '#5a6478', fontSize: '0.7rem' }}>
          {vulns.length} finding{vulns.length === 1 ? '' : 's'} · click any card to see the evidence chain
        </Typography>
      </Box>
      <Box sx={{ flexGrow: 1, overflowY: 'auto', p: 1.5, display: 'flex', flexDirection: 'column', gap: 1 }}>
        {ordered.map(v => {
          const sevColor = SEVERITY_COLOURS[v.severity] ?? '#5a6478';
          const statusColor = STATUS_COLOURS[v.verification_status] ?? '#5a6478';
          return (
            <Box
              key={v.id}
              onClick={() => openEvidence(v.id)}
              sx={{
                cursor: 'pointer',
                px: 1.5,
                py: 1,
                border: '1px solid rgba(30,41,60,0.08)',
                borderLeft: `3px solid ${sevColor}`,
                borderRadius: 1,
                backgroundColor: '#ffffff',
                '&:hover': { backgroundColor: 'rgba(78,92,237,0.04)', borderColor: '#4e5ced' },
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5, flexWrap: 'wrap' }}>
                <Chip label={v.severity.toUpperCase()} size="small"
                  sx={{ backgroundColor: `${sevColor}1f`, color: sevColor, fontSize: '0.6rem', height: 16, fontWeight: 700 }} />
                <Chip label={v.verification_status} size="small"
                  sx={{ backgroundColor: `${statusColor}1f`, color: statusColor, fontSize: '0.6rem', height: 16 }} />
                {v.cvss_score != null && (
                  <Typography sx={{ color: '#5a6478', fontSize: '0.65rem', fontFamily: 'monospace' }}>
                    CVSS {v.cvss_score.toFixed(1)}
                  </Typography>
                )}
                <Typography sx={{ color: '#5a6478', fontSize: '0.62rem', fontFamily: 'monospace', ml: 'auto' }}>
                  conf {(v.confidence ?? 0).toFixed(2)}
                </Typography>
              </Box>
              <Typography sx={{ color: '#1a1f2e', fontSize: '0.78rem', fontWeight: 600, mb: 0.25 }}>
                {v.title}
              </Typography>
              {v.affected_service && (
                <Typography sx={{ color: '#5a6478', fontSize: '0.68rem', fontFamily: 'monospace' }}>
                  {v.affected_service}
                  {v.port != null ? `:${v.port}` : ''}
                </Typography>
              )}
            </Box>
          );
        })}
      </Box>

      <Dialog open={openId != null} onClose={close} maxWidth="md" fullWidth>
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          Evidence trail
          <Box sx={{ flexGrow: 1 }} />
          <Button size="small" onClick={close} startIcon={<CloseIcon />}>Close</Button>
        </DialogTitle>
        <DialogContent dividers>
          {loading && (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <CircularProgress size={16} />
              <Typography variant="caption">Loading evidence…</Typography>
            </Box>
          )}
          {error && (
            <Typography variant="caption" sx={{ color: '#f44336' }}>Error: {error}</Typography>
          )}
          {evidence && (
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              <Box>
                <Typography sx={{ fontSize: '1rem', fontWeight: 700, mb: 0.5 }}>{evidence.title}</Typography>
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                  <Chip label={evidence.severity} size="small"
                    sx={{ backgroundColor: `${SEVERITY_COLOURS[evidence.severity] ?? '#5a6478'}1f`, color: SEVERITY_COLOURS[evidence.severity] ?? '#5a6478' }} />
                  <Chip label={evidence.verification_status} size="small"
                    sx={{ backgroundColor: `${STATUS_COLOURS[evidence.verification_status] ?? '#5a6478'}1f`, color: STATUS_COLOURS[evidence.verification_status] ?? '#5a6478' }} />
                  {evidence.tool_used && <Chip label={`tool: ${evidence.tool_used}`} size="small" variant="outlined" />}
                  {evidence.technique_tag && <Chip label={evidence.technique_tag} size="small" variant="outlined" />}
                </Box>
              </Box>

              <Box>
                <Typography variant="subtitle2" sx={{ mb: 0.5 }}>Cited evidence</Typography>
                {evidence.evidence_for.length === 0 ? (
                  <Typography variant="caption" sx={{ color: '#8a93a6' }}>
                    No evidence_for cited — finding sits at "{evidence.verification_status}" because the
                    agent didn't back it with an oracle-verifiable observation.
                  </Typography>
                ) : (
                  <Box component="ul" sx={{ m: 0, pl: 2 }}>
                    {evidence.evidence_for.map((line, i) => (
                      <Box component="li" key={i} sx={{ fontSize: '0.82rem', color: '#1a1f2e', mb: 0.5 }}>
                        <code style={{ fontFamily: 'monospace', fontSize: '0.78rem' }}>{line}</code>
                      </Box>
                    ))}
                  </Box>
                )}
              </Box>

              {evidence.verification_output && (
                <Box>
                  <Typography variant="subtitle2" sx={{ mb: 0.5 }}>Audit trail</Typography>
                  <Box component="pre" sx={{
                    margin: 0, p: 1, fontSize: '0.72rem', fontFamily: 'monospace',
                    backgroundColor: '#f5f6f9', border: '1px solid #dfe3ec', borderRadius: 1,
                    whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: 180, overflow: 'auto',
                  }}>
                    {evidence.verification_output}
                  </Box>
                </Box>
              )}

              <Box>
                <Typography variant="subtitle2" sx={{ mb: 0.5 }}>
                  Candidate tool outputs {evidence.tool_used ? `(${evidence.tool_used})` : ''}
                </Typography>
                {evidence.candidate_tool_outputs.length === 0 ? (
                  <Typography variant="caption" sx={{ color: '#8a93a6' }}>
                    No tool_output rows found. Either the agent didn't record a tool for this
                    finding in its metadata, or the session's tool_outputs have been pruned.
                  </Typography>
                ) : (
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                    {evidence.candidate_tool_outputs.slice(0, 5).map((out, i) => (
                      <Box key={out._id ?? i} sx={{ border: '1px solid #dfe3ec', borderRadius: 1, p: 1 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                          <Typography sx={{ color: '#4e5ced', fontFamily: 'monospace', fontSize: '0.7rem', fontWeight: 700 }}>
                            ▶ {out.tool_name}
                          </Typography>
                          <Typography sx={{ color: '#8a93a6', fontSize: '0.65rem', ml: 'auto', fontFamily: 'monospace' }}>
                            {new Date(out.timestamp).toLocaleString()}
                          </Typography>
                        </Box>
                        <Box component="pre" sx={{
                          margin: 0, fontSize: '0.7rem', fontFamily: 'monospace',
                          whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: 200, overflow: 'auto',
                          backgroundColor: '#0a0a0a', color: '#c8e6c9', p: 1, borderRadius: 0.5,
                        }}>
                          {(out.raw_output ?? '').substring(0, 2400) || '(empty)'}
                        </Box>
                      </Box>
                    ))}
                  </Box>
                )}
              </Box>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={close}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default EvidenceFlowStrip;

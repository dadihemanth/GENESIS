// FindingDetailDialog — when an operator clicks a Finding row, this dialog
// explains how it was identified: which hypothesis the agent was testing,
// which custom script (or stock tool) produced the evidence, and whether
// the finding ties to a known CVE or is novel.
import React, { useEffect, useState } from 'react';
import {
  Dialog, DialogTitle, DialogContent, DialogActions, IconButton, Typography,
  Box, Chip, Button, CircularProgress, Alert, Tooltip, Collapse,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';
import LinkIcon from '@mui/icons-material/Link';
import LightbulbIcon from '@mui/icons-material/Lightbulb';
import ScienceIcon from '@mui/icons-material/Science';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';

import { vulnerabilitiesApi } from '../services/api';
import type { VulnIdentification, DrivingToolCall } from '../services/api';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#f44336', high: '#ff6d00', medium: '#ff9800', low: '#2979ff', info: '#5a6478',
};
const VERDICT_COLORS: Record<string, string> = {
  pass: '#4caf50', fail: '#f44336', partial: '#ff9800', no_oracle: '#8a93a6',
};

function copyToClipboard(text: string) {
  if (!text) return;
  try { navigator.clipboard?.writeText(text).catch(() => {}); } catch { /* */ }
}

function safeTime(ts: string): string {
  try { return new Date(ts).toLocaleTimeString(); } catch { return ts; }
}

interface Props {
  vulnId: string | null;
  onClose: () => void;
}

const ToolCallCard: React.FC<{ call: DrivingToolCall }> = ({ call }) => {
  const [expanded, setExpanded] = useState(false);
  const params = call.params || {};
  const code = String((params as { code?: string }).code || '');
  const template = String((params as { template_code?: string }).template_code || '');
  const variants = String((params as { variants?: string }).variants || '');
  const url = String((params as { url?: string }).url || '');
  const method = String((params as { method?: string }).method || 'GET');
  const body = String((params as { body?: string }).body || '');
  const rationale = String((params as { rationale?: string }).rationale || '');
  const verdict = (call.oracle_verdict || '').toLowerCase();
  const verdictColor = VERDICT_COLORS[verdict] || '#8a93a6';
  const accent = call.is_custom_script ? '#7c4dff' : '#5a6478';

  // Pick the primary payload string for the dark code-viewer pane
  const primaryPayload =
    call.tool_name === 'forge_runner' ? code :
    call.tool_name === 'payload_swarm' ? template :
    call.tool_name === 'ai_request_forge' ? `${method} ${url}\n${body ? '\n' + body : ''}` :
    JSON.stringify(params, null, 2);

  return (
    <Box sx={{
      borderRadius: 2,
      backgroundColor: '#ffffff',
      borderLeft: `3px solid ${accent}`,
      boxShadow: '0 1px 2px rgba(0,0,0,0.04)',
      mb: 1.5,
      overflow: 'hidden',
    }}>
      <Box sx={{ p: 1.5 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap', mb: 0.5 }}>
          {call.is_custom_script ? (
            <ScienceIcon sx={{ fontSize: 16, color: accent }} />
          ) : (
            <LinkIcon sx={{ fontSize: 16, color: accent }} />
          )}
          <Typography sx={{ fontWeight: 700, fontSize: '0.85rem', color: '#1a1f2e' }}>
            {call.tool_name}
          </Typography>
          {call.is_custom_script && (
            <Chip label="custom script" size="small"
              sx={{ height: 16, fontSize: '0.58rem', fontWeight: 700,
                    backgroundColor: 'rgba(124,77,255,0.15)', color: '#7c4dff' }} />
          )}
          <Box sx={{ flexGrow: 1 }} />
          <Typography sx={{ fontSize: '0.65rem', color: '#8a93a6', fontFamily: 'monospace' }}>
            {safeTime(call.timestamp)}
          </Typography>
          {call.duration_seconds != null && (
            <Typography sx={{ fontSize: '0.65rem', color: '#8a93a6', fontFamily: 'monospace' }}>
              {call.duration_seconds.toFixed(1)}s
            </Typography>
          )}
        </Box>

        {rationale && (
          <Typography sx={{ fontSize: '0.8rem', color: '#1a1f2e', fontStyle: 'italic', mb: 1 }}>
            “{rationale}”
          </Typography>
        )}

        <Box sx={{ display: 'flex', gap: 0.75, mb: 1, flexWrap: 'wrap' }}>
          {call.oracle_verdict && call.oracle_verdict !== 'no_oracle' && (
            <Chip
              icon={
                verdict === 'pass' ? <CheckCircleIcon sx={{ fontSize: '12px !important', color: `${verdictColor} !important` }} /> :
                verdict === 'fail' ? <CancelIcon sx={{ fontSize: '12px !important', color: `${verdictColor} !important` }} /> :
                <HelpOutlineIcon sx={{ fontSize: '12px !important', color: `${verdictColor} !important` }} />
              }
              label={`oracle: ${call.oracle_verdict}`}
              size="small"
              sx={{ height: 18, fontSize: '0.62rem', fontFamily: 'monospace', fontWeight: 700,
                    backgroundColor: `${verdictColor}1a`, color: verdictColor }}
            />
          )}
          <Tooltip title="Higher score = stronger evidence-overlap match">
            <Chip label={`match ${call.match_score}`} size="small"
              sx={{ height: 18, fontSize: '0.62rem', fontFamily: 'monospace',
                    backgroundColor: '#f4f6fb', color: '#5a6478' }} />
          </Tooltip>
        </Box>

        <Box sx={{ borderRadius: 1.5, overflow: 'hidden', border: '1px solid rgba(30,41,60,0.10)' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', px: 1.25, py: 0.5, backgroundColor: '#1a1f2e' }}>
            <Typography sx={{ flexGrow: 1, fontSize: '0.65rem', color: '#c3cad7', fontFamily: 'monospace', fontWeight: 600 }}>
              {expanded ? '▼ Payload' : '▶ Payload'} · {primaryPayload.length} chars
            </Typography>
            <Tooltip title="Copy">
              <IconButton size="small" onClick={(e) => { e.stopPropagation(); copyToClipboard(primaryPayload); }} sx={{ color: '#c3cad7', p: 0.25 }}>
                <ContentCopyIcon sx={{ fontSize: 13 }} />
              </IconButton>
            </Tooltip>
            <IconButton size="small" onClick={() => setExpanded(v => !v)} sx={{ color: '#c3cad7', p: 0.25 }}>
              {expanded ? <ExpandLessIcon sx={{ fontSize: 16 }} /> : <ExpandMoreIcon sx={{ fontSize: 16 }} />}
            </IconButton>
          </Box>
          <Collapse in={expanded}>
            <Box component="pre" sx={{
              m: 0, px: 1.5, py: 1, backgroundColor: '#0f1320', color: '#dfe3ec',
              fontSize: '0.7rem', fontFamily: 'monospace', overflow: 'auto', maxHeight: 280, whiteSpace: 'pre',
            }}>
              {primaryPayload || '(no payload captured)'}
            </Box>
            {variants && (
              <>
                <Box sx={{ px: 1.25, py: 0.5, backgroundColor: '#1a1f2e', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                  <Typography sx={{ fontSize: '0.65rem', color: '#c3cad7', fontFamily: 'monospace', fontWeight: 600 }}>
                    ▼ Variants spec
                  </Typography>
                </Box>
                <Box component="pre" sx={{
                  m: 0, px: 1.5, py: 1, backgroundColor: '#0f1320', color: '#dfe3ec',
                  fontSize: '0.65rem', fontFamily: 'monospace', overflow: 'auto', maxHeight: 200, whiteSpace: 'pre',
                }}>
                  {variants}
                </Box>
              </>
            )}
            {call.raw_output && (
              <>
                <Box sx={{ px: 1.25, py: 0.5, backgroundColor: '#f4f6fb' }}>
                  <Typography sx={{ fontSize: '0.65rem', color: '#5a6478', fontFamily: 'monospace', fontWeight: 600 }}>
                    ▼ Tool output
                  </Typography>
                </Box>
                <Box component="pre" sx={{
                  m: 0, px: 1.5, py: 1, backgroundColor: '#fafbfc', color: '#1a1f2e',
                  fontSize: '0.7rem', fontFamily: 'monospace', overflow: 'auto', maxHeight: 220, whiteSpace: 'pre',
                }}>
                  {call.raw_output.substring(0, 4000)}
                </Box>
              </>
            )}
            {call.oracle_reasons && call.oracle_reasons.length > 0 && (
              <Box sx={{ px: 1.5, py: 1, backgroundColor: '#fafbfc', borderTop: '1px solid rgba(30,41,60,0.06)' }}>
                <Typography sx={{ fontSize: '0.65rem', color: '#5a6478', fontFamily: 'monospace', fontWeight: 600, mb: 0.25 }}>
                  Oracle checks:
                </Typography>
                {call.oracle_reasons.map((r, i) => (
                  <Typography key={i} sx={{
                    fontSize: '0.7rem', fontFamily: 'monospace',
                    color: r.startsWith('PASS') ? '#4caf50' : r.startsWith('FAIL') ? '#f44336' : '#5a6478',
                  }}>{r}</Typography>
                ))}
              </Box>
            )}
          </Collapse>
        </Box>
      </Box>
    </Box>
  );
};

const FindingDetailDialog: React.FC<Props> = ({ vulnId, onClose }) => {
  const [data, setData] = useState<VulnIdentification | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!vulnId) {
      setData(null); setError(null); return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    setData(null);
    vulnerabilitiesApi.identification(vulnId)
      .then((d) => { if (!cancelled) setData(d); })
      .catch((err) => { if (!cancelled) setError(err instanceof Error ? err.message : String(err)); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [vulnId]);

  const open = vulnId !== null;
  const sev = (data?.severity || 'info').toLowerCase();
  const sevColor = SEVERITY_COLORS[sev] || '#5a6478';

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth scroll="paper">
      <DialogTitle sx={{ pr: 6, pb: 1, borderBottom: '1px solid rgba(30,41,60,0.06)' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
          {data && (
            <Chip label={sev.toUpperCase()} size="small"
              sx={{ height: 22, fontSize: '0.7rem', fontWeight: 800, fontFamily: 'monospace',
                    backgroundColor: `${sevColor}22`, color: sevColor, border: `1px solid ${sevColor}66` }} />
          )}
          <Typography sx={{ fontSize: '1rem', fontWeight: 700, color: '#1a1f2e', flexGrow: 1 }}>
            {data?.title || (loading ? 'Loading…' : 'Finding')}
          </Typography>
        </Box>
        <IconButton onClick={onClose} sx={{ position: 'absolute', right: 8, top: 8, color: '#5a6478' }}>
          <CloseIcon />
        </IconButton>
      </DialogTitle>

      <DialogContent sx={{ p: 0, backgroundColor: '#fafbfc' }}>
        {loading && (
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', py: 6, gap: 1 }}>
            <CircularProgress size={18} />
            <Typography sx={{ color: '#5a6478', fontSize: '0.85rem' }}>Tracing identification path…</Typography>
          </Box>
        )}
        {error && <Alert severity="error" sx={{ m: 2 }}>{error}</Alert>}
        {data && !loading && (
          <Box sx={{ p: 2 }}>
            {/* Top-line stats */}
            <Box sx={{ display: 'flex', gap: 0.75, flexWrap: 'wrap', mb: 2 }}>
              <Chip label={`status · ${data.verification_status}`} size="small"
                sx={{ height: 22, fontSize: '0.7rem', fontFamily: 'monospace',
                      backgroundColor: data.verification_status === 'confirmed' || data.verification_status === 'exploited'
                        ? 'rgba(76,175,80,0.15)' : 'rgba(138,147,166,0.10)',
                      color: data.verification_status === 'confirmed' || data.verification_status === 'exploited'
                        ? '#4caf50' : '#5a6478', fontWeight: 700 }} />
              <Chip label={`confidence · ${Math.round((data.confidence ?? 0) * 100)}%`} size="small"
                sx={{ height: 22, fontSize: '0.7rem', fontFamily: 'monospace',
                      backgroundColor: 'rgba(78,92,237,0.10)', color: '#4e5ced' }} />
              {data.endpoint && (
                <Chip label={data.endpoint} size="small"
                  sx={{ height: 22, fontSize: '0.7rem', fontFamily: 'monospace',
                        backgroundColor: '#f4f6fb', color: '#1a1f2e' }} />
              )}
              {data.technique_tag && (
                <Chip label={data.technique_tag} size="small"
                  sx={{ height: 22, fontSize: '0.7rem', fontFamily: 'monospace',
                        backgroundColor: '#f4f6fb', color: '#5a6478' }} />
              )}
              {data.mitre_techniques
                .filter((t): t is string => typeof t === 'string' && t.length > 0)
                .slice(0, 3).map(t => (
                <Chip key={t} label={t} size="small" component="a" clickable
                  href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}`}
                  target="_blank" rel="noopener noreferrer"
                  sx={{ height: 22, fontSize: '0.7rem', fontFamily: 'monospace',
                        backgroundColor: 'rgba(79,195,247,0.10)', color: '#4fc3f7' }} />
              ))}
            </Box>

            {/* §1 — Is this a known vulnerability? */}
            <Box sx={{
              p: 2, mb: 2, borderRadius: 2,
              backgroundColor: data.is_known ? 'rgba(78,92,237,0.06)' : 'rgba(255,152,0,0.06)',
              border: `1px solid ${data.is_known ? 'rgba(78,92,237,0.20)' : 'rgba(255,152,0,0.20)'}`,
            }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                <Typography sx={{ fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: 0.5, color: '#8a93a6', fontWeight: 700 }}>
                  Is this a known vulnerability?
                </Typography>
                <Chip label={data.is_known ? 'YES — known' : data.is_zero_day ? 'NO — novel / zero-day' : 'NO — not a known CVE'}
                  size="small"
                  sx={{ height: 20, fontSize: '0.7rem', fontWeight: 800,
                        backgroundColor: data.is_known ? 'rgba(78,92,237,0.20)' : 'rgba(255,152,0,0.20)',
                        color: data.is_known ? '#4e5ced' : '#ff9800' }} />
              </Box>
              <Typography sx={{ fontSize: '0.85rem', color: '#1a1f2e', lineHeight: 1.5 }}>
                {data.known_explanation}
              </Typography>
              {data.cve_ids.length > 0 && (
                <Box sx={{ display: 'flex', gap: 0.5, mt: 1, flexWrap: 'wrap' }}>
                  {data.cve_ids.map(cve => (
                    <Chip key={cve} label={cve} size="small" component="a" clickable
                      href={`https://nvd.nist.gov/vuln/detail/${cve}`} target="_blank" rel="noopener noreferrer"
                      icon={<LinkIcon sx={{ fontSize: '11px !important' }} />}
                      sx={{ height: 22, fontSize: '0.7rem', fontFamily: 'monospace', fontWeight: 700,
                            backgroundColor: 'rgba(78,92,237,0.15)', color: '#4e5ced',
                            '& .MuiChip-icon': { color: '#4e5ced' } }} />
                  ))}
                </Box>
              )}
            </Box>

            {/* §2 — Driving hypothesis */}
            <Typography sx={{ fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: 0.5, color: '#8a93a6', fontWeight: 700, mb: 1, display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <LightbulbIcon sx={{ fontSize: 14 }} /> Driving hypothesis
            </Typography>
            {data.driving_hypothesis ? (
              <Box sx={{
                p: 2, mb: 2, borderRadius: 2, backgroundColor: '#ffffff',
                borderLeft: '3px solid #ffd54f', boxShadow: '0 1px 2px rgba(0,0,0,0.04)',
              }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, mb: 1, flexWrap: 'wrap' }}>
                  <Chip label={data.driving_hypothesis.hyp_id || 'h?'} size="small"
                    sx={{ height: 18, fontSize: '0.62rem', fontFamily: 'monospace', fontWeight: 700,
                          backgroundColor: 'rgba(255,213,79,0.20)', color: '#a17900' }} />
                  <Chip label={data.driving_hypothesis.status} size="small"
                    sx={{ height: 18, fontSize: '0.62rem', fontFamily: 'monospace', fontWeight: 700,
                          backgroundColor: data.driving_hypothesis.status === 'confirmed' ? 'rgba(76,175,80,0.15)' : 'rgba(138,147,166,0.10)',
                          color: data.driving_hypothesis.status === 'confirmed' ? '#4caf50' : '#5a6478' }} />
                  <Chip label={`conf ${Math.round((data.driving_hypothesis.confidence ?? 0) * 100)}%`} size="small"
                    sx={{ height: 18, fontSize: '0.62rem', fontFamily: 'monospace',
                          backgroundColor: 'rgba(78,92,237,0.10)', color: '#4e5ced' }} />
                </Box>
                <Typography sx={{ fontSize: '0.9rem', color: '#1a1f2e', lineHeight: 1.5, mb: 1, fontWeight: 500 }}>
                  “{data.driving_hypothesis.statement}”
                </Typography>
                {data.driving_hypothesis.next_test && (
                  <Typography sx={{ fontSize: '0.78rem', color: '#5a6478', mb: 0.5 }}>
                    <strong style={{ color: '#1a1f2e' }}>Test plan:</strong> {data.driving_hypothesis.next_test}
                  </Typography>
                )}
                {data.driving_hypothesis.falsification_criteria && (
                  <Typography sx={{ fontSize: '0.78rem', color: '#5a6478' }}>
                    <strong style={{ color: '#1a1f2e' }}>Would have been falsified by:</strong> {data.driving_hypothesis.falsification_criteria}
                  </Typography>
                )}
              </Box>
            ) : (
              <Box sx={{ p: 1.5, mb: 2, borderRadius: 2, backgroundColor: '#f4f6fb' }}>
                <Typography sx={{ fontSize: '0.8rem', color: '#5a6478', fontStyle: 'italic' }}>
                  No matching hypothesis recorded — this finding came from a direct tool result without a journaled hypothesis. The agent should always emit a hypothesis first; if you see this often, the agent is taking a shortcut.
                </Typography>
              </Box>
            )}

            {/* §3 — How was it identified? (driving tool calls) */}
            <Typography sx={{ fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: 0.5, color: '#8a93a6', fontWeight: 700, mb: 1, display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <ScienceIcon sx={{ fontSize: 14 }} /> How was this identified?
            </Typography>
            {data.driving_tool_calls.length > 0 ? (
              <>
                <Typography sx={{ fontSize: '0.78rem', color: '#5a6478', mb: 1 }}>
                  {data.driving_tool_calls.filter(c => c.is_custom_script).length > 0
                    ? `Identified by ${data.driving_tool_calls.filter(c => c.is_custom_script).length} custom script invocation${data.driving_tool_calls.filter(c => c.is_custom_script).length === 1 ? '' : 's'} the agent authored — not a stock scanner. The matched calls below are ranked by how strongly their output overlaps the cited evidence.`
                    : `Identified by stock tool output. Ranked by evidence-overlap score.`}
                </Typography>
                {data.driving_tool_calls.map(c => <ToolCallCard key={c.id} call={c} />)}
              </>
            ) : (
              <Box sx={{ p: 1.5, mb: 2, borderRadius: 2, backgroundColor: '#f4f6fb' }}>
                <Typography sx={{ fontSize: '0.8rem', color: '#5a6478', fontStyle: 'italic' }}>
                  No matching tool output found. The evidence_for entries didn't substring-match any captured tool result — possibly evidence drawn from agent reasoning rather than literal tool output.
                </Typography>
              </Box>
            )}

            {/* §4 — Cited evidence */}
            {data.evidence_for.length > 0 && (
              <>
                <Typography sx={{ fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: 0.5, color: '#8a93a6', fontWeight: 700, mb: 1, mt: 2 }}>
                  Cited evidence
                </Typography>
                <Box sx={{ p: 1.5, borderRadius: 2, backgroundColor: '#ffffff', boxShadow: '0 1px 2px rgba(0,0,0,0.04)' }}>
                  {data.evidence_for.map((e, i) => (
                    <Typography key={i} sx={{
                      fontSize: '0.78rem', fontFamily: 'monospace', color: '#1a1f2e',
                      mb: 0.5, pl: 1, borderLeft: '2px solid rgba(76,175,80,0.4)',
                      whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                    }}>
                      {e}
                    </Typography>
                  ))}
                </Box>
              </>
            )}
          </Box>
        )}
      </DialogContent>
      <DialogActions sx={{ borderTop: '1px solid rgba(30,41,60,0.06)' }}>
        <Button onClick={onClose} sx={{ textTransform: 'none' }}>Close</Button>
      </DialogActions>
    </Dialog>
  );
};

export default FindingDetailDialog;

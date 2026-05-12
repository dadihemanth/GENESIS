/**
 * v7.x — Novel Vulnerabilities tab.
 *
 * Sandbox-verified PoC findings only: verification_status in
 * {confirmed, exploited} AND tool_used in {forge_runner, payload_swarm,
 * ai_request_forge}, OR is_zero_day=true. Same definition the CSV
 * `novel` column uses.
 */
import React, { useCallback, useEffect, useState } from 'react';
import {
  Accordion, AccordionDetails, AccordionSummary,
  Box, Button, Chip, CircularProgress, IconButton, Tooltip, Typography,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import RefreshIcon from '@mui/icons-material/Refresh';
import StarIcon from '@mui/icons-material/Star';
import { vulnerabilitiesApi } from '../services/api';

type NovelData = Awaited<ReturnType<typeof vulnerabilitiesApi.listNovel>>;
type NovelItem = NovelData['items'][number];

interface Props { sessionId: string; }

const SEV_COLOR: Record<string, string> = {
  critical: '#f44336', high: '#ff6d00', medium: '#ff9800',
  low: '#2979ff', info: '#5a6478',
};

const NovelVulnerabilitiesPanel: React.FC<Props> = ({ sessionId }) => {
  const [data, setData] = useState<NovelData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  const refresh = useCallback(() => {
    setLoading(true);
    vulnerabilitiesApi.listNovel(sessionId)
      .then(d => { setData(d); setError(null); })
      .catch(() => setError('Failed to load novel findings.'))
      .finally(() => setLoading(false));
  }, [sessionId]);

  useEffect(() => { refresh(); }, [refresh]);

  if (loading && !data) {
    return <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}><CircularProgress size={28} /></Box>;
  }
  if (!data) {
    return (
      <Box sx={{ p: 3, textAlign: 'center' }}>
        <Typography sx={{ color: '#8a93a6', fontSize: '0.85rem' }}>{error ?? 'No novel data.'}</Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 2 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 1.5, gap: 1 }}>
        <StarIcon sx={{ color: '#b8740c' }} />
        <Typography sx={{ fontSize: '1rem', fontWeight: 600 }}>Novel Vulnerabilities</Typography>
        <Chip size="small" label={`${data.novel_count} / ${data.total_findings}`} sx={{ fontSize: '0.7rem' }} />
        <Tooltip title="Refresh"><IconButton size="small" sx={{ ml: 'auto' }} onClick={refresh}><RefreshIcon fontSize="small" /></IconButton></Tooltip>
      </Box>

      <Box sx={{ mb: 2, p: 1.25, borderRadius: 1, backgroundColor: 'rgba(184,116,12,0.07)', border: '1px solid rgba(184,116,12,0.25)' }}>
        <Typography sx={{ fontSize: '0.78rem', color: '#3a4258' }}>
          <strong>What counts as novel:</strong> verification_status in {`{confirmed, exploited}`} AND
          {' '}tool_used includes <code>forge_runner</code> / <code>payload_swarm</code> / <code>ai_request_forge</code>
          {' '}(sandbox-executed PoC). OR <code>is_zero_day=true</code>. These are the findings backed by an
          executed exploit, not just scanner output.
        </Typography>
      </Box>

      {data.items.length === 0 ? (
        <Box sx={{ p: 3, textAlign: 'center' }}>
          <StarIcon sx={{ fontSize: 40, color: '#dfe3ec', mb: 1 }} />
          <Typography sx={{ color: '#8a93a6', fontSize: '0.85rem' }}>
            No sandbox-verified PoC findings yet.
          </Typography>
          <Typography sx={{ color: '#5a6478', fontSize: '0.75rem', mt: 0.5, maxWidth: 540, mx: 'auto' }}>
            Run a session with <code>scan_profile=deep_research</code> — its mandatory verification step
            forces every confirmed finding through forge_runner / payload_swarm.
          </Typography>
        </Box>
      ) : (
        data.items.map(item => {
          const isOpen = expanded === item.id;
          return (
            <Accordion
              key={item.id}
              expanded={isOpen}
              onChange={() => setExpanded(isOpen ? null : item.id)}
              disableGutters
              sx={{ borderRadius: 1, mb: 1, '&:before': { display: 'none' } }}
            >
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: 'flex', flex: 1, alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                  <Chip
                    size="small"
                    label={item.severity.toUpperCase()}
                    sx={{
                      backgroundColor: SEV_COLOR[item.severity] ?? '#5a6478',
                      color: 'white', fontWeight: 700, fontSize: '0.65rem',
                    }}
                  />
                  {item.is_zero_day && (
                    <Chip size="small" label="0-DAY" sx={{ backgroundColor: '#b53030', color: 'white', fontWeight: 700, fontSize: '0.65rem' }} />
                  )}
                  {item.cvss_score !== null && (
                    <Chip size="small" variant="outlined" label={`CVSS ${item.cvss_score.toFixed(1)}`} sx={{ fontSize: '0.65rem' }} />
                  )}
                  <Typography sx={{ fontSize: '0.85rem', flex: 1, minWidth: 200, color: '#1a1f2c', fontWeight: 600 }}>
                    {item.title}
                  </Typography>
                  <Chip size="small" variant="outlined" label={item.tool_used || 'forge_runner'} sx={{ fontSize: '0.65rem' }} />
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Box sx={{ fontSize: '0.78rem', color: '#3a4258' }}>
                  <Box sx={{ mb: 1 }}>
                    <strong>Target:</strong> {item.affected_service} {item.port ? `:${item.port}` : ''}
                    {item.endpoint && <> · <code>{item.endpoint}</code></>}
                  </Box>
                  {item.cve_ids.length > 0 && (
                    <Box sx={{ mb: 1 }}>
                      <strong>CVE:</strong> {item.cve_ids.join(', ')}
                    </Box>
                  )}
                  {item.mitre_techniques.length > 0 && (
                    <Box sx={{ mb: 1 }}>
                      <strong>MITRE:</strong> {item.mitre_techniques.join(', ')}
                    </Box>
                  )}
                  {item.remediation && (
                    <Box sx={{ mb: 1 }}>
                      <strong>Remediation:</strong> {item.remediation}
                    </Box>
                  )}
                  {item.exploit_code && (
                    <Box sx={{ mt: 1.5 }}>
                      <Typography sx={{ fontSize: '0.75rem', fontWeight: 600, mb: 0.5 }}>Exploit / PoC</Typography>
                      <Box component="pre" sx={{
                        fontSize: '0.72rem', backgroundColor: '#0e1119', color: '#cfd6e4',
                        padding: 1.5, borderRadius: 1, whiteSpace: 'pre-wrap',
                        wordBreak: 'break-word', maxHeight: 280, overflowY: 'auto', margin: 0,
                      }}>
                        {item.exploit_code}
                      </Box>
                    </Box>
                  )}
                </Box>
              </AccordionDetails>
            </Accordion>
          );
        })
      )}
    </Box>
  );
};

export default NovelVulnerabilitiesPanel;

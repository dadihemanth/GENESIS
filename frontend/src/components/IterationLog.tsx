// Iterations tab — events grouped by iteration number, all expanded by default.
// Shows the full prose thoughts, every tool call (with raw output), every
// hypothesis touched, and every vulnerability landed in that iteration.
import React, { useMemo } from 'react';
import { Box, Chip, Typography, Accordion, AccordionSummary, AccordionDetails } from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';

import type { AgentThought, ToolOutput, Hypothesis, Vulnerability } from '../types';
import { splitAgentPrefix, stripJsonBlocks, humanizeTool } from '../utils/humanize';

interface IterationBucket {
  n: number;
  thoughts: AgentThought[];
  tools: ToolOutput[];
  hypotheses: Hypothesis[];
  vulns: Vulnerability[];
  startTs: string;
  endTs: string;
}

interface Props {
  thoughts: AgentThought[];
  toolOutputs: ToolOutput[];
  hypotheses: Hypothesis[];
  vulns: Vulnerability[];
}

// Rough rule for assigning a tool/vuln/hypothesis to an iteration: find the
// most recent thought whose timestamp is <= the event's timestamp, take its
// iteration. Falls back to iteration 0 when no thought exists yet.
function attachIterations(
  thoughts: AgentThought[],
  events: Array<{ timestamp: string; ref: ToolOutput | Hypothesis | Vulnerability; kind: 'tool' | 'hyp' | 'vuln' }>,
): Map<number, { tools: ToolOutput[]; hypotheses: Hypothesis[]; vulns: Vulnerability[] }> {
  const sortedThoughts = [...thoughts].sort((a, b) => String(a.timestamp ?? '').localeCompare(String(b.timestamp ?? '')));
  const buckets = new Map<number, { tools: ToolOutput[]; hypotheses: Hypothesis[]; vulns: Vulnerability[] }>();

  function bucket(n: number) {
    if (!buckets.has(n)) buckets.set(n, { tools: [], hypotheses: [], vulns: [] });
    return buckets.get(n)!;
  }

  for (const ev of events) {
    let iter = 0;
    for (const t of sortedThoughts) {
      if (t.timestamp <= ev.timestamp) iter = t.iteration;
      else break;
    }
    if (ev.kind === 'tool') bucket(iter).tools.push(ev.ref as ToolOutput);
    else if (ev.kind === 'hyp') bucket(iter).hypotheses.push(ev.ref as Hypothesis);
    else if (ev.kind === 'vuln') bucket(iter).vulns.push(ev.ref as Vulnerability);
  }
  return buckets;
}

const safeTime = (ts: string): string => {
  try { return new Date(ts).toLocaleTimeString(); } catch { return ts; }
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#f44336', high: '#ff6d00', medium: '#ff9800', low: '#2979ff', info: '#5a6478',
};

const IterationLog: React.FC<Props> = ({ thoughts, toolOutputs, hypotheses, vulns }) => {
  const buckets = useMemo<IterationBucket[]>(() => {
    if (thoughts.length === 0 && toolOutputs.length === 0) return [];

    const byIter = new Map<number, IterationBucket>();
    for (const t of thoughts) {
      if (!byIter.has(t.iteration)) {
        byIter.set(t.iteration, { n: t.iteration, thoughts: [], tools: [], hypotheses: [], vulns: [], startTs: t.timestamp, endTs: t.timestamp });
      }
      const b = byIter.get(t.iteration)!;
      b.thoughts.push(t);
      if (t.timestamp < b.startTs) b.startTs = t.timestamp;
      if (t.timestamp > b.endTs) b.endTs = t.timestamp;
    }

    const events: Array<{ timestamp: string; ref: ToolOutput | Hypothesis | Vulnerability; kind: 'tool' | 'hyp' | 'vuln' }> = [
      ...toolOutputs.map(t => ({ timestamp: t.timestamp, ref: t, kind: 'tool' as const })),
      ...hypotheses.map(h => ({ timestamp: h.updated_at, ref: h, kind: 'hyp' as const })),
      ...vulns.map(v => ({ timestamp: v.created_at, ref: v, kind: 'vuln' as const })),
    ];
    const attached = attachIterations(thoughts, events);
    for (const [n, attach] of attached) {
      if (!byIter.has(n)) {
        byIter.set(n, { n, thoughts: [], tools: [], hypotheses: [], vulns: [], startTs: '', endTs: '' });
      }
      const b = byIter.get(n)!;
      b.tools.push(...attach.tools);
      b.hypotheses.push(...attach.hypotheses);
      b.vulns.push(...attach.vulns);
    }

    return Array.from(byIter.values()).sort((a, b) => a.n - b.n);
  }, [thoughts, toolOutputs, hypotheses, vulns]);

  if (buckets.length === 0) {
    return (
      <Box sx={{ p: 4, textAlign: 'center' }}>
        <Typography variant="caption" sx={{ color: '#c3cad7' }}>
          No iterations recorded yet. Each iteration is one decision-loop pass —
          they fill in as the session runs.
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ flexGrow: 1, overflowY: 'auto', p: 1, backgroundColor: '#fafbfc' }}>
      {buckets.map(b => {
        const dur = (b.startTs && b.endTs && b.startTs !== b.endTs)
          ? `${Math.round((new Date(b.endTs).getTime() - new Date(b.startTs).getTime()) / 1000)}s`
          : null;
        const headerSeverity = b.vulns.reduce<string>((acc, v) =>
          ['critical', 'high', 'medium', 'low', 'info'].indexOf(v.severity) <
          ['critical', 'high', 'medium', 'low', 'info'].indexOf(acc || 'info')
            ? v.severity : acc, '');
        const headerColor = headerSeverity ? SEVERITY_COLORS[headerSeverity] : '#4e5ced';
        return (
          <Accordion
            key={b.n}
            defaultExpanded
            disableGutters
            sx={{ mb: 1, borderLeft: `3px solid ${headerColor}`, '&:before': { display: 'none' } }}
          >
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap', flexGrow: 1 }}>
                <Typography sx={{ fontSize: '0.85rem', fontWeight: 700, color: '#1a1f2e' }}>
                  Iteration {b.n}
                </Typography>
                {b.startTs && (
                  <Typography sx={{ color: '#5a6478', fontSize: '0.7rem', fontFamily: 'monospace' }}>
                    {safeTime(b.startTs)}
                  </Typography>
                )}
                {dur && (
                  <Chip label={dur} size="small"
                    sx={{ backgroundColor: 'rgba(94,103,144,0.10)', color: '#5e6790', fontSize: '0.6rem', height: 16 }} />
                )}
                <Box sx={{ flexGrow: 1 }} />
                {b.tools.length > 0 && (
                  <Chip label={`${b.tools.length} tool${b.tools.length === 1 ? '' : 's'}`} size="small"
                    sx={{ backgroundColor: 'rgba(78,92,237,0.10)', color: '#4e5ced', fontSize: '0.6rem', height: 16 }} />
                )}
                {b.hypotheses.length > 0 && (
                  <Chip label={`${b.hypotheses.length} hyp`} size="small"
                    sx={{ backgroundColor: 'rgba(255,152,0,0.10)', color: '#ff9800', fontSize: '0.6rem', height: 16 }} />
                )}
                {b.vulns.length > 0 && (
                  <Chip label={`${b.vulns.length} finding${b.vulns.length === 1 ? '' : 's'}`} size="small"
                    sx={{ backgroundColor: `${headerColor}1a`, color: headerColor, fontSize: '0.6rem', height: 16, fontWeight: 700 }} />
                )}
              </Box>
            </AccordionSummary>
            <AccordionDetails sx={{ pt: 0, pb: 1.5 }}>
              {b.thoughts.length > 0 && (
                <Box sx={{ mb: 1.5 }}>
                  <Typography sx={{ fontSize: '0.65rem', color: '#5a6478', fontWeight: 700, mb: 0.5 }}>THOUGHTS</Typography>
                  {b.thoughts.map((t, i) => {
                    const { agent, body } = splitAgentPrefix(t.thought);
                    return (
                      <Box key={i} sx={{ pl: 1.5, borderLeft: '2px solid rgba(78,92,237,0.15)', mb: 0.75 }}>
                        {agent && (
                          <Chip label={agent} size="small"
                            sx={{ backgroundColor: 'rgba(78,92,237,0.10)', color: '#4e5ced', fontSize: '0.58rem', height: 14, mb: 0.25 }} />
                        )}
                        <Typography sx={{ color: '#1a1f2e', fontSize: '0.76rem', whiteSpace: 'pre-wrap', wordBreak: 'break-word', lineHeight: 1.45 }}>
                          {stripJsonBlocks(body)}
                        </Typography>
                      </Box>
                    );
                  })}
                </Box>
              )}

              {b.tools.length > 0 && (
                <Box sx={{ mb: 1.5 }}>
                  <Typography sx={{ fontSize: '0.65rem', color: '#5a6478', fontWeight: 700, mb: 0.5 }}>TOOL CALLS</Typography>
                  {b.tools.map((t, i) => (
                    <Box key={i} sx={{ pl: 1.5, mb: 0.75 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 0.25, flexWrap: 'wrap' }}>
                        <Typography sx={{ color: '#4e5ced', fontSize: '0.74rem', fontFamily: 'monospace', fontWeight: 700 }}>
                          ▶ {t.tool_name}
                        </Typography>
                        <Typography sx={{ color: '#5a6478', fontSize: '0.7rem', fontStyle: 'italic' }}>
                          {humanizeTool(t.tool_name)}
                        </Typography>
                        {t.duration_seconds != null && (
                          <Typography sx={{ color: '#8a93a6', fontSize: '0.62rem', fontFamily: 'monospace', ml: 'auto' }}>
                            {t.duration_seconds.toFixed(1)}s
                          </Typography>
                        )}
                      </Box>
                      {t.raw_output && (
                        <Box component="pre" sx={{ m: 0, p: 0.75, fontFamily: 'monospace', fontSize: '0.66rem', whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: 200, overflowY: 'auto', backgroundColor: '#0a0a0a', color: '#c8e6c9', borderRadius: 0.5 }}>
                          {t.raw_output.substring(0, 2400)}{t.raw_output.length > 2400 ? '\n...[truncated]' : ''}
                        </Box>
                      )}
                    </Box>
                  ))}
                </Box>
              )}

              {b.hypotheses.length > 0 && (
                <Box sx={{ mb: 1.5 }}>
                  <Typography sx={{ fontSize: '0.65rem', color: '#5a6478', fontWeight: 700, mb: 0.5 }}>HYPOTHESES</Typography>
                  {b.hypotheses.map((h, i) => {
                    const c = h.status === 'confirmed' ? '#4caf50' : h.status === 'ruled_out' ? '#f44336' : '#ff9800';
                    return (
                      <Box key={i} sx={{ pl: 1.5, borderLeft: `2px solid ${c}`, mb: 0.5 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, flexWrap: 'wrap' }}>
                          <Chip label={h.status} size="small"
                            sx={{ backgroundColor: `${c}1a`, color: c, fontSize: '0.58rem', height: 14, fontWeight: 700 }} />
                          <Typography sx={{ color: '#5a6478', fontSize: '0.6rem', fontFamily: 'monospace' }}>{h.hyp_id} · conf {h.confidence.toFixed(2)}</Typography>
                        </Box>
                        <Typography sx={{ color: '#1a1f2e', fontSize: '0.76rem' }}>{h.statement}</Typography>
                      </Box>
                    );
                  })}
                </Box>
              )}

              {b.vulns.length > 0 && (
                <Box>
                  <Typography sx={{ fontSize: '0.65rem', color: '#5a6478', fontWeight: 700, mb: 0.5 }}>FINDINGS THIS ITERATION</Typography>
                  {b.vulns.map((v, i) => {
                    const c = SEVERITY_COLORS[v.severity] ?? '#5a6478';
                    return (
                      <Box key={i} sx={{ pl: 1.5, borderLeft: `3px solid ${c}`, mb: 0.5 }}>
                        <Chip label={v.severity.toUpperCase()} size="small"
                          sx={{ backgroundColor: `${c}1a`, color: c, fontSize: '0.6rem', height: 16, fontWeight: 700, mr: 0.5 }} />
                        <Chip label={v.verification_status} size="small"
                          sx={{ backgroundColor: 'rgba(94,103,144,0.10)', color: '#5e6790', fontSize: '0.58rem', height: 14, mr: 0.5 }} />
                        <Typography component="span" sx={{ color: '#1a1f2e', fontSize: '0.78rem', fontWeight: 600 }}>
                          {v.title}
                        </Typography>
                      </Box>
                    );
                  })}
                </Box>
              )}
            </AccordionDetails>
          </Accordion>
        );
      })}
    </Box>
  );
};

export default IterationLog;

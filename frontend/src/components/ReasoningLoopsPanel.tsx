/**
 * v7.0 (Tier-9) — Reasoning Loops panel.
 *
 * Lists every deliberation loop fired during the session. Drill-in shows
 * each tick (state snapshot diff, branches considered, chosen path, tokens).
 *
 * Subscribes to `loop_started`, `loop_tick`, `loop_finished` WS events so the
 * tab streams live without re-fetching. Falls back to a manual refresh on
 * open.
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Accordion, AccordionDetails, AccordionSummary,
  Box, Button, Chip, CircularProgress, Divider, IconButton,
  LinearProgress, Tooltip, Typography,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import PsychologyAltIcon from '@mui/icons-material/PsychologyAlt';
import RefreshIcon from '@mui/icons-material/Refresh';
import { loopsApi, type ReasoningLoop, type ReasoningLoopTick } from '../services/api';

interface Props {
  sessionId: string;
  // Live deltas from WebSocket — parent passes them in.
  liveStartedIds: string[];
  liveTicks: Record<string, ReasoningLoopTick[]>;
  liveFinished: Record<string, { status: string }>;
}

const STATUS_COLOR: Record<string, string> = {
  running: '#4e5ced',
  complete: '#137a4e',
  aborted: '#b53030',
};

const ReasoningLoopsPanel: React.FC<Props> = ({ sessionId, liveStartedIds, liveTicks, liveFinished }) => {
  const [loops, setLoops] = useState<ReasoningLoop[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | false>(false);
  const [detail, setDetail] = useState<Record<string, ReasoningLoop>>({});

  const refresh = useCallback(() => {
    setLoading(true);
    loopsApi.listForSession(sessionId)
      .then(data => { setLoops(data.loops || []); setError(null); })
      .catch(() => setError('Failed to load reasoning loops.'))
      .finally(() => setLoading(false));
  }, [sessionId]);

  useEffect(() => { refresh(); }, [refresh]);

  useEffect(() => {
    if (loops.length > 0 || liveStartedIds.length > 0) return;
    const interval = window.setInterval(refresh, 10000);
    return () => window.clearInterval(interval);
  }, [loops.length, liveStartedIds.length, refresh]);

  // Whenever a new loop is started live, re-fetch the list so its summary card
  // appears immediately (tick deltas merge separately for already-listed loops).
  useEffect(() => {
    if (liveStartedIds.length > 0) refresh();
  }, [liveStartedIds.length, refresh]);

  // Apply live finished status onto the cached list without a re-fetch.
  const finalizedLoops: ReasoningLoop[] = useMemo(() => {
    return loops.map(l => {
      const fin = liveFinished[l.loop_id];
      if (fin) return { ...l, status: (fin.status as ReasoningLoop['status']) ?? l.status };
      return l;
    });
  }, [loops, liveFinished]);

  const handleAccordion = useCallback((loopId: string) => async (_: React.SyntheticEvent, isOpen: boolean) => {
    setExpanded(isOpen ? loopId : false);
    if (isOpen && !detail[loopId]) {
      try {
        const full = await loopsApi.getDetail(loopId);
        setDetail(prev => ({ ...prev, [loopId]: full }));
      } catch {
        // Live ticks will still render even without backend detail.
      }
    }
  }, [detail]);

  if (loading && loops.length === 0) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
        <CircularProgress size={28} />
      </Box>
    );
  }

  if (!loading && finalizedLoops.length === 0) {
    return (
      <Box sx={{ p: 3, textAlign: 'center' }}>
        <PsychologyAltIcon sx={{ fontSize: 40, color: '#dfe3ec', mb: 1 }} />
        <Typography sx={{ color: '#8a93a6', fontSize: '0.85rem' }}>
          No reasoning loops have fired yet.
        </Typography>
        <Typography sx={{ color: '#5a6478', fontSize: '0.75rem', mt: 0.5, maxWidth: 520, mx: 'auto' }}>
          v7.0 reasoning loops (T155–T166) fire when the agent calls the
          <code style={{ margin: '0 4px' }}>deliberate</code>
          tool. All 12 loops are live: code-intent, invariant-tracker, causal-trace,
          counterfactual, long-context-code, hypothesis-decomp, plus the four exploit
          loops (rop_composition, chain_composer, heap_layout, self_correcting).
          The orchestrator nudges the agent toward
          <code style={{ margin: '0 4px' }}>deliberate</code>
          at iteration 5 and escalates to mandatory at iteration 8 — start a fresh
          session to see loops fire.
        </Typography>
        {error && (
          <Typography sx={{ color: '#b53030', fontSize: '0.75rem', mt: 1 }}>{error}</Typography>
        )}
        <Button size="small" startIcon={<RefreshIcon sx={{ fontSize: 16 }} />} onClick={refresh} sx={{ mt: 2, fontSize: '0.75rem', textTransform: 'none' }}>
          Refresh
        </Button>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 2, overflowY: 'auto', height: '100%' }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
        <PsychologyAltIcon sx={{ color: '#4e5ced', fontSize: 20 }} />
        <Typography sx={{ fontWeight: 700, fontSize: '0.9rem', color: '#1a1f2e' }}>
          Reasoning Loops (v7.0)
        </Typography>
        <Chip label={`${finalizedLoops.length} loop${finalizedLoops.length === 1 ? '' : 's'}`} size="small" sx={{ ml: 'auto', fontSize: '0.7rem' }} />
        <Tooltip title="Refresh">
          <IconButton size="small" onClick={refresh}><RefreshIcon sx={{ fontSize: 16 }} /></IconButton>
        </Tooltip>
      </Box>
      <Box sx={{ mb: 2, p: 1.25, borderRadius: 1, backgroundColor: 'rgba(78,92,237,0.06)', border: '1px solid rgba(78,92,237,0.15)' }}>
        <Typography sx={{ fontSize: '0.78rem', color: '#1a1f2e', fontWeight: 600, mb: 0.5 }}>
          What this tab shows (in plain English)
        </Typography>
        <Typography sx={{ fontSize: '0.74rem', color: '#3a4258', lineHeight: 1.5 }}>
          When the agent hits a wall — a WAF blocking a payload, a hypothesis it can&apos;t confirm, or
          a planning step it can&apos;t reason through with one tool call — it invokes a structured
          <strong> reasoning loop</strong>. Each loop runs a few short LLM ticks, picks a path, and
          records what it considered. Useful loops:
          <strong> counterfactual</strong> (try alternate attack paths around an obstacle),
          <strong> hypothesis_decomp</strong> (break a vague hypothesis into atomic claims),
          <strong> code_intent</strong> (Heartbleed-style review of a focal function),
          <strong> chain_composer</strong> (stitch primitives into an end-to-end chain).
          Each card below: which loop, how many ticks it ran, the tokens it spent, and per-tick
          reasoning + chosen branch. <em>Empty Loops tab usually means the agent never called
          <code style={{ marginLeft: 4, marginRight: 4 }}>deliberate(loop_type=...)</code> — try
          a deeper scan, or wait for the iter-8 backstop to fire.</em>
        </Typography>
      </Box>

      {finalizedLoops.map(loop => {
        const fullDetail = detail[loop.loop_id];
        const liveTickList = liveTicks[loop.loop_id] || [];
        // Merge live ticks with persisted ticks; persisted is authoritative.
        const persistedTicks = (fullDetail?.ticks ?? []) as ReasoningLoopTick[];
        const persistedIters = new Set(persistedTicks.map(t => t.iteration));
        const tickList: ReasoningLoopTick[] = [
          ...persistedTicks,
          ...liveTickList.filter(t => !persistedIters.has(t.iteration)),
        ].sort((a, b) => a.iteration - b.iteration);

        const tickCount = Math.max(loop.tick_count, tickList.length);
        const tokensSpent = fullDetail?.tokens_spent ?? loop.tokens_spent;

        return (
          <Accordion
            key={loop.loop_id}
            expanded={expanded === loop.loop_id}
            onChange={handleAccordion(loop.loop_id)}
            sx={{ mb: 1, border: '1px solid #dfe3ec', borderRadius: 1, '&:before': { display: 'none' } }}
          >
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flex: 1, minWidth: 0 }}>
                <Chip
                  label={loop.loop_type}
                  size="small"
                  sx={{ fontSize: '0.7rem', backgroundColor: '#e8eafd', color: '#4e5ced', fontFamily: 'monospace' }}
                />
                <Chip
                  label={loop.status}
                  size="small"
                  sx={{
                    fontSize: '0.7rem',
                    backgroundColor: (STATUS_COLOR[loop.status] ?? '#8a93a6') + '22',
                    color: STATUS_COLOR[loop.status] ?? '#8a93a6',
                    fontWeight: 600,
                  }}
                />
                <Typography sx={{ fontSize: '0.78rem', color: '#5a6478', ml: 1 }}>
                  {tickCount} tick{tickCount === 1 ? '' : 's'} · {tokensSpent} tok
                </Typography>
                <Typography sx={{ fontSize: '0.7rem', color: '#8a93a6', ml: 'auto', fontFamily: 'monospace', textOverflow: 'ellipsis', overflow: 'hidden' }}>
                  {loop.loop_id}
                </Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails sx={{ backgroundColor: '#fafbfd' }}>
              {loop.status === 'running' && <LinearProgress sx={{ mb: 1 }} />}
              {tickList.length === 0 ? (
                <Typography sx={{ fontSize: '0.78rem', color: '#8a93a6' }}>No ticks yet.</Typography>
              ) : (
                tickList.map((tick) => (
                  <Box key={tick.iteration} sx={{ mb: 1, p: 1, backgroundColor: '#fff', border: '1px solid #ecf0f7', borderRadius: 1 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                      <Chip label={`#${tick.iteration}`} size="small" sx={{ fontSize: '0.65rem', height: 18, backgroundColor: '#dfe3ec', color: '#1a1f2e' }} />
                      {tick.chosen && (
                        <Chip label={`→ ${tick.chosen}`} size="small" sx={{ fontSize: '0.65rem', height: 18, backgroundColor: '#d6f0e3', color: '#0f7a55', fontFamily: 'monospace' }} />
                      )}
                      <Typography sx={{ fontSize: '0.7rem', color: '#8a93a6', ml: 'auto' }}>
                        {tick.tokens} tok · {tick.branches?.length ?? 0} branches
                      </Typography>
                    </Box>
                    <Typography sx={{ fontSize: '0.78rem', color: '#2a3045', whiteSpace: 'pre-wrap' }}>
                      {tick.reasoning || <em>(no reasoning recorded)</em>}
                    </Typography>
                  </Box>
                ))
              )}

              {fullDetail?.result !== undefined && fullDetail.result !== null && (
                <>
                  <Divider sx={{ my: 1 }} />
                  <Typography sx={{ fontSize: '0.7rem', color: '#5a6478', textTransform: 'uppercase', letterSpacing: 0.5, mb: 0.5 }}>
                    Result
                  </Typography>
                  <Box
                    component="pre"
                    sx={{
                      fontSize: '0.7rem',
                      color: '#2a3045',
                      backgroundColor: '#f1f3f9',
                      p: 1,
                      borderRadius: 0.5,
                      overflow: 'auto',
                      maxHeight: 240,
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-word',
                    }}
                  >
                    {JSON.stringify(fullDetail.result, null, 2)}
                  </Box>
                </>
              )}
            </AccordionDetails>
          </Accordion>
        );
      })}
    </Box>
  );
};

export default ReasoningLoopsPanel;

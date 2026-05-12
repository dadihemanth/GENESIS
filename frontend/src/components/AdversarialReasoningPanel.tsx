/**
 * v7.x — Adversarial Reasoning panel.
 *
 * Two sections in one tab:
 *   • Red vs Blue Dialectics  — every red→blue exchange (raw text + verdict)
 *   • Philosopher Insights    — anomaly-driven bug-class hypotheses
 *
 * Subscribes to `adversarial_round_complete` WS events through a parent-supplied
 * `liveRounds` array so new entries appear without re-fetching. Falls back to a
 * manual refresh button.
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Accordion, AccordionDetails, AccordionSummary,
  Box, Button, Chip, CircularProgress, Divider, IconButton,
  Tooltip, Typography,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import GavelIcon from '@mui/icons-material/Gavel';
import RefreshIcon from '@mui/icons-material/Refresh';
import PsychologyIcon from '@mui/icons-material/Psychology';
import { adversarialApi } from '../services/api';
import type { AdversarialRound } from '../types';

interface Props {
  sessionId: string;
  // Compact summaries pushed live from SessionViewer (one per WS event). The
  // panel merges these with the on-load fetch and re-fetches the full doc on
  // expand so the heavy red.raw / blue.raw payload only loads on demand.
  liveRounds: AdversarialRound[];
}

const VERDICT_COLOR: Record<string, string> = {
  survives: '#137a4e',
  killed: '#b53030',
  parse_failed: '#8a93a6',
  blue_blocked: '#b8740c',     // amber — red ran but blue was content-filtered
  no_response: '#8a93a6',      // grey — blue returned empty content; not approval
  red_no_response: '#8a93a6',  // grey — red returned empty content
};

const formatTime = (iso: string): string => {
  if (!iso) return '';
  try {
    return new Date(iso).toLocaleTimeString();
  } catch {
    return iso;
  }
};

const RawBlock: React.FC<{ label: string; text: string; color?: string }> = ({ label, text, color }) => (
  <Box sx={{ mb: 1.5 }}>
    <Typography sx={{ fontSize: '0.75rem', fontWeight: 600, color: color ?? '#5a6478', mb: 0.5 }}>
      {label}
    </Typography>
    <Box
      component="pre"
      sx={{
        fontSize: '0.78rem',
        backgroundColor: '#0e1119',
        color: '#cfd6e4',
        padding: 1.5,
        borderRadius: 1,
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-word',
        maxHeight: 320,
        overflowY: 'auto',
        margin: 0,
      }}
    >
      {text || '(empty)'}
    </Box>
  </Box>
);

const RedBlueRow: React.FC<{ round: AdversarialRound; expanded: boolean; onToggle: (id: string) => void }> = ({ round, expanded, onToggle }) => {
  const verdict = round.verdict ?? 'survives';
  const headline = (round.red?.parsed as { hypothesis?: string } | undefined)?.hypothesis
    ?? (round.red?.raw ?? '').slice(0, 120)
    ?? '(no proposal)';
  return (
    <Accordion
      expanded={expanded}
      onChange={() => onToggle(round._id)}
      disableGutters
      sx={{ borderRadius: 1, mb: 1, '&:before': { display: 'none' } }}
    >
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Box sx={{ display: 'flex', flex: 1, alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
          <Chip
            size="small"
            label={verdict}
            sx={{
              backgroundColor: VERDICT_COLOR[verdict] ?? '#5a6478',
              color: 'white',
              fontWeight: 600,
              textTransform: 'uppercase',
              letterSpacing: 0.5,
            }}
          />
          <Chip
            size="small"
            variant="outlined"
            label={round.trigger}
            sx={{ fontSize: '0.7rem' }}
          />
          {typeof round.round === 'number' && (
            <Chip size="small" variant="outlined" label={`round ${round.round}`} sx={{ fontSize: '0.7rem' }} />
          )}
          <Typography sx={{ fontSize: '0.85rem', flex: 1, minWidth: 200, color: '#1a1f2c' }}>
            {headline}
          </Typography>
          <Typography sx={{ fontSize: '0.7rem', color: '#8a93a6' }}>{formatTime(round.created_at)}</Typography>
        </Box>
      </AccordionSummary>
      <AccordionDetails>
        <RawBlock
          label="Red — proposal"
          color="#b53030"
          text={
            (round.red?.raw && round.red.raw.length > 0)
              ? round.red.raw
              : round.verdict === 'red_no_response'
                ? '(red returned empty content — bump max_tokens for the red_blue role profile)'
                : round.verdict === 'parse_failed'
                  ? '(red emitted text but no valid JSON — model may need a clearer system prompt)'
                  : '(empty)'
          }
        />
        <RawBlock
          label="Blue — challenge"
          color="#1f5fa0"
          text={
            (round.blue?.raw && round.blue.raw.length > 0)
              ? round.blue.raw
              : round.verdict === 'no_response'
                ? '(blue returned empty content — model likely consumed budget on internal reasoning; bump max_tokens or switch to a non-reasoning model)'
                : round.verdict === 'blue_blocked'
                  ? `(blue blocked: ${(round.blue as any)?.error ?? 'content filter or 4xx'})`
                  : round.verdict === 'red_no_response' || round.verdict === 'parse_failed'
                    ? '(blue not called — red did not produce a hypothesis to challenge)'
                    : '(blue did not respond)'
          }
        />
        {round.linked_hypothesis_id && (
          <Typography sx={{ fontSize: '0.75rem', color: '#5a6478' }}>
            Linked hypothesis: <code>{round.linked_hypothesis_id}</code>
          </Typography>
        )}
      </AccordionDetails>
    </Accordion>
  );
};

const PhilosopherRow: React.FC<{ round: AdversarialRound; expanded: boolean; onToggle: (id: string) => void }> = ({ round, expanded, onToggle }) => {
  const parsed = (round.parsed ?? {}) as { bug_class?: string; explanation?: string; novel_hypotheses?: Array<{ text: string; confidence: number }> };
  const bugClass = parsed.bug_class ?? '(unparsed)';
  return (
    <Accordion
      expanded={expanded}
      onChange={() => onToggle(round._id)}
      disableGutters
      sx={{ borderRadius: 1, mb: 1, '&:before': { display: 'none' } }}
    >
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Box sx={{ display: 'flex', flex: 1, alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
          <Chip size="small" label="philosopher" sx={{ backgroundColor: '#5d3a9a', color: 'white', fontWeight: 600, fontSize: '0.7rem' }} />
          <Typography sx={{ fontSize: '0.85rem', flex: 1, minWidth: 200, color: '#1a1f2c' }}>
            {bugClass} — {(parsed.explanation ?? '').slice(0, 120)}
          </Typography>
          <Typography sx={{ fontSize: '0.7rem', color: '#8a93a6' }}>{formatTime(round.created_at)}</Typography>
        </Box>
      </AccordionSummary>
      <AccordionDetails>
        {round.anomalies_summary && (
          <RawBlock label="Anomalies fed in" text={round.anomalies_summary} />
        )}
        <RawBlock label="Philosopher response" color="#5d3a9a" text={round.raw ?? ''} />
        {Array.isArray(parsed.novel_hypotheses) && parsed.novel_hypotheses.length > 0 && (
          <Box sx={{ mt: 1 }}>
            <Typography sx={{ fontSize: '0.75rem', fontWeight: 600, color: '#5a6478', mb: 0.5 }}>
              Novel hypotheses spawned
            </Typography>
            {parsed.novel_hypotheses.map((nh, i) => (
              <Box key={i} sx={{ display: 'flex', gap: 1, mb: 0.5 }}>
                <Chip size="small" label={`${(nh.confidence ?? 0).toFixed(2)}`} sx={{ fontSize: '0.7rem' }} />
                <Typography sx={{ fontSize: '0.8rem', color: '#1a1f2c' }}>{nh.text}</Typography>
              </Box>
            ))}
          </Box>
        )}
        {round.linked_hypothesis_ids && round.linked_hypothesis_ids.length > 0 && (
          <Typography sx={{ fontSize: '0.75rem', color: '#5a6478', mt: 1 }}>
            Linked hypotheses: {round.linked_hypothesis_ids.join(', ')}
          </Typography>
        )}
      </AccordionDetails>
    </Accordion>
  );
};

const AdversarialReasoningPanel: React.FC<Props> = ({ sessionId, liveRounds }) => {
  const [persistedRounds, setPersistedRounds] = useState<AdversarialRound[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const refresh = useCallback(() => {
    setLoading(true);
    adversarialApi.listForSession(sessionId)
      .then(data => { setPersistedRounds(data.items || []); setError(null); })
      .catch(() => setError('Failed to load adversarial reasoning.'))
      .finally(() => setLoading(false));
  }, [sessionId]);

  useEffect(() => { refresh(); }, [refresh]);

  // Whenever a live round arrives, re-fetch so the full document (with raw
  // red+blue text) replaces the compact summary the WS event carried.
  useEffect(() => {
    if (liveRounds.length > 0) refresh();
  }, [liveRounds.length, refresh]);

  const merged: AdversarialRound[] = useMemo(() => {
    // Merge persisted + live, dedup by _id, newest first.
    const map = new Map<string, AdversarialRound>();
    for (const r of liveRounds) {
      if (r && r._id) map.set(r._id, r);
    }
    for (const r of persistedRounds) {
      if (r && r._id && !map.has(r._id)) map.set(r._id, r);
    }
    return Array.from(map.values()).sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
  }, [persistedRounds, liveRounds]);

  const redBlue = useMemo(() => merged.filter(r => r.kind === 'red_blue'), [merged]);
  const philosopher = useMemo(() => merged.filter(r => r.kind === 'philosopher'), [merged]);
  const insider = useMemo(() => merged.filter(r => r.kind === 'insider'), [merged]);
  const nationState = useMemo(() => merged.filter(r => r.kind === 'nation_state'), [merged]);

  const onToggle = useCallback((id: string) => {
    setExpandedId(prev => (prev === id ? null : id));
  }, []);

  if (loading && persistedRounds.length === 0) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
        <CircularProgress size={28} />
      </Box>
    );
  }

  if (!loading && merged.length === 0) {
    return (
      <Box sx={{ p: 3, textAlign: 'center' }}>
        <GavelIcon sx={{ fontSize: 40, color: '#dfe3ec', mb: 1 }} />
        <Typography sx={{ color: '#8a93a6', fontSize: '0.85rem' }}>
          No adversarial rounds yet.
        </Typography>
        <Typography sx={{ color: '#5a6478', fontSize: '0.75rem', mt: 0.5, maxWidth: 540, mx: 'auto' }}>
          The Red/Blue Dialectic seeds the hypothesis market at iteration 5 (or after Phase 1 in
          multi-agent mode), then runs once more on every confirmed hypothesis with confidence ≥ 0.7.
          The Philosopher fires once when the session has accumulated enough anomalies.
        </Typography>
        <Tooltip title="Refresh">
          <IconButton onClick={refresh} size="small" sx={{ mt: 1 }}>
            <RefreshIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 2 }}>
      {error && (
        <Typography sx={{ color: '#b53030', fontSize: '0.8rem', mb: 1 }}>{error}</Typography>
      )}

      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
        <Typography sx={{ fontSize: '1rem', fontWeight: 600 }}>
          Adversarial Reasoning
        </Typography>
        <Button
          size="small"
          startIcon={<RefreshIcon fontSize="small" />}
          onClick={refresh}
          disabled={loading}
        >
          Refresh
        </Button>
      </Box>

      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
          <GavelIcon fontSize="small" sx={{ color: '#1a1f2c' }} />
          <Typography sx={{ fontSize: '0.9rem', fontWeight: 600 }}>
            Red vs Blue Dialectics
          </Typography>
          <Chip size="small" label={`${redBlue.length}`} sx={{ fontSize: '0.7rem' }} />
        </Box>
        {redBlue.length === 0 ? (
          <Typography sx={{ fontSize: '0.8rem', color: '#8a93a6', pl: 4 }}>
            No red/blue rounds yet for this session.
          </Typography>
        ) : (
          redBlue.map(r => (
            <RedBlueRow key={r._id} round={r} expanded={expandedId === r._id} onToggle={onToggle} />
          ))
        )}
      </Box>

      <Divider sx={{ my: 2 }} />

      <Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
          <PsychologyIcon fontSize="small" sx={{ color: '#5d3a9a' }} />
          <Typography sx={{ fontSize: '0.9rem', fontWeight: 600 }}>
            Philosopher Insights
          </Typography>
          <Chip size="small" label={`${philosopher.length}`} sx={{ fontSize: '0.7rem' }} />
        </Box>
        {philosopher.length === 0 ? (
          <Typography sx={{ fontSize: '0.8rem', color: '#8a93a6', pl: 4 }}>
            Philosopher hasn&apos;t fired yet.
          </Typography>
        ) : (
          philosopher.map(r => (
            <PhilosopherRow key={r._id} round={r} expanded={expandedId === r._id} onToggle={onToggle} />
          ))
        )}
      </Box>

      <Divider sx={{ my: 2 }} />

      <Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
          <PsychologyIcon fontSize="small" sx={{ color: '#0e7c5a' }} />
          <Typography sx={{ fontSize: '0.9rem', fontWeight: 600 }}>
            Insider-Threat Hypotheses
          </Typography>
          <Chip size="small" label={`${insider.length}`} sx={{ fontSize: '0.7rem' }} />
        </Box>
        {insider.length === 0 ? (
          <Typography sx={{ fontSize: '0.8rem', color: '#8a93a6', pl: 4 }}>
            Insider agent hasn&apos;t fired yet (runs alongside the philosopher).
          </Typography>
        ) : (
          insider.map(r => (
            <PhilosopherRow key={r._id} round={r} expanded={expandedId === r._id} onToggle={onToggle} />
          ))
        )}
      </Box>

      <Divider sx={{ my: 2 }} />

      <Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
          <PsychologyIcon fontSize="small" sx={{ color: '#8c2f2f' }} />
          <Typography sx={{ fontSize: '0.9rem', fontWeight: 600 }}>
            Nation-State / APT Hypotheses
          </Typography>
          <Chip size="small" label={`${nationState.length}`} sx={{ fontSize: '0.7rem' }} />
        </Box>
        {nationState.length === 0 ? (
          <Typography sx={{ fontSize: '0.8rem', color: '#8a93a6', pl: 4 }}>
            Nation-state agent hasn&apos;t fired yet (runs alongside the philosopher).
          </Typography>
        ) : (
          nationState.map(r => (
            <PhilosopherRow key={r._id} round={r} expanded={expandedId === r._id} onToggle={onToggle} />
          ))
        )}
      </Box>
    </Box>
  );
};

export default AdversarialReasoningPanel;

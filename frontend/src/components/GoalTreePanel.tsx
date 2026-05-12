import React, { useEffect, useState } from 'react';
import {
  Box, Typography, Chip, CircularProgress,
  Accordion, AccordionSummary, AccordionDetails,
  LinearProgress,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import TrackChangesIcon from '@mui/icons-material/TrackChanges';
import { goalsApi } from '../services/api';
import type { Goal } from '../types';

interface ProgressEntry {
  status?: string;
  evidence_count?: number;
}

interface Props {
  sessionId: string;
  // Live progress map keyed by `"<phase_idx>.<subgoal_idx>"`, pushed via the
  // `goal_progress` WS event. SessionViewer owns the state; this component
  // merges it over the static tree at render time so the dot colors update
  // without re-fetching.
  liveProgress?: Record<string, ProgressEntry>;
}

const GoalTreePanel: React.FC<Props> = ({ sessionId, liveProgress }) => {
  const [tree, setTree] = useState<Goal | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    goalsApi.get(sessionId)
      .then(data => { if (data) { setTree(data); setError(null); } else { setError('No goal tree compiled for this session.'); } })
      .catch(() => setError('No goal tree compiled for this session.'))
      .finally(() => setLoading(false));
  }, [sessionId]);

  // Resolve a sub_goal's effective state: live WS update wins over the static
  // tree value (the GET endpoint also bakes the same map in for first paint,
  // but live takes precedence so subsequent ticks don't get reverted).
  const resolveSubGoalState = (pi: number, si: number, sg: any): { status: string; evidence_count: number } => {
    const live = liveProgress?.[`${pi}.${si}`];
    return {
      status: (live?.status ?? sg.status ?? 'pending') as string,
      evidence_count: live?.evidence_count ?? sg.evidence_count ?? 0,
    };
  };

  const dotColor = (status: string): string => {
    if (status === 'done') return '#4caf50';
    if (status === 'in_progress') return '#1976d2';
    return '#dfe3ec';
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
        <CircularProgress size={28} />
      </Box>
    );
  }

  if (error || !tree) {
    return (
      <Box sx={{ p: 3, textAlign: 'center' }}>
        <TrackChangesIcon sx={{ fontSize: 40, color: '#dfe3ec', mb: 1 }} />
        <Typography sx={{ color: '#8a93a6', fontSize: '0.85rem' }}>
          {error ?? 'No goal tree available.'}
        </Typography>
        <Typography sx={{ color: '#5a6478', fontSize: '0.75rem', mt: 0.5 }}>
          Set an operator goal when creating the session to enable T132 goal compilation.
        </Typography>
      </Box>
    );
  }

  const phases = tree.compiled_tree?.phases ?? [];
  const totalSubGoals = phases.reduce((acc: number, p: any) => acc + (p.sub_goals?.length ?? 0), 0);
  let completedSubGoals = 0;
  let inProgressSubGoals = 0;
  phases.forEach((p: any, pi: number) => {
    (p.sub_goals ?? []).forEach((sg: any, si: number) => {
      const { status } = resolveSubGoalState(pi, si, sg);
      if (status === 'done') completedSubGoals += 1;
      else if (status === 'in_progress') inProgressSubGoals += 1;
    });
  });
  const progress = totalSubGoals > 0 ? Math.round((completedSubGoals / totalSubGoals) * 100) : 0;

  return (
    <Box sx={{ p: 2, overflowY: 'auto', height: '100%' }}>
      {/* Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <TrackChangesIcon sx={{ color: '#4e5ced', fontSize: 20 }} />
        <Typography sx={{ fontWeight: 700, fontSize: '0.9rem', color: '#1a1f2e' }}>
          Operator Goal
        </Typography>
        <Chip
          label={tree.status ?? 'active'}
          size="small"
          sx={{
            fontSize: '0.7rem', height: 18,
            backgroundColor: tree.status === 'completed' ? '#e8f5e9' : '#e8eafd',
            color: tree.status === 'completed' ? '#2e7d32' : '#4e5ced',
          }}
        />
      </Box>

      <Typography sx={{ color: '#1a1f2e', fontSize: '0.85rem', mb: 1.5, fontStyle: 'italic' }}>
        &ldquo;{tree.goal_text}&rdquo;
      </Typography>

      {totalSubGoals > 0 && (
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5, alignItems: 'center', gap: 1 }}>
            <Typography sx={{ fontSize: '0.72rem', color: '#8a93a6' }}>
              Progress: {completedSubGoals}/{totalSubGoals} sub-goals
              {inProgressSubGoals > 0 && (
                <span style={{ marginLeft: 6, color: '#1976d2' }}>
                  ({inProgressSubGoals} in progress)
                </span>
              )}
            </Typography>
            <Typography sx={{ fontSize: '0.72rem', color: '#4e5ced' }}>{progress}%</Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={progress}
            sx={{ height: 4, borderRadius: 2, backgroundColor: '#e8eafd', '& .MuiLinearProgress-bar': { backgroundColor: '#4e5ced' } }}
          />
        </Box>
      )}

      {/* Goal tree root */}
      {tree.compiled_tree?.root && (
        <Box sx={{ mb: 1.5, p: 1.5, backgroundColor: '#f5f6ff', borderRadius: 1, border: '1px solid #e8eafd' }}>
          <Typography sx={{ fontSize: '0.78rem', color: '#5a6478', mb: 0.5 }}>Root objective</Typography>
          <Typography sx={{ fontSize: '0.85rem', color: '#1a1f2e', fontWeight: 600 }}>
            {tree.compiled_tree.root}
          </Typography>
        </Box>
      )}

      {/* Phases */}
      {phases.map((phase: any, pi: number) => {
        const subGoals = phase.sub_goals ?? [];
        const phaseDone = subGoals.filter((sg: any, si: number) => resolveSubGoalState(pi, si, sg).status === 'done').length;
        const phaseInProgress = subGoals.filter((sg: any, si: number) => resolveSubGoalState(pi, si, sg).status === 'in_progress').length;
        return (
          <Accordion
            key={pi}
            defaultExpanded={pi === 0}
            sx={{
              mb: 0.75, boxShadow: 'none',
              border: '1px solid #e8eafd', borderRadius: '6px !important',
              '&:before': { display: 'none' },
            }}
          >
            <AccordionSummary
              expandIcon={<ExpandMoreIcon sx={{ fontSize: 16 }} />}
              sx={{ minHeight: 40, '& .MuiAccordionSummary-content': { my: 0.5 } }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flex: 1 }}>
                <Typography sx={{ fontSize: '0.82rem', fontWeight: 600, color: '#1a1f2e' }}>
                  Phase {pi + 1}: {phase.name}
                </Typography>
                <Typography sx={{ fontSize: '0.72rem', color: '#8a93a6' }}>
                  ({phaseDone}/{subGoals.length} done
                  {phaseInProgress > 0 ? `, ${phaseInProgress} active` : ''})
                </Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails sx={{ pt: 0, pb: 1.5 }}>
              {subGoals.map((sg: any, si: number) => {
                const { status, evidence_count } = resolveSubGoalState(pi, si, sg);
                return (
                  <Box
                    key={si}
                    sx={{
                      display: 'flex', alignItems: 'flex-start', gap: 1, py: 0.75,
                      borderBottom: si < subGoals.length - 1 ? '1px solid #f0f2f8' : 'none',
                    }}
                  >
                    <Box
                      sx={{
                        width: 8, height: 8, borderRadius: '50%', mt: 0.5, flexShrink: 0,
                        backgroundColor: dotColor(status),
                        // Pulse for in_progress so the user sees the agent is "working" on this sub_goal.
                        animation: status === 'in_progress' ? 'goalPulse 1.6s ease-in-out infinite' : 'none',
                        '@keyframes goalPulse': {
                          '0%, 100%': { opacity: 1 },
                          '50%': { opacity: 0.4 },
                        },
                      }}
                    />
                    <Box sx={{ flex: 1, minWidth: 0 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
                        <Typography sx={{ fontSize: '0.8rem', color: '#1a1f2e', textDecoration: status === 'done' ? 'line-through' : 'none', opacity: status === 'done' ? 0.7 : 1 }}>
                          {sg.description}
                        </Typography>
                        {evidence_count > 0 && (
                          <Chip
                            label={`${evidence_count} ev`}
                            size="small"
                            sx={{
                              fontSize: '0.65rem', height: 16,
                              backgroundColor: status === 'done' ? '#e8f5e9' : '#e3f2fd',
                              color: status === 'done' ? '#2e7d32' : '#1976d2',
                            }}
                          />
                        )}
                      </Box>
                      {sg.probe_hints?.length > 0 && (
                        <Typography sx={{ fontSize: '0.72rem', color: '#8a93a6', mt: 0.25 }}>
                          Hints: {sg.probe_hints.join(', ')}
                        </Typography>
                      )}
                    </Box>
                  </Box>
                );
              })}
            </AccordionDetails>
          </Accordion>
        );
      })}
    </Box>
  );
};

export default GoalTreePanel;

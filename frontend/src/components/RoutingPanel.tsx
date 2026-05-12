/**
 * v7.x — Routing tab.
 *
 * Shows the live role -> profile -> model resolution for this session, plus
 * actual usage counts and an explanation of why each role exists. Makes it
 * impossible to misread "Opus is $0" — you can see exactly which role was
 * assigned to it and whether that role even fires in the current agent_mode.
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert, Box, Chip, CircularProgress, IconButton, Paper, Table, TableBody, TableCell,
  TableContainer, TableHead, TableRow, Tooltip, Typography,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import RouteIcon from '@mui/icons-material/Route';
import { sessionsApi } from '../services/api';

interface Props { sessionId: string; }

type RoutingData = Awaited<ReturnType<typeof sessionsApi.getRouting>>;
type RoutingRow = RoutingData['rows'][number];

const fmt = (n: number) => n >= 1_000_000 ? `${(n / 1_000_000).toFixed(2)}M`
  : n >= 1_000 ? `${(n / 1_000).toFixed(1)}k` : String(n);

function modelMismatchWarning(row: RoutingRow): string | null {
  // Compare assigned model vs models actually observed for this role's sources.
  if (!row.assigned_model || row.observed_models.length === 0) return null;
  const observedNotAssigned = row.observed_models.filter(m => m !== row.assigned_model);
  if (observedNotAssigned.length === 0) return null;
  return `Observed ${observedNotAssigned.join(', ')} despite assignment to ${row.assigned_model} — routing may not have applied to early calls.`;
}

type ReproData = Awaited<ReturnType<typeof sessionsApi.getReproducibility>>;

const RoutingPanel: React.FC<Props> = ({ sessionId }) => {
  const [data, setData] = useState<RoutingData | null>(null);
  const [repro, setRepro] = useState<ReproData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(() => {
    setLoading(true);
    sessionsApi.getRouting(sessionId)
      .then(d => { setData(d); setError(null); })
      .catch(() => setError('Failed to load routing.'))
      .finally(() => setLoading(false));
    sessionsApi.getReproducibility(sessionId)
      .then(d => setRepro(d))
      .catch(() => setRepro(null));
  }, [sessionId]);

  useEffect(() => { refresh(); }, [refresh]);

  const sortedRows = useMemo(() => {
    if (!data) return [];
    // Active-this-mode roles first, then alphabetical.
    return [...data.rows].sort((a, b) => {
      if (a.active_for_this_session_mode !== b.active_for_this_session_mode) {
        return a.active_for_this_session_mode ? -1 : 1;
      }
      return a.role.localeCompare(b.role);
    });
  }, [data]);

  if (loading && !data) {
    return <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}><CircularProgress size={28} /></Box>;
  }
  if (!data) {
    return (
      <Box sx={{ p: 3, textAlign: 'center' }}>
        <RouteIcon sx={{ fontSize: 40, color: '#dfe3ec', mb: 1 }} />
        <Typography sx={{ color: '#8a93a6', fontSize: '0.85rem' }}>{error ?? 'No routing data.'}</Typography>
      </Box>
    );
  }

  const isMulti = data.llm_mode === 'multi';

  return (
    <Box sx={{ p: 2 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 1.5, gap: 1 }}>
        <RouteIcon sx={{ color: '#4e5ced' }} />
        <Typography sx={{ fontSize: '1rem', fontWeight: 600 }}>Model Routing</Typography>
        <Chip
          size="small"
          label={isMulti ? 'Multi-model mode' : 'Single-model mode'}
          color={isMulti ? 'primary' : 'default'}
          sx={{ fontSize: '0.7rem' }}
        />
        <Chip
          size="small"
          variant="outlined"
          label={`${data.profiles_configured} profile${data.profiles_configured === 1 ? '' : 's'}`}
          sx={{ fontSize: '0.7rem' }}
        />
        <Tooltip title="Refresh"><IconButton size="small" sx={{ ml: 'auto' }} onClick={refresh}><RefreshIcon fontSize="small" /></IconButton></Tooltip>
      </Box>

      {!isMulti && (
        <Alert severity="info" sx={{ mb: 2, fontSize: '0.78rem' }}>
          You're in <strong>single-model mode</strong> — every role uses the legacy single-model
          settings (the Models tab in Settings is hidden until you switch to Multi-model). To see
          per-role routing in action, set <code>LLM mode → Multi-model</code> in Settings.
        </Alert>
      )}

      <Alert severity="warning" sx={{ mb: 2, fontSize: '0.78rem' }}>
        <strong>Common confusion:</strong> the <code>primary</code> role only fires in
        <strong> solo agent_mode</strong>. In multi-agent runs (the default), every sub-agent
        uses the <code>subagent</code> role instead. If you want a model to drive the actual scan
        in multi-agent, assign it to <code>subagent</code>, not <code>primary</code>.
      </Alert>

      {repro && (
        <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
            <Typography sx={{ fontSize: '0.95rem', fontWeight: 700 }}>
              Reproducibility Report
            </Typography>
            {repro.first_time_target && (
              <Chip size="small" label="first-time target" color="warning" sx={{ fontSize: '0.65rem' }} />
            )}
            {repro.first_time_floors_applied && (
              <Chip size="small" label={`floors bumped (min_iter=${repro.min_iter_floor_used})`} sx={{ fontSize: '0.65rem' }} />
            )}
          </Box>
          <Typography sx={{ fontSize: '0.7rem', color: '#5a6478', mb: 1.5 }}>
            What was deterministic this run + what was target-specific. Use to compare runs of the same target.
          </Typography>
          <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', md: '1fr 1fr' }, gap: 1.5 }}>
            {/* Specialists */}
            <Box>
              <Typography sx={{ fontSize: '0.78rem', fontWeight: 600, mb: 0.5 }}>Specialists</Typography>
              <Box sx={{ fontSize: '0.72rem', color: '#5a6478' }}>
                <div><strong>Baseline (always-on):</strong> {repro.specialists_baseline_used.join(', ') || '—'}</div>
                <div><strong>Detected (signal-driven):</strong> {repro.specialists_detected.join(', ') || '—'}</div>
                <div><strong>Inherited (memory):</strong> {repro.specialists_inherited_from_memory.join(', ') || '—'}</div>
                <div style={{ color: '#137a4e', marginTop: 4 }}>
                  <strong>Actually ran:</strong> {repro.specialists_actually_ran.join(', ') || '—'}
                </div>
              </Box>
            </Box>
            {/* Attack-class coverage */}
            <Box>
              <Typography sx={{ fontSize: '0.78rem', fontWeight: 600, mb: 0.5 }}>Attack-class coverage</Typography>
              <Box sx={{ fontSize: '0.72rem', color: '#5a6478' }}>
                <div>
                  <strong>Attempted:</strong> {repro.attack_classes_attempted.length}/16 ·{' '}
                  <span style={{ color: '#137a4e' }}>{repro.attack_classes_attempted.join(', ') || '—'}</span>
                </div>
                {repro.attack_classes_unmet.length > 0 && (
                  <div style={{ marginTop: 4 }}>
                    <strong>Unmet:</strong>{' '}
                    <span style={{ color: '#b53030' }}>{repro.attack_classes_unmet.join(', ')}</span>
                  </div>
                )}
                <div style={{ marginTop: 4 }}>
                  <strong>Tool calls:</strong> {repro.tool_call_total} total / {repro.tool_call_distinct} distinct tools
                </div>
              </Box>
            </Box>
            {/* Cross-session intel */}
            <Box>
              <Typography sx={{ fontSize: '0.78rem', fontWeight: 600, mb: 0.5 }}>Cross-session intel</Typography>
              <Box sx={{ fontSize: '0.72rem', color: '#5a6478' }}>
                <div><strong>Prior findings injected:</strong> {repro.prior_intel_findings_injected}</div>
                <div><strong>Prior not_achieved sub-goals:</strong> {repro.prior_not_achieved_subgoals_injected}</div>
                {repro.deeper_than_last_time_targets.length > 0 && (
                  <div style={{ marginTop: 4 }}>
                    <strong>Asked to go deeper on:</strong>
                    <ul style={{ margin: '2px 0 0 16px', padding: 0 }}>
                      {repro.deeper_than_last_time_targets.slice(0, 5).map((t, i) => (
                        <li key={i} style={{ fontSize: '0.7rem' }}>{t}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </Box>
            </Box>
            {/* Run config */}
            <Box>
              <Typography sx={{ fontSize: '0.78rem', fontWeight: 600, mb: 0.5 }}>Run config</Typography>
              <Box sx={{ fontSize: '0.72rem', color: '#5a6478' }}>
                <div><strong>agent_mode:</strong> {repro.agent_mode}</div>
                <div><strong>scan_profile:</strong> {repro.scan_profile}</div>
                <div><strong>min_iter floor used:</strong> {repro.min_iter_floor_used}</div>
                <div><strong>target:</strong> {repro.target_ip}</div>
              </Box>
            </Box>
          </Box>

          {/* v7.x — High-water mark comparison */}
          {(repro.target_high_water_findings ?? 0) > 0 && (
            <Box sx={{
              mt: 2, p: 1.5, borderRadius: 1,
              backgroundColor: repro.this_run_beats_high_water
                ? 'rgba(19,122,78,0.08)'
                : (repro.this_run_vs_high_water_pct ?? 0) >= 80
                  ? 'rgba(184,116,12,0.08)'
                  : 'rgba(181,48,48,0.08)',
              border: `1px solid ${
                repro.this_run_beats_high_water ? '#137a4e'
                : (repro.this_run_vs_high_water_pct ?? 0) >= 80 ? '#b8740c'
                : '#b53030'
              }`,
            }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                <Typography sx={{ fontSize: '0.85rem', fontWeight: 700 }}>
                  Target high-water mark
                </Typography>
                {repro.this_run_beats_high_water === true && (
                  <Chip size="small" label="NEW BEST" color="success" sx={{ fontSize: '0.65rem', fontWeight: 700 }} />
                )}
                {repro.this_run_beats_high_water === false && (
                  <Chip
                    size="small"
                    label={`${repro.this_run_vs_high_water_pct ?? 0}% of best`}
                    sx={{
                      fontSize: '0.65rem', fontWeight: 700,
                      backgroundColor: (repro.this_run_vs_high_water_pct ?? 0) >= 80 ? '#b8740c' : '#b53030',
                      color: 'white',
                    }}
                  />
                )}
              </Box>
              <Typography sx={{ fontSize: '0.72rem', color: '#5a6478' }}>
                <strong>Prior best:</strong> {repro.target_high_water_findings} findings in {repro.target_high_water_duration_min} min
                {repro.target_high_water_session_id && (
                  <> (session <code>{(repro.target_high_water_session_id || '').slice(0, 8)}</code>)</>
                )}
                <br />
                <strong>This run:</strong> {repro.this_run_findings_count ?? 0} confirmed/exploited findings
              </Typography>
              {repro.this_run_beats_high_water === false && (repro.this_run_vs_high_water_pct ?? 0) < 80 && (
                <Typography sx={{ fontSize: '0.7rem', color: '#b53030', mt: 0.5, fontWeight: 500 }}>
                  ⚠ Far below prior best — consider re-running with scan_profile=&apos;deep_research&apos; (6h wallclock floor + max_rounds=10).
                </Typography>
              )}
            </Box>
          )}
        </Paper>
      )}

      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell sx={{ width: 110 }}>Role</TableCell>
              <TableCell sx={{ width: 130 }}>Fires in</TableCell>
              <TableCell sx={{ width: 200 }}>Assigned profile</TableCell>
              <TableCell sx={{ width: 220 }}>Resolved model</TableCell>
              <TableCell sx={{ width: 90 }}>Calls</TableCell>
              <TableCell sx={{ width: 130 }}>Tokens (in/out)</TableCell>
              <TableCell>Why this role</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {sortedRows.map(r => {
              const mismatch = modelMismatchWarning(r);
              const inactive = !r.active_for_this_session_mode;
              return (
                <TableRow
                  key={r.role}
                  sx={{ opacity: inactive ? 0.55 : 1 }}
                  hover
                >
                  <TableCell>
                    <Typography sx={{ fontFamily: 'monospace', fontSize: '0.8rem', fontWeight: 600 }}>
                      {r.role}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Chip
                      size="small"
                      label={r.fires_in}
                      sx={{
                        fontSize: '0.65rem',
                        backgroundColor: r.active_for_this_session_mode ? '#137a4e' : '#5a6478',
                        color: 'white',
                      }}
                    />
                  </TableCell>
                  <TableCell>
                    <Typography sx={{ fontSize: '0.78rem', fontWeight: 600 }}>
                      {r.assigned_profile_name ?? '(none)'}
                    </Typography>
                    {r.fallback_to_primary && (
                      <Typography sx={{ fontSize: '0.65rem', color: '#b8740c' }}>
                        ↳ fallback (no explicit assignment)
                      </Typography>
                    )}
                    <Typography sx={{ fontSize: '0.65rem', color: '#8a93a6' }}>
                      {r.assigned_provider ?? '—'}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography sx={{ fontFamily: 'monospace', fontSize: '0.78rem' }}>
                      {r.assigned_model ?? '—'}
                    </Typography>
                    {r.observed_models.length > 0 && (
                      <Typography sx={{ fontSize: '0.65rem', color: '#5a6478' }}>
                        observed: {r.observed_models.join(', ')}
                      </Typography>
                    )}
                    {mismatch && (
                      <Typography sx={{ fontSize: '0.65rem', color: '#b53030', mt: 0.25 }}>
                        ⚠ {mismatch}
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell>
                    <Chip
                      size="small"
                      label={r.calls_this_session}
                      sx={{
                        fontSize: '0.7rem',
                        backgroundColor: r.calls_this_session > 0 ? '#137a4e' : '#dfe3ec',
                        color: r.calls_this_session > 0 ? 'white' : '#5a6478',
                        fontWeight: 600,
                      }}
                    />
                  </TableCell>
                  <TableCell>
                    <Typography sx={{ fontSize: '0.72rem', color: '#5a6478', fontFamily: 'monospace' }}>
                      {fmt(r.input_tokens_this_session)} / {fmt(r.output_tokens_this_session)}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Tooltip title={r.purpose}>
                      <Typography sx={{ fontSize: '0.78rem', color: '#1a1f2c' }}>
                        {r.purpose.length > 130 ? r.purpose.slice(0, 130) + '…' : r.purpose}
                      </Typography>
                    </Tooltip>
                    <Typography sx={{ fontSize: '0.7rem', color: '#5a6478', mt: 0.25 }}>
                      <em>Recommended:</em> {r.good_models}
                    </Typography>
                    <Typography sx={{ fontSize: '0.7rem', color: '#4e5ced', mt: 0.25 }}>
                      ↳ {r.why_assigned}
                    </Typography>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </TableContainer>

      <Box sx={{ mt: 2, p: 1.5, borderRadius: 1, backgroundColor: 'rgba(78,92,237,0.05)' }}>
        <Typography sx={{ fontSize: '0.75rem', color: '#5a6478' }}>
          <strong>How resolution works:</strong> at each call site, the orchestrator looks up
          <code>role_assignments[role]</code>. If unset, it falls back to the <code>primary</code>
          assignment. The model is whatever <code>profile.model</code> says for that profile.
          If <code>llm_mode</code> is <code>single</code>, every role bypasses this and uses the
          legacy single-model fields.
        </Typography>
      </Box>
    </Box>
  );
};

export default RoutingPanel;

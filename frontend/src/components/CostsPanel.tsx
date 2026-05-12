/**
 * v7.x — Session Costs panel.
 *
 * Header: total USD spent.
 * Chart: cumulative cost per iteration (raw SVG, no chart library dep).
 * Tables: token-class breakdown, cost-by-source, cost-by-model.
 *
 * Live updates via `llm_usage_recorded` WS events bumped down from
 * SessionViewer; the panel re-fetches on every event arrival so the totals
 * stay accurate (recompute is cheap server-side — one Mongo aggregation).
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Box, Button, Chip, CircularProgress, Divider,
  Paper, Table, TableBody, TableCell, TableHead, TableRow,
  Tooltip, Typography,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import PaidIcon from '@mui/icons-material/Paid';
import { costsApi } from '../services/api';
import type { SessionCostsResponse } from '../types';

interface Props {
  sessionId: string;
  // Bumped from SessionViewer — increments any time a llm_usage_recorded event
  // arrives. We don't pass payloads; we just refetch on tick to keep the
  // breakdowns consistent (and avoid duplicating the cost math on the client).
  liveTick: number;
}

const fmtUSD = (n: number): string => {
  if (n === 0) return '$0.00';
  if (n < 0.01) return `$${n.toFixed(5)}`;
  if (n < 1) return `$${n.toFixed(4)}`;
  return `$${n.toFixed(2)}`;
};

const fmtTokens = (n: number): string => {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
};


// Tiny inline cumulative-cost line chart. No external lib — just SVG.
const CumulativeChart: React.FC<{ data: SessionCostsResponse['by_iteration'] }> = ({ data }) => {
  if (!data.length) return null;
  const W = 760;
  const H = 220;
  const PAD_L = 50;
  const PAD_R = 12;
  const PAD_T = 12;
  const PAD_B = 28;
  const innerW = W - PAD_L - PAD_R;
  const innerH = H - PAD_T - PAD_B;

  const xs = data.map(d => d.iteration);
  const ys = data.map(d => d.cumulative_usd);
  const maxX = Math.max(1, ...xs);
  const minX = Math.min(0, ...xs);
  const maxY = Math.max(0.0001, ...ys);

  const xPos = (x: number): number => PAD_L + ((x - minX) / Math.max(1, maxX - minX)) * innerW;
  const yPos = (y: number): number => PAD_T + innerH - (y / maxY) * innerH;

  const points = data.map(d => `${xPos(d.iteration).toFixed(1)},${yPos(d.cumulative_usd).toFixed(1)}`).join(' ');

  // Y-axis ticks (4 evenly spaced)
  const yTicks = [0, 0.25, 0.5, 0.75, 1].map(p => ({
    y: yPos(maxY * p),
    label: fmtUSD(maxY * p),
  }));

  return (
    <Box sx={{ overflowX: 'auto', mb: 2 }}>
      <svg width={W} height={H} style={{ display: 'block' }}>
        {/* Y-axis grid */}
        {yTicks.map((t, i) => (
          <g key={i}>
            <line x1={PAD_L} y1={t.y} x2={W - PAD_R} y2={t.y} stroke="#e9ecf3" strokeWidth={1} />
            <text x={PAD_L - 6} y={t.y + 3} fontSize={10} fill="#8a93a6" textAnchor="end">
              {t.label}
            </text>
          </g>
        ))}
        {/* X-axis */}
        <line x1={PAD_L} y1={H - PAD_B} x2={W - PAD_R} y2={H - PAD_B} stroke="#cfd6e4" strokeWidth={1} />
        <text x={PAD_L} y={H - 8} fontSize={10} fill="#8a93a6">iter {minX}</text>
        <text x={W - PAD_R} y={H - 8} fontSize={10} fill="#8a93a6" textAnchor="end">iter {maxX}</text>
        {/* Filled area under the line for emphasis */}
        <polygon
          fill="rgba(78,92,237,0.12)"
          points={`${PAD_L},${H - PAD_B} ${points} ${W - PAD_R},${H - PAD_B}`}
        />
        {/* Line */}
        <polyline
          fill="none"
          stroke="#4e5ced"
          strokeWidth={2}
          points={points}
        />
        {/* Final dot */}
        {data.length > 0 && (
          <circle
            cx={xPos(data[data.length - 1].iteration)}
            cy={yPos(data[data.length - 1].cumulative_usd)}
            r={3}
            fill="#4e5ced"
          />
        )}
      </svg>
    </Box>
  );
};


const CostsPanel: React.FC<Props> = ({ sessionId, liveTick }) => {
  const [data, setData] = useState<SessionCostsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(() => {
    setLoading(true);
    costsApi.getForSession(sessionId)
      .then(d => { setData(d); setError(null); })
      .catch(() => setError('Failed to load costs.'))
      .finally(() => setLoading(false));
  }, [sessionId]);

  useEffect(() => { refresh(); }, [refresh]);

  // Each new llm_usage_recorded event bumps liveTick — refetch.
  useEffect(() => {
    if (liveTick > 0) refresh();
  }, [liveTick, refresh]);

  const sourceRows = useMemo(() => {
    if (!data) return [];
    return Object.entries(data.by_source)
      .sort(([, a], [, b]) => b - a)
      .map(([source, cost]) => ({ source, cost }));
  }, [data]);

  const modelRows = useMemo(() => {
    if (!data) return [];
    return Object.entries(data.by_model)
      .sort(([, a], [, b]) => b - a)
      .map(([model, cost]) => ({ model, cost }));
  }, [data]);

  if (loading && !data) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
        <CircularProgress size={28} />
      </Box>
    );
  }

  if (!data) {
    return (
      <Box sx={{ p: 3, textAlign: 'center' }}>
        <PaidIcon sx={{ fontSize: 40, color: '#dfe3ec', mb: 1 }} />
        <Typography sx={{ color: '#8a93a6', fontSize: '0.85rem' }}>
          {error ?? 'No cost data available.'}
        </Typography>
      </Box>
    );
  }

  const cacheTokens = data.tokens.cache_create + data.tokens.cache_read;

  return (
    <Box sx={{ p: 2 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
        <Box>
          <Typography sx={{ fontSize: '0.75rem', color: '#8a93a6', textTransform: 'uppercase', letterSpacing: 0.5 }}>
            Session cost
          </Typography>
          <Typography sx={{ fontSize: '2rem', fontWeight: 600, color: '#1a1f2c', lineHeight: 1.1 }}>
            {fmtUSD(data.total_usd)}
          </Typography>
          <Typography sx={{ fontSize: '0.75rem', color: '#5a6478', mt: 0.25 }}>
            {fmtTokens(data.tokens.input)} input · {fmtTokens(data.tokens.output)} output
            {cacheTokens > 0 ? ` · ${fmtTokens(cacheTokens)} cached` : ''}
          </Typography>
        </Box>
        <Button size="small" startIcon={<RefreshIcon fontSize="small" />} onClick={refresh} disabled={loading}>
          Refresh
        </Button>
      </Box>

      {data.unknown_models.length > 0 && (
        <Alert severity="warning" sx={{ mb: 2, fontSize: '0.8rem' }}>
          No pricing configured for: <code>{data.unknown_models.join(', ')}</code>.
          Cost for these calls is shown as $0. Edit
          <strong> Settings → LLM → Pricing</strong> to set rates.
        </Alert>
      )}

      <Typography sx={{ fontSize: '0.85rem', fontWeight: 600, mb: 1, color: '#5a6478' }}>
        Cumulative cost by iteration
      </Typography>
      {data.by_iteration.length > 0 ? (
        <CumulativeChart data={data.by_iteration} />
      ) : (
        <Typography sx={{ fontSize: '0.8rem', color: '#8a93a6', mb: 2 }}>
          No iterations recorded yet.
        </Typography>
      )}

      <Divider sx={{ my: 2 }} />

      <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', md: '1fr 1fr' }, gap: 2 }}>
        <Paper variant="outlined" sx={{ p: 1.5 }}>
          <Typography sx={{ fontSize: '0.85rem', fontWeight: 600, mb: 1 }}>Token breakdown</Typography>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Class</TableCell>
                <TableCell align="right">Tokens</TableCell>
                <TableCell align="right">Cost</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              <TableRow>
                <TableCell>Input</TableCell>
                <TableCell align="right">{fmtTokens(data.tokens.input)}</TableCell>
                <TableCell align="right">{fmtUSD(data.totals.input)}</TableCell>
              </TableRow>
              <TableRow>
                <TableCell>Output</TableCell>
                <TableCell align="right">{fmtTokens(data.tokens.output)}</TableCell>
                <TableCell align="right">{fmtUSD(data.totals.output)}</TableCell>
              </TableRow>
              <TableRow>
                <Tooltip title="cache_create = 1.25× input rate">
                  <TableCell>Cache create</TableCell>
                </Tooltip>
                <TableCell align="right">{fmtTokens(data.tokens.cache_create)}</TableCell>
                <TableCell align="right">{fmtUSD(data.totals.cache_create)}</TableCell>
              </TableRow>
              <TableRow>
                <Tooltip title="cache_read = 0.1× input rate">
                  <TableCell>Cache read</TableCell>
                </Tooltip>
                <TableCell align="right">{fmtTokens(data.tokens.cache_read)}</TableCell>
                <TableCell align="right">{fmtUSD(data.totals.cache_read)}</TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </Paper>

        <Paper variant="outlined" sx={{ p: 1.5 }}>
          <Typography sx={{ fontSize: '0.85rem', fontWeight: 600, mb: 1 }}>By source</Typography>
          {sourceRows.length === 0 ? (
            <Typography sx={{ fontSize: '0.8rem', color: '#8a93a6' }}>(no data)</Typography>
          ) : (
            <Table size="small">
              <TableBody>
                {sourceRows.map(r => (
                  <TableRow key={r.source}>
                    <TableCell>{r.source}</TableCell>
                    <TableCell align="right">{fmtUSD(r.cost)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </Paper>
      </Box>

      <Box sx={{ mt: 2 }}>
        <Paper variant="outlined" sx={{ p: 1.5 }}>
          <Typography sx={{ fontSize: '0.85rem', fontWeight: 600, mb: 1 }}>By model</Typography>
          {modelRows.length === 0 ? (
            <Typography sx={{ fontSize: '0.8rem', color: '#8a93a6' }}>(no data)</Typography>
          ) : (
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Model</TableCell>
                  <TableCell align="right">Cost</TableCell>
                  <TableCell align="right">Rate ($/1M in / out)</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {modelRows.map(r => {
                  const rate = data.rates_used[r.model];
                  return (
                    <TableRow key={r.model}>
                      <TableCell>
                        {r.model}
                        {!rate && (
                          <Chip
                            size="small"
                            label="no rate"
                            sx={{ ml: 1, fontSize: '0.65rem', height: 18 }}
                            color="warning"
                          />
                        )}
                      </TableCell>
                      <TableCell align="right">{fmtUSD(r.cost)}</TableCell>
                      <TableCell align="right">
                        {rate ? `$${rate.input} / $${rate.output}` : '—'}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </Paper>
      </Box>
    </Box>
  );
};

export default CostsPanel;

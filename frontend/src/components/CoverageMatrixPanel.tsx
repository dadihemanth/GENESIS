/**
 * v7.x — Coverage matrix tab.
 *
 * Per-endpoint × per-attack-class heatmap. Each cell shows whether an
 * attack class was tested against an endpoint and whether a verified
 * finding landed there. Untested cells are coverage gaps; the agent gets
 * a 'gaps remaining' nudge each iteration during the scan.
 *
 *   gray   = not tested
 *   amber  = attempted (probe ran, no verified finding)
 *   green  = confirmed (a verified vulnerability is attached here)
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Box, Chip, CircularProgress, IconButton, Tooltip, Typography,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import GridViewIcon from '@mui/icons-material/GridView';
import { sessionsApi } from '../services/api';

type CoverageData = Awaited<ReturnType<typeof sessionsApi.getCoverageMatrix>>;
type Cell = CoverageData['cells'][string][string];

interface Props { sessionId: string; }

const cellColor = (cell: Cell | undefined): string => {
  if (!cell || cell.attempted === 0) return '#e6e9f0';
  if (cell.confirmed) return '#2e7d32';
  return '#ed6c02';
};

const cellTextColor = (cell: Cell | undefined): string => {
  if (!cell || cell.attempted === 0) return '#8a93a6';
  return 'white';
};

const CoverageMatrixPanel: React.FC<Props> = ({ sessionId }) => {
  const [data, setData] = useState<CoverageData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(() => {
    setLoading(true);
    sessionsApi.getCoverageMatrix(sessionId)
      .then(d => { setData(d); setError(null); })
      .catch(() => setError('Failed to load coverage matrix.'))
      .finally(() => setLoading(false));
  }, [sessionId]);

  useEffect(() => { refresh(); }, [refresh]);

  const orderedEndpoints = useMemo(() => {
    if (!data) return [];
    // Endpoints with confirmed findings first, then by attempted count desc.
    return [...data.endpoints].sort((a, b) => {
      const ca = data.classes.reduce((acc, c) => acc + (data.cells[a]?.[c]?.confirmed ? 1 : 0), 0);
      const cb = data.classes.reduce((acc, c) => acc + (data.cells[b]?.[c]?.confirmed ? 1 : 0), 0);
      if (ca !== cb) return cb - ca;
      const aa = data.classes.reduce((acc, c) => acc + (data.cells[a]?.[c]?.attempted ?? 0), 0);
      const bb = data.classes.reduce((acc, c) => acc + (data.cells[b]?.[c]?.attempted ?? 0), 0);
      return bb - aa;
    });
  }, [data]);

  if (loading && !data) {
    return <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}><CircularProgress size={28} /></Box>;
  }
  if (!data) {
    return (
      <Box sx={{ p: 3, textAlign: 'center' }}>
        <Typography sx={{ color: '#8a93a6', fontSize: '0.85rem' }}>{error ?? 'No coverage data.'}</Typography>
      </Box>
    );
  }

  const { density } = data;

  return (
    <Box sx={{ p: 2 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 1.5, gap: 1 }}>
        <GridViewIcon sx={{ color: '#1565c0' }} />
        <Typography sx={{ fontSize: '1rem', fontWeight: 600 }}>Coverage Matrix</Typography>
        <Chip
          size="small"
          label={`${density.coverage_pct}% — ${density.attempted_cells}/${density.total_cells} cells probed`}
          sx={{ fontSize: '0.7rem', backgroundColor: 'rgba(21,101,192,0.1)', color: '#1565c0' }}
        />
        {density.confirmed_cells > 0 && (
          <Chip
            size="small"
            label={`${density.confirmed_cells} confirmed`}
            sx={{ fontSize: '0.7rem', backgroundColor: 'rgba(46,125,50,0.12)', color: '#2e7d32' }}
          />
        )}
        <Tooltip title="Refresh"><IconButton size="small" sx={{ ml: 'auto' }} onClick={refresh}><RefreshIcon fontSize="small" /></IconButton></Tooltip>
      </Box>

      <Box sx={{ mb: 2, p: 1.25, borderRadius: 1, backgroundColor: 'rgba(21,101,192,0.06)', border: '1px solid rgba(21,101,192,0.2)' }}>
        <Typography sx={{ fontSize: '0.78rem', color: '#3a4258' }}>
          <strong>How to read this:</strong> rows are endpoints discovered this run, columns are the 16 attack
          classes the agent is checked against. <span style={{ color: '#2e7d32', fontWeight: 600 }}>Green</span>{' '}
          = a verified finding landed there. <span style={{ color: '#ed6c02', fontWeight: 600 }}>Amber</span> =
          a probe ran but didn't confirm. <span style={{ color: '#8a93a6', fontWeight: 600 }}>Gray</span> =
          coverage gap (the agent never tried this class against this endpoint). Cell number is the count of
          probe invocations.
        </Typography>
      </Box>

      {orderedEndpoints.length === 0 ? (
        <Box sx={{ p: 3, textAlign: 'center' }}>
          <GridViewIcon sx={{ fontSize: 40, color: '#dfe3ec', mb: 1 }} />
          <Typography sx={{ color: '#8a93a6', fontSize: '0.85rem' }}>No targeted-probe activity yet.</Typography>
          <Typography sx={{ color: '#5a6478', fontSize: '0.75rem', mt: 0.5 }}>
            The matrix populates once the agent starts running attack-class probes
            (jwt_probe, sqlmap_test, ssrf_scheme_probe, etc.).
          </Typography>
        </Box>
      ) : (
        <Box sx={{ overflowX: 'auto', border: '1px solid #e0e3eb', borderRadius: 1 }}>
          <Box sx={{ display: 'inline-block', minWidth: '100%' }}>
            {/* Header row */}
            <Box sx={{ display: 'flex', backgroundColor: '#f3f4f8', borderBottom: '1px solid #e0e3eb' }}>
              <Box sx={{
                width: 240, minWidth: 240, p: 1, fontSize: '0.7rem', fontWeight: 600,
                color: '#3a4258', borderRight: '1px solid #e0e3eb', position: 'sticky', left: 0,
                backgroundColor: '#f3f4f8', zIndex: 1,
              }}>
                Endpoint
              </Box>
              {data.classes.map(c => (
                <Box key={c} sx={{
                  width: 84, minWidth: 84, p: 0.75, fontSize: '0.62rem', fontWeight: 600,
                  color: '#3a4258', textAlign: 'center', borderRight: '1px solid #e0e3eb',
                  whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                }} title={c}>
                  {c}
                </Box>
              ))}
            </Box>
            {/* Body rows */}
            {orderedEndpoints.map(ep => (
              <Box key={ep} sx={{ display: 'flex', borderBottom: '1px solid #eef0f5' }}>
                <Box
                  title={ep}
                  sx={{
                    width: 240, minWidth: 240, p: 1, fontSize: '0.72rem',
                    fontFamily: 'ui-monospace, "Cascadia Code", Menlo, monospace',
                    color: '#1a1f2c', borderRight: '1px solid #e0e3eb',
                    whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                    position: 'sticky', left: 0, backgroundColor: 'white', zIndex: 1,
                  }}
                >
                  {ep}
                </Box>
                {data.classes.map(c => {
                  const cell = data.cells[ep]?.[c];
                  return (
                    <Tooltip
                      key={c}
                      arrow
                      title={
                        cell && cell.attempted > 0
                          ? `${ep} × ${c}: ${cell.attempted} probe${cell.attempted === 1 ? '' : 's'}` +
                            (cell.last_tool ? ` (last: ${cell.last_tool})` : '') +
                            (cell.confirmed ? ' — CONFIRMED' : '')
                          : `${ep} × ${c}: not tested`
                      }
                    >
                      <Box sx={{
                        width: 84, minWidth: 84, height: 36,
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        backgroundColor: cellColor(cell), color: cellTextColor(cell),
                        fontSize: '0.7rem', fontWeight: 600, cursor: 'default',
                        borderRight: '1px solid #e0e3eb',
                      }}>
                        {cell && cell.attempted > 0 ? cell.attempted : ''}
                      </Box>
                    </Tooltip>
                  );
                })}
              </Box>
            ))}
          </Box>
        </Box>
      )}
    </Box>
  );
};

export default CoverageMatrixPanel;

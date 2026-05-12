/**
 * Hypotheses tab — sortable table view.
 *
 * Replaces the Cytoscape graph for primary readability. Columns:
 * id, statement, confidence, status, evidence (for/against counts),
 * next_test, updated_at.
 */
import React, { useMemo, useState } from 'react';
import {
  Box, Chip, Paper, Table, TableBody, TableCell, TableContainer, TableHead,
  TablePagination, TableRow, TableSortLabel, Tooltip, Typography,
} from '@mui/material';
import type { Hypothesis } from '../types';

type SortKey = 'hyp_id' | 'statement' | 'confidence' | 'status' | 'updated_at';

interface Props {
  hypotheses: Hypothesis[];
}

const STATUS_COLOR: Record<string, string> = {
  active: '#3f51b5',
  confirmed: '#137a4e',
  ruled_out: '#b53030',
  pending: '#8a93a6',
  in_progress: '#b8740c',
};

const fmtTime = (s: string): string => {
  if (!s) return '';
  try { return new Date(s).toLocaleString(); } catch { return s; }
};

export default function HypothesesTable({ hypotheses }: Props) {
  const [sortKey, setSortKey] = useState<SortKey>('confidence');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);

  const sorted = useMemo(() => {
    const copy = [...hypotheses];
    copy.sort((a: any, b: any) => {
      const av = a[sortKey];
      const bv = b[sortKey];
      let cmp = 0;
      if (typeof av === 'number' && typeof bv === 'number') cmp = av - bv;
      else cmp = String(av ?? '').localeCompare(String(bv ?? ''));
      return sortDir === 'asc' ? cmp : -cmp;
    });
    return copy;
  }, [hypotheses, sortKey, sortDir]);

  const slice = useMemo(
    () => sorted.slice(page * rowsPerPage, (page + 1) * rowsPerPage),
    [sorted, page, rowsPerPage],
  );

  const onSort = (key: SortKey) => {
    if (sortKey === key) setSortDir(d => (d === 'asc' ? 'desc' : 'asc'));
    else { setSortKey(key); setSortDir('desc'); }
  };

  if (hypotheses.length === 0) {
    return (
      <Box sx={{ p: 3, textAlign: 'center' }}>
        <Typography color="text.secondary">No hypotheses recorded yet.</Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 1 }}>
      <TableContainer component={Paper} variant="outlined">
        <Table size="small" stickyHeader>
          <TableHead>
            <TableRow>
              <TableCell sx={{ width: 80 }}>
                <TableSortLabel active={sortKey === 'hyp_id'} direction={sortDir} onClick={() => onSort('hyp_id')}>
                  ID
                </TableSortLabel>
              </TableCell>
              <TableCell>
                <TableSortLabel active={sortKey === 'statement'} direction={sortDir} onClick={() => onSort('statement')}>
                  Statement
                </TableSortLabel>
              </TableCell>
              <TableCell sx={{ width: 100 }}>
                <TableSortLabel active={sortKey === 'confidence'} direction={sortDir} onClick={() => onSort('confidence')}>
                  Confidence
                </TableSortLabel>
              </TableCell>
              <TableCell sx={{ width: 110 }}>
                <TableSortLabel active={sortKey === 'status'} direction={sortDir} onClick={() => onSort('status')}>
                  Status
                </TableSortLabel>
              </TableCell>
              <TableCell sx={{ width: 90 }}>Evidence</TableCell>
              <TableCell sx={{ width: 240 }}>Next test</TableCell>
              <TableCell sx={{ width: 150 }}>
                <TableSortLabel active={sortKey === 'updated_at'} direction={sortDir} onClick={() => onSort('updated_at')}>
                  Updated
                </TableSortLabel>
              </TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {slice.map(h => (
              <TableRow key={`${h.session_id}-${h.hyp_id}`} hover>
                <TableCell>
                  <Typography sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                    {h.hyp_id}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Tooltip title={h.statement} placement="top-start">
                    <Typography sx={{ fontSize: '0.85rem' }}>
                      {h.statement.length > 140 ? h.statement.slice(0, 140) + '…' : h.statement}
                    </Typography>
                  </Tooltip>
                </TableCell>
                <TableCell>
                  <Chip
                    size="small"
                    label={(h.confidence ?? 0).toFixed(2)}
                    sx={{
                      backgroundColor: h.confidence >= 0.7 ? '#137a4e' : h.confidence >= 0.4 ? '#b8740c' : '#8a93a6',
                      color: 'white',
                      fontWeight: 600,
                      fontSize: '0.7rem',
                    }}
                  />
                </TableCell>
                <TableCell>
                  <Chip
                    size="small"
                    label={h.status}
                    sx={{
                      backgroundColor: STATUS_COLOR[h.status] ?? '#5a6478',
                      color: 'white',
                      fontWeight: 500,
                      fontSize: '0.7rem',
                    }}
                  />
                </TableCell>
                <TableCell>
                  <Tooltip title={`for=${h.evidence_for?.length ?? 0} against=${h.evidence_against?.length ?? 0}`}>
                    <Typography sx={{ fontSize: '0.78rem', color: '#5a6478' }}>
                      ✓{h.evidence_for?.length ?? 0} / ✗{h.evidence_against?.length ?? 0}
                    </Typography>
                  </Tooltip>
                </TableCell>
                <TableCell>
                  <Tooltip title={h.next_test || '(no next test)'}>
                    <Typography sx={{ fontSize: '0.78rem', color: '#5a6478' }}>
                      {h.next_test
                        ? (h.next_test.length > 60 ? h.next_test.slice(0, 60) + '…' : h.next_test)
                        : '—'}
                    </Typography>
                  </Tooltip>
                </TableCell>
                <TableCell>
                  <Typography sx={{ fontSize: '0.72rem', color: '#8a93a6' }}>
                    {fmtTime(h.updated_at)}
                  </Typography>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
      <TablePagination
        rowsPerPageOptions={[10, 25, 50, 100]}
        component="div"
        count={sorted.length}
        rowsPerPage={rowsPerPage}
        page={page}
        onPageChange={(_, p) => setPage(p)}
        onRowsPerPageChange={e => { setRowsPerPage(parseInt(e.target.value, 10)); setPage(0); }}
      />
    </Box>
  );
}

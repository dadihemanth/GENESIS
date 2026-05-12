import React, { useEffect, useState } from 'react';
import {
  Box, Chip, CircularProgress, Paper, Table, TableBody, TableCell,
  TableHead, TableRow, Typography, Alert,
} from '@mui/material';
import { authApi } from '../services/api';
import type { AuditEntry } from '../types';

const ROLE_COLORS: Record<string, 'default' | 'primary' | 'secondary' | 'success' | 'warning' | 'error'> = {
  admin: 'error',
  operator: 'warning',
  reviewer: 'primary',
  read_only: 'default',
};

export default function UsersPage() {
  const [auditLog, setAuditLog] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    authApi.getAuditLog({ page: 1, size: 50 })
      .then(data => setAuditLog(data.items))
      .catch(err => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <Box sx={{ p: 4, display: 'flex', justifyContent: 'center' }}><CircularProgress /></Box>;

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h5" fontWeight={700} sx={{ mb: 3 }}>Users & Audit Log</Typography>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 2 }}>
        Recent audit entries (last 50 actions)
      </Typography>

      <Paper variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Time</TableCell>
              <TableCell>Action</TableCell>
              <TableCell>Resource</TableCell>
              <TableCell>IP</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {auditLog.length === 0 && (
              <TableRow>
                <TableCell colSpan={4}>
                  <Typography color="text.secondary" align="center">No audit entries</Typography>
                </TableCell>
              </TableRow>
            )}
            {auditLog.map(entry => (
              <TableRow key={entry.id} hover>
                <TableCell sx={{ whiteSpace: 'nowrap' }}>
                  {new Date(entry.ts).toLocaleString()}
                </TableCell>
                <TableCell>
                  <Chip label={entry.action} size="small" variant="outlined" />
                </TableCell>
                <TableCell>
                  <Typography variant="caption" color="text.secondary">
                    {entry.resource_type}{entry.resource_id ? `:${entry.resource_id.slice(0, 8)}` : ''}
                  </Typography>
                </TableCell>
                <TableCell>
                  <Typography variant="caption" color="text.secondary">{entry.ip_address || '—'}</Typography>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Paper>
    </Box>
  );
}

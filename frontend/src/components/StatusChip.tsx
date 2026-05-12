import React from 'react';
import { Chip } from '@mui/material';

interface StatusChipProps {
  status: string;
  size?: 'small' | 'medium';
}

const statusConfig: Record<string, { color: 'default' | 'primary' | 'secondary' | 'error' | 'info' | 'success' | 'warning'; label: string }> = {
  running: { color: 'primary', label: 'Running' },
  completed: { color: 'success', label: 'Completed' },
  failed: { color: 'error', label: 'Failed' },
  paused: { color: 'warning', label: 'Paused' },
  pending: { color: 'default', label: 'Pending' },
  available: { color: 'success', label: 'Available' },
  missing: { color: 'error', label: 'Missing' },
  error: { color: 'error', label: 'Error' },
};

const StatusChip: React.FC<StatusChipProps> = ({ status, size = 'small' }) => {
  const config = statusConfig[status] ?? { color: 'default' as const, label: status };
  return (
    <Chip
      label={config.label}
      color={config.color}
      size={size}
      sx={{ textTransform: 'capitalize', fontFamily: 'monospace', fontWeight: 600 }}
    />
  );
};

export default StatusChip;

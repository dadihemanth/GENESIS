import React from 'react';
import { Chip } from '@mui/material';
import type { Severity } from '../types';

interface SeverityBadgeProps {
  severity: Severity;
  size?: 'small' | 'medium';
}

const severityConfig: Record<Severity, { bg: string; color: string; label: string }> = {
  critical: { bg: '#d32f2f', color: '#fff', label: 'CRITICAL' },
  high: { bg: '#e64a19', color: '#fff', label: 'HIGH' },
  medium: { bg: '#f57c00', color: '#fff', label: 'MEDIUM' },
  low: { bg: '#1565c0', color: '#fff', label: 'LOW' },
  info: { bg: '#424242', color: '#fff', label: 'INFO' },
};

const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'small' }) => {
  const config = severityConfig[severity] ?? { bg: '#424242', color: '#fff', label: severity.toUpperCase() };
  return (
    <Chip
      label={config.label}
      size={size}
      sx={{
        backgroundColor: config.bg,
        color: config.color,
        fontWeight: 700,
        fontFamily: 'monospace',
        fontSize: size === 'small' ? '0.7rem' : '0.8rem',
        letterSpacing: '0.05em',
      }}
    />
  );
};

export default SeverityBadge;

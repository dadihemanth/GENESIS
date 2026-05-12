import React from 'react';
import { Chip } from '@mui/material';
import type { Severity } from '../types';

interface SeverityBadgeProps {
  severity: Severity;
  size?: 'small' | 'medium';
}

const severityConfig: Record<Severity, { bg: string; color: string; label: string }> = {
  critical: { bg: '#b53030', color: '#fff', label: 'CRITICAL' },
  high:     { bg: '#d65a1e', color: '#fff', label: 'HIGH' },
  medium:   { bg: '#b5581a', color: '#fff', label: 'MEDIUM' },
  low:      { bg: '#4e5ced', color: '#fff', label: 'LOW' },
  info:     { bg: '#e8ecf4', color: '#1a1f2e', label: 'INFO' },
};

const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'small' }) => {
  const config = severityConfig[severity] ?? { bg: '#e8ecf4', color: '#1a1f2e', label: severity.toUpperCase() };
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

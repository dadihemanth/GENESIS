import React from 'react';
import {
  Box, Chip, Paper, Typography,
} from '@mui/material';
import LightbulbIcon from '@mui/icons-material/Lightbulb';
import type { ExplanationEvent } from '../types';

interface ExplanationPanelProps {
  events: ExplanationEvent[];
  onHypothesisClick?: (hypId: string) => void;
}

export default function ExplanationPanel({ events, onHypothesisClick }: ExplanationPanelProps) {
  const lastThree = events.slice(-3).reverse();

  if (lastThree.length === 0) return null;

  return (
    <Paper
      elevation={2}
      sx={{
        position: 'fixed',
        bottom: 16,
        left: 16,
        width: 320,
        zIndex: 1200,
        background: 'rgba(18, 24, 40, 0.95)',
        backdropFilter: 'blur(10px)',
        border: '1px solid rgba(99, 130, 255, 0.2)',
        borderRadius: 2,
        overflow: 'hidden',
      }}
    >
      <Box sx={{ p: 1.5, borderBottom: '1px solid rgba(255,255,255,0.1)', display: 'flex', alignItems: 'center', gap: 1 }}>
        <LightbulbIcon fontSize="small" sx={{ color: 'warning.main' }} />
        <Typography variant="caption" fontWeight={700} color="text.secondary">
          WHY IS THE AGENT DOING THIS?
        </Typography>
      </Box>

      {lastThree.map((event, idx) => (
        <Box
          key={idx}
          sx={{
            p: 1.5,
            opacity: idx === 0 ? 1 : 0.5 + (0.25 * (lastThree.length - idx - 1)),
            borderBottom: idx < lastThree.length - 1 ? '1px solid rgba(255,255,255,0.05)' : 'none',
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 0.5 }}>
            <Chip label={event.tool_name} size="small" sx={{ fontSize: '0.65rem', height: 18 }} />
            {event.driving_hypothesis_id && (
              <Chip
                label={`H:${event.driving_hypothesis_id.slice(0, 6)}`}
                size="small"
                variant="outlined"
                color="primary"
                sx={{ fontSize: '0.65rem', height: 18, cursor: 'pointer' }}
                onClick={() => onHypothesisClick?.(event.driving_hypothesis_id!)}
              />
            )}
          </Box>
          <Typography variant="caption" color="text.secondary" display="block" sx={{ lineHeight: 1.4 }}>
            {event.explanation}
          </Typography>
        </Box>
      ))}
    </Paper>
  );
}

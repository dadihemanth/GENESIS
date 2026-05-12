// Shared empty-state for session tabs.
//
// The Findings/Chains/Sandbox/Graph/Evidence/Errors tabs depend on data
// that arrives later in the session lifecycle (first VULNERABILITY block,
// first graph delta, first chain link, etc.). Without this component each
// tab rendered a quiet "No X yet" caption that made it look like the tab
// was broken. This component standardises the empty-state pattern:
//   - clear icon + title
//   - one sentence describing what triggers data to appear
//   - a live "still scanning" pill with rolling counters when the session
//     is running (so the operator can see things ARE happening, just on
//     other tabs).
import React from 'react';
import { Box, Typography, keyframes } from '@mui/material';

const pulse = keyframes`
  0%   { box-shadow: 0 0 0 0 rgba(76,175,80,0.55); }
  70%  { box-shadow: 0 0 0 8px rgba(76,175,80,0); }
  100% { box-shadow: 0 0 0 0 rgba(76,175,80,0); }
`;

export interface EmptyTabCounter {
  label: string;
  value: number;
}

interface Props {
  icon: React.ReactNode;
  title: string;
  trigger: string;
  /** "running" | "completed" | "stopped" | "failed" | "paused" | undefined */
  sessionStatus?: string | null;
  /** Rolling counters shown when sessionStatus === 'running'. */
  counters?: EmptyTabCounter[];
}

const EmptyTabState: React.FC<Props> = ({ icon, title, trigger, sessionStatus, counters }) => {
  const isRunning = sessionStatus === 'running';
  const stoppedNote =
    sessionStatus === 'completed' ? 'Session has finished. If nothing showed up here, the agent did not produce data of this type.' :
    sessionStatus === 'stopped'   ? 'Session was stopped. The agent may have been working on this data when it was halted.' :
    sessionStatus === 'failed'    ? 'Session failed before reaching this stage.' :
    sessionStatus === 'paused'    ? 'Session is paused. Resume to continue.' :
    null;

  return (
    <Box sx={{ p: 4, textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 1 }}>
      <Box sx={{ color: '#c3cad7', fontSize: 36, mb: 0.5 }}>{icon}</Box>
      <Typography sx={{ color: '#1a1f2e', fontSize: '0.95rem', fontWeight: 600 }}>
        {title}
      </Typography>
      <Typography sx={{ color: '#5a6478', fontSize: '0.78rem', maxWidth: 480, lineHeight: 1.5 }}>
        {trigger}
      </Typography>

      {isRunning && counters && counters.length > 0 && (
        <Box sx={{
          mt: 1.5, display: 'inline-flex', alignItems: 'center', gap: 1.25,
          px: 1.5, py: 0.75, borderRadius: 4,
          backgroundColor: 'rgba(76,175,80,0.08)',
          border: '1px solid rgba(76,175,80,0.30)',
        }}>
          <Box sx={{
            width: 8, height: 8, borderRadius: '50%',
            backgroundColor: '#4caf50',
            animation: `${pulse} 1.6s ease-out infinite`,
          }} />
          <Typography sx={{ color: '#1a1f2e', fontSize: '0.72rem', fontWeight: 600 }}>
            Still scanning
          </Typography>
          <Box sx={{ width: 1, height: 12, backgroundColor: 'rgba(30,41,60,0.15)' }} />
          {counters.map((c, i) => (
            <Box key={c.label} sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Typography sx={{ color: '#4e5ced', fontSize: '0.74rem', fontWeight: 700, fontFamily: 'monospace' }}>
                {c.value}
              </Typography>
              <Typography sx={{ color: '#5a6478', fontSize: '0.68rem' }}>
                {c.label}
              </Typography>
              {i < counters.length - 1 && (
                <Typography sx={{ color: '#c3cad7', fontSize: '0.7rem', ml: 0.5 }}>·</Typography>
              )}
            </Box>
          ))}
        </Box>
      )}

      {!isRunning && stoppedNote && (
        <Typography sx={{ color: '#8a93a6', fontSize: '0.7rem', mt: 1, fontStyle: 'italic' }}>
          {stoppedNote}
        </Typography>
      )}
    </Box>
  );
};

export default EmptyTabState;

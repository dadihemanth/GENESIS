// Activity tab — chronological merged feed of every event the operator cares
// about: agent thoughts, tool calls, hypothesis form/update events.
// Replaces the old left + middle panels of SessionViewer with one stream.
import React, { useMemo, useRef, useEffect } from 'react';
import { Box, Chip, Typography, CircularProgress, Tooltip } from '@mui/material';
import PsychologyIcon from '@mui/icons-material/Psychology';
import TerminalIcon from '@mui/icons-material/Terminal';
import LightbulbIcon from '@mui/icons-material/Lightbulb';

import type { AgentThought, ToolOutput, Hypothesis } from '../types';
import { splitAgentPrefix, stripJsonBlocks, humanizeTool } from '../utils/humanize';

const AGENT_COLORS: Record<string, string> = {
  recon: '#4e5ced', analyst: '#26a69a', exploit: '#e91e63', code: '#8e24aa',
  crypto: '#3f51b5', auth: '#00838f', reveng: '#6a1b9a',
  exploitdev: '#c62828', network: '#ef6c00',
};

type EventKind = 'thought' | 'tool' | 'hypothesis';

interface UnifiedEvent {
  kind: EventKind;
  timestamp: string;
  iteration?: number;
  // raw refs for content-specific render
  thought?: AgentThought;
  tool?: ToolOutput;
  hypothesis?: Hypothesis;
}

const safeTime = (ts: string): string => {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString();
  } catch { return ts; }
};

interface Props {
  thoughts: AgentThought[];
  toolOutputs: ToolOutput[];
  hypotheses: Hypothesis[];
  autoScroll?: boolean;
}

const ActivityPanel: React.FC<Props> = ({ thoughts, toolOutputs, hypotheses, autoScroll = true }) => {
  const scrollRef = useRef<HTMLDivElement>(null);

  const merged = useMemo<UnifiedEvent[]>(() => {
    const out: UnifiedEvent[] = [];
    for (const t of thoughts) {
      out.push({ kind: 'thought', timestamp: t.timestamp, iteration: t.iteration, thought: t });
    }
    for (const t of toolOutputs) {
      out.push({ kind: 'tool', timestamp: t.timestamp, tool: t });
    }
    for (const h of hypotheses) {
      out.push({ kind: 'hypothesis', timestamp: h.updated_at, hypothesis: h });
    }
    return out.sort((a, b) => (a.timestamp > b.timestamp ? 1 : a.timestamp < b.timestamp ? -1 : 0));
  }, [thoughts, toolOutputs, hypotheses]);

  useEffect(() => {
    if (!autoScroll || !scrollRef.current) return;
    scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [merged.length, autoScroll]);

  if (merged.length === 0) {
    return (
      <Box sx={{ p: 4, textAlign: 'center' }}>
        <Typography variant="caption" sx={{ color: '#c3cad7' }}>
          Activity will appear here as the agent thinks, calls tools, and forms hypotheses.
        </Typography>
      </Box>
    );
  }

  return (
    <Box ref={scrollRef} sx={{ flexGrow: 1, overflowY: 'auto', backgroundColor: '#fafbfc' }}>
      {merged.map((ev, idx) => {
        if (ev.kind === 'thought' && ev.thought) {
          const { agent, body } = splitAgentPrefix(ev.thought.thought);
          const color = agent ? AGENT_COLORS[agent] ?? '#5a6478' : '#5a6478';
          const cleanBody = stripJsonBlocks(body);
          return (
            <Box key={`t-${ev.thought.id ?? idx}`} sx={{ display: 'flex', gap: 1, px: 2, py: 1.25, borderBottom: '1px solid rgba(30,41,60,0.04)', '&:hover': { backgroundColor: 'rgba(78,92,237,0.03)' } }}>
              <Box sx={{ flexShrink: 0, width: 22, color, pt: 0.25 }}><PsychologyIcon sx={{ fontSize: 18 }} /></Box>
              <Box sx={{ flexGrow: 1, minWidth: 0 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, mb: 0.25, flexWrap: 'wrap' }}>
                  <Chip label="thought" size="small"
                    sx={{ backgroundColor: 'rgba(94,103,144,0.10)', color: '#5e6790', fontSize: '0.6rem', height: 16 }} />
                  {agent && (
                    <Chip label={agent} size="small"
                      sx={{ backgroundColor: `${color}1a`, color, fontSize: '0.6rem', height: 16, fontWeight: 700 }} />
                  )}
                  <Typography sx={{ color: '#8a93a6', fontSize: '0.65rem', fontFamily: 'monospace' }}>iter {ev.thought.iteration}</Typography>
                  <Typography sx={{ color: '#c3cad7', fontSize: '0.62rem', ml: 'auto', fontFamily: 'monospace' }}>{safeTime(ev.thought.timestamp)}</Typography>
                </Box>
                <Typography sx={{ color: '#1a1f2e', fontSize: '0.78rem', lineHeight: 1.45, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                  {cleanBody || <em style={{ color: '#8a93a6' }}>(JSON-only thought; structured event captured elsewhere)</em>}
                </Typography>
              </Box>
            </Box>
          );
        }

        if (ev.kind === 'tool' && ev.tool) {
          const running = ev.tool.duration_seconds == null;
          const human = humanizeTool(ev.tool.tool_name);
          const paramSummary = Object.entries(ev.tool.params || {})
            .slice(0, 3)
            .map(([k, v]) => `${k}=${typeof v === 'string' ? v.substring(0, 40) : JSON.stringify(v).substring(0, 40)}`)
            .join(' ');
          return (
            <Box key={`o-${ev.tool.id ?? idx}`} sx={{ display: 'flex', gap: 1, px: 2, py: 1.25, borderBottom: '1px solid rgba(30,41,60,0.04)', '&:hover': { backgroundColor: 'rgba(78,92,237,0.03)' } }}>
              <Box sx={{ flexShrink: 0, width: 22, color: '#4e5ced', pt: 0.25 }}>
                {running ? <CircularProgress size={14} thickness={5} sx={{ color: '#ff9800' }} /> : <TerminalIcon sx={{ fontSize: 18 }} />}
              </Box>
              <Box sx={{ flexGrow: 1, minWidth: 0 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, mb: 0.25, flexWrap: 'wrap' }}>
                  <Chip label="tool" size="small"
                    sx={{ backgroundColor: 'rgba(78,92,237,0.10)', color: '#4e5ced', fontSize: '0.6rem', height: 16, fontWeight: 700 }} />
                  <Typography sx={{ color: '#1a1f2e', fontSize: '0.74rem', fontFamily: 'monospace', fontWeight: 700 }}>
                    {ev.tool.tool_name}
                  </Typography>
                  {!running && (
                    <Chip label={`${(ev.tool.duration_seconds ?? 0).toFixed(1)}s`} size="small"
                      sx={{ backgroundColor: 'rgba(76,175,80,0.12)', color: '#4caf50', fontSize: '0.6rem', height: 16 }} />
                  )}
                  <Typography sx={{ color: '#c3cad7', fontSize: '0.62rem', ml: 'auto', fontFamily: 'monospace' }}>{safeTime(ev.tool.timestamp)}</Typography>
                </Box>
                <Tooltip title={human} placement="top-start">
                  <Typography sx={{ color: '#5a6478', fontSize: '0.7rem', fontStyle: 'italic', mb: 0.25 }}>{human}</Typography>
                </Tooltip>
                {paramSummary && (
                  <Typography sx={{ color: '#4fc3f7', fontFamily: 'monospace', fontSize: '0.7rem', wordBreak: 'break-all', mb: 0.25 }}>
                    $ {paramSummary}
                  </Typography>
                )}
                {ev.tool.raw_output && !running && (
                  <Box component="pre" sx={{ color: '#1a1f2e', fontFamily: 'monospace', fontSize: '0.68rem', m: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: 160, overflowY: 'auto', backgroundColor: '#0a0a0a', color2: '#c8e6c9', borderRadius: 0.5, p: 0.75 }}>
                    <span style={{ color: '#c8e6c9' }}>{ev.tool.raw_output.substring(0, 1500)}{ev.tool.raw_output.length > 1500 ? '\n...' : ''}</span>
                  </Box>
                )}
              </Box>
            </Box>
          );
        }

        if (ev.kind === 'hypothesis' && ev.hypothesis) {
          const h = ev.hypothesis;
          const statusColor = h.status === 'confirmed' ? '#4caf50' : h.status === 'ruled_out' ? '#f44336' : '#ff9800';
          return (
            <Box key={`h-${h.hyp_id}-${idx}`} sx={{ display: 'flex', gap: 1, px: 2, py: 1.25, borderBottom: '1px solid rgba(30,41,60,0.04)', backgroundColor: `${statusColor}08`, '&:hover': { backgroundColor: `${statusColor}14` } }}>
              <Box sx={{ flexShrink: 0, width: 22, color: statusColor, pt: 0.25 }}><LightbulbIcon sx={{ fontSize: 18 }} /></Box>
              <Box sx={{ flexGrow: 1, minWidth: 0 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, mb: 0.25, flexWrap: 'wrap' }}>
                  <Chip label="hypothesis" size="small"
                    sx={{ backgroundColor: `${statusColor}1a`, color: statusColor, fontSize: '0.6rem', height: 16, fontWeight: 700 }} />
                  <Chip label={h.status} size="small"
                    sx={{ backgroundColor: `${statusColor}1a`, color: statusColor, fontSize: '0.6rem', height: 16 }} />
                  <Typography sx={{ color: '#5a6478', fontSize: '0.65rem', fontFamily: 'monospace' }}>conf {(h.confidence ?? 0).toFixed(2)}</Typography>
                  <Typography sx={{ color: '#8a93a6', fontSize: '0.65rem', fontFamily: 'monospace' }}>{h.hyp_id}</Typography>
                  <Typography sx={{ color: '#c3cad7', fontSize: '0.62rem', ml: 'auto', fontFamily: 'monospace' }}>{safeTime(h.updated_at)}</Typography>
                </Box>
                <Typography sx={{ color: '#1a1f2e', fontSize: '0.78rem', fontWeight: 600, mb: 0.25 }}>{h.statement}</Typography>
                {h.next_test && (
                  <Typography sx={{ color: '#5a6478', fontSize: '0.7rem', fontStyle: 'italic' }}>next test: {h.next_test}</Typography>
                )}
              </Box>
            </Box>
          );
        }
        return null;
      })}
    </Box>
  );
};

export default ActivityPanel;

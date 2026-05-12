import React, { useEffect, useRef, useState } from 'react';
import {
  Box, Card, CardContent, Chip, Grid, Typography, CircularProgress,
} from '@mui/material';
import PsychologyIcon from '@mui/icons-material/Psychology';
import type { AgentState } from '../types';
import { SessionWebSocket } from '../services/websocket';

const AGENT_COLORS: Record<string, string> = {
  orchestrator: '#3f51b5',
  recon: '#5c6bc0',
  analyst: '#009688',
  exploit: '#e91e63',
  code: '#9c27b0',
  'iot-specialist': '#ff9800',
  'mobile-specialist': '#4caf50',
  'ot-specialist': '#f44336',
  'embedded-specialist': '#795548',
  persona_paranoid_pentester: '#607d8b',
  persona_ransomware_operator: '#d32f2f',
  persona_nation_state_apt: '#1565c0',
  persona_insider_threat: '#6a1b9a',
  persona_opportunistic: '#e65100',
};

interface AgentChorusPageProps {
  sessionId?: string;
}

export default function AgentChorusPage({ sessionId }: AgentChorusPageProps) {
  const [agents, setAgents] = useState<Map<string, AgentState>>(new Map());
  const wsRef = useRef<SessionWebSocket | null>(null);

  useEffect(() => {
    if (!sessionId) return;
    // Reuse SessionWebSocket so this page connects to the canonical
    // /ws/{session_id}?token=<api-key> endpoint with auth + auto-reconnect.
    // The previous raw WebSocket pointed at /api/v1/sessions/{id}/ws (which
    // doesn't exist) and skipped the X-API-Key token, so it silently failed.
    const ws = new SessionWebSocket(sessionId);
    wsRef.current = ws;

    const unsubscribe = ws.onMessage((msg) => {
      const data = (msg.data ?? {}) as Record<string, unknown>;

      // v7.x — token-usage events tell us which model an agent burned.
      // source labels: orchestrator | critic | brief | history_compress |
      // red_agent | blue_agent | philosopher | insider | nation_state |
      // subagent:<role> | reasoning_loop | backstop_loop
      if (msg.type === 'llm_usage_recorded') {
        const source = String(data.source ?? '');
        const model = String(data.model ?? '');
        const inTok = Number(data.input_tokens ?? 0);
        const outTok = Number(data.output_tokens ?? 0);
        // Map source -> stable agent_id (subagent:exploit -> exploit, etc.)
        const aid = source.startsWith('subagent:')
          ? source.slice('subagent:'.length)
          : source;
        if (!aid) return;
        setAgents(prev => {
          const next = new Map(prev);
          const existing = next.get(aid);
          next.set(aid, {
            agent_id: aid,
            agent_type: existing?.agent_type ?? aid,
            current_action: existing?.current_action ?? '',
            last_thought: existing?.last_thought ?? '',
            status: 'thinking',
            model,
            total_input_tokens: (existing?.total_input_tokens ?? 0) + inTok,
            total_output_tokens: (existing?.total_output_tokens ?? 0) + outTok,
            last_active: String(data.ts ?? msg.timestamp),
          });
          return next;
        });
        return;
      }

      // Activity events. Solo orchestrator emits agent_id="orchestrator" on
      // agent_thought; multi-agent's SubAgent emits agent_id+agent_type on
      // every event. Also accept the bare `agent` field (some events use it).
      const agentId =
        (data.agent_id as string | undefined)
        ?? (data.agent as string | undefined);
      if (!agentId) return;
      const agentType = (data.agent_type as string) || agentId;
      const thought =
        (data.thought as string) ||
        (data.content as string) ||
        (data.value as string) ||
        '';
      const action = (data.tool_name as string) || (data.tool as string) || msg.type || '';

      let status: AgentState['status'] = 'thinking';
      if (msg.type === 'tool_execution') status = 'executing';
      else if (msg.type === 'agent_complete') status = 'idle';
      else if (msg.type === 'agent_start') status = 'thinking';

      setAgents(prev => {
        const next = new Map(prev);
        const existing = next.get(agentId);
        next.set(agentId, {
          agent_id: agentId,
          agent_type: agentType,
          current_action: action,
          last_thought: thought || (existing?.last_thought ?? ''),
          status,
          model: existing?.model,
          total_input_tokens: existing?.total_input_tokens,
          total_output_tokens: existing?.total_output_tokens,
          last_active: msg.timestamp,
        });
        return next;
      });
    });

    ws.connect();

    return () => {
      unsubscribe();
      ws.disconnect();
    };
  }, [sessionId]);

  const agentList = Array.from(agents.values());

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 3 }}>
        <PsychologyIcon />
        <Typography variant="h5" fontWeight={700}>Agent Chorus</Typography>
        {sessionId && (
          <Chip label={`Session ${sessionId.slice(0, 8)}`} size="small" variant="outlined" />
        )}
      </Box>

      {!sessionId && (
        <Typography color="text.secondary">Select a running session to view agent activity.</Typography>
      )}

      {sessionId && agentList.length === 0 && (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <CircularProgress size={20} />
          <Typography color="text.secondary">Waiting for agent activity…</Typography>
        </Box>
      )}

      <Grid container spacing={2}>
        {agentList.map(agent => {
          const color = AGENT_COLORS[agent.agent_id] || AGENT_COLORS[agent.agent_type] || '#607d8b';
          return (
            <Grid item xs={12} sm={6} md={4} key={agent.agent_id}>
              <Card
                variant="outlined"
                sx={{ borderLeft: `4px solid ${color}`, opacity: agent.status === 'idle' ? 0.6 : 1 }}
              >
                <CardContent>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                    <Typography variant="subtitle2" fontWeight={700} sx={{ color }}>
                      {agent.agent_type}
                    </Typography>
                    <Chip
                      label={agent.status}
                      size="small"
                      color={agent.status === 'executing' ? 'warning' : agent.status === 'thinking' ? 'primary' : 'default'}
                    />
                  </Box>

                  {agent.model && (
                    <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 0.25 }}>
                      <Box component="span" sx={{ fontWeight: 600, color: '#4e5ced' }}>model:</Box>{' '}
                      <Box component="span" sx={{ fontFamily: 'monospace' }}>{agent.model}</Box>
                      {(agent.total_input_tokens || agent.total_output_tokens) ? (
                        <Box component="span" sx={{ ml: 1, color: '#8a93a6' }}>
                          · {Math.round((agent.total_input_tokens ?? 0) / 1000)}k in / {Math.round((agent.total_output_tokens ?? 0) / 1000)}k out
                        </Box>
                      ) : null}
                    </Typography>
                  )}
                  {agent.current_action && (
                    <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 0.5 }}>
                      ▶ {agent.current_action}
                    </Typography>
                  )}

                  <Typography
                    variant="body2"
                    sx={{
                      mt: 1, p: 1,
                      background: 'rgba(255,255,255,0.04)',
                      borderRadius: 1,
                      fontSize: '0.75rem',
                      maxHeight: 80,
                      overflow: 'hidden',
                      display: '-webkit-box',
                      WebkitLineClamp: 3,
                      WebkitBoxOrient: 'vertical',
                    }}
                  >
                    {agent.last_thought || '—'}
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          );
        })}
      </Grid>
    </Box>
  );
}

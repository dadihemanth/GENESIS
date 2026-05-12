// Story tab — plain-English narration of the session for non-technical readers.
// Pure client-side: maps existing events into friendly sentences via
// utils/humanize. No LLM calls, no extra backend traffic.
import React, { useMemo } from 'react';
import { Box, Typography, Chip } from '@mui/material';

import type { AgentThought, ToolOutput, Hypothesis, Vulnerability, Session } from '../types';
import {
  humanizeTool, humanizeAgent, humanizeSeverity, humanizeStatus, humanizePhase,
  splitAgentPrefix, stripJsonBlocks,
} from '../utils/humanize';

interface StoryBeat {
  ts: string;
  emoji: string;
  sentence: string;
  detail?: string;
  color?: string;
  iteration?: number;
}

interface Props {
  session: Session | null;
  thoughts: AgentThought[];
  toolOutputs: ToolOutput[];
  hypotheses: Hypothesis[];
  vulns: Vulnerability[];
}

const safeTime = (ts: string): string => {
  try { return new Date(ts).toLocaleTimeString(); } catch { return ts; }
};

// Pick the first sentence from a thought as a "what was the agent thinking" cue.
function leadSentence(text: string): string {
  const cleaned = stripJsonBlocks(text || '').replace(/\s+/g, ' ').trim();
  if (!cleaned) return '';
  const m = /^(.+?[.!?])(\s|$)/.exec(cleaned);
  return (m ? m[1] : cleaned).substring(0, 240);
}

const Storyboard: React.FC<Props> = ({ session, thoughts, toolOutputs, hypotheses, vulns }) => {
  const beats = useMemo<StoryBeat[]>(() => {
    const out: StoryBeat[] = [];

    if (session) {
      out.push({
        ts: session.started_at || session.created_at,
        emoji: '🚀',
        sentence: `The session started against ${session.target_ip}.`,
        detail: `Mode: ${session.agent_mode}. Profile: ${session.scan_profile}.`,
        color: '#4e5ced',
      });
    }

    // Render hypotheses as story beats (form / confirm / rule_out)
    for (const h of hypotheses) {
      const verb = h.status === 'confirmed' ? 'confirmed a hunch'
                  : h.status === 'ruled_out' ? 'ruled out a hunch'
                  : 'started checking a hunch';
      const emoji = h.status === 'confirmed' ? '💡'
                   : h.status === 'ruled_out' ? '🚫' : '🤔';
      const color = h.status === 'confirmed' ? '#4caf50'
                   : h.status === 'ruled_out' ? '#f44336' : '#ff9800';
      out.push({
        ts: h.updated_at,
        emoji,
        sentence: `The agent ${verb}: "${h.statement}".`,
        detail: h.next_test ? `Next test: ${h.next_test}` : undefined,
        color,
      });
    }

    // First action by each agent type — narrate a "specialist arrived" beat
    const seenAgents = new Set<string>();
    const sortedThoughts = [...thoughts].sort((a, b) => String(a.timestamp ?? '').localeCompare(String(b.timestamp ?? '')));
    for (const t of sortedThoughts) {
      const { agent, body } = splitAgentPrefix(t.thought);
      if (agent && !seenAgents.has(agent)) {
        seenAgents.add(agent);
        out.push({
          ts: t.timestamp,
          emoji: '🎬',
          sentence: `${humanizeAgent(agent).replace(/^./, c => c.toUpperCase())} joined the session.`,
          color: '#26a69a',
          iteration: t.iteration,
        });
      }
      const lead = leadSentence(body);
      if (lead) {
        out.push({
          ts: t.timestamp,
          emoji: '🧠',
          sentence: `${humanizeAgent(agent).replace(/^./, c => c.toUpperCase())} thought: "${lead}"`,
          color: '#5a6478',
          iteration: t.iteration,
        });
      }
    }

    // Tools — narrate each invocation
    for (const t of toolOutputs) {
      out.push({
        ts: t.timestamp,
        emoji: '🔧',
        sentence: `The agent ${humanizeTool(t.tool_name)}.`,
        detail: t.duration_seconds != null ? `Took ${t.duration_seconds.toFixed(1)}s.` : 'Still running…',
        color: '#4e5ced',
      });
    }

    // Vulnerabilities — narrate each one with status + severity
    for (const v of vulns) {
      const sev = humanizeSeverity(v.severity);
      const status = humanizeStatus(v.verification_status);
      const emoji = v.verification_status === 'exploited' ? '💥'
                   : v.verification_status === 'confirmed' ? '✅'
                   : v.verification_status === 'disputed' ? '⚠️' : '❓';
      const color = v.severity === 'critical' ? '#f44336'
                   : v.severity === 'high' ? '#ff6d00'
                   : v.severity === 'medium' ? '#ff9800'
                   : '#5a6478';
      out.push({
        ts: v.created_at,
        emoji,
        sentence: `The agent found something ${sev} (${status}): ${v.title}.`,
        detail: v.affected_service ? `Affects: ${v.affected_service}${v.port ? `:${v.port}` : ''}.` : undefined,
        color,
      });
    }

    if (session?.completed_at) {
      out.push({
        ts: session.completed_at,
        emoji: '🏁',
        sentence: `The session finished. The agent saved ${session.vulnerability_count ?? 0} finding${(session.vulnerability_count ?? 0) === 1 ? '' : 's'} in total.`,
        color: '#4caf50',
      });
    } else if (session?.phase) {
      out.push({
        ts: new Date().toISOString(),
        emoji: '⏳',
        sentence: `Right now the agent is ${humanizePhase(session.phase)}.`,
        color: '#5a6478',
      });
    }

    return out.sort((a, b) => (a.ts > b.ts ? 1 : a.ts < b.ts ? -1 : 0));
  }, [session, thoughts, toolOutputs, hypotheses, vulns]);

  if (beats.length === 0) {
    return (
      <Box sx={{ p: 4, textAlign: 'center' }}>
        <Typography variant="caption" sx={{ color: '#c3cad7' }}>
          The story will fill in as the agent works. Each line is one moment in the
          session, told in plain English.
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ flexGrow: 1, overflowY: 'auto', backgroundColor: '#fafbfc', p: 3 }}>
      <Box sx={{ maxWidth: 760, mx: 'auto' }}>
        <Typography variant="h6" sx={{ color: '#1a1f2e', mb: 0.5 }}>📖 The story so far</Typography>
        <Typography sx={{ color: '#5a6478', fontSize: '0.78rem', mb: 3 }}>
          A plain-English narration of what the agent has been doing. One line per moment.
          Refresh whenever you want — it auto-updates as the session runs.
        </Typography>

        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.25 }}>
          {beats.map((b, i) => (
            <Box
              key={i}
              sx={{
                display: 'flex',
                gap: 1.5,
                px: 1.5,
                py: 1.25,
                borderRadius: 1.5,
                backgroundColor: '#ffffff',
                borderLeft: `3px solid ${b.color ?? '#4e5ced'}`,
                boxShadow: '0 1px 2px rgba(0,0,0,0.04)',
              }}
            >
              <Box sx={{ flexShrink: 0, fontSize: '1.4rem', lineHeight: 1, pt: 0.25 }}>{b.emoji}</Box>
              <Box sx={{ flexGrow: 1, minWidth: 0 }}>
                <Typography sx={{ color: '#1a1f2e', fontSize: '0.9rem', lineHeight: 1.45 }}>
                  {b.sentence}
                </Typography>
                {b.detail && (
                  <Typography sx={{ color: '#5a6478', fontSize: '0.78rem', mt: 0.25, fontStyle: 'italic' }}>
                    {b.detail}
                  </Typography>
                )}
                <Box sx={{ display: 'flex', gap: 0.75, mt: 0.5, alignItems: 'center' }}>
                  <Typography sx={{ color: '#8a93a6', fontSize: '0.65rem', fontFamily: 'monospace' }}>
                    {safeTime(b.ts)}
                  </Typography>
                  {b.iteration != null && (
                    <Chip label={`iter ${b.iteration}`} size="small"
                      sx={{ backgroundColor: 'rgba(94,103,144,0.10)', color: '#5e6790', fontSize: '0.55rem', height: 13 }} />
                  )}
                </Box>
              </Box>
            </Box>
          ))}
        </Box>
      </Box>
    </Box>
  );
};

export default Storyboard;

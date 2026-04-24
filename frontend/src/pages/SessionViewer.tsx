import React, { useEffect, useRef, useState, useCallback } from 'react';
import {
  Box,
  Typography,
  Chip,
  IconButton,
  Button,
  LinearProgress,
  CircularProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Snackbar,
  Alert,
  Tooltip,
  Tabs,
  Tab,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Stepper,
  Step,
  StepLabel,
  StepContent,
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import PauseIcon from '@mui/icons-material/Pause';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import StopIcon from '@mui/icons-material/Stop';
import PsychologyIcon from '@mui/icons-material/Psychology';
import TerminalIcon from '@mui/icons-material/Terminal';
import BugReportIcon from '@mui/icons-material/BugReport';
import WifiIcon from '@mui/icons-material/Wifi';
import WifiOffIcon from '@mui/icons-material/WifiOff';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import LinkIcon from '@mui/icons-material/Link';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import CodeIcon from '@mui/icons-material/Code';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline';
import ReportProblemIcon from '@mui/icons-material/ReportProblem';
import { useNavigate, useParams } from 'react-router-dom';
import { format } from 'date-fns';

import { sessionsApi, vulnerabilitiesApi } from '../services/api';
import { SessionWebSocket } from '../services/websocket';
import SeverityBadge from '../components/SeverityBadge';
import StatusChip from '../components/StatusChip';
import type { Session, AgentThought, ToolOutput, Vulnerability, DeepThought, AttackChain, NetworkTopology, Hypothesis, SessionError } from '../types';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#f44336', high: '#ff6d00', medium: '#ff9800', low: '#2979ff', info: '#9e9e9e',
};
const VERIFICATION_COLORS: Record<string, string> = {
  unverified: '#9e9e9e', confirmed: '#4caf50', exploited: '#f44336', disputed: '#ff9800',
};

// Hard caps on in-memory arrays so long-running sessions can't balloon the
// React state until the tab OOMs. On overflow we drop the oldest entries —
// the full history is still available in PostgreSQL / MongoDB via the
// session's API endpoints.
const MAX_THOUGHTS = 500;
const MAX_TOOL_OUTPUTS = 500;
const MAX_DEEP_THOUGHTS = 200;
const MAX_SESSION_ERRORS = 200;

const capTail = <T,>(arr: T[], limit: number): T[] =>
  arr.length <= limit ? arr : arr.slice(arr.length - limit);

/**
 * Format a timestamp defensively — if the input is null/undefined or parses
 * to an invalid Date, return '' instead of throwing. date-fns `format()`
 * throws on Invalid Date, which used to propagate up to the render and
 * blank the whole Session Viewer.
 */
const safeTime = (ts: string | null | undefined): string => {
  if (!ts) return '';
  const d = new Date(ts);
  if (isNaN(d.getTime())) return '';
  try {
    return format(d, 'HH:mm:ss');
  } catch {
    return '';
  }
};

// Small SVG topology mini-map
const TopologyMiniMap: React.FC<{ topology: NetworkTopology }> = ({ topology }) => {
  const W = 200, H = 110;
  const nodes = topology?.nodes ?? [];
  const edges = topology?.edges ?? [];
  if (nodes.length === 0) return null;

  const angleStep = nodes.length > 1 ? (2 * Math.PI) / nodes.length : 0;
  const cx = W / 2, cy = H / 2, r = Math.min(W, H) / 2 - 20;

  const pos: Record<string, { x: number; y: number }> = {};
  nodes.forEach((n, i) => {
    pos[n.id] = {
      x: cx + r * Math.cos(angleStep * i - Math.PI / 2),
      y: cy + r * Math.sin(angleStep * i - Math.PI / 2),
    };
  });

  return (
    <Box sx={{ border: '1px solid rgba(255,255,255,0.1)', borderRadius: 1, overflow: 'hidden', flexShrink: 0 }}>
      <svg width={W} height={H} style={{ background: '#0d0d0d', display: 'block' }}>
        {edges.map((e, i) => {
          const from = pos[e.from], to = pos[e.to];
          if (!from || !to) return null;
          return <line key={i} x1={from.x} y1={from.y} x2={to.x} y2={to.y} stroke="rgba(134,188,37,0.3)" strokeWidth={1} />;
        })}
        {nodes.map((n) => {
          const p = pos[n.id];
          if (!p) return null;
          const color = n.severity ? SEVERITY_COLORS[n.severity] : n.type === 'host' ? '#4fc3f7' : '#86BC25';
          return (
            <g key={n.id}>
              <circle cx={p.x} cy={p.y} r={5} fill={color} opacity={0.9} />
              <text x={p.x} y={p.y + 14} textAnchor="middle" fill="#9e9e9e" fontSize={7} fontFamily="monospace">
                {n.label.substring(0, 12)}
              </text>
            </g>
          );
        })}
      </svg>
    </Box>
  );
};

const SessionViewer: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [session, setSession] = useState<Session | null>(null);
  const [thoughts, setThoughts] = useState<AgentThought[]>([]);
  const [toolOutputs, setToolOutputs] = useState<ToolOutput[]>([]);
  const [liveVulns, setLiveVulns] = useState<Vulnerability[]>([]);
  const [deepThoughts, setDeepThoughts] = useState<DeepThought[]>([]);
  const [attackChains, setAttackChains] = useState<AttackChain[]>([]);
  const [hypotheses, setHypotheses] = useState<Hypothesis[]>([]);
  const [topology, setTopology] = useState<NetworkTopology>({ nodes: [], edges: [] });
  const [sessionErrors, setSessionErrors] = useState<SessionError[]>([]);
  const [rightTab, setRightTab] = useState(0);
  const [patchDialogVuln, setPatchDialogVuln] = useState<Vulnerability | null>(null);
  const [wsConnected, setWsConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [completedDialog, setCompletedDialog] = useState(false);
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false, message: '', severity: 'success',
  });

  const thoughtsRef = useRef<HTMLDivElement>(null);
  const toolsRef = useRef<HTMLDivElement>(null);
  const vulnsRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<SessionWebSocket | null>(null);

  const scrollToBottom = (ref: React.RefObject<HTMLDivElement>) => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  };

  useEffect(() => { scrollToBottom(thoughtsRef); }, [thoughts]);
  useEffect(() => { scrollToBottom(toolsRef); }, [toolOutputs]);
  useEffect(() => { scrollToBottom(vulnsRef); }, [liveVulns]);

  const loadAttackChains = useCallback(async () => {
    if (!id) return;
    try {
      const chains = await sessionsApi.getAttackChains(id);
      setAttackChains(chains);
    } catch { /* non-critical */ }
  }, [id]);

  const loadErrors = useCallback(async () => {
    if (!id) return;
    try {
      const result = await sessionsApi.getErrors(id, { size: 100 });
      setSessionErrors(capTail(result.items ?? [], MAX_SESSION_ERRORS));
    } catch { /* non-critical */ }
  }, [id]);

  // Initial data load
  useEffect(() => {
    if (!id) return;
    const load = async () => {
      setLoading(true);
      try {
        const [sessionData, thoughtsData, toolsData, vulnsData, topologyData, hypsData] = await Promise.allSettled([
          sessionsApi.get(id),
          sessionsApi.getThoughts(id, { size: 100 }),
          sessionsApi.getToolOutputs(id, { size: 100 }),
          vulnerabilitiesApi.list({ session_id: id, size: 50 }),
          sessionsApi.getNetworkTopology(id),
          sessionsApi.getHypotheses(id),
        ]);
        if (sessionData.status === 'fulfilled') {
          setSession(sessionData.value);
          if (sessionData.value.network_topology) setTopology(sessionData.value.network_topology);
        }
        if (thoughtsData.status === 'fulfilled') {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const v = thoughtsData.value as any;
          const arr = Array.isArray(v) ? v : (v?.items ?? []);
          setThoughts(capTail(arr, MAX_THOUGHTS));
        }
        if (toolsData.status === 'fulfilled') {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const v = toolsData.value as any;
          const arr = Array.isArray(v) ? v : (v?.items ?? []);
          setToolOutputs(capTail(arr, MAX_TOOL_OUTPUTS));
        }
        if (vulnsData.status === 'fulfilled') setLiveVulns(vulnsData.value.items);
        if (topologyData.status === 'fulfilled') setTopology(topologyData.value);
        if (hypsData.status === 'fulfilled') {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const v = hypsData.value as any;
          setHypotheses(Array.isArray(v) ? v : (v?.items ?? []));
        }
      } finally {
        setLoading(false);
      }
    };
    load();
    loadAttackChains();
    loadErrors();
  }, [id, loadAttackChains, loadErrors]);

  // WebSocket
  useEffect(() => {
    if (!id) return;
    const ws = new SessionWebSocket(id);
    wsRef.current = ws;

    const unsubscribe = ws.onMessage((msg) => {
      switch (msg.type) {
        case 'agent_thought': {
          const thought = msg.data as unknown as AgentThought;
          setThoughts(prev => capTail([...prev, thought], MAX_THOUGHTS));
          break;
        }
        case 'deep_thought': {
          const dt: DeepThought = {
            content: String(msg.data.content ?? ''),
            iteration: Number(msg.data.iteration ?? 0),
            timestamp: msg.timestamp,
          };
          setDeepThoughts(prev => capTail([...prev, dt], MAX_DEEP_THOUGHTS));
          break;
        }
        case 'tool_execution': {
          const output = msg.data as unknown as ToolOutput;
          setToolOutputs(prev => {
            const existing = prev.findIndex(t => t.tool_name === output.tool_name && !t.duration_seconds);
            if (existing >= 0) {
              const updated = [...prev];
              updated[existing] = output;
              return updated;
            }
            return capTail([...prev, output], MAX_TOOL_OUTPUTS);
          });
          break;
        }
        case 'vulnerability_found': {
          const vuln = msg.data as unknown as Vulnerability;
          setLiveVulns(prev => {
            if (prev.find(v => v.id === vuln.id)) return prev;
            return [...prev, vuln];
          });
          break;
        }
        case 'session_update': {
          const updates = msg.data as Partial<Session>;
          setSession(prev => prev ? { ...prev, ...updates } : prev);
          break;
        }
        case 'topology_update': {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const update = msg.data as any;
          setTopology(prev => {
            const next = { nodes: [...(prev.nodes ?? [])], edges: [...(prev.edges ?? [])] };
            if (update.action === 'add_node' && update.node) {
              if (!next.nodes.find(n => n.id === update.node.id)) next.nodes.push(update.node);
            } else if (update.action === 'add_edge' && update.edge) {
              next.edges.push(update.edge);
            }
            return next;
          });
          break;
        }
        case 'hypothesis_update': {
          const hyp = msg.data as unknown as Hypothesis;
          setHypotheses(prev => {
            const idx = prev.findIndex(h => h.hyp_id === hyp.hyp_id && h.session_id === hyp.session_id);
            if (idx >= 0) {
              const updated = [...prev];
              updated[idx] = hyp;
              return updated;
            }
            return [...prev, hyp];
          });
          break;
        }
        case 'session_complete': {
          setSession(prev => prev ? { ...prev, status: 'completed' } : prev);
          setCompletedDialog(true);
          loadAttackChains();
          // refresh errors in case non-fatal tool errors accumulated
          loadErrors();
          break;
        }
        case 'session_error': {
          const data = msg.data as Record<string, unknown>;
          // Append a synthetic entry so the Errors tab updates live even
          // before we re-fetch from the server.
          const entry: SessionError = {
            id: `live-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
            session_id: id ?? '',
            phase: String(data.phase ?? 'unhandled'),
            error_type: String(data.error_type ?? 'Error'),
            error_message: String(data.message ?? ''),
            traceback: '',
            iteration: typeof data.iteration === 'number' ? data.iteration : null,
            tool: typeof data.tool === 'string' ? data.tool : null,
            context: {},
            timestamp: msg.timestamp,
          };
          setSessionErrors(prev => capTail([...prev, entry], MAX_SESSION_ERRORS));
          setSnackbar({
            open: true,
            message: `[${entry.phase}] ${entry.error_type}: ${entry.error_message}`.slice(0, 240),
            severity: 'error',
          });
          // Pull the full entry (with traceback) from the backend.
          loadErrors();
          break;
        }
        case 'error': {
          setSnackbar({ open: true, message: String(msg.data.message ?? 'WebSocket error'), severity: 'error' });
          break;
        }
      }
    });

    ws.connect();
    const interval = setInterval(() => setWsConnected(ws.isConnected()), 1000);

    return () => {
      unsubscribe();
      ws.disconnect();
      clearInterval(interval);
    };
  }, [id, loadAttackChains, loadErrors]);

  const handleAction = useCallback(async (action: 'pause' | 'resume' | 'stop') => {
    if (!id) return;
    setActionLoading(true);
    try {
      if (action === 'pause') await sessionsApi.pause(id);
      else if (action === 'resume') await sessionsApi.resume(id);
      else await sessionsApi.stop(id);
      const updated = await sessionsApi.get(id);
      setSession(updated);
    } catch (err) {
      setSnackbar({ open: true, message: err instanceof Error ? err.message : 'Action failed', severity: 'error' });
    } finally {
      setActionLoading(false);
    }
  }, [id]);

  const severityCounts = {
    critical: liveVulns.filter(v => v.severity === 'critical').length,
    high: liveVulns.filter(v => v.severity === 'high').length,
    medium: liveVulns.filter(v => v.severity === 'medium').length,
    low: liveVulns.filter(v => v.severity === 'low').length,
  };

  const isRunning = session?.status === 'running';
  const isPaused = session?.status === 'paused';
  const canStop = session?.status === 'running' || session?.status === 'paused';

  const panelSx = {
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
    borderRight: '1px solid rgba(255,255,255,0.06)',
  };

  const panelHeaderSx = {
    display: 'flex',
    alignItems: 'center',
    gap: 1,
    px: 2,
    py: 1.5,
    borderBottom: '1px solid rgba(255,255,255,0.06)',
    backgroundColor: '#1a1a1a',
    flexShrink: 0,
  };

  const scrollableSx = {
    flexGrow: 1,
    overflowY: 'auto' as const,
    '&::-webkit-scrollbar': { width: 4 },
    '&::-webkit-scrollbar-track': { background: 'transparent' },
    '&::-webkit-scrollbar-thumb': { background: 'rgba(255,255,255,0.12)', borderRadius: 2 },
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 'calc(100vh - 64px)' }}>
        <CircularProgress color="primary" />
      </Box>
    );
  }

  if (!session) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">Session not found.</Alert>
      </Box>
    );
  }

  return (
    <Box sx={{ height: 'calc(100vh - 64px)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Top control bar */}
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: 1.5,
          px: 2,
          py: 1.5,
          backgroundColor: '#1a1a1a',
          borderBottom: '1px solid rgba(134,188,37,0.10)',
          flexShrink: 0,
          flexWrap: 'wrap',
        }}
      >
        <IconButton size="small" onClick={() => navigate('/')} sx={{ color: '#9e9e9e' }}>
          <ArrowBackIcon fontSize="small" />
        </IconButton>

        <Chip
          label={session.target_ip}
          variant="outlined"
          color="primary"
          size="small"
          sx={{ fontFamily: 'monospace', fontWeight: 700 }}
        />

        <StatusChip status={session.status} />

        {session.scan_profile && (
          <Chip
            label={session.scan_profile.toUpperCase()}
            size="small"
            sx={{ backgroundColor: 'rgba(134,188,37,0.08)', color: '#86BC25', fontSize: '0.65rem', height: 18 }}
          />
        )}

        {session.agent_mode === 'multi_agent' && (
          <Chip
            label="MULTI-AGENT"
            size="small"
            sx={{ backgroundColor: 'rgba(255,152,0,0.15)', color: '#ff9800', fontSize: '0.65rem', height: 18 }}
          />
        )}

        <Chip
          label={`Iter ${session.iteration}`}
          size="small"
          sx={{ backgroundColor: 'rgba(255,255,255,0.06)', color: '#86BC25', fontFamily: 'monospace', fontSize: '0.75rem' }}
        />

        <Box sx={{ flexGrow: 1 }} />

        {/* Topology mini-map */}
        {(topology?.nodes?.length ?? 0) > 0 && (
          <TopologyMiniMap topology={topology} />
        )}

        <Tooltip title={wsConnected ? 'WebSocket connected' : 'WebSocket disconnected'}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
            {wsConnected
              ? <WifiIcon sx={{ color: '#4caf50', fontSize: 16 }} />
              : <WifiOffIcon sx={{ color: '#f44336', fontSize: 16 }} />}
            <Typography variant="caption" sx={{ color: wsConnected ? '#4caf50' : '#f44336', fontSize: '0.7rem' }}>
              {wsConnected ? 'LIVE' : 'OFFLINE'}
            </Typography>
          </Box>
        </Tooltip>

        {isRunning && (
          <Button size="small" variant="outlined" color="warning"
            startIcon={actionLoading ? <CircularProgress size={12} color="inherit" /> : <PauseIcon fontSize="small" />}
            onClick={() => handleAction('pause')} disabled={actionLoading} sx={{ fontSize: '0.75rem', py: 0.5 }}>
            Pause
          </Button>
        )}
        {isPaused && (
          <Button size="small" variant="outlined" color="primary"
            startIcon={actionLoading ? <CircularProgress size={12} color="inherit" /> : <PlayArrowIcon fontSize="small" />}
            onClick={() => handleAction('resume')} disabled={actionLoading} sx={{ fontSize: '0.75rem', py: 0.5 }}>
            Resume
          </Button>
        )}
        {canStop && (
          <Button size="small" variant="outlined" color="error"
            startIcon={actionLoading ? <CircularProgress size={12} color="inherit" /> : <StopIcon fontSize="small" />}
            onClick={() => handleAction('stop')} disabled={actionLoading} sx={{ fontSize: '0.75rem', py: 0.5 }}>
            Stop
          </Button>
        )}
      </Box>

      {isRunning && <LinearProgress color="primary" sx={{ height: 2, flexShrink: 0 }} />}

      {/* Failed-session banner */}
      {session.status === 'failed' && (
        <Box
          sx={{
            px: 2,
            py: 1.25,
            flexShrink: 0,
            backgroundColor: 'rgba(244,67,54,0.08)',
            borderBottom: '1px solid rgba(244,67,54,0.35)',
            display: 'flex',
            alignItems: 'flex-start',
            gap: 1.5,
          }}
        >
          <ReportProblemIcon sx={{ color: '#f44336', fontSize: 20, mt: '1px' }} />
          <Box sx={{ flexGrow: 1, minWidth: 0 }}>
            <Typography sx={{ color: '#f44336', fontWeight: 700, fontSize: '0.85rem' }}>
              Session failed
              {sessionErrors.length > 0 && (
                <Typography component="span" sx={{ color: '#bdbdbd', fontWeight: 400, ml: 1, fontSize: '0.75rem' }}>
                  — {sessionErrors.length} error{sessionErrors.length === 1 ? '' : 's'} recorded
                </Typography>
              )}
            </Typography>
            <Typography sx={{ color: '#e0e0e0', fontSize: '0.78rem', mt: 0.25, wordBreak: 'break-word' }}>
              {session.summary || 'Session ended in a failed state. See Errors tab for details.'}
            </Typography>
          </Box>
          <Button
            size="small"
            variant="outlined"
            color="error"
            onClick={() => setRightTab(3)}
            sx={{ fontSize: '0.7rem', py: 0.25, flexShrink: 0 }}
          >
            View Errors
          </Button>
        </Box>
      )}

      {/* Deep Thoughts collapsible panel */}
      {deepThoughts.length > 0 && (
        <Box sx={{ borderBottom: '1px solid rgba(255,152,0,0.15)', flexShrink: 0, maxHeight: 200, ...scrollableSx }}>
          {deepThoughts.map((dt, i) => (
            <Accordion
              key={i}
              disableGutters
              sx={{
                backgroundColor: '#0d0d0d',
                border: 'none',
                borderLeft: '3px solid #ff9800',
                '&:before': { display: 'none' },
                mb: 0,
              }}
            >
              <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: '#ff9800', fontSize: 16 }} />} sx={{ minHeight: 32, py: 0, px: 2 }}>
                <PsychologyIcon sx={{ color: '#ff9800', fontSize: 14, mr: 1 }} />
                <Typography sx={{ color: '#ff9800', fontSize: '0.72rem', fontFamily: 'monospace' }}>
                  Extended Reasoning — Iteration {dt.iteration}
                </Typography>
                <Typography sx={{ color: '#616161', fontSize: '0.65rem', ml: 2 }}>
                  {safeTime(dt.timestamp)}
                </Typography>
              </AccordionSummary>
              <AccordionDetails sx={{ backgroundColor: '#0a0a0a', px: 2, py: 1 }}>
                <Box component="pre" sx={{ color: '#ffcc80', fontFamily: 'monospace', fontSize: '0.72rem', whiteSpace: 'pre-wrap', wordBreak: 'break-word', margin: 0 }}>
                  {dt.content}
                </Box>
              </AccordionDetails>
            </Accordion>
          ))}
        </Box>
      )}

      {/* Three-panel layout */}
      <Box sx={{ display: 'flex', flexGrow: 1, overflow: 'hidden' }}>
        {/* Left panel – Agent Thoughts (30%) */}
        <Box sx={{ ...panelSx, width: '30%', backgroundColor: '#1a1a1a' }}>
          <Box sx={panelHeaderSx}>
            <PsychologyIcon sx={{ color: '#86BC25', fontSize: 18 }} />
            <Typography variant="body2" sx={{ color: '#f0f0f0', fontWeight: 600, fontSize: '0.8rem' }}>
              Agent Thoughts
            </Typography>
            <Chip label={thoughts.length} size="small"
              sx={{ ml: 'auto', backgroundColor: 'rgba(134,188,37,0.10)', color: '#86BC25', height: 18, fontSize: '0.65rem' }} />
          </Box>
          <Box ref={thoughtsRef} sx={scrollableSx}>
            {thoughts.length === 0 ? (
              <Box sx={{ p: 3, textAlign: 'center' }}>
                <Typography variant="caption" sx={{ color: '#424242' }}>Awaiting agent reasoning...</Typography>
              </Box>
            ) : (
              thoughts.map((thought, idx) => (
                <Box key={thought.id ?? idx} sx={{ px: 2, py: 1.5, borderBottom: '1px solid rgba(255,255,255,0.04)', '&:hover': { backgroundColor: 'rgba(134,188,37,0.03)' } }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                    <Chip label={thought.phase} size="small"
                      sx={{ backgroundColor: 'rgba(255,255,255,0.06)', color: '#86BC25', fontFamily: 'monospace', fontSize: '0.6rem', height: 16, textTransform: 'uppercase' }} />
                    <Typography sx={{ color: '#424242', fontSize: '0.65rem', fontFamily: 'monospace' }}>#{thought.iteration}</Typography>
                  </Box>
                  <Typography variant="body2" sx={{ color: '#f0f0f0', fontSize: '0.8rem', lineHeight: 1.5, mb: 0.5 }}>
                    {thought.thought}
                  </Typography>
                  <Typography variant="caption" sx={{ color: '#424242', fontSize: '0.68rem' }}>
                    {safeTime(thought.timestamp)}
                  </Typography>
                </Box>
              ))
            )}
          </Box>
        </Box>

        {/* Middle panel – Tool Console (40%) */}
        <Box sx={{ ...panelSx, width: '40%', backgroundColor: '#0a0a0a' }}>
          <Box sx={panelHeaderSx}>
            <TerminalIcon sx={{ color: '#86BC25', fontSize: 18 }} />
            <Typography variant="body2" sx={{ color: '#f0f0f0', fontWeight: 600, fontSize: '0.8rem' }}>Tool Console</Typography>
            <Chip label={toolOutputs.length} size="small"
              sx={{ ml: 'auto', backgroundColor: 'rgba(134,188,37,0.10)', color: '#86BC25', height: 18, fontSize: '0.65rem' }} />
          </Box>
          <Box ref={toolsRef} sx={scrollableSx}>
            {toolOutputs.length === 0 ? (
              <Box sx={{ p: 3, textAlign: 'center' }}>
                <Typography variant="caption" sx={{ color: '#1a2a3a', fontFamily: 'monospace' }}>$ _</Typography>
              </Box>
            ) : (
              toolOutputs.map((output, idx) => (
                <Box key={output.id ?? idx} sx={{ px: 2, py: 1.5, borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                    <Typography sx={{ color: '#86BC25', fontFamily: 'monospace', fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase' }}>
                      ▶ {output.tool_name}
                    </Typography>
                    {output.duration_seconds == null
                      ? <CircularProgress size={10} thickness={5} sx={{ color: '#ff9800', ml: 'auto' }} />
                      : <Chip label="done" size="small" sx={{ ml: 'auto', backgroundColor: 'rgba(76,175,80,0.12)', color: '#4caf50', height: 16, fontSize: '0.6rem' }} />}
                  </Box>
                  {Object.keys(output.params).length > 0 && (
                    <Typography sx={{ color: '#4fc3f7', fontFamily: 'monospace', fontSize: '0.72rem', mb: 0.5, wordBreak: 'break-all' }}>
                      $ {output.tool_name} {Object.entries(output.params).map(([k, v]) => `--${k}=${v}`).join(' ')}
                    </Typography>
                  )}
                  {output.raw_output && (
                    <Box component="pre" sx={{ color: '#c8e6c9', fontFamily: 'monospace', fontSize: '0.7rem', margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: 200, overflowY: 'auto', backgroundColor: 'rgba(0,0,0,0.3)', borderRadius: 1, p: 1, mb: 0.5 }}>
                      {output.raw_output}
                    </Box>
                  )}
                  {output.duration_seconds != null && output.duration_seconds > 0 && (
                    <Typography sx={{ color: '#424242', fontFamily: 'monospace', fontSize: '0.68rem' }}>
                      Duration: {output.duration_seconds.toFixed(1)}s
                    </Typography>
                  )}
                </Box>
              ))
            )}
          </Box>
        </Box>

        {/* Right panel – Findings + Attack Chains tabs (30%) */}
        <Box sx={{ width: '30%', display: 'flex', flexDirection: 'column', overflow: 'hidden', backgroundColor: '#1a1a1a' }}>
          <Tabs
            value={rightTab}
            onChange={(_, v) => setRightTab(v)}
            sx={{
              minHeight: 38,
              borderBottom: '1px solid rgba(255,255,255,0.06)',
              '& .MuiTab-root': { minHeight: 38, fontSize: '0.72rem', color: '#616161', py: 0.5, textTransform: 'none' },
              '& .Mui-selected': { color: '#f0f0f0' },
              '& .MuiTabs-indicator': { backgroundColor: '#86BC25', height: 2 },
              backgroundColor: '#1a1a1a',
              flexShrink: 0,
            }}
          >
            <Tab icon={<BugReportIcon sx={{ fontSize: 14 }} />} iconPosition="start" label={`Findings (${liveVulns.length})`} />
            <Tab icon={<AccountTreeIcon sx={{ fontSize: 14 }} />} iconPosition="start" label={`Chains (${attackChains.length})`} />
            <Tab icon={<PsychologyIcon sx={{ fontSize: 14 }} />} iconPosition="start" label={`Hypotheses (${hypotheses.length})`} />
            <Tab
              icon={<ErrorOutlineIcon sx={{ fontSize: 14 }} />}
              iconPosition="start"
              label={`Errors (${sessionErrors.length})`}
              sx={sessionErrors.length > 0 ? { color: '#f44336 !important' } : undefined}
            />
          </Tabs>

          {/* Findings tab */}
          {rightTab === 0 && (
            <>
              {liveVulns.length > 0 && (
                <Box sx={{ display: 'flex', gap: 1, px: 2, py: 1, borderBottom: '1px solid rgba(255,255,255,0.04)', flexShrink: 0, flexWrap: 'wrap' }}>
                  {[
                    { label: 'C', count: severityCounts.critical, color: '#f44336' },
                    { label: 'H', count: severityCounts.high, color: '#ff6d00' },
                    { label: 'M', count: severityCounts.medium, color: '#ff9800' },
                    { label: 'L', count: severityCounts.low, color: '#2979ff' },
                  ].map(item => (
                    <Box key={item.label} sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                      <Typography sx={{ color: item.color, fontFamily: 'monospace', fontSize: '0.7rem', fontWeight: 700 }}>{item.label}</Typography>
                      <Typography sx={{ color: '#9e9e9e', fontFamily: 'monospace', fontSize: '0.7rem' }}>{item.count}</Typography>
                    </Box>
                  ))}
                </Box>
              )}
              <Box ref={vulnsRef} sx={scrollableSx}>
                {liveVulns.length === 0 ? (
                  <Box sx={{ p: 3, textAlign: 'center' }}>
                    <BugReportIcon sx={{ fontSize: 32, color: '#1a2633', mb: 1 }} />
                    <Typography variant="caption" sx={{ color: '#424242', display: 'block' }}>No vulnerabilities found yet</Typography>
                  </Box>
                ) : (
                  liveVulns.map((vuln, idx) => (
                    <Box key={vuln.id ?? idx} sx={{ px: 2, py: 1.5, borderBottom: '1px solid rgba(255,255,255,0.04)', '&:hover': { backgroundColor: 'rgba(255,23,68,0.03)' } }}>
                      {/* Severity + badges row */}
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 0.5, flexWrap: 'wrap' }}>
                        <SeverityBadge severity={vuln.severity} />
                        {vuln.is_zero_day && (
                          <Chip label="0-DAY" size="small" sx={{ backgroundColor: 'rgba(255,215,0,0.15)', color: '#ffd700', fontSize: '0.6rem', height: 16, fontWeight: 700 }} />
                        )}
                        {vuln.verification_status && vuln.verification_status !== 'unverified' && (
                          <Chip
                            label={vuln.verification_status}
                            size="small"
                            sx={{ backgroundColor: `${VERIFICATION_COLORS[vuln.verification_status]}20`, color: VERIFICATION_COLORS[vuln.verification_status], fontSize: '0.6rem', height: 16 }}
                          />
                        )}
                      </Box>
                      <Typography sx={{ fontSize: '0.82rem', color: '#f0f0f0', fontWeight: 600, mb: 0.5, lineHeight: 1.3 }}>
                        {vuln.title}
                      </Typography>
                      <Typography sx={{ fontSize: '0.72rem', color: '#616161', fontFamily: 'monospace', mb: 0.5 }}>
                        {vuln.affected_service}{vuln.port ? `:${vuln.port}` : ''}
                      </Typography>
                      {/* MITRE techniques */}
                      {vuln.mitre_techniques && vuln.mitre_techniques.length > 0 && (
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mb: 0.5 }}>
                          {vuln.mitre_techniques.slice(0, 4).map(t => (
                            <Chip
                              key={t}
                              label={t}
                              size="small"
                              clickable
                              component="a"
                              href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              icon={<LinkIcon sx={{ fontSize: '10px !important' }} />}
                              sx={{ backgroundColor: 'rgba(79,195,247,0.10)', color: '#4fc3f7', fontSize: '0.6rem', height: 16, '& .MuiChip-icon': { color: '#4fc3f7' } }}
                            />
                          ))}
                        </Box>
                      )}
                      {/* Confidence bar */}
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 0.5 }}>
                        <Box sx={{ height: 3, flexGrow: 1, backgroundColor: 'rgba(134,188,37,0.10)', borderRadius: 1, overflow: 'hidden' }}>
                          <Box sx={{
                            height: '100%',
                            width: `${(vuln.confidence ?? 0) * 100}%`,
                            backgroundColor: (vuln.confidence ?? 0) > 0.8 ? '#4caf50' : (vuln.confidence ?? 0) > 0.5 ? '#ff9800' : '#f44336',
                            borderRadius: 1,
                          }} />
                        </Box>
                        <Typography sx={{ fontSize: '0.68rem', color: '#616161', fontFamily: 'monospace', flexShrink: 0 }}>
                          {Math.round((vuln.confidence ?? 0) * 100)}%
                        </Typography>
                      </Box>
                      {/* Patch button */}
                      {vuln.patch_code && (
                        <Button
                          size="small"
                          variant="outlined"
                          startIcon={<CodeIcon sx={{ fontSize: '12px !important' }} />}
                          onClick={() => setPatchDialogVuln(vuln)}
                          sx={{ fontSize: '0.65rem', py: 0.25, px: 1, height: 22, borderColor: 'rgba(134,188,37,0.3)', color: '#86BC25', '&:hover': { borderColor: '#86BC25', backgroundColor: 'rgba(134,188,37,0.06)' } }}
                        >
                          View Patch
                        </Button>
                      )}
                    </Box>
                  ))
                )}
              </Box>
            </>
          )}

          {/* Hypotheses tab */}
          {rightTab === 2 && (
            <Box sx={{ ...scrollableSx, px: 0, py: 0 }}>
              {hypotheses.length === 0 ? (
                <Box sx={{ p: 3, textAlign: 'center' }}>
                  <PsychologyIcon sx={{ fontSize: 32, color: '#1a2633', mb: 1 }} />
                  <Typography variant="caption" sx={{ color: '#424242', display: 'block' }}>
                    No hypotheses formed yet
                  </Typography>
                </Box>
              ) : (
                hypotheses.map((hyp, idx) => {
                  const statusColor = hyp.status === 'confirmed' ? '#4caf50' : hyp.status === 'ruled_out' ? '#f44336' : '#ff9800';
                  return (
                    <Box
                      key={hyp.hyp_id || idx}
                      sx={{ px: 2, py: 1.5, borderBottom: '1px solid rgba(255,255,255,0.06)', borderLeft: `3px solid ${statusColor}` }}
                    >
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.75 }}>
                        <Chip
                          label={hyp.status.toUpperCase()}
                          size="small"
                          sx={{ backgroundColor: `${statusColor}20`, color: statusColor, fontSize: '0.6rem', height: 16, fontWeight: 700 }}
                        />
                        <Typography sx={{ color: '#424242', fontSize: '0.65rem', fontFamily: 'monospace' }}>
                          {hyp.hyp_id}
                        </Typography>
                      </Box>
                      <Typography sx={{ fontSize: '0.8rem', color: '#e0e0e0', lineHeight: 1.4, mb: 0.75 }}>
                        {hyp.statement}
                      </Typography>
                      {/* Confidence bar */}
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 0.75 }}>
                        <Box sx={{ height: 3, flexGrow: 1, backgroundColor: 'rgba(134,188,37,0.10)', borderRadius: 1, overflow: 'hidden' }}>
                          <Box sx={{
                            height: '100%',
                            width: `${(hyp.confidence ?? 0) * 100}%`,
                            backgroundColor: hyp.confidence > 0.7 ? '#4caf50' : hyp.confidence > 0.4 ? '#ff9800' : '#f44336',
                            borderRadius: 1,
                          }} />
                        </Box>
                        <Typography sx={{ fontSize: '0.68rem', color: '#616161', fontFamily: 'monospace', flexShrink: 0 }}>
                          {Math.round((hyp.confidence ?? 0) * 100)}%
                        </Typography>
                      </Box>
                      {hyp.evidence_for && hyp.evidence_for.length > 0 && (
                        <Box sx={{ mb: 0.5 }}>
                          <Typography sx={{ fontSize: '0.65rem', color: '#4caf50', fontFamily: 'monospace', mb: 0.25 }}>FOR:</Typography>
                          {hyp.evidence_for.map((e, i) => (
                            <Typography key={i} sx={{ fontSize: '0.68rem', color: '#9e9e9e', pl: 1, lineHeight: 1.4 }}>• {e}</Typography>
                          ))}
                        </Box>
                      )}
                      {hyp.evidence_against && hyp.evidence_against.length > 0 && (
                        <Box sx={{ mb: 0.5 }}>
                          <Typography sx={{ fontSize: '0.65rem', color: '#f44336', fontFamily: 'monospace', mb: 0.25 }}>AGAINST:</Typography>
                          {hyp.evidence_against.map((e, i) => (
                            <Typography key={i} sx={{ fontSize: '0.68rem', color: '#9e9e9e', pl: 1, lineHeight: 1.4 }}>• {e}</Typography>
                          ))}
                        </Box>
                      )}
                      {hyp.next_test && (
                        <Typography sx={{ fontSize: '0.68rem', color: '#4fc3f7', fontFamily: 'monospace', fontStyle: 'italic' }}>
                          Next: {hyp.next_test}
                        </Typography>
                      )}
                    </Box>
                  );
                })
              )}
            </Box>
          )}

          {/* Attack Chains tab */}
          {rightTab === 1 && (
            <Box sx={{ ...scrollableSx, px: 0, py: 0 }}>
              {attackChains.length === 0 ? (
                <Box sx={{ p: 3, textAlign: 'center' }}>
                  <AccountTreeIcon sx={{ fontSize: 32, color: '#1a2633', mb: 1 }} />
                  <Typography variant="caption" sx={{ color: '#424242', display: 'block' }}>
                    {session.status === 'completed' ? 'No attack chains detected' : 'Chains available after session completes'}
                  </Typography>
                  {session.status === 'completed' && (
                    <Button size="small" onClick={loadAttackChains} sx={{ mt: 1, fontSize: '0.7rem', color: '#86BC25' }}>Refresh</Button>
                  )}
                </Box>
              ) : (
                attackChains.map((chain) => (
                  <Box key={chain.chain_id} sx={{ px: 2, py: 1.5, borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                      <Chip
                        label={chain.max_severity.toUpperCase()}
                        size="small"
                        sx={{ backgroundColor: `${SEVERITY_COLORS[chain.max_severity]}20`, color: SEVERITY_COLORS[chain.max_severity], fontSize: '0.6rem', height: 16, fontWeight: 700 }}
                      />
                      {chain.fully_exploitable && (
                        <Chip label="EXPLOITABLE" size="small" sx={{ backgroundColor: 'rgba(244,67,54,0.15)', color: '#f44336', fontSize: '0.6rem', height: 16 }} />
                      )}
                      <Typography sx={{ color: '#424242', fontSize: '0.65rem', fontFamily: 'monospace', ml: 'auto' }}>
                        {chain.total_steps} steps
                      </Typography>
                    </Box>
                    <Typography sx={{ fontSize: '0.75rem', color: '#9e9e9e', mb: 1 }}>
                      <span style={{ color: '#86BC25' }}>{chain.entry_point}</span>
                      {' → '}
                      <span style={{ color: SEVERITY_COLORS[chain.max_severity] }}>{chain.final_impact}</span>
                    </Typography>
                    <Stepper orientation="vertical" sx={{ '& .MuiStepConnector-line': { borderColor: 'rgba(255,255,255,0.08)' } }}>
                      {chain.steps.map((step) => (
                        <Step key={step.vuln_id} active completed={step.verification_status === 'confirmed' || step.verification_status === 'exploited'}>
                          <StepLabel
                            StepIconProps={{
                              sx: {
                                color: `${SEVERITY_COLORS[step.severity]}`,
                                '&.Mui-completed': { color: `${SEVERITY_COLORS[step.severity]}` },
                                '&.Mui-active': { color: `${SEVERITY_COLORS[step.severity]}` },
                                fontSize: 16,
                              },
                            }}
                          >
                            <Typography sx={{ fontSize: '0.73rem', color: '#e0e0e0', lineHeight: 1.3 }}>{step.title}</Typography>
                          </StepLabel>
                          <StepContent>
                            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                              {step.mitre_techniques.slice(0, 3).map(t => (
                                <Chip key={t} label={t} size="small" sx={{ backgroundColor: 'rgba(79,195,247,0.08)', color: '#4fc3f7', fontSize: '0.6rem', height: 14 }} />
                              ))}
                            </Box>
                          </StepContent>
                        </Step>
                      ))}
                    </Stepper>
                  </Box>
                ))
              )}
            </Box>
          )}

          {/* Errors tab */}
          {rightTab === 3 && (
            <Box sx={{ ...scrollableSx, px: 0, py: 0 }}>
              {sessionErrors.length === 0 ? (
                <Box sx={{ p: 3, textAlign: 'center' }}>
                  <ErrorOutlineIcon sx={{ fontSize: 32, color: '#1a2633', mb: 1 }} />
                  <Typography variant="caption" sx={{ color: '#424242', display: 'block' }}>
                    No errors recorded for this session
                  </Typography>
                  <Button size="small" onClick={loadErrors} sx={{ mt: 1, fontSize: '0.7rem', color: '#86BC25' }}>
                    Refresh
                  </Button>
                </Box>
              ) : (
                <>
                  <Box sx={{ px: 2, py: 1, borderBottom: '1px solid rgba(255,255,255,0.04)', display: 'flex', alignItems: 'center', gap: 1 }}>
                    <Typography sx={{ color: '#9e9e9e', fontSize: '0.68rem', fontFamily: 'monospace' }}>
                      {sessionErrors.length} error{sessionErrors.length === 1 ? '' : 's'} · oldest first
                    </Typography>
                    <Box sx={{ flexGrow: 1 }} />
                    <Button size="small" onClick={loadErrors} sx={{ fontSize: '0.65rem', color: '#86BC25', py: 0, minWidth: 'auto' }}>
                      Refresh
                    </Button>
                  </Box>
                  {sessionErrors.map((err) => {
                    const phaseColor =
                      err.phase === 'anthropic_api' ? '#ff6d00'
                      : err.phase === 'settings_load' ? '#ff9800'
                      : err.phase === 'mcp_call' || err.phase === 'tool_execute' ? '#ffb300'
                      : err.phase === 'subagent_api' ? '#ce93d8'
                      : err.phase === 'celery_task' ? '#ef5350'
                      : err.phase === 'unhandled' ? '#f44336'
                      : '#9e9e9e';
                    const ts = safeTime(err.timestamp);
                    return (
                      <Accordion
                        key={err.id}
                        disableGutters
                        square
                        sx={{
                          backgroundColor: 'transparent',
                          borderBottom: '1px solid rgba(255,255,255,0.06)',
                          boxShadow: 'none',
                          '&:before': { display: 'none' },
                        }}
                      >
                        <AccordionSummary
                          expandIcon={<ExpandMoreIcon sx={{ color: '#616161', fontSize: 16 }} />}
                          sx={{ px: 2, py: 0, minHeight: 48, '& .MuiAccordionSummary-content': { my: 1 } }}
                        >
                          <Box sx={{ width: '100%' }}>
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, mb: 0.25, flexWrap: 'wrap' }}>
                              <Chip
                                label={err.phase}
                                size="small"
                                sx={{ backgroundColor: `${phaseColor}22`, color: phaseColor, fontSize: '0.6rem', height: 16, fontWeight: 700 }}
                              />
                              <Chip
                                label={err.error_type}
                                size="small"
                                sx={{ backgroundColor: 'rgba(244,67,54,0.12)', color: '#f44336', fontSize: '0.6rem', height: 16, fontFamily: 'monospace' }}
                              />
                              {typeof err.iteration === 'number' && (
                                <Typography sx={{ color: '#616161', fontSize: '0.62rem', fontFamily: 'monospace' }}>
                                  iter {err.iteration}
                                </Typography>
                              )}
                              {err.tool && (
                                <Typography sx={{ color: '#616161', fontSize: '0.62rem', fontFamily: 'monospace' }}>
                                  tool {err.tool}
                                </Typography>
                              )}
                              <Box sx={{ flexGrow: 1 }} />
                              <Typography sx={{ color: '#616161', fontSize: '0.62rem', fontFamily: 'monospace' }}>
                                {ts}
                              </Typography>
                            </Box>
                            <Typography sx={{ fontSize: '0.75rem', color: '#e0e0e0', wordBreak: 'break-word' }}>
                              {err.error_message || '(no message)'}
                            </Typography>
                          </Box>
                        </AccordionSummary>
                        <AccordionDetails sx={{ px: 2, py: 1, backgroundColor: 'rgba(0,0,0,0.25)' }}>
                          {err.traceback ? (
                            <Box
                              component="pre"
                              sx={{
                                m: 0,
                                fontSize: '0.68rem',
                                color: '#e0e0e0',
                                fontFamily: 'monospace',
                                whiteSpace: 'pre-wrap',
                                wordBreak: 'break-word',
                                maxHeight: 320,
                                overflow: 'auto',
                              }}
                            >
                              {err.traceback}
                            </Box>
                          ) : (
                            <Typography sx={{ fontSize: '0.68rem', color: '#616161', fontStyle: 'italic' }}>
                              No traceback captured (error surfaced via WebSocket before full record landed — hit Refresh).
                            </Typography>
                          )}
                          {err.context && Object.keys(err.context).length > 0 && (
                            <Box sx={{ mt: 1 }}>
                              <Typography sx={{ color: '#9e9e9e', fontSize: '0.62rem', fontWeight: 700, mb: 0.25 }}>
                                CONTEXT
                              </Typography>
                              <Box
                                component="pre"
                                sx={{
                                  m: 0,
                                  fontSize: '0.66rem',
                                  color: '#b0bec5',
                                  fontFamily: 'monospace',
                                  whiteSpace: 'pre-wrap',
                                  wordBreak: 'break-word',
                                }}
                              >
                                {JSON.stringify(err.context, null, 2)}
                              </Box>
                            </Box>
                          )}
                        </AccordionDetails>
                      </Accordion>
                    );
                  })}
                </>
              )}
            </Box>
          )}
        </Box>
      </Box>

      {/* Patch code dialog */}
      <Dialog
        open={patchDialogVuln !== null}
        onClose={() => setPatchDialogVuln(null)}
        maxWidth="md"
        fullWidth
        PaperProps={{ sx: { backgroundColor: '#1a1a1a', border: '1px solid rgba(134,188,37,0.2)' } }}
      >
        <DialogTitle sx={{ color: '#86BC25', fontSize: '0.95rem', pb: 1 }}>
          Patch: {patchDialogVuln?.title}
        </DialogTitle>
        <DialogContent>
          <Box component="pre" sx={{ color: '#c8e6c9', fontFamily: 'monospace', fontSize: '0.78rem', whiteSpace: 'pre-wrap', wordBreak: 'break-all', backgroundColor: '#0a0a0a', borderRadius: 1, p: 2, margin: 0, border: '1px solid rgba(255,255,255,0.06)', maxHeight: 500, overflowY: 'auto' }}>
            {patchDialogVuln?.patch_code}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setPatchDialogVuln(null)} sx={{ color: '#9e9e9e' }}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Completion Dialog */}
      <Dialog
        open={completedDialog}
        onClose={() => setCompletedDialog(false)}
        PaperProps={{ sx: { backgroundColor: '#242424', border: '1px solid rgba(255,255,255,0.12)' } }}
      >
        <DialogTitle sx={{ color: '#4caf50' }}>Assessment Complete</DialogTitle>
        <DialogContent>
          <Typography sx={{ color: '#9e9e9e', mb: 2 }}>
            MYTHOS autonomous assessment for{' '}
            <strong style={{ color: '#86BC25' }}>{session.target_ip}</strong> has completed.
          </Typography>
          <Box sx={{ display: 'flex', gap: 3 }}>
            <Box sx={{ textAlign: 'center' }}>
              <Typography variant="h4" sx={{ color: '#f44336', fontWeight: 700 }}>{liveVulns.length}</Typography>
              <Typography variant="caption" sx={{ color: '#616161' }}>Vulnerabilities</Typography>
            </Box>
            <Box sx={{ textAlign: 'center' }}>
              <Typography variant="h4" sx={{ color: '#f44336', fontWeight: 700 }}>{severityCounts.critical}</Typography>
              <Typography variant="caption" sx={{ color: '#616161' }}>Critical</Typography>
            </Box>
            <Box sx={{ textAlign: 'center' }}>
              <Typography variant="h4" sx={{ color: '#ff9800', fontWeight: 700 }}>{attackChains.length}</Typography>
              <Typography variant="caption" sx={{ color: '#616161' }}>Attack Chains</Typography>
            </Box>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCompletedDialog(false)} sx={{ color: '#9e9e9e' }}>Stay Here</Button>
          <Button onClick={() => { setCompletedDialog(false); setRightTab(1); }} color="warning" variant="outlined">
            View Chains
          </Button>
          <Button onClick={() => navigate('/vulnerabilities')} color="primary" variant="contained">
            View Vulnerabilities
          </Button>
        </DialogActions>
      </Dialog>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={5000}
        onClose={() => setSnackbar(s => ({ ...s, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert severity={snackbar.severity} onClose={() => setSnackbar(s => ({ ...s, open: false }))}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default SessionViewer;

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
import DownloadIcon from '@mui/icons-material/Download';
import PsychologyIcon from '@mui/icons-material/Psychology';
import PsychologyAltIcon from '@mui/icons-material/PsychologyAlt';
import TerminalIcon from '@mui/icons-material/Terminal';
import BugReportIcon from '@mui/icons-material/BugReport';
import WifiIcon from '@mui/icons-material/Wifi';
import WifiOffIcon from '@mui/icons-material/WifiOff';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import LinkIcon from '@mui/icons-material/Link';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import HubIcon from '@mui/icons-material/Hub';
import TimelineIcon from '@mui/icons-material/Timeline';
import ForumIcon from '@mui/icons-material/Forum';
import HistoryIcon from '@mui/icons-material/History';
import MenuBookIcon from '@mui/icons-material/MenuBook';
import BuildIcon from '@mui/icons-material/Build';
import CodeIcon from '@mui/icons-material/Code';
import ErrorOutlineIcon from '@mui/icons-material/ErrorOutline';
import ReportProblemIcon from '@mui/icons-material/ReportProblem';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import LightbulbIcon from '@mui/icons-material/Lightbulb';
import AutoAwesomeIcon from '@mui/icons-material/AutoAwesome';
import { useNavigate, useParams } from 'react-router-dom';
import { format } from 'date-fns';

import { sessionsApi, vulnerabilitiesApi } from '../services/api';
import { SessionWebSocket } from '../services/websocket';
import SeverityBadge from '../components/SeverityBadge';
import StatusChip from '../components/StatusChip';
import AttackGraphPanel from '../components/AttackGraphPanel';
import EvidenceFlowStrip from '../components/EvidenceFlowStrip';
import ActivityPanel from '../components/ActivityPanel';
import IterationLog from '../components/IterationLog';
import Storyboard from '../components/Storyboard';
import ToolsPanel from '../components/ToolsPanel';
import SandboxPanel from '../components/SandboxPanel';
import FindingDetailDialog from '../components/FindingDetailDialog';
import EmptyTabState from '../components/EmptyTabState';
import ScienceIcon from '@mui/icons-material/Science';
import TrackChangesIcon from '@mui/icons-material/TrackChanges';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import BubbleChartIcon from '@mui/icons-material/BubbleChart';
import GoalTreePanel from '../components/GoalTreePanel';
import ExplanationPanel from '../components/ExplanationPanel';
import HypothesisTreeViewer from '../components/HypothesisTreeViewer';  // legacy graph view (kept in case we need to revert)
import HypothesesTable from '../components/HypothesesTable';
import AgentChorusPage from './AgentChorusPage';
import ReasoningLoopsPanel from '../components/ReasoningLoopsPanel';
import AdversarialReasoningPanel from '../components/AdversarialReasoningPanel';
import CostsPanel from '../components/CostsPanel';
import RoutingPanel from '../components/RoutingPanel';
import CoverageMatrixPanel from '../components/CoverageMatrixPanel';
import NovelVulnerabilitiesPanel from '../components/NovelVulnerabilitiesPanel';
import GavelIcon from '@mui/icons-material/Gavel';
import PaidIcon from '@mui/icons-material/Paid';
import RouteIcon from '@mui/icons-material/Route';
import GridViewIcon from '@mui/icons-material/GridView';
import StarIcon from '@mui/icons-material/Star';
import type { ReasoningLoopTick } from '../services/api';
import type {
  Session, AgentThought, ToolOutput, Vulnerability, DeepThought,
  AttackChain, NetworkTopology, Hypothesis, SessionError, WSMessage,
  GraphPayload, ExplanationEvent,
} from '../types';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#f44336', high: '#ff6d00', medium: '#ff9800', low: '#2979ff', info: '#5a6478',
};
const VERIFICATION_COLORS: Record<string, string> = {
  unverified: '#5a6478', confirmed: '#4caf50', exploited: '#f44336', disputed: '#ff9800',
};

// T22 — colour the [agent_type] prefix in a thought so operators can scan the
// feed by agent at a glance. Unknown types (future specialists) fall through
// to a neutral grey.
const AGENT_COLORS: Record<string, string> = {
  recon:      '#4e5ced',  // indigo — generalist
  analyst:    '#26a69a',  // teal   — generalist
  exploit:    '#e91e63',  // pink   — generalist
  code:       '#8e24aa',  // purple — generalist
  // Tier-5 specialists (T22)
  crypto:     '#3f51b5',  // deep blue
  auth:       '#00838f',  // cyan
  reveng:     '#6a1b9a',  // violet
  exploitdev: '#c62828',  // dark red
  network:    '#ef6c00',  // orange
};

// Parses a `[agent_type]` prefix, e.g. `[crypto] hypothesis h1…`.
// Returns `{agent, body}` — `agent` is null when no prefix is present.
const parseAgentPrefix = (text: string): { agent: string | null; body: string } => {
  const m = /^\s*\[([a-z_]{2,20})\]\s*(.*)$/s.exec(text);
  if (!m) return { agent: null, body: text };
  return { agent: m[1], body: m[2] };
};

// Hard caps on in-memory arrays so long-running sessions can't balloon the
// React state until the tab OOMs. On overflow we drop the oldest entries —
// the full history is still available in PostgreSQL / MongoDB via the
// session's API endpoints.
const MAX_THOUGHTS = 2000;
const MAX_TOOL_OUTPUTS = 2000;
const MAX_DEEP_THOUGHTS = 200;
const MAX_SESSION_ERRORS = 200;

const capTail = <T,>(arr: T[], limit: number): T[] =>
  arr.length <= limit ? arr : arr.slice(arr.length - limit);

// ── Live status banner ──────────────────────────────────────────────────────
// Human-readable "what is the agent doing right now" strip, driven off the
// same Redis → WebSocket event stream that populates the panels below.
type LiveStatusKind =
  | 'thinking' | 'deep' | 'tool' | 'tool_done' | 'vuln'
  | 'hyp_new' | 'hyp_confirmed' | 'hyp_ruled'
  | 'topo' | 'plan' | 'replan' | 'alert' | 'chain' | 'brief'
  | 'state' | 'done' | 'error';

interface LiveStatus {
  kind: LiveStatusKind;
  label: string;
  detail: string;
  color: string;
  timestamp: string;
}

const clip = (s: string | null | undefined, n = 140): string => {
  const flat = String(s ?? '').replace(/\s+/g, ' ').trim();
  return flat.length > n ? `${flat.substring(0, n)}…` : flat;
};

const phaseLabel = (phase: string | null | undefined): string => {
  const p = String(phase ?? '').toLowerCase();
  if (p.includes('recon')) return 'Reconning';
  if (p.includes('exploit')) return 'Exploiting';
  if (p.includes('analy') || p.includes('hypoth')) return 'Analysing';
  if (p.includes('plan')) return 'Planning';
  if (p.includes('wrap') || p.includes('report')) return 'Wrapping up';
  return 'Thinking';
};

const summarizeEvent = (msg: WSMessage): LiveStatus | null => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const d = (msg.data ?? {}) as Record<string, any>;
  const ts = msg.timestamp;

  switch (msg.type) {
    case 'agent_thought':
      return { kind: 'thinking', label: phaseLabel(String(d.phase ?? '')), detail: clip(String(d.thought ?? '')), color: '#4e5ced', timestamp: ts };
    case 'deep_thought':
      return { kind: 'deep', label: 'Deep reasoning', detail: clip(String(d.content ?? '')), color: '#ff9800', timestamp: ts };
    case 'tool_execution': {
      const tool = String(d.tool_name ?? 'tool');
      const done = Number(d.duration_seconds) > 0 || d.status === 'complete';
      if (done) {
        const secs = d.duration_seconds != null ? `${Number(d.duration_seconds).toFixed(1)}s` : '';
        return { kind: 'tool_done', label: `${tool} finished`, detail: secs, color: '#4caf50', timestamp: ts };
      }
      const params = d.params as Record<string, unknown> | undefined;
      const paramStr = params
        ? Object.entries(params).slice(0, 2).map(([k, v]) => `${k}=${String(v).substring(0, 60)}`).join(' ')
        : '';
      return { kind: 'tool', label: `Running ${tool}`, detail: paramStr, color: '#4e5ced', timestamp: ts };
    }
    case 'vulnerability_found': {
      const sev = String(d.severity ?? 'info').toLowerCase();
      return {
        kind: 'vuln',
        label: `Found ${sev}`,
        detail: clip(String(d.title ?? '')),
        color: SEVERITY_COLORS[sev] ?? '#4e5ced',
        timestamp: ts,
      };
    }
    case 'hypothesis_update': {
      const status = String(d.status ?? 'active').toLowerCase();
      const stmt = clip(String(d.statement ?? ''));
      if (status === 'confirmed') return { kind: 'hyp_confirmed', label: 'Hypothesis confirmed', detail: stmt, color: '#4caf50', timestamp: ts };
      if (status === 'ruled_out')  return { kind: 'hyp_ruled',     label: 'Hypothesis ruled out', detail: stmt, color: '#8a93a6', timestamp: ts };
      return { kind: 'hyp_new', label: 'New hypothesis', detail: stmt, color: '#4e5ced', timestamp: ts };
    }
    case 'topology_update': {
      if (d.action === 'add_node' && d.node) {
        const n = d.node as Record<string, unknown>;
        return { kind: 'topo', label: 'Mapped node', detail: String(n.label ?? n.id ?? ''), color: '#4e5ced', timestamp: ts };
      }
      if (d.action === 'add_edge' && d.edge) {
        const e = d.edge as Record<string, unknown>;
        return { kind: 'topo', label: 'Linked', detail: `${e.from} → ${e.to}`, color: '#4e5ced', timestamp: ts };
      }
      return null;
    }
    case 'plan_tree_seeded': {
      const n = Number(d.node_count ?? 0);
      return { kind: 'plan', label: 'Plan seeded', detail: `${n} nodes`, color: '#4e5ced', timestamp: ts };
    }
    case 'plan_replan':
      return { kind: 'replan', label: 'Replanning', detail: clip(String(d.reason ?? '')), color: '#ff9800', timestamp: ts };
    case 'loop_break':
      return { kind: 'alert', label: 'Loop broken', detail: String(d.tool ?? ''), color: '#ff9800', timestamp: ts };
    case 'chain_suggestion':
      return { kind: 'chain', label: 'Chain suggestion', detail: clip(String(d.suggested_probe ?? '')), color: '#4e5ced', timestamp: ts };
    case 'target_brief':
      return { kind: 'brief', label: 'Target brief ready', detail: clip(String(d.summary ?? '')), color: '#4e5ced', timestamp: ts };
    case 'session_update': {
      const status = String(d.status ?? '').toLowerCase();
      if (!status) return null;
      return { kind: 'state', label: `State → ${status}`, detail: String(d.phase ?? ''), color: '#4e5ced', timestamp: ts };
    }
    case 'session_complete':
      return { kind: 'done', label: 'Session complete', detail: '', color: '#4caf50', timestamp: ts };
    case 'session_error':
      return { kind: 'error', label: `Error · ${String(d.phase ?? 'unhandled')}`, detail: clip(String(d.message ?? '')), color: '#f44336', timestamp: ts };
    default:
      return null;
  }
};

const LiveStatusIcon: React.FC<{ kind: LiveStatusKind }> = ({ kind }) => {
  const sx = { fontSize: 16 };
  switch (kind) {
    case 'thinking': return <PsychologyIcon sx={sx} />;
    case 'deep':     return <AutoAwesomeIcon sx={sx} />;
    case 'tool':     return <TerminalIcon sx={sx} />;
    case 'tool_done':return <CheckCircleIcon sx={sx} />;
    case 'vuln':     return <BugReportIcon sx={sx} />;
    case 'hyp_new':
    case 'hyp_confirmed':
    case 'hyp_ruled':return <LightbulbIcon sx={sx} />;
    case 'topo':     return <AccountTreeIcon sx={sx} />;
    case 'plan':
    case 'replan':   return <AccountTreeIcon sx={sx} />;
    case 'alert':    return <ReportProblemIcon sx={sx} />;
    case 'chain':    return <LinkIcon sx={sx} />;
    case 'brief':    return <CodeIcon sx={sx} />;
    case 'state':    return <CodeIcon sx={sx} />;
    case 'done':     return <CheckCircleIcon sx={sx} />;
    case 'error':    return <ErrorOutlineIcon sx={sx} />;
    default:         return <PsychologyIcon sx={sx} />;
  }
};

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
    <Box sx={{ border: '1px solid #dfe3ec', borderRadius: 1, overflow: 'hidden', flexShrink: 0 }}>
      <svg width={W} height={H} style={{ background: '#0d0d0d', display: 'block' }}>
        {edges.map((e, i) => {
          const from = pos[e.from], to = pos[e.to];
          if (!from || !to) return null;
          return <line key={i} x1={from.x} y1={from.y} x2={to.x} y2={to.y} stroke="rgba(78,92,237,0.3)" strokeWidth={1} />;
        })}
        {nodes.map((n) => {
          const p = pos[n.id];
          if (!p) return null;
          const color = n.severity ? SEVERITY_COLORS[n.severity] : n.type === 'host' ? '#4fc3f7' : '#4e5ced';
          return (
            <g key={n.id}>
              <circle cx={p.x} cy={p.y} r={5} fill={color} opacity={0.9} />
              <text x={p.x} y={p.y + 14} textAnchor="middle" fill="#5a6478" fontSize={7} fontFamily="monospace">
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
  // T27 — latest graph_delta pushed by the backend; AttackGraphPanel subscribes
  // to this and appends to its Cytoscape instance without a full re-layout.
  const [graphDelta, setGraphDelta] = useState<GraphPayload | null>(null);
  const [sessionErrors, setSessionErrors] = useState<SessionError[]>([]);
  const [liveStatus, setLiveStatus] = useState<LiveStatus | null>(null);
  const [rightTab, setRightTab] = useState(0);
  const [patchDialogVuln, setPatchDialogVuln] = useState<Vulnerability | null>(null);
  // When a Finding node in AttackGraphPanel is clicked, we jump to the
  // Findings tab and flash the matching row so the user can see which
  // graph node maps to which finding.
  const [highlightedVulnId, setHighlightedVulnId] = useState<string | null>(null);
  // When a Finding row is clicked, open the identification dialog that
  // explains how it was identified (driving hypothesis + custom-script trail).
  const [detailVulnId, setDetailVulnId] = useState<string | null>(null);
  const [reportDownloading, setReportDownloading] = useState(false);
  const [explanationEvents, setExplanationEvents] = useState<ExplanationEvent[]>([]);
  const [complianceFramework, setComplianceFramework] = useState<string>('pci_dss');
  // v7.0 — live reasoning-loop state
  const [loopStartedIds, setLoopStartedIds] = useState<string[]>([]);
  const [loopTicks, setLoopTicks] = useState<Record<string, ReasoningLoopTick[]>>({});
  const [loopFinished, setLoopFinished] = useState<Record<string, { status: string }>>({});
  // v7.x — live adversarial-round state (red/blue + philosopher).
  const [adversarialRounds, setAdversarialRounds] = useState<import('../types').AdversarialRound[]>([]);
  // v7.x — bumps every time a llm_usage_recorded event arrives so CostsPanel refetches.
  const [costsTick, setCostsTick] = useState(0);
  // Live operator-goal subtask progress (keyed by "phase_idx.subgoal_idx").
  const [goalProgress, setGoalProgress] = useState<Record<string, { status?: string; evidence_count?: number }>>({});
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
  const isMounted = useRef(true);
  useEffect(() => () => { isMounted.current = false; }, []);

  const scrollToBottom = (ref: React.RefObject<HTMLDivElement>) => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  };

  useEffect(() => { scrollToBottom(thoughtsRef); }, [thoughts]);
  useEffect(() => { scrollToBottom(toolsRef); }, [toolOutputs]);
  useEffect(() => { scrollToBottom(vulnsRef); }, [liveVulns]);

  // When a Finding node in the graph is clicked, scroll its row into view in
  // the Findings tab and auto-clear the highlight after a few seconds.
  useEffect(() => {
    if (!highlightedVulnId || rightTab !== 0) return;
    const t = window.setTimeout(() => {
      const root = vulnsRef.current;
      if (!root) return;
      const el = root.querySelector<HTMLDivElement>(`[data-vuln-id="${CSS.escape(highlightedVulnId)}"]`);
      if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }, 60);
    const clear = window.setTimeout(() => setHighlightedVulnId(null), 2800);
    return () => { window.clearTimeout(t); window.clearTimeout(clear); };
  }, [highlightedVulnId, rightTab]);

  const loadAttackChains = useCallback(async () => {
    if (!id) return;
    try {
      const chains = await sessionsApi.getAttackChains(id);
      if (isMounted.current) setAttackChains(chains);
    } catch { /* non-critical */ }
  }, [id]);

  const loadErrors = useCallback(async () => {
    if (!id) return;
    try {
      const result = await sessionsApi.getErrors(id, { size: 100 });
      if (isMounted.current) setSessionErrors(capTail(result.items ?? [], MAX_SESSION_ERRORS));
    } catch { /* non-critical */ }
  }, [id]);

  // Initial data load
  useEffect(() => {
    if (!id) return;
    let cancelled = false;
    const load = async () => {
      setLoading(true);
      try {
        const [sessionData, thoughtsData, toolsData, vulnsData, topologyData, hypsData] = await Promise.allSettled([
          sessionsApi.get(id),
          sessionsApi.getThoughts(id, { size: 500 }),
          sessionsApi.getToolOutputs(id, { size: 500 }),
          vulnerabilitiesApi.list({ session_id: id, size: 500 }),
          sessionsApi.getNetworkTopology(id),
          sessionsApi.getHypotheses(id),
        ]);
        if (cancelled) return;
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
        if (!cancelled) setLoading(false);
      }
    };
    load();
    loadAttackChains();
    loadErrors();
    return () => { cancelled = true; };
  }, [id, loadAttackChains, loadErrors]);

  // WebSocket
  useEffect(() => {
    if (!id) return;
    const ws = new SessionWebSocket(id);
    wsRef.current = ws;

    const unsubscribe = ws.onMessage((msg) => {
      const summary = summarizeEvent(msg);
      if (summary) setLiveStatus(summary);
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
          // v6 T147: capture explanation events for ExplanationPanel
          const expl = (msg.data as any)?.explanation;
          const drivingHypId = (msg.data as any)?.driving_hypothesis_id;
          if (expl && (msg.data as any)?.status === 'complete') {
            const ev: ExplanationEvent = {
              tool_name: (msg.data as any)?.tool_name ?? '',
              explanation: expl,
              driving_hypothesis_id: drivingHypId ?? null,
              timestamp: msg.timestamp,
            };
            setExplanationEvents(prev => prev.length >= 50 ? [...prev.slice(1), ev] : [...prev, ev]);
          }
          break;
        }
        case 'vulnerability_found': {
          const vuln = msg.data as unknown as Vulnerability;
          setLiveVulns(prev => {
            if (prev.find(v => v.id === vuln.id)) return prev;
            return [...prev, vuln];
          });
          // Attack chains are derived server-side from the vulnerabilities'
          // attack_chain_id column; re-fetching on every vuln lets the Chains
          // tab populate live during long multi-agent runs instead of waiting
          // until session_complete. The endpoint is cheap (single SELECT).
          loadAttackChains();
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
        case 'graph_delta': {
          // T27 — every new Neo4j node / edge is pushed as a delta. Store the
          // latest slice; AttackGraphPanel merges it into its Cytoscape instance.
          setGraphDelta(msg.data as unknown as GraphPayload);
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
        // ── v7.0 reasoning-loop events ───────────────────────────────────
        case 'loop_started': {
          const data = msg.data as { loop_id?: string; loop_type?: string };
          if (data.loop_id) setLoopStartedIds(prev => [...prev, data.loop_id!]);
          break;
        }
        case 'loop_tick': {
          const data = msg.data as {
            loop_id?: string;
            iteration?: number;
            chosen?: string | null;
            reasoning?: string;
            branch_count?: number;
            tokens?: number;
          };
          if (!data.loop_id) break;
          const tick: ReasoningLoopTick = {
            iteration: Number(data.iteration ?? 0),
            state_snapshot: {},
            branches: Array.from({ length: Number(data.branch_count ?? 0) }, () => ({})),
            chosen: data.chosen ?? null,
            reasoning: String(data.reasoning ?? ''),
            tokens: Number(data.tokens ?? 0),
            ts: msg.timestamp,
          };
          setLoopTicks(prev => {
            const list = prev[data.loop_id!] ?? [];
            return { ...prev, [data.loop_id!]: [...list, tick] };
          });
          break;
        }
        case 'loop_finished': {
          const data = msg.data as { loop_id?: string; status?: string };
          if (!data.loop_id) break;
          setLoopFinished(prev => ({ ...prev, [data.loop_id!]: { status: data.status ?? 'complete' } }));
          break;
        }
        // v7.x — token usage recorded for the Costs tab. We only bump a
        // tick; the panel refetches the aggregate so totals stay correct
        // without duplicating the cost math on the client.
        case 'llm_usage_recorded': {
          setCostsTick(prev => prev + 1);
          break;
        }
        // v7.x — adversarial reasoning (red/blue + philosopher) summary push.
        case 'adversarial_round_complete': {
          const round = msg.data as unknown as import('../types').AdversarialRound;
          if (!round || !round._id) break;
          setAdversarialRounds(prev => {
            const idx = prev.findIndex(r => r._id === round._id);
            if (idx >= 0) {
              const next = [...prev];
              next[idx] = { ...prev[idx], ...round };
              return next;
            }
            return [round, ...prev];
          });
          break;
        }
        // Operator-goal subtask progress (debounced, fires on tool/vuln/hypothesis events).
        case 'goal_progress': {
          const data = msg.data as { progress?: Record<string, { status?: string; evidence_count?: number }> };
          if (data.progress) setGoalProgress(data.progress);
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

  const downloadReport = useCallback(async () => {
    if (!id) return;
    setReportDownloading(true);
    try {
      const { filename, body } = await sessionsApi.downloadReport(id);
      const blob = new Blob([body], { type: 'text/markdown;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setSnackbar({ open: true, message: `Downloaded ${filename}`, severity: 'success' });
    } catch (err) {
      setSnackbar({ open: true, message: err instanceof Error ? err.message : 'Download failed', severity: 'error' });
    } finally {
      setReportDownloading(false);
    }
  }, [id]);

  const severityCounts = {
    critical: liveVulns.filter(v => v.severity === 'critical').length,
    high: liveVulns.filter(v => v.severity === 'high').length,
    medium: liveVulns.filter(v => v.severity === 'medium').length,
    low: liveVulns.filter(v => v.severity === 'low').length,
  };

  // Verification-status breakdown. Needed because comparing session totals
  // (e.g. "fast=23 vs full=12") is apples-to-oranges without knowing how
  // many were confirmed vs unverified vs disputed. One line each.
  const statusCounts = {
    confirmed:  liveVulns.filter(v => v.verification_status === 'confirmed').length,
    exploited:  liveVulns.filter(v => v.verification_status === 'exploited').length,
    unverified: liveVulns.filter(v => v.verification_status === 'unverified').length,
    disputed:   liveVulns.filter(v => v.verification_status === 'disputed').length,
  };

  const isRunning = session?.status === 'running';
  const isPaused = session?.status === 'paused';
  const canStop = session?.status === 'running' || session?.status === 'paused';

  const panelSx = {
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
    borderRight: '1px solid #dfe3ec',
  };

  const panelHeaderSx = {
    display: 'flex',
    alignItems: 'center',
    gap: 1,
    px: 2,
    py: 1.5,
    borderBottom: '1px solid #dfe3ec',
    backgroundColor: '#ffffff',
    flexShrink: 0,
  };

  const scrollableSx = {
    flexGrow: 1,
    overflowY: 'auto' as const,
    '&::-webkit-scrollbar': { width: 4 },
    '&::-webkit-scrollbar-track': { background: 'transparent' },
    '&::-webkit-scrollbar-thumb': { background: '#dfe3ec', borderRadius: 2 },
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
          backgroundColor: '#ffffff',
          borderBottom: '1px solid rgba(78,92,237,0.10)',
          flexShrink: 0,
          flexWrap: 'wrap',
        }}
      >
        <IconButton size="small" onClick={() => navigate('/')} sx={{ color: '#5a6478' }}>
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
            sx={{ backgroundColor: 'rgba(78,92,237,0.08)', color: '#4e5ced', fontSize: '0.65rem', height: 18 }}
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
          sx={{ backgroundColor: '#dfe3ec', color: '#4e5ced', fontFamily: 'monospace', fontSize: '0.75rem' }}
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
        <Button
          size="small"
          variant="outlined"
          startIcon={reportDownloading ? <CircularProgress size={12} color="inherit" /> : <DownloadIcon fontSize="small" />}
          onClick={downloadReport}
          disabled={reportDownloading}
          sx={{ fontSize: '0.75rem', py: 0.5, color: '#4e5ced', borderColor: 'rgba(78,92,237,0.4)' }}
        >
          Download report
        </Button>
      </Box>

      {isRunning && <LinearProgress color="primary" sx={{ height: 2, flexShrink: 0 }} />}

      {/* Live status banner — surfaces the latest WS event as a single line */}
      {(isRunning || isPaused || liveStatus) && session.status !== 'failed' && (
        <Box
          sx={{
            display: 'flex',
            alignItems: 'center',
            gap: 1.25,
            px: 2,
            py: 0.85,
            flexShrink: 0,
            backgroundColor: liveStatus ? `${liveStatus.color}0D` : 'rgba(78,92,237,0.05)',
            borderBottom: `1px solid ${liveStatus?.color ?? '#4e5ced'}2A`,
            minHeight: 34,
            '@keyframes ls-pulse': {
              '0%,100%': { opacity: 0.35, transform: 'scale(0.85)' },
              '50%':     { opacity: 1,   transform: 'scale(1.15)' },
            },
          }}
        >
          <Box
            sx={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              backgroundColor: liveStatus?.color ?? '#4e5ced',
              flexShrink: 0,
              animation: isRunning ? 'ls-pulse 1.3s ease-in-out infinite' : 'none',
            }}
          />
          <Box sx={{ color: liveStatus?.color ?? '#4e5ced', display: 'flex', alignItems: 'center', flexShrink: 0 }}>
            {liveStatus
              ? <LiveStatusIcon kind={liveStatus.kind} />
              : <PsychologyIcon sx={{ fontSize: 16 }} />}
          </Box>
          <Typography sx={{ color: liveStatus?.color ?? '#4e5ced', fontWeight: 700, fontSize: '0.78rem', flexShrink: 0 }}>
            {liveStatus?.label ?? (isRunning ? 'Agent starting…' : isPaused ? 'Paused' : 'Idle')}
          </Typography>
          {liveStatus?.detail && (
            <Typography
              sx={{
                color: '#2a3045',
                fontSize: '0.78rem',
                fontFamily: 'monospace',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
                flexGrow: 1,
                minWidth: 0,
              }}
              title={liveStatus.detail}
            >
              · {liveStatus.detail}
            </Typography>
          )}
          {!liveStatus?.detail && <Box sx={{ flexGrow: 1 }} />}
          {liveStatus && (
            <Typography sx={{ color: '#8a93a6', fontSize: '0.7rem', fontFamily: 'monospace', flexShrink: 0 }}>
              {safeTime(liveStatus.timestamp)}
            </Typography>
          )}
        </Box>
      )}

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
                <Typography component="span" sx={{ color: '#5a6478', fontWeight: 400, ml: 1, fontSize: '0.75rem' }}>
                  — {sessionErrors.length} error{sessionErrors.length === 1 ? '' : 's'} recorded
                </Typography>
              )}
            </Typography>
            <Typography sx={{ color: '#2a3045', fontSize: '0.78rem', mt: 0.25, wordBreak: 'break-word' }}>
              {session.summary || 'Session ended in a failed state. See Errors tab for details.'}
            </Typography>
          </Box>
          <Button
            size="small"
            variant="outlined"
            color="error"
            onClick={() => setRightTab(9)}
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
                <Typography sx={{ color: '#8a93a6', fontSize: '0.65rem', ml: 2 }}>
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

      {/* Full-width tabbed layout (replaces the old 3-panel layout). */}
      <Box sx={{ display: 'flex', flexGrow: 1, overflow: 'hidden' }}>
        <Box sx={{ width: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden', backgroundColor: '#ffffff' }}>
          <Tabs
            value={rightTab}
            onChange={(_, v) => setRightTab(v)}
            variant="scrollable"
            scrollButtons="auto"
            sx={{
              minHeight: 40,
              borderBottom: '1px solid #dfe3ec',
              '& .MuiTab-root': { minHeight: 40, fontSize: '0.74rem', color: '#8a93a6', py: 0.5, textTransform: 'none' },
              '& .Mui-selected': { color: '#1a1f2e' },
              '& .MuiTabs-indicator': { backgroundColor: '#4e5ced', height: 2 },
              backgroundColor: '#ffffff',
              flexShrink: 0,
            }}
          >
            <Tab
              icon={<BugReportIcon sx={{ fontSize: 16 }} />}
              iconPosition="start"
              label={`Findings (${liveVulns.length}${session?.vulnerability_count != null && session.vulnerability_count > liveVulns.length ? `/${session.vulnerability_count}` : ''})`}
            />
            <Tab icon={<AccountTreeIcon sx={{ fontSize: 16 }} />} iconPosition="start" label={`Chains (${attackChains.length})`} />
            <Tab icon={<ForumIcon sx={{ fontSize: 16 }} />} iconPosition="start" label={`Activity (${thoughts.length + toolOutputs.length + hypotheses.length})`} />
            <Tab icon={<BuildIcon sx={{ fontSize: 16 }} />} iconPosition="start" label={`Tools (${toolOutputs.length})`} />
            <Tab icon={<ScienceIcon sx={{ fontSize: 16 }} />} iconPosition="start" label={`Sandbox (${toolOutputs.filter(t => ['forge_runner','payload_swarm','ai_request_forge','instrument_trace','crypto_padding_oracle','crypto_bleichenbacher','crypto_ecdsa_nonce_reuse','crypto_length_extension','crypto_rsa_low_e','crypto_lattice','crypto_jwt_confusion'].includes(t.tool_name)).length})`} />
            <Tab icon={<HistoryIcon sx={{ fontSize: 16 }} />} iconPosition="start" label="Iterations" />
            <Tab icon={<MenuBookIcon sx={{ fontSize: 16 }} />} iconPosition="start" label="Story" />
            <Tab icon={<HubIcon sx={{ fontSize: 16 }} />} iconPosition="start" label="Graph" />
            <Tab icon={<TimelineIcon sx={{ fontSize: 16 }} />} iconPosition="start" label="Evidence" />
            <Tab
              icon={<ErrorOutlineIcon sx={{ fontSize: 16 }} />}
              iconPosition="start"
              label={`Errors (${sessionErrors.length})`}
              sx={sessionErrors.length > 0 ? { color: '#f44336 !important' } : undefined}
            />
            <Tab icon={<TrackChangesIcon sx={{ fontSize: 16 }} />} iconPosition="start" label="Goal" />
            <Tab icon={<VerifiedUserIcon sx={{ fontSize: 16 }} />} iconPosition="start" label="Compliance" />
            <Tab icon={<BubbleChartIcon sx={{ fontSize: 16 }} />} iconPosition="start" label="Hypotheses" />
            <Tab icon={<PsychologyIcon sx={{ fontSize: 16 }} />} iconPosition="start" label="Chorus" />
            {/* v7.0 — Reasoning Loops (T155–T166) */}
            <Tab icon={<PsychologyAltIcon sx={{ fontSize: 16 }} />} iconPosition="start" label="Loops" />
            {/* v7.x — Adversarial reasoning (red/blue + philosopher) */}
            <Tab
              icon={<GavelIcon sx={{ fontSize: 16 }} />}
              iconPosition="start"
              label={`Adversarial (${adversarialRounds.length})`}
            />
            {/* v7.x — Session token spend */}
            <Tab icon={<PaidIcon sx={{ fontSize: 16 }} />} iconPosition="start" label="Costs" />
            {/* v7.x — Live role -> profile -> model resolution + per-role usage */}
            <Tab icon={<RouteIcon sx={{ fontSize: 16 }} />} iconPosition="start" label="Routing" />
            {/* v7.x — Per-endpoint × per-attack-class coverage heatmap */}
            <Tab icon={<GridViewIcon sx={{ fontSize: 16 }} />} iconPosition="start" label="Coverage" />
            {/* v7.x — Sandbox-verified PoC findings only */}
            <Tab icon={<StarIcon sx={{ fontSize: 16 }} />} iconPosition="start" label="Novel" />
          </Tabs>

          {/* Findings tab */}
          {rightTab === 0 && (
            <>
              {liveVulns.length > 0 && (
                <>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, px: 2, py: 1, borderBottom: '1px solid rgba(30,41,60,0.04)', flexShrink: 0, flexWrap: 'wrap' }}>
                    {[
                      { label: 'C', count: severityCounts.critical, color: '#f44336' },
                      { label: 'H', count: severityCounts.high, color: '#ff6d00' },
                      { label: 'M', count: severityCounts.medium, color: '#ff9800' },
                      { label: 'L', count: severityCounts.low, color: '#2979ff' },
                    ].map(item => (
                      <Box key={item.label} sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                        <Typography sx={{ color: item.color, fontFamily: 'monospace', fontSize: '0.7rem', fontWeight: 700 }}>{item.label}</Typography>
                        <Typography sx={{ color: '#5a6478', fontFamily: 'monospace', fontSize: '0.7rem' }}>{item.count}</Typography>
                      </Box>
                    ))}
                    <Button
                      size="small"
                      variant="outlined"
                      sx={{ ml: 'auto', fontSize: '0.7rem', textTransform: 'none' }}
                      onClick={async () => {
                        if (!id) return;
                        try {
                          const blob = await vulnerabilitiesApi.exportCsv(id);
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement('a');
                          a.href = url;
                          a.download = `findings-${id}.csv`;
                          document.body.appendChild(a);
                          a.click();
                          document.body.removeChild(a);
                          URL.revokeObjectURL(url);
                        } catch (err) {
                          // ignore — error toast not wired here
                          console.error('CSV export failed', err);
                        }
                      }}
                    >
                      Download CSV
                    </Button>
                  </Box>
                  <Box sx={{ display: 'flex', gap: 1.25, px: 2, py: 0.75, borderBottom: '1px solid rgba(30,41,60,0.04)', flexShrink: 0, flexWrap: 'wrap' }}>
                    {[
                      { label: 'confirmed',  count: statusCounts.confirmed,  color: '#4caf50' },
                      { label: 'exploited',  count: statusCounts.exploited,  color: '#f44336' },
                      { label: 'unverified', count: statusCounts.unverified, color: '#8a93a6' },
                      { label: 'disputed',   count: statusCounts.disputed,   color: '#ff9800' },
                    ].map(item => (
                      <Tooltip key={item.label} title={`${item.count} finding${item.count === 1 ? '' : 's'} with verification_status="${item.label}"`}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, opacity: item.count === 0 ? 0.45 : 1 }}>
                          <Box sx={{ width: 6, height: 6, borderRadius: '50%', backgroundColor: item.color }} />
                          <Typography sx={{ color: '#5a6478', fontSize: '0.65rem', fontFamily: 'monospace' }}>{item.label}</Typography>
                          <Typography sx={{ color: item.color, fontSize: '0.7rem', fontFamily: 'monospace', fontWeight: 700 }}>{item.count}</Typography>
                        </Box>
                      </Tooltip>
                    ))}
                  </Box>
                </>
              )}
              <Box ref={vulnsRef} sx={scrollableSx}>
                {liveVulns.length === 0 ? (
                  <EmptyTabState
                    icon={<BugReportIcon sx={{ fontSize: 36 }} />}
                    title="Findings will appear here."
                    trigger={'A finding is added when the agent confirms a hypothesis and emits a {"VULNERABILITY": {...}} block. Until then, the agent is still gathering evidence — watch the Activity tab.'}
                    sessionStatus={session?.status}
                    counters={[
                      { label: 'iterations', value: session?.iteration ?? 0 },
                      { label: 'hypotheses', value: hypotheses.length },
                      { label: 'tool calls', value: toolOutputs.length },
                    ]}
                  />
                ) : (
                  liveVulns.map((vuln, idx) => (
                    <Box
                      key={vuln.id ?? idx}
                      data-vuln-id={vuln.id ?? ''}
                      onClick={() => { if (vuln.id) setDetailVulnId(String(vuln.id)); }}
                      sx={{
                        px: 2,
                        py: 1.5,
                        borderBottom: '1px solid rgba(30,41,60,0.04)',
                        backgroundColor: highlightedVulnId && vuln.id === highlightedVulnId ? 'rgba(78,92,237,0.10)' : 'transparent',
                        boxShadow: highlightedVulnId && vuln.id === highlightedVulnId ? 'inset 3px 0 0 0 #4e5ced' : 'none',
                        transition: 'background-color 200ms ease, box-shadow 200ms ease',
                        cursor: vuln.id ? 'pointer' : 'default',
                        '&:hover': {
                          backgroundColor: vuln.id ? 'rgba(78,92,237,0.06)' : 'transparent',
                          boxShadow: vuln.id ? 'inset 3px 0 0 0 rgba(78,92,237,0.4)' : 'none',
                        },
                      }}
                    >
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
                      <Typography sx={{ fontSize: '0.82rem', color: '#1a1f2e', fontWeight: 600, mb: 0.5, lineHeight: 1.3 }}>
                        {vuln.title}
                      </Typography>
                      <Typography sx={{ fontSize: '0.72rem', color: '#8a93a6', fontFamily: 'monospace', mb: 0.5 }}>
                        {vuln.affected_service}{vuln.port ? `:${vuln.port}` : ''}
                      </Typography>
                      {/* MITRE techniques */}
                      {vuln.mitre_techniques && vuln.mitre_techniques.length > 0 && (
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mb: 0.5 }}>
                          {vuln.mitre_techniques
                            .filter((t): t is string => typeof t === 'string' && t.length > 0)
                            .slice(0, 4).map(t => (
                            <Chip
                              key={t}
                              label={t}
                              size="small"
                              clickable
                              component="a"
                              href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              onClick={(e) => e.stopPropagation()}
                              icon={<LinkIcon sx={{ fontSize: '10px !important' }} />}
                              sx={{ backgroundColor: 'rgba(79,195,247,0.10)', color: '#4fc3f7', fontSize: '0.6rem', height: 16, '& .MuiChip-icon': { color: '#4fc3f7' } }}
                            />
                          ))}
                        </Box>
                      )}
                      {/* Confidence bar */}
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 0.5 }}>
                        <Box sx={{ height: 3, flexGrow: 1, backgroundColor: 'rgba(78,92,237,0.10)', borderRadius: 1, overflow: 'hidden' }}>
                          <Box sx={{
                            height: '100%',
                            width: `${(vuln.confidence ?? 0) * 100}%`,
                            backgroundColor: (vuln.confidence ?? 0) > 0.8 ? '#4caf50' : (vuln.confidence ?? 0) > 0.5 ? '#ff9800' : '#f44336',
                            borderRadius: 1,
                          }} />
                        </Box>
                        <Typography sx={{ fontSize: '0.68rem', color: '#8a93a6', fontFamily: 'monospace', flexShrink: 0 }}>
                          {Math.round((vuln.confidence ?? 0) * 100)}%
                        </Typography>
                      </Box>
                      {/* Patch button */}
                      {vuln.patch_code && (
                        <Button
                          size="small"
                          variant="outlined"
                          startIcon={<CodeIcon sx={{ fontSize: '12px !important' }} />}
                          onClick={(e) => { e.stopPropagation(); setPatchDialogVuln(vuln); }}
                          sx={{ fontSize: '0.65rem', py: 0.25, px: 1, height: 22, borderColor: 'rgba(78,92,237,0.3)', color: '#4e5ced', '&:hover': { borderColor: '#4e5ced', backgroundColor: 'rgba(78,92,237,0.06)' } }}
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

          {/* Activity tab — merged thoughts + tool calls + hypotheses */}
          {rightTab === 2 && (
            <Box sx={{ display: 'flex', flexDirection: 'column', flexGrow: 1, minHeight: 0 }}>
              <ActivityPanel thoughts={thoughts} toolOutputs={toolOutputs} hypotheses={hypotheses} />
            </Box>
          )}

          {/* Tools tab — every tool call + custom-script detail (forge_runner etc.) */}
          {rightTab === 3 && (
            <Box sx={{ display: 'flex', flexDirection: 'column', flexGrow: 1, minHeight: 0 }}>
              <ToolsPanel toolOutputs={toolOutputs} />
            </Box>
          )}

          {/* Sandbox tab — every sandbox-bound payload + oracle verdict + swarm result */}
          {rightTab === 4 && (
            <Box sx={{ display: 'flex', flexDirection: 'column', flexGrow: 1, minHeight: 0 }}>
              <SandboxPanel
                toolOutputs={toolOutputs}
                sessionStatus={session?.status}
                iterationCount={session?.iteration ?? 0}
                hypothesisCount={hypotheses.length}
              />
            </Box>
          )}

          {/* Iterations tab — per-iteration expanded log */}
          {rightTab === 5 && (
            <Box sx={{ display: 'flex', flexDirection: 'column', flexGrow: 1, minHeight: 0 }}>
              <IterationLog
                thoughts={thoughts}
                toolOutputs={toolOutputs}
                hypotheses={hypotheses}
                vulns={liveVulns}
              />
            </Box>
          )}

          {/* Story tab — plain English narration */}
          {rightTab === 6 && (
            <Box sx={{ display: 'flex', flexDirection: 'column', flexGrow: 1, minHeight: 0 }}>
              <Storyboard
                session={session}
                thoughts={thoughts}
                toolOutputs={toolOutputs}
                hypotheses={hypotheses}
                vulns={liveVulns}
              />
            </Box>
          )}

          {/* Attack Chains tab */}
          {rightTab === 1 && (
            <Box sx={{ ...scrollableSx, px: 0, py: 0 }}>
              {attackChains.length === 0 ? (
                <Box>
                  <EmptyTabState
                    icon={<AccountTreeIcon sx={{ fontSize: 36 }} />}
                    title="Attack chains will appear here."
                    trigger={liveVulns.length === 0
                      ? 'A chain is built when 2+ findings share the same attack_chain_id (e.g. open port → service detection → exploitable CVE → RCE). Findings come first; chains follow.'
                      : 'Findings exist but the agent has not yet linked them with attack_chain_id values. Refresh once the agent emits a chain-linked VULNERABILITY block.'}
                    sessionStatus={session?.status}
                    counters={[
                      { label: 'findings', value: liveVulns.length },
                      { label: 'iterations', value: session?.iteration ?? 0 },
                      { label: 'hypotheses', value: hypotheses.length },
                    ]}
                  />
                  <Box sx={{ textAlign: 'center', mt: 1 }}>
                    <Button size="small" onClick={loadAttackChains} sx={{ fontSize: '0.7rem', color: '#4e5ced' }}>
                      Refresh
                    </Button>
                  </Box>
                </Box>
              ) : (
                <>
                  {/* Color legend — what the step-icon colors mean. */}
                  <Box sx={{
                    display: 'flex', flexWrap: 'wrap', gap: 1.5, alignItems: 'center',
                    px: 2, py: 1, borderBottom: '1px solid #dfe3ec',
                    backgroundColor: 'rgba(78,92,237,0.04)',
                  }}>
                    <Typography sx={{ fontSize: '0.7rem', color: '#5a6478', fontWeight: 600 }}>
                      Step colors:
                    </Typography>
                    {[
                      { c: '#f44336', l: 'critical' },
                      { c: '#ff6d00', l: 'high' },
                      { c: '#ff9800', l: 'medium' },
                      { c: '#2979ff', l: 'low' },
                      { c: '#5a6478', l: 'info' },
                    ].map(({ c, l }) => (
                      <Box key={l} sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                        <Box sx={{ width: 10, height: 10, borderRadius: '50%', backgroundColor: c }} />
                        <Typography sx={{ fontSize: '0.7rem', color: '#5a6478' }}>{l}</Typography>
                      </Box>
                    ))}
                    <Typography sx={{ fontSize: '0.7rem', color: '#8a93a6', ml: 1 }}>
                      · Solid icon = confirmed / exploited · Outline = unverified
                    </Typography>
                  </Box>
                  {attackChains.map((chain) => (
                  <Box key={chain.chain_id} sx={{ px: 2, py: 1.5, borderBottom: '1px solid #dfe3ec' }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                      <Chip
                        label={chain.max_severity.toUpperCase()}
                        size="small"
                        sx={{ backgroundColor: `${SEVERITY_COLORS[chain.max_severity]}20`, color: SEVERITY_COLORS[chain.max_severity], fontSize: '0.6rem', height: 16, fontWeight: 700 }}
                      />
                      {chain.fully_exploitable && (
                        <Chip label="EXPLOITABLE" size="small" sx={{ backgroundColor: 'rgba(244,67,54,0.15)', color: '#f44336', fontSize: '0.6rem', height: 16 }} />
                      )}
                      <Typography sx={{ color: '#c3cad7', fontSize: '0.65rem', fontFamily: 'monospace', ml: 'auto' }}>
                        {chain.total_steps} steps
                      </Typography>
                    </Box>
                    <Typography sx={{ fontSize: '0.75rem', color: '#5a6478', mb: 1 }}>
                      <span style={{ color: '#4e5ced' }}>{chain.entry_point}</span>
                      {' → '}
                      <span style={{ color: SEVERITY_COLORS[chain.max_severity] }}>{chain.final_impact}</span>
                    </Typography>
                    <Stepper orientation="vertical" sx={{ '& .MuiStepConnector-line': { borderColor: '#dfe3ec' } }}>
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
                            <Typography sx={{ fontSize: '0.73rem', color: '#2a3045', lineHeight: 1.3 }}>{step.title}</Typography>
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
                  ))}
                </>
              )}
            </Box>
          )}

          {/* Errors tab */}
          {rightTab === 9 && (
            <Box sx={{ ...scrollableSx, px: 0, py: 0 }}>
              {sessionErrors.length === 0 ? (
                <Box>
                  <EmptyTabState
                    icon={<ErrorOutlineIcon sx={{ fontSize: 36 }} />}
                    title="No errors recorded — green is good."
                    trigger="An entry appears here when a tool fails, the LLM API errors out, or the orchestrator catches a non-fatal exception. An empty tab means the session is healthy."
                    sessionStatus={session?.status}
                    counters={[
                      { label: 'iterations', value: session?.iteration ?? 0 },
                      { label: 'tool calls', value: toolOutputs.length },
                    ]}
                  />
                  <Box sx={{ textAlign: 'center', mt: 1 }}>
                    <Button size="small" onClick={loadErrors} sx={{ fontSize: '0.7rem', color: '#4e5ced' }}>
                      Refresh
                    </Button>
                  </Box>
                </Box>
              ) : (
                <>
                  <Box sx={{ px: 2, py: 1, borderBottom: '1px solid rgba(30,41,60,0.04)', display: 'flex', alignItems: 'center', gap: 1 }}>
                    <Typography sx={{ color: '#5a6478', fontSize: '0.68rem', fontFamily: 'monospace' }}>
                      {sessionErrors.length} error{sessionErrors.length === 1 ? '' : 's'} · oldest first
                    </Typography>
                    <Box sx={{ flexGrow: 1 }} />
                    <Button size="small" onClick={loadErrors} sx={{ fontSize: '0.65rem', color: '#4e5ced', py: 0, minWidth: 'auto' }}>
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
                      : '#5a6478';
                    const ts = safeTime(err.timestamp);
                    return (
                      <Accordion
                        key={err.id}
                        disableGutters
                        square
                        sx={{
                          backgroundColor: 'transparent',
                          borderBottom: '1px solid #dfe3ec',
                          boxShadow: 'none',
                          '&:before': { display: 'none' },
                        }}
                      >
                        <AccordionSummary
                          expandIcon={<ExpandMoreIcon sx={{ color: '#8a93a6', fontSize: 16 }} />}
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
                                <Typography sx={{ color: '#8a93a6', fontSize: '0.62rem', fontFamily: 'monospace' }}>
                                  iter {err.iteration}
                                </Typography>
                              )}
                              {err.tool && (
                                <Typography sx={{ color: '#8a93a6', fontSize: '0.62rem', fontFamily: 'monospace' }}>
                                  tool {err.tool}
                                </Typography>
                              )}
                              <Box sx={{ flexGrow: 1 }} />
                              <Typography sx={{ color: '#8a93a6', fontSize: '0.62rem', fontFamily: 'monospace' }}>
                                {ts}
                              </Typography>
                            </Box>
                            <Typography sx={{ fontSize: '0.75rem', color: '#2a3045', wordBreak: 'break-word' }}>
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
                                color: '#2a3045',
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
                            <Typography sx={{ fontSize: '0.68rem', color: '#8a93a6', fontStyle: 'italic' }}>
                              No traceback captured (error surfaced via WebSocket before full record landed — hit Refresh).
                            </Typography>
                          )}
                          {err.context && Object.keys(err.context).length > 0 && (
                            <Box sx={{ mt: 1 }}>
                              <Typography sx={{ color: '#5a6478', fontSize: '0.62rem', fontWeight: 700, mb: 0.25 }}>
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

          {/* T27 — Attack Graph tab */}
          {rightTab === 7 && id && (
            <Box sx={{ display: 'flex', flexDirection: 'column', flexGrow: 1, minHeight: 0 }}>
              <AttackGraphPanel
                sessionId={id}
                graphDelta={graphDelta}
                onSelectFinding={(vulnId) => {
                  setRightTab(0);
                  setHighlightedVulnId(vulnId);
                }}
                sessionStatus={session?.status}
                iterationCount={session?.iteration ?? 0}
                toolCallCount={toolOutputs.length}
              />
            </Box>
          )}

          {/* T27 — Evidence Flow tab */}
          {rightTab === 8 && (
            <Box sx={{ display: 'flex', flexDirection: 'column', flexGrow: 1, minHeight: 0 }}>
              <EvidenceFlowStrip
                vulns={liveVulns}
                sessionStatus={session?.status}
                iterationCount={session?.iteration ?? 0}
                hypothesisCount={hypotheses.length}
                toolCallCount={toolOutputs.length}
              />
            </Box>
          )}

          {/* v6 T132 — Goal tab */}
          {rightTab === 10 && id && (
            <Box sx={{ display: 'flex', flexDirection: 'column', flexGrow: 1, minHeight: 0, overflowY: 'auto' }}>
              <GoalTreePanel sessionId={id} liveProgress={goalProgress} />
            </Box>
          )}

          {/* v6 T144 — Compliance tab */}
          {rightTab === 11 && id && (
            <Box sx={{ display: 'flex', flexDirection: 'column', flexGrow: 1, minHeight: 0, p: 2, overflowY: 'auto' }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                <VerifiedUserIcon sx={{ color: '#4e5ced', fontSize: 20 }} />
                <Typography sx={{ fontWeight: 700, fontSize: '0.9rem', color: '#1a1f2e' }}>
                  Compliance Report
                </Typography>
              </Box>
              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 2 }}>
                {['pci_dss', 'hipaa', 'soc2', 'iso27001', 'nist_csf', 'owasp_asvs'].map(fw => (
                  <Chip
                    key={fw}
                    label={fw.toUpperCase().replace('_', ' ')}
                    size="small"
                    onClick={() => setComplianceFramework(fw)}
                    sx={{
                      fontSize: '0.7rem', cursor: 'pointer',
                      backgroundColor: complianceFramework === fw ? '#4e5ced' : '#e8eafd',
                      color: complianceFramework === fw ? '#fff' : '#4e5ced',
                    }}
                  />
                ))}
              </Box>
              <Button
                variant="outlined"
                size="small"
                onClick={() => window.open(`/api/v1/compliance/sessions/${id}/${complianceFramework}`, '_blank')}
                sx={{ alignSelf: 'flex-start', fontSize: '0.78rem', textTransform: 'none', borderColor: '#4e5ced', color: '#4e5ced' }}
              >
                Generate {complianceFramework.toUpperCase()} Report
              </Button>
              <Typography sx={{ fontSize: '0.78rem', color: '#8a93a6', mt: 2 }}>
                Click &ldquo;Generate&rdquo; to open the compliance report in a new tab.
                Reports map confirmed findings to framework control IDs.
              </Typography>
            </Box>
          )}

          {/* v6 T149 — Hypothesis tab. Switched from Cytoscape graph to a
              sortable table (much more readable for long lists). */}
          {rightTab === 12 && id && (
            <Box sx={{ display: 'flex', flexDirection: 'column', flexGrow: 1, minHeight: 0, overflow: 'auto' }}>
              <HypothesesTable hypotheses={hypotheses as any} />
            </Box>
          )}

          {/* v6 T148 — Agent Chorus tab */}
          {rightTab === 13 && (
            <Box sx={{ display: 'flex', flexDirection: 'column', flexGrow: 1, minHeight: 0, overflow: 'auto' }}>
              <AgentChorusPage sessionId={id} />
            </Box>
          )}

          {/* v7.0 — Reasoning Loops tab (T155–T166) */}
          {rightTab === 14 && id && (
            <Box sx={{ display: 'flex', flexDirection: 'column', flexGrow: 1, minHeight: 0, overflow: 'auto' }}>
              <ReasoningLoopsPanel
                sessionId={id}
                liveStartedIds={loopStartedIds}
                liveTicks={loopTicks}
                liveFinished={loopFinished}
              />
            </Box>
          )}

          {/* v7.x — Adversarial Reasoning tab (red/blue + philosopher) */}
          {rightTab === 15 && id && (
            <Box sx={{ display: 'flex', flexDirection: 'column', flexGrow: 1, minHeight: 0, overflow: 'auto' }}>
              <AdversarialReasoningPanel
                sessionId={id}
                liveRounds={adversarialRounds}
              />
            </Box>
          )}

          {/* v7.x — Costs tab */}
          {rightTab === 16 && id && (
            <Box sx={{ display: 'flex', flexDirection: 'column', flexGrow: 1, minHeight: 0, overflow: 'auto' }}>
              <CostsPanel sessionId={id} liveTick={costsTick} />
            </Box>
          )}

          {/* v7.x — Routing tab */}
          {rightTab === 17 && id && (
            <Box sx={{ display: 'flex', flexDirection: 'column', flexGrow: 1, minHeight: 0, overflow: 'auto' }}>
              <RoutingPanel sessionId={id} />
            </Box>
          )}

          {/* v7.x — Coverage matrix tab (per-endpoint × per-attack-class) */}
          {rightTab === 18 && id && (
            <Box sx={{ display: 'flex', flexDirection: 'column', flexGrow: 1, minHeight: 0, overflow: 'auto' }}>
              <CoverageMatrixPanel sessionId={id} />
            </Box>
          )}

          {/* v7.x — Novel vulnerabilities tab (sandbox-verified PoCs only) */}
          {rightTab === 19 && id && (
            <Box sx={{ display: 'flex', flexDirection: 'column', flexGrow: 1, minHeight: 0, overflow: 'auto' }}>
              <NovelVulnerabilitiesPanel sessionId={id} />
            </Box>
          )}
        </Box>
      </Box>

      {/* v6 T147 — Explanation Panel (sticky overlay, bottom-left) */}
      {explanationEvents.length > 0 && (
        <ExplanationPanel
          events={explanationEvents}
          onHypothesisClick={() => setRightTab(12)}
        />
      )}

      {/* Finding identification dialog (click any Finding row to open) */}
      <FindingDetailDialog
        vulnId={detailVulnId}
        onClose={() => setDetailVulnId(null)}
      />

      {/* Patch code dialog */}
      <Dialog
        open={patchDialogVuln !== null}
        onClose={() => setPatchDialogVuln(null)}
        maxWidth="md"
        fullWidth
        PaperProps={{ sx: { backgroundColor: '#ffffff', border: '1px solid rgba(78,92,237,0.2)' } }}
      >
        <DialogTitle sx={{ color: '#4e5ced', fontSize: '0.95rem', pb: 1 }}>
          Patch: {patchDialogVuln?.title}
        </DialogTitle>
        <DialogContent>
          <Box component="pre" sx={{ color: '#c8e6c9', fontFamily: 'monospace', fontSize: '0.78rem', whiteSpace: 'pre-wrap', wordBreak: 'break-all', backgroundColor: '#0a0a0a', borderRadius: 1, p: 2, margin: 0, border: '1px solid #dfe3ec', maxHeight: 500, overflowY: 'auto' }}>
            {patchDialogVuln?.patch_code}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setPatchDialogVuln(null)} sx={{ color: '#5a6478' }}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Completion Dialog */}
      <Dialog
        open={completedDialog}
        onClose={() => setCompletedDialog(false)}
        PaperProps={{ sx: { backgroundColor: '#242424', border: '1px solid #dfe3ec' } }}
      >
        <DialogTitle sx={{ color: '#4caf50' }}>Assessment Complete</DialogTitle>
        <DialogContent>
          <Typography sx={{ color: '#5a6478', mb: 2 }}>
            MYTHOS autonomous assessment for{' '}
            <strong style={{ color: '#4e5ced' }}>{session.target_ip}</strong> has completed.
          </Typography>
          <Box sx={{ display: 'flex', gap: 3 }}>
            <Box sx={{ textAlign: 'center' }}>
              <Typography variant="h4" sx={{ color: '#f44336', fontWeight: 700 }}>{liveVulns.length}</Typography>
              <Typography variant="caption" sx={{ color: '#8a93a6' }}>Vulnerabilities</Typography>
            </Box>
            <Box sx={{ textAlign: 'center' }}>
              <Typography variant="h4" sx={{ color: '#f44336', fontWeight: 700 }}>{severityCounts.critical}</Typography>
              <Typography variant="caption" sx={{ color: '#8a93a6' }}>Critical</Typography>
            </Box>
            <Box sx={{ textAlign: 'center' }}>
              <Typography variant="h4" sx={{ color: '#ff9800', fontWeight: 700 }}>{attackChains.length}</Typography>
              <Typography variant="caption" sx={{ color: '#8a93a6' }}>Attack Chains</Typography>
            </Box>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCompletedDialog(false)} sx={{ color: '#5a6478' }}>Stay Here</Button>
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

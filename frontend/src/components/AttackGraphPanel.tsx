// T27 — Live attack-graph visualisation.
//
// Renders the per-session Neo4j graph (T21) with Cytoscape. On mount fetches
// the current graph from GET /api/v1/graph/session/{id}, then subscribes to
// `graph_delta` WebSocket events and appends new nodes/edges as the agent
// works. Node colour follows the label; edge colour follows confidence /
// severity where applicable.
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Box, Button, Chip, CircularProgress, IconButton, Tooltip, Typography } from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import RemoveIcon from '@mui/icons-material/Remove';
import CenterFocusStrongIcon from '@mui/icons-material/CenterFocusStrong';
import FitScreenIcon from '@mui/icons-material/FitScreen';
import CytoscapeComponent from 'react-cytoscapejs';
import cytoscape, { Core, ElementDefinition } from 'cytoscape';
// @ts-expect-error — cytoscape-fcose ships without a type declaration in npm
import fcose from 'cytoscape-fcose';

import type { GraphPayload, GraphNode, GraphEdge } from '../types';
import HubIcon from '@mui/icons-material/Hub';
import EmptyTabState from './EmptyTabState';

// Register fcose once (idempotent — the layout plugin guards against re-reg).
try {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  cytoscape.use(fcose as any);
} catch {
  /* already registered */
}

// Cytoscape's canvas defaults to pixel-ratio 1 which renders at half-resolution
// on 2x / 1.5x DPI displays (HiDPI laptops, Bastion-RDP scaling). The fix is to
// match the device pixel ratio so the canvas's internal resolution equals the
// CSS resolution. Read once at module load — the value rarely changes mid-session.
const DEVICE_PIXEL_RATIO = typeof window !== 'undefined'
  ? Math.max(1, Math.min(3, window.devicePixelRatio || 1))
  : 1;

// The frontend runs behind the same reverse proxy as the backend, so all
// /api/v1/... calls resolve locally. We use plain fetch here rather than the
// shared axios instance because Cytoscape's one-shot graph export is a
// simple GET + optional X-API-Key header.
const API_KEY_STORAGE = 'genesis_api_key';
const apiHeaders = (): HeadersInit => {
  const key = localStorage.getItem(API_KEY_STORAGE);
  return key ? { 'X-API-Key': key } : {};
};

const LABEL_COLOURS: Record<string, string> = {
  Host:       '#4fc3f7',
  Service:    '#81c784',
  Finding:    '#f44336',
  Credential: '#ffd54f',
  Token:      '#ffb74d',
  Privilege:  '#ba68c8',
  Target:     '#90a4ae',
};
const SEVERITY_OVERRIDE: Record<string, string> = {
  critical: '#f44336', high: '#ff6d00', medium: '#ff9800', low: '#2979ff', info: '#5a6478',
};
const EDGE_COLOURS: Record<string, string> = {
  LISTENS_ON:       '#4e5ced',
  AFFECTS:          '#f44336',
  AFFECTS_HOST:     '#ef5350',
  CHAINS_INTO:      '#ff9800',
  AUTHENTICATES_TO: '#ffd54f',
  GRANTS:           '#ba68c8',
  ON_TARGET:        '#607d8b',
};

// Per-label shape so nodes are visually distinguishable at a glance.
const LABEL_SHAPES: Record<string, string> = {
  Host:       'round-rectangle',
  Service:    'ellipse',
  Finding:    'diamond',
  Credential: 'tag',
  Token:      'hexagon',
  Privilege:  'octagon',
  Target:     'barrel',
};
const LABEL_SIZES: Record<string, number> = {
  Host:       46,
  Service:    34,
  Finding:    40,
  Credential: 34,
  Token:      32,
  Privilege:  34,
  Target:     50,
};

function truncate(s: string, n: number): string {
  if (!s) return '';
  return s.length > n ? `${s.substring(0, n - 1)}…` : s;
}

// Build a clean type-aware caption — no leading punctuation, no noisy parens.
function nodeCaption(n: GraphNode, label: string): string {
  const t = (v: unknown) => (v == null ? '' : String(v).trim());
  switch (label) {
    case 'Host': {
      const head = t(n.hostname) || t(n.ip) || 'Host';
      return truncate(head, 22);
    }
    case 'Service': {
      const port = n.port != null ? `${n.port}/${t(n.protocol) || 'tcp'}` : '';
      const banner = truncate(t(n.banner), 22);
      return [port, banner].filter(Boolean).join('  ·  ') || 'Service';
    }
    case 'Finding':
      return truncate(t(n.title) || 'Finding', 28);
    case 'Credential': {
      const u = t(n.username);
      const r = t(n.realm);
      return truncate(u && r ? `${u}@${r}` : (u || r || 'Credential'), 22);
    }
    case 'Token':
      return truncate(t(n.kind) || 'Token', 18);
    case 'Privilege':
      return truncate(t(n.name) || 'Privilege', 18);
    case 'Target':
      return truncate(t(n.ip) || 'Target', 20);
    default:
      return truncate(t(n.title) || label, 22);
  }
}

function nodeElement(n: GraphNode): ElementDefinition {
  const label = n.labels?.[0] ?? 'Host';
  const severity = typeof n.severity === 'string' ? n.severity.toLowerCase() : undefined;
  const colour = (label === 'Finding' && severity && SEVERITY_OVERRIDE[severity])
    ? SEVERITY_OVERRIDE[severity]
    : (LABEL_COLOURS[label] ?? '#5a6478');
  return {
    data: {
      id: n.id,
      label: nodeCaption(n, label),
      labelType: label,
      shape: LABEL_SHAPES[label] ?? 'ellipse',
      size: LABEL_SIZES[label] ?? 34,
      colour,
      raw: n,
    },
  };
}

// Friendlier edge labels — used only when an edge is selected.
const EDGE_LABEL_HUMAN: Record<string, string> = {
  LISTENS_ON:       'listens on',
  AFFECTS:          'affects',
  AFFECTS_HOST:     'affects host',
  CHAINS_INTO:      'chains into',
  AUTHENTICATES_TO: 'auth to',
  GRANTS:           'grants',
  ON_TARGET:        'on target',
};

function edgeElement(e: GraphEdge, idx: number): ElementDefinition {
  const type = String(e.type ?? '');
  return {
    data: {
      id: `${e.source}__${e.target}__${type}__${idx}`,
      source: e.source,
      target: e.target,
      label: EDGE_LABEL_HUMAN[type] ?? (type ? type.toLowerCase().replace(/_/g, ' ') : 'edge'),
      colour: EDGE_COLOURS[type] ?? '#8a93a6',
    },
  };
}

interface Props {
  sessionId: string;
  graphDelta?: GraphPayload | null;
  onSelectFinding?: (vulnId: string) => void;
  sessionStatus?: string | null;
  iterationCount?: number;
  toolCallCount?: number;
}

const AttackGraphPanel: React.FC<Props> = ({ sessionId, graphDelta, onSelectFinding, sessionStatus, iterationCount, toolCallCount }) => {
  const cyRef = useRef<Core | null>(null);
  const [initial, setInitial] = useState<GraphPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Initial fetch.
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    (async () => {
      try {
        const res = await fetch(`/api/v1/graph/session/${sessionId}`, {
          headers: apiHeaders(),
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const body = await res.json();
        if (!cancelled) {
          setInitial({ nodes: body.nodes ?? [], edges: body.edges ?? [] });
        }
      } catch (err) {
        if (!cancelled) setError(String(err));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [sessionId]);

  // Apply incremental deltas by inserting into the live cy instance so the
  // layout doesn't fully re-run on every event.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy || !graphDelta) return;
    let changed = false;
    for (const n of graphDelta.nodes ?? []) {
      if (!cy.$id(n.id).length) {
        cy.add(nodeElement(n));
        changed = true;
      }
    }
    for (let i = 0; i < (graphDelta.edges ?? []).length; i++) {
      const e = graphDelta.edges![i];
      const eid = `${e.source}__${e.target}__${e.type}__${i}`;
      if (!cy.$id(eid).length && cy.$id(e.source).length && cy.$id(e.target).length) {
        cy.add(edgeElement(e, i));
        changed = true;
      }
    }
    if (changed) {
      try {
        cy.layout({
          name: 'fcose',
          animate: false,
          fit: false,
          randomize: false,
          quality: 'default',
          nodeRepulsion: 9000,
          idealEdgeLength: 110,
          nodeSeparation: 90,
          gravity: 0.3,
          packComponents: true,
        } as unknown as cytoscape.LayoutOptions).run();
      } catch {
        cy.layout({ name: 'cose', animate: false, fit: false } as cytoscape.LayoutOptions).run();
      }
    }
  }, [graphDelta]);

  const elements = useMemo<ElementDefinition[]>(() => {
    if (!initial) return [];
    const out: ElementDefinition[] = initial.nodes.map(nodeElement);
    initial.edges.forEach((e, i) => out.push(edgeElement(e, i)));
    return out;
  }, [initial]);

  const stylesheet = useMemo<unknown[]>(() => [
    {
      selector: 'node',
      style: {
        'background-color': 'data(colour)',
        'shape': 'data(shape)',
        'width': 'data(size)',
        'height': 'data(size)',
        'label': 'data(label)',
        'color': '#1a1f2e',
        'font-size': '13px',
        'font-family': 'system-ui, -apple-system, "Segoe UI", sans-serif',
        'font-weight': 600,
        'text-wrap': 'ellipsis',
        'text-max-width': '180px',
        'text-valign': 'bottom',
        'text-halign': 'center',
        'text-margin-y': 6,
        'text-background-color': '#ffffff',
        'text-background-opacity': 0.9,
        'text-background-padding': '3px',
        'text-background-shape': 'roundrectangle',
        'border-width': 2,
        'border-color': '#ffffff',
        'border-opacity': 1,
        'overlay-padding': 6,
        'transition-property': 'background-color, border-color, border-width',
        'transition-duration': '120ms',
      },
    },
    // Highlight the high-severity findings — slightly bolder.
    {
      selector: 'node[labelType = "Finding"]',
      style: {
        'border-color': '#ffffff',
        'border-width': 2.5,
      },
    },
    {
      selector: 'node[labelType = "Target"]',
      style: {
        'font-weight': 700,
        'font-size': '14px',
      },
    },
    {
      selector: 'edge',
      style: {
        'line-color': 'data(colour)',
        'line-opacity': 0.55,
        'target-arrow-color': 'data(colour)',
        'target-arrow-shape': 'triangle-backcurve',
        'arrow-scale': 0.9,
        'curve-style': 'bezier',
        'control-point-step-size': 40,
        'width': 1.4,
        // Edge labels are noisy when always-on. Hide them and reveal on select/hover.
        'label': '',
        'font-size': '10px',
        'color': '#1a1f2e',
        'text-rotation': 'autorotate',
        'text-background-color': '#ffffff',
        'text-background-opacity': 0.95,
        'text-background-padding': '3px',
        'text-background-shape': 'roundrectangle',
      },
    },
    // Reveal edge label only when hovered or selected.
    {
      selector: 'edge:selected, edge.hover',
      style: {
        'label': 'data(label)',
        'line-opacity': 1,
        'width': 2,
      },
    },
    {
      selector: 'node:selected, node.hover',
      style: {
        'border-color': '#1a1f2e',
        'border-width': 3,
      },
    },
    // Fade siblings when something is selected so the focus path stands out.
    {
      selector: 'node.faded, edge.faded',
      style: {
        'opacity': 0.18,
      },
    },
  ], []);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const n of initial?.nodes ?? []) {
      const l = n.labels?.[0] ?? 'Unknown';
      c[l] = (c[l] ?? 0) + 1;
    }
    return c;
  }, [initial]);

  const runLayout = useCallback((cy: Core, randomize: boolean) => {
    const fcoseOpts = {
      name: 'fcose',
      animate: false,
      fit: true,
      padding: 40,
      randomize,
      quality: 'proof',
      nodeRepulsion: 9000,
      idealEdgeLength: 110,
      edgeElasticity: 0.45,
      nodeSeparation: 90,
      gravity: 0.3,
      gravityRangeCompound: 1.5,
      uniformNodeDimensions: false,
      packComponents: true,
      tile: true,
    } as unknown as cytoscape.LayoutOptions;
    try {
      cy.layout(fcoseOpts).run();
    } catch {
      cy.layout({
        name: 'cose',
        animate: false,
        fit: true,
        padding: 40,
        nodeRepulsion: () => 9000,
        idealEdgeLength: () => 110,
      } as unknown as cytoscape.LayoutOptions).run();
    }
  }, []);

  const handleCy = useCallback((cy: Core) => {
    cyRef.current = cy;
    runLayout(cy, true);

    // Hover ring: fade everything except the hovered node and its 1-hop neighbours.
    cy.on('mouseover', 'node', (evt) => {
      const n = evt.target;
      const focus = n.closedNeighborhood();
      cy.elements().difference(focus).addClass('faded');
      n.addClass('hover');
      focus.connectedEdges().addClass('hover');
    });
    cy.on('mouseout', 'node', () => {
      cy.elements().removeClass('faded hover');
    });
    cy.on('mouseover', 'edge', (evt) => evt.target.addClass('hover'));
    cy.on('mouseout', 'edge', (evt) => evt.target.removeClass('hover'));

    // Click on a Finding node → open the matching row in the Findings tab.
    cy.on('tap', 'node', (evt) => {
      const n = evt.target;
      if (n.data('labelType') === 'Finding' && onSelectFinding) {
        onSelectFinding(String(n.id()));
      }
    });
  }, [runLayout, onSelectFinding]);

  // Tweak Finding-node styling so they look obviously interactive.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.nodes('[labelType = "Finding"]').style('cursor', 'pointer');
  }, [initial]);

  if (loading) {
    return (
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 1 }}>
        <CircularProgress size={16} />
        <Typography variant="caption" sx={{ color: '#c3cad7' }}>Loading graph…</Typography>
      </Box>
    );
  }
  if (error) {
    return (
      <Box sx={{ p: 2 }}>
        <Typography variant="caption" sx={{ color: '#f44336' }}>Graph unavailable: {error}</Typography>
      </Box>
    );
  }
  if (!initial || initial.nodes.length === 0) {
    return (
      <EmptyTabState
        icon={<HubIcon sx={{ fontSize: 36 }} />}
        title="Attack graph is empty."
        trigger="Nodes appear as the agent enumerates hosts, services, credentials, and findings (Neo4j is updated on every topology event and confirmed VULNERABILITY block). Edges connect them — LISTENS_ON, AFFECTS, CHAINS_INTO, GRANTS, AUTHENTICATES_TO."
        sessionStatus={sessionStatus}
        counters={[
          { label: 'iterations', value: iterationCount ?? 0 },
          { label: 'tool calls', value: toolCallCount ?? 0 },
        ]}
      />
    );
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, px: 1.5, py: 1, borderBottom: '1px solid rgba(30,41,60,0.06)', flexWrap: 'wrap', flexShrink: 0 }}>
        {Object.entries(counts).map(([label, n]) => (
          <Chip
            key={label}
            label={`${label} · ${n}`}
            size="small"
            sx={{
              backgroundColor: `${LABEL_COLOURS[label] ?? '#5a6478'}22`,
              color: LABEL_COLOURS[label] ?? '#5a6478',
              fontSize: '0.68rem',
              fontWeight: 600,
              height: 22,
              borderRadius: 1,
              border: `1px solid ${LABEL_COLOURS[label] ?? '#5a6478'}55`,
            }}
          />
        ))}
        <Box sx={{ flexGrow: 1 }} />
        <Button
          size="small"
          variant="outlined"
          onClick={() => { if (cyRef.current) runLayout(cyRef.current, true); }}
          sx={{ textTransform: 'none', fontSize: '0.7rem', height: 24, py: 0, px: 1.25, color: '#4e5ced', borderColor: 'rgba(78,92,237,0.4)' }}
        >
          Re-layout
        </Button>
        <Button
          size="small"
          variant="outlined"
          onClick={() => { if (cyRef.current) cyRef.current.fit(undefined, 40); }}
          sx={{ textTransform: 'none', fontSize: '0.7rem', height: 24, py: 0, px: 1.25, color: '#5a6478', borderColor: 'rgba(90,100,120,0.3)' }}
        >
          Fit
        </Button>
      </Box>
      <Box sx={{ flexGrow: 1, minHeight: 0, backgroundColor: '#fafbfc', position: 'relative' }}>
        <CytoscapeComponent
          elements={elements}
          stylesheet={stylesheet as never}
          cy={handleCy}
          style={{ width: '100%', height: '100%' }}
          wheelSensitivity={0.5}
          minZoom={0.05}
          maxZoom={12}
          pixelRatio={DEVICE_PIXEL_RATIO}
          textureOnViewport={false}
          motionBlur={false}
          hideEdgesOnViewport={false}
          autoungrabify={false}
        />
        {/* Floating zoom controls — bottom-right corner of the canvas */}
        <Box sx={{
          position: 'absolute', bottom: 12, right: 12, display: 'flex',
          flexDirection: 'column', gap: 0.5, zIndex: 5,
        }}>
          <Tooltip title="Zoom in" placement="left">
            <IconButton size="small" onClick={() => {
              const cy = cyRef.current; if (!cy) return;
              cy.zoom({ level: cy.zoom() * 1.4, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
            }} sx={{ backgroundColor: '#ffffff', border: '1px solid rgba(30,41,60,0.10)', '&:hover': { backgroundColor: '#f4f6fb' } }}>
              <AddIcon sx={{ fontSize: 18, color: '#1a1f2e' }} />
            </IconButton>
          </Tooltip>
          <Tooltip title="Zoom out" placement="left">
            <IconButton size="small" onClick={() => {
              const cy = cyRef.current; if (!cy) return;
              cy.zoom({ level: cy.zoom() / 1.4, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
            }} sx={{ backgroundColor: '#ffffff', border: '1px solid rgba(30,41,60,0.10)', '&:hover': { backgroundColor: '#f4f6fb' } }}>
              <RemoveIcon sx={{ fontSize: 18, color: '#1a1f2e' }} />
            </IconButton>
          </Tooltip>
          <Tooltip title="Reset to 100%" placement="left">
            <IconButton size="small" onClick={() => {
              const cy = cyRef.current; if (!cy) return;
              cy.zoom({ level: 1, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
              cy.center();
            }} sx={{ backgroundColor: '#ffffff', border: '1px solid rgba(30,41,60,0.10)', '&:hover': { backgroundColor: '#f4f6fb' } }}>
              <CenterFocusStrongIcon sx={{ fontSize: 18, color: '#1a1f2e' }} />
            </IconButton>
          </Tooltip>
          <Tooltip title="Fit to view" placement="left">
            <IconButton size="small" onClick={() => {
              const cy = cyRef.current; if (!cy) return;
              cy.fit(undefined, 40);
            }} sx={{ backgroundColor: '#ffffff', border: '1px solid rgba(30,41,60,0.10)', '&:hover': { backgroundColor: '#f4f6fb' } }}>
              <FitScreenIcon sx={{ fontSize: 18, color: '#1a1f2e' }} />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>
    </Box>
  );
};

export default AttackGraphPanel;

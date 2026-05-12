import React, { useEffect, useRef, useState, useCallback } from 'react';
import {
  Box,
  Typography,
  CircularProgress,
  Alert,
  Chip,
  IconButton,
  Button,
  Drawer,
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import { useNavigate, useParams } from 'react-router-dom';

import { sessionsApi } from '../services/api';
import type { AttackChain, AttackChainStep, NetworkTopology, NetworkNode, NetworkEdge } from '../types';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#f44336', high: '#ff6d00', medium: '#ff9800', low: '#2979ff', info: '#5a6478',
};

interface GraphNode {
  id: string;
  label: string;
  type: 'host' | 'service' | 'vuln';
  severity?: string;
  x: number;
  y: number;
}

interface GraphEdge {
  from: string;
  to: string;
  label: string;
  isChain: boolean;
}

function buildGraph(topology: NetworkTopology, chains: AttackChain[]): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodeMap = new Map<string, GraphNode>();
  const edges: GraphEdge[] = [];
  const W = 900, H = 600;

  // Add topology nodes
  (topology?.nodes ?? []).forEach((n: NetworkNode, i: number) => {
    const angle = (2 * Math.PI * i) / Math.max(topology.nodes.length, 1);
    nodeMap.set(n.id, {
      id: n.id,
      label: n.label || n.id,
      type: n.type,
      severity: n.severity,
      x: W / 2 + (W / 3) * Math.cos(angle),
      y: H / 2 + (H / 3) * Math.sin(angle),
    });
  });

  // Add topology edges
  (topology?.edges ?? []).forEach((e: NetworkEdge) => {
    edges.push({ from: e.from, to: e.to, label: e.label, isChain: false });
  });

  // Add chain vulns as nodes
  let vuln_x = 80;
  chains.forEach((chain, ci) => {
    const baseY = 100 + ci * 120;
    chain.steps.forEach((step: AttackChainStep, si: number) => {
      const nid = `vuln-${step.vuln_id}`;
      if (!nodeMap.has(nid)) {
        nodeMap.set(nid, {
          id: nid,
          label: step.title.substring(0, 20),
          type: 'vuln',
          severity: step.severity,
          x: vuln_x + si * 150,
          y: baseY,
        });
      }
      if (si > 0) {
        const prevId = `vuln-${chain.steps[si - 1].vuln_id}`;
        edges.push({ from: prevId, to: nid, label: `step ${si + 1}`, isChain: true });
      }
    });
    vuln_x = 80;
  });

  return { nodes: Array.from(nodeMap.values()), edges };
}

const AttackGraph: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const svgRef = useRef<SVGSVGElement>(null);
  const [chains, setChains] = useState<AttackChain[]>([]);
  const [topology, setTopology] = useState<NetworkTopology>({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(true);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [transform, setTransform] = useState({ x: 0, y: 0, scale: 1 });
  const dragRef = useRef<{ startX: number; startY: number; tx: number; ty: number } | null>(null);

  useEffect(() => {
    if (!id) return;
    const load = async () => {
      setLoading(true);
      try {
        const [c, t] = await Promise.allSettled([
          sessionsApi.getAttackChains(id),
          sessionsApi.getNetworkTopology(id),
        ]);
        if (c.status === 'fulfilled') setChains(c.value);
        if (t.status === 'fulfilled') setTopology(t.value);
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [id]);

  const { nodes, edges } = buildGraph(topology, chains);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    dragRef.current = { startX: e.clientX, startY: e.clientY, tx: transform.x, ty: transform.y };
  }, [transform]);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (!dragRef.current) return;
    setTransform(prev => ({
      ...prev,
      x: dragRef.current!.tx + (e.clientX - dragRef.current!.startX),
      y: dragRef.current!.ty + (e.clientY - dragRef.current!.startY),
    }));
  }, []);

  const handleMouseUp = useCallback(() => { dragRef.current = null; }, []);

  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    setTransform(prev => ({ ...prev, scale: Math.max(0.3, Math.min(3, prev.scale - e.deltaY * 0.001)) }));
  }, []);

  const handleNodeClick = (node: GraphNode) => {
    setSelectedNode(node);
    setDrawerOpen(true);
  };

  const exportPng = () => {
    if (!svgRef.current) return;
    const svgData = new XMLSerializer().serializeToString(svgRef.current);
    const canvas = document.createElement('canvas');
    canvas.width = 900;
    canvas.height = 600;
    const ctx = canvas.getContext('2d')!;
    const img = new Image();
    img.onload = () => { ctx.drawImage(img, 0, 0); canvas.toBlob(b => { if (b) { const a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = `attack-graph-${id}.png`; a.click(); } }); };
    img.src = 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svgData)));
  };

  if (loading) return (
    <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh', backgroundColor: '#0a0a0a' }}>
      <CircularProgress color="primary" />
    </Box>
  );

  return (
    <Box sx={{ height: '100vh', display: 'flex', flexDirection: 'column', backgroundColor: '#0a0a0a', overflow: 'hidden' }}>
      {/* Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, px: 2, py: 1.5, backgroundColor: '#ffffff', borderBottom: '1px solid #dfe3ec', flexShrink: 0 }}>
        <IconButton size="small" onClick={() => navigate(-1)} sx={{ color: '#5a6478' }}>
          <ArrowBackIcon fontSize="small" />
        </IconButton>
        <AccountTreeIcon sx={{ color: '#4e5ced' }} />
        <Typography variant="h6" sx={{ color: '#1a1f2e', fontSize: '0.95rem', fontWeight: 600 }}>
          Attack Graph
        </Typography>
        <Chip label={`${chains.length} chains`} size="small" sx={{ backgroundColor: 'rgba(78,92,237,0.1)', color: '#4e5ced' }} />
        <Chip label={`${nodes.length} nodes`} size="small" sx={{ backgroundColor: '#dfe3ec', color: '#5a6478' }} />
        <Box sx={{ flexGrow: 1 }} />
        <Button size="small" variant="outlined" onClick={exportPng} sx={{ color: '#4e5ced', borderColor: 'rgba(78,92,237,0.3)', fontSize: '0.75rem' }}>
          Export PNG
        </Button>
      </Box>

      {/* SVG canvas */}
      {nodes.length === 0 ? (
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', flexGrow: 1 }}>
          <Alert severity="info" sx={{ backgroundColor: 'rgba(30,41,60,0.04)', color: '#5a6478' }}>
            No graph data available for this session yet.
          </Alert>
        </Box>
      ) : (
        <Box sx={{ flexGrow: 1, position: 'relative', cursor: 'grab', '&:active': { cursor: 'grabbing' } }}
          onMouseDown={handleMouseDown} onMouseMove={handleMouseMove} onMouseUp={handleMouseUp} onWheel={handleWheel}>
          <svg ref={svgRef} width="100%" height="100%" style={{ display: 'block' }}>
            <defs>
              <marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
                <path d="M0,0 L0,6 L8,3 z" fill="rgba(244,67,54,0.7)" />
              </marker>
              <marker id="arrow-gray" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
                <path d="M0,0 L0,6 L8,3 z" fill="rgba(78,92,237,0.4)" />
              </marker>
            </defs>
            <g transform={`translate(${transform.x},${transform.y}) scale(${transform.scale})`}>
              {edges.map((e, i) => {
                const from = nodes.find(n => n.id === e.from);
                const to = nodes.find(n => n.id === e.to);
                if (!from || !to) return null;
                return (
                  <g key={i}>
                    <line x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                      stroke={e.isChain ? 'rgba(244,67,54,0.5)' : 'rgba(78,92,237,0.3)'}
                      strokeWidth={e.isChain ? 2 : 1}
                      markerEnd={e.isChain ? 'url(#arrow)' : 'url(#arrow-gray)'} />
                    <text x={(from.x + to.x) / 2} y={(from.y + to.y) / 2 - 4} fill="#8a93a6" fontSize={9} textAnchor="middle" fontFamily="monospace">
                      {e.label}
                    </text>
                  </g>
                );
              })}
              {nodes.map(n => {
                const color = n.severity ? SEVERITY_COLORS[n.severity] : n.type === 'host' ? '#4fc3f7' : n.type === 'service' ? '#4e5ced' : '#f44336';
                const shape = n.type === 'vuln' ? (
                  <polygon
                    points={`${n.x},${n.y - 14} ${n.x + 12},${n.y + 8} ${n.x - 12},${n.y + 8}`}
                    fill={`${color}30`} stroke={color} strokeWidth={1.5}
                    style={{ cursor: 'pointer' }}
                    onClick={() => handleNodeClick(n)}
                  />
                ) : n.type === 'service' ? (
                  <rect x={n.x - 14} y={n.y - 10} width={28} height={20} rx={3}
                    fill={`${color}20`} stroke={color} strokeWidth={1.5}
                    style={{ cursor: 'pointer' }}
                    onClick={() => handleNodeClick(n)}
                  />
                ) : (
                  <circle cx={n.x} cy={n.y} r={14} fill={`${color}20`} stroke={color} strokeWidth={1.5}
                    style={{ cursor: 'pointer' }}
                    onClick={() => handleNodeClick(n)}
                  />
                );
                return (
                  <g key={n.id}>
                    {shape}
                    <text x={n.x} y={n.y + 26} textAnchor="middle" fill="#2a3045" fontSize={10} fontFamily="monospace" style={{ pointerEvents: 'none' }}>
                      {n.label.substring(0, 16)}
                    </text>
                  </g>
                );
              })}
            </g>
          </svg>

          {/* Legend */}
          <Box sx={{ position: 'absolute', bottom: 16, left: 16, backgroundColor: 'rgba(0,0,0,0.7)', border: '1px solid #dfe3ec', borderRadius: 1, p: 1.5 }}>
            {[
              { shape: '●', color: '#4fc3f7', label: 'Host' },
              { shape: '■', color: '#4e5ced', label: 'Service' },
              { shape: '◆', color: '#f44336', label: 'Vulnerability' },
            ].map(item => (
              <Box key={item.label} sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                <Typography sx={{ color: item.color, fontSize: '0.75rem' }}>{item.shape}</Typography>
                <Typography sx={{ color: '#5a6478', fontSize: '0.7rem' }}>{item.label}</Typography>
              </Box>
            ))}
          </Box>
        </Box>
      )}

      {/* Detail drawer */}
      <Drawer anchor="right" open={drawerOpen} onClose={() => setDrawerOpen(false)}
        PaperProps={{ sx: { width: 320, backgroundColor: '#ffffff', border: '1px solid #dfe3ec', p: 2 } }}>
        {selectedNode && (
          <>
            <Typography variant="h6" sx={{ color: '#1a1f2e', mb: 1, fontSize: '0.95rem' }}>{selectedNode.label}</Typography>
            <Chip label={selectedNode.type} size="small" sx={{ mb: 1, backgroundColor: '#dfe3ec', color: '#5a6478' }} />
            {selectedNode.severity && (
              <Chip label={selectedNode.severity.toUpperCase()} size="small"
                sx={{ ml: 1, mb: 1, backgroundColor: `${SEVERITY_COLORS[selectedNode.severity]}20`, color: SEVERITY_COLORS[selectedNode.severity] }} />
            )}
            <Typography variant="caption" sx={{ color: '#8a93a6', display: 'block' }}>ID: {selectedNode.id}</Typography>
          </>
        )}
      </Drawer>
    </Box>
  );
};

export default AttackGraph;

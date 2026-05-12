import React, { useEffect, useRef } from 'react';
import { Box, Typography } from '@mui/material';
import type { HypothesisNode } from '../types';

interface HypothesisTreeViewerProps {
  hypotheses: HypothesisNode[];
  onNodeClick?: (hypId: string) => void;
}

const STATUS_COLORS: Record<string, string> = {
  active: '#3f51b5',
  confirmed: '#4caf50',
  ruled_out: '#f44336',
};

export default function HypothesisTreeViewer({ hypotheses, onNodeClick }: HypothesisTreeViewerProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<unknown>(null);

  useEffect(() => {
    if (!containerRef.current || hypotheses.length === 0) return;

    // Dynamically load cytoscape to avoid build issues
    import('cytoscape').then((cytoscapeModule) => {
      const cytoscape = cytoscapeModule.default;
      if (!containerRef.current) return;

      // Destroy previous instance
      if (cyRef.current) {
        (cyRef.current as { destroy: () => void }).destroy();
      }

      const nodes = hypotheses.map(h => ({
        data: {
          id: h.hyp_id,
          label: h.statement.slice(0, 40) + (h.statement.length > 40 ? '…' : ''),
          status: h.status,
          confidence: h.confidence,
          curiosity_score: h.curiosity_score ?? 0,
        },
      }));

      const edges = hypotheses
        .filter(h => h.parent_id)
        .map(h => ({
          data: {
            id: `${h.parent_id}->${h.hyp_id}`,
            source: h.parent_id!,
            target: h.hyp_id,
          },
        }));

      const cy = cytoscape({
        container: containerRef.current,
        elements: { nodes, edges },
        style: [
          {
            selector: 'node',
            style: {
              'background-color': (ele: { data: (key: string) => string }) => STATUS_COLORS[ele.data('status')] || '#607d8b',
              'label': 'data(label)',
              'text-valign': 'center',
              'text-halign': 'center',
              'font-size': '10px',
              'color': '#fff',
              'text-wrap': 'wrap',
              'text-max-width': '80px',
              'width': (ele: { data: (key: string) => number }) => 20 + ele.data('confidence') * 30,
              'height': (ele: { data: (key: string) => number }) => 20 + ele.data('confidence') * 30,
            },
          },
          {
            selector: 'edge',
            style: {
              'width': 1,
              'line-color': 'rgba(255,255,255,0.2)',
              'target-arrow-color': 'rgba(255,255,255,0.2)',
              'target-arrow-shape': 'triangle',
              'curve-style': 'bezier',
            },
          },
        ],
        layout: {
          name: 'breadthfirst',
          directed: true,
          padding: 10,
        },
      });

      cy.on('tap', 'node', (evt: { target: { id: () => string } }) => {
        onNodeClick?.(evt.target.id());
      });

      cyRef.current = cy;
    }).catch(() => { /* cytoscape not available */ });

    return () => {
      if (cyRef.current) {
        (cyRef.current as { destroy: () => void }).destroy();
        cyRef.current = null;
      }
    };
  }, [hypotheses, onNodeClick]);

  if (hypotheses.length === 0) {
    return (
      <Box sx={{ p: 3, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <Typography color="text.secondary">No hypotheses to display yet</Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ width: '100%', height: 400 }}>
      <Box
        ref={containerRef}
        sx={{
          width: '100%',
          height: '100%',
          background: 'rgba(0,0,0,0.2)',
          borderRadius: 1,
        }}
      />
    </Box>
  );
}

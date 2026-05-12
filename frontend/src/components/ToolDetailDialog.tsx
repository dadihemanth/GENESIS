// ToolDetailDialog — opens when an operator clicks a tool card on the
// Tools page. Pulls knowledge from frontend/src/data/toolKnowledge.ts and
// falls back to the MCP server's `description` for tools that don't yet
// have a curated entry.
import React from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Box,
  Typography,
  Chip,
  IconButton,
  Divider,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import LightbulbIcon from '@mui/icons-material/Lightbulb';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';
import GavelIcon from '@mui/icons-material/Gavel';
import EmojiObjectsIcon from '@mui/icons-material/EmojiObjects';

import type { ToolInfo } from '../types';
import { getToolKnowledge } from '../data/toolKnowledge';

interface Props {
  tool: ToolInfo | null;
  onClose: () => void;
}

const STATUS_COLOR: Record<string, string> = {
  available: '#4caf50',
  missing: '#f44336',
  error: '#ff9800',
  unknown: '#8a93a6',
};

const Section: React.FC<{ icon: React.ReactNode; title: string; accent: string; children: React.ReactNode }> = ({
  icon, title, accent, children,
}) => (
  <Box sx={{
    p: 2, mb: 2, borderRadius: 2, backgroundColor: '#ffffff',
    borderLeft: `3px solid ${accent}`, boxShadow: '0 1px 2px rgba(0,0,0,0.04)',
  }}>
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, mb: 1 }}>
      <Box sx={{ color: accent, display: 'flex', alignItems: 'center' }}>{icon}</Box>
      <Typography sx={{ fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: 0.5, color: '#8a93a6', fontWeight: 700 }}>
        {title}
      </Typography>
    </Box>
    <Typography sx={{ fontSize: '0.88rem', color: '#1a1f2e', lineHeight: 1.6 }}>
      {children}
    </Typography>
  </Box>
);

const ToolDetailDialog: React.FC<Props> = ({ tool, onClose }) => {
  const open = tool !== null;
  const knowledge = tool ? getToolKnowledge(tool.name) : null;
  const statusColor = STATUS_COLOR[tool?.status ?? 'unknown'] ?? '#8a93a6';

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth scroll="paper">
      <DialogTitle sx={{ pr: 6, pb: 1, borderBottom: '1px solid rgba(30,41,60,0.06)' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
          <Typography sx={{ fontSize: '1.05rem', fontWeight: 700, color: '#1a1f2e', fontFamily: 'monospace' }}>
            {tool?.name}
          </Typography>
          {tool?.version && (
            <Chip
              label={tool.version.split('\n')[0].substring(0, 40)}
              size="small"
              sx={{ height: 20, fontSize: '0.65rem', fontFamily: 'monospace',
                    backgroundColor: 'rgba(78,92,237,0.10)', color: '#4e5ced' }}
            />
          )}
          <Box sx={{ flexGrow: 1 }} />
          <Chip
            label={tool?.status ?? 'unknown'}
            size="small"
            sx={{ height: 20, fontSize: '0.65rem', fontFamily: 'monospace', fontWeight: 700,
                  backgroundColor: `${statusColor}1a`, color: statusColor,
                  border: `1px solid ${statusColor}55` }}
          />
        </Box>
        <IconButton onClick={onClose} sx={{ position: 'absolute', right: 8, top: 8, color: '#5a6478' }}>
          <CloseIcon />
        </IconButton>
      </DialogTitle>

      <DialogContent sx={{ p: 2, backgroundColor: '#fafbfc' }}>
        {!knowledge && tool?.description && (
          <Box sx={{ p: 2, mb: 2, borderRadius: 2, backgroundColor: '#ffffff', borderLeft: '3px solid #8a93a6' }}>
            <Typography sx={{ fontSize: '0.7rem', textTransform: 'uppercase', letterSpacing: 0.5, color: '#8a93a6', fontWeight: 700, mb: 1 }}>
              Description (from MCP)
            </Typography>
            <Typography sx={{ fontSize: '0.88rem', color: '#1a1f2e', lineHeight: 1.6 }}>
              {tool.description}
            </Typography>
            <Typography sx={{ mt: 1.5, fontSize: '0.72rem', color: '#8a93a6', fontStyle: 'italic' }}>
              No curated knowledge entry yet for this tool. Falling back to the MCP server's tool definition.
            </Typography>
          </Box>
        )}

        {knowledge && (
          <>
            <Section icon={<HelpOutlineIcon sx={{ fontSize: 16 }} />} title="What it is" accent="#4e5ced">
              {knowledge.what}
            </Section>
            <Section icon={<LightbulbIcon sx={{ fontSize: 16 }} />} title="Why it's used" accent="#ffd54f">
              {knowledge.why}
            </Section>
            <Section icon={<GavelIcon sx={{ fontSize: 16 }} />} title="Example attack" accent="#f44336">
              {knowledge.attack}
            </Section>
            <Section icon={<EmojiObjectsIcon sx={{ fontSize: 16 }} />} title="Analogy" accent="#26a69a">
              {knowledge.analogy}
            </Section>
            {tool?.description && (
              <>
                <Divider sx={{ my: 1 }} />
                <Box sx={{ p: 1.5, borderRadius: 2, backgroundColor: '#f4f6fb' }}>
                  <Typography sx={{ fontSize: '0.65rem', color: '#8a93a6', fontFamily: 'monospace', textTransform: 'uppercase', letterSpacing: 0.5, mb: 0.5 }}>
                    MCP definition
                  </Typography>
                  <Typography sx={{ fontSize: '0.78rem', color: '#5a6478', fontFamily: 'monospace' }}>
                    {tool.description}
                  </Typography>
                </Box>
              </>
            )}
          </>
        )}

        {!knowledge && !tool?.description && (
          <Typography sx={{ p: 4, textAlign: 'center', color: '#8a93a6', fontSize: '0.88rem' }}>
            No information available for this tool yet.
          </Typography>
        )}
      </DialogContent>

      <DialogActions sx={{ borderTop: '1px solid rgba(30,41,60,0.06)' }}>
        <Button onClick={onClose} sx={{ textTransform: 'none' }}>Close</Button>
      </DialogActions>
    </Dialog>
  );
};

export default ToolDetailDialog;

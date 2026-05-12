// Tools tab — every tool call the agent has made, with first-class detail
// for forge_runner / ai_request_forge / forge-ish tools that send custom
// LLM-authored scripts. Lets the operator see exactly which custom payloads
// the agent generated and what the sandbox returned.
import React, { useMemo, useState } from 'react';
import {
  Box, Chip, Typography, Accordion, AccordionSummary, AccordionDetails,
  TextField, ToggleButton, ToggleButtonGroup, Tooltip, IconButton,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';

import type { ToolOutput } from '../types';
import { humanizeTool } from '../utils/humanize';

interface Props {
  toolOutputs: ToolOutput[];
}

const safeTime = (ts: string): string => {
  try { return new Date(ts).toLocaleTimeString(); } catch { return ts; }
};

// Tools whose params include LLM-authored bodies the operator should see in full.
const SCRIPT_TOOLS = new Set<string>([
  'forge_runner',         // Python/Node/Bash script in the sandbox
  'ai_request_forge',     // Crafted HTTP request + oracle
  'instrument_trace',     // Frida JS hook spec
  'graph_query',          // Cypher query
]);

// For each script-tool, which param holds the "interesting" body the operator
// most wants to read. Other params are still rendered (just not as prominently).
const SCRIPT_BODY_FIELD: Record<string, string> = {
  forge_runner:     'code',
  ai_request_forge: 'body',
  instrument_trace: 'hook_spec',
  graph_query:      'cypher',
};

const SCRIPT_LANG_FIELD: Record<string, string> = {
  forge_runner:     'lang',
  ai_request_forge: 'method',
  instrument_trace: 'mode',
};

function paramAsString(v: unknown): string {
  if (v == null) return '';
  if (typeof v === 'string') return v;
  try { return JSON.stringify(v); } catch { return String(v); }
}

const ToolsPanel: React.FC<Props> = ({ toolOutputs }) => {
  const [filterText, setFilterText] = useState('');
  const [filterMode, setFilterMode] = useState<'all' | 'scripts' | 'running'>('all');

  const filtered = useMemo(() => {
    let out = [...toolOutputs];
    if (filterMode === 'scripts') out = out.filter(t => SCRIPT_TOOLS.has(t.tool_name));
    if (filterMode === 'running') out = out.filter(t => t.duration_seconds == null);
    if (filterText.trim()) {
      const ft = filterText.trim().toLowerCase();
      out = out.filter(t =>
        t.tool_name.toLowerCase().includes(ft)
        || JSON.stringify(t.params || {}).toLowerCase().includes(ft)
        || (t.raw_output ?? '').toLowerCase().includes(ft),
      );
    }
    return out.sort((a, b) => String(a.timestamp ?? '').localeCompare(String(b.timestamp ?? '')));
  }, [toolOutputs, filterMode, filterText]);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const t of toolOutputs) c[t.tool_name] = (c[t.tool_name] ?? 0) + 1;
    return Object.entries(c).sort((a, b) => b[1] - a[1]);
  }, [toolOutputs]);

  const scriptCount = toolOutputs.filter(t => SCRIPT_TOOLS.has(t.tool_name)).length;
  const runningCount = toolOutputs.filter(t => t.duration_seconds == null).length;

  if (toolOutputs.length === 0) {
    return (
      <Box sx={{ p: 4, textAlign: 'center' }}>
        <Typography variant="caption" sx={{ color: '#c3cad7' }}>
          No tool calls yet. As the agent executes tools, each call (and its raw output) will
          appear here. Custom-script tools — forge_runner, ai_request_forge, instrument_trace
          — get a full code-view so you can see exactly what the agent wrote.
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', flexGrow: 1, minHeight: 0, backgroundColor: '#fafbfc' }}>
      {/* Filter bar + tool histogram */}
      <Box sx={{ flexShrink: 0, px: 2, py: 1, borderBottom: '1px solid rgba(30,41,60,0.04)', backgroundColor: '#ffffff' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, flexWrap: 'wrap' }}>
          <ToggleButtonGroup
            size="small"
            value={filterMode}
            exclusive
            onChange={(_, v) => v && setFilterMode(v)}
            sx={{ '& .MuiToggleButton-root': { fontSize: '0.7rem', textTransform: 'none', py: 0.25, px: 1 } }}
          >
            <ToggleButton value="all">All ({toolOutputs.length})</ToggleButton>
            <ToggleButton value="scripts">Custom scripts ({scriptCount})</ToggleButton>
            <ToggleButton value="running">Running ({runningCount})</ToggleButton>
          </ToggleButtonGroup>
          <TextField
            size="small"
            value={filterText}
            onChange={e => setFilterText(e.target.value)}
            placeholder="filter by tool name, param, or output…"
            sx={{ flexGrow: 1, minWidth: 240, '& .MuiInputBase-input': { fontSize: '0.78rem', py: 0.5 } }}
          />
        </Box>
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 1 }}>
          {counts.slice(0, 12).map(([tool, n]) => (
            <Chip
              key={tool}
              label={`${tool} · ${n}`}
              size="small"
              clickable
              onClick={() => setFilterText(tool)}
              sx={{
                backgroundColor: SCRIPT_TOOLS.has(tool) ? 'rgba(255,152,0,0.12)' : 'rgba(78,92,237,0.10)',
                color: SCRIPT_TOOLS.has(tool) ? '#ff9800' : '#4e5ced',
                fontFamily: 'monospace',
                fontSize: '0.62rem',
                height: 18,
                fontWeight: SCRIPT_TOOLS.has(tool) ? 700 : 500,
              }}
            />
          ))}
        </Box>
      </Box>

      {/* Tool-call list */}
      <Box sx={{ flexGrow: 1, overflowY: 'auto', p: 1 }}>
        {filtered.map((t, idx) => {
          const isScript = SCRIPT_TOOLS.has(t.tool_name);
          const bodyField = SCRIPT_BODY_FIELD[t.tool_name];
          const langField = SCRIPT_LANG_FIELD[t.tool_name];
          const bodyVal = bodyField ? paramAsString((t.params || {})[bodyField]) : '';
          const langVal = langField ? paramAsString((t.params || {})[langField]) : '';
          const otherParams = Object.entries(t.params || {})
            .filter(([k]) => k !== bodyField);
          const running = t.duration_seconds == null;
          const accentColor = isScript ? '#ff9800' : '#4e5ced';

          return (
            <Accordion
              key={t.id ?? idx}
              defaultExpanded={isScript}
              disableGutters
              sx={{
                mb: 0.75,
                borderLeft: `3px solid ${accentColor}`,
                '&:before': { display: 'none' },
                backgroundColor: '#ffffff',
              }}
            >
              <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ py: 0, minHeight: 36 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap', flexGrow: 1 }}>
                  <Typography sx={{ color: accentColor, fontFamily: 'monospace', fontSize: '0.78rem', fontWeight: 700 }}>
                    ▶ {t.tool_name}
                  </Typography>
                  {isScript && (
                    <Chip label="custom script" size="small"
                      sx={{ backgroundColor: 'rgba(255,152,0,0.15)', color: '#ff9800', fontSize: '0.58rem', height: 14, fontWeight: 700 }} />
                  )}
                  {langVal && (
                    <Chip label={langVal} size="small"
                      sx={{ backgroundColor: 'rgba(94,103,144,0.10)', color: '#5e6790', fontSize: '0.58rem', height: 14 }} />
                  )}
                  <Typography sx={{ color: '#5a6478', fontSize: '0.7rem', fontStyle: 'italic' }}>
                    {humanizeTool(t.tool_name)}
                  </Typography>
                  <Box sx={{ flexGrow: 1 }} />
                  {running ? (
                    <Chip label="running" size="small" sx={{ backgroundColor: 'rgba(255,152,0,0.15)', color: '#ff9800', fontSize: '0.6rem', height: 16 }} />
                  ) : (
                    <Chip label={`${(t.duration_seconds ?? 0).toFixed(1)}s`} size="small"
                      sx={{ backgroundColor: 'rgba(76,175,80,0.12)', color: '#4caf50', fontSize: '0.6rem', height: 16 }} />
                  )}
                  <Typography sx={{ color: '#8a93a6', fontSize: '0.62rem', fontFamily: 'monospace' }}>
                    {safeTime(t.timestamp)}
                  </Typography>
                </Box>
              </AccordionSummary>
              <AccordionDetails sx={{ pt: 0, pb: 1.5, px: 2 }}>
                {/* Custom script body (forge_runner code, JS hook, Cypher, etc.) */}
                {bodyVal && (
                  <Box sx={{ mb: 1.25 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                      <Typography sx={{ fontSize: '0.62rem', color: '#5a6478', fontWeight: 700, letterSpacing: 0.5 }}>
                        {bodyField?.toUpperCase() ?? 'BODY'}
                      </Typography>
                      {langVal && (
                        <Typography sx={{ fontSize: '0.62rem', color: '#8a93a6', fontFamily: 'monospace' }}>
                          {langVal} · {bodyVal.length} chars
                        </Typography>
                      )}
                      <Box sx={{ flexGrow: 1 }} />
                      <Tooltip title="Copy script">
                        <IconButton size="small" onClick={() => navigator.clipboard?.writeText(bodyVal)}>
                          <ContentCopyIcon sx={{ fontSize: 14 }} />
                        </IconButton>
                      </Tooltip>
                    </Box>
                    <Box component="pre" sx={{
                      m: 0, p: 1.25, fontFamily: 'monospace', fontSize: '0.72rem',
                      whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                      maxHeight: 360, overflowY: 'auto',
                      backgroundColor: '#1a1f2e', color: '#c8e6c9',
                      borderRadius: 0.5, border: '1px solid rgba(255,152,0,0.3)',
                    }}>
                      {bodyVal}
                    </Box>
                  </Box>
                )}

                {/* Other params (everything except the script body) */}
                {otherParams.length > 0 && (
                  <Box sx={{ mb: 1.25 }}>
                    <Typography sx={{ fontSize: '0.62rem', color: '#5a6478', fontWeight: 700, letterSpacing: 0.5, mb: 0.5 }}>
                      PARAMS
                    </Typography>
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.25, pl: 1 }}>
                      {otherParams.map(([k, v]) => {
                        const vs = paramAsString(v);
                        const isLong = vs.length > 120;
                        return (
                          <Box key={k} sx={{ display: 'flex', gap: 0.75, fontFamily: 'monospace', fontSize: '0.7rem', alignItems: 'flex-start' }}>
                            <Typography sx={{ color: '#4fc3f7', fontFamily: 'monospace', fontSize: '0.7rem', flexShrink: 0 }}>
                              {k}=
                            </Typography>
                            <Typography sx={{ color: '#1a1f2e', fontFamily: 'monospace', fontSize: '0.7rem', wordBreak: 'break-all' }}>
                              {isLong ? `${vs.substring(0, 120)}…` : vs}
                            </Typography>
                          </Box>
                        );
                      })}
                    </Box>
                  </Box>
                )}

                {/* Output */}
                {t.raw_output && (
                  <Box>
                    <Typography sx={{ fontSize: '0.62rem', color: '#5a6478', fontWeight: 700, letterSpacing: 0.5, mb: 0.5 }}>
                      OUTPUT
                    </Typography>
                    <Box component="pre" sx={{
                      m: 0, p: 1.25, fontFamily: 'monospace', fontSize: '0.7rem',
                      whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                      maxHeight: 280, overflowY: 'auto',
                      backgroundColor: '#0a0a0a', color: '#c8e6c9', borderRadius: 0.5,
                    }}>
                      {t.raw_output.substring(0, 4000)}{t.raw_output.length > 4000 ? '\n...[truncated]' : ''}
                    </Box>
                  </Box>
                )}
              </AccordionDetails>
            </Accordion>
          );
        })}
        {filtered.length === 0 && (
          <Box sx={{ p: 4, textAlign: 'center' }}>
            <Typography variant="caption" sx={{ color: '#c3cad7' }}>
              No tools match the current filter.
            </Typography>
          </Box>
        )}
      </Box>
    </Box>
  );
};

export default ToolsPanel;

// Sandbox Workshop — every sandbox-bound tool call surfaced as a card.
//
// This is the operator's window into how the agent is *creatively* probing
// the target: which custom payloads were prepared, what hypothesis each
// tested, which oracles passed, and (for payload_swarm) which variants
// produced novel behaviour.
//
// We filter to the tools that actually drive sandbox-side execution:
//   - forge_runner       — single LLM-authored script
//   - payload_swarm      — N variants in parallel
//   - ai_request_forge   — single oracle-evaluated HTTP request
//   - instrument_trace   — Frida / DynamoRIO live trace
//   - crypto_*           — primitive-attack helpers (driver scripts)
import React, { useMemo, useState } from 'react';
import { Box, Chip, Typography, Tooltip, IconButton, Collapse } from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CancelIcon from '@mui/icons-material/Cancel';
import HelpOutlineIcon from '@mui/icons-material/HelpOutline';
import AutoAwesomeIcon from '@mui/icons-material/AutoAwesome';

import type { ToolOutput } from '../types';
import EmptyTabState from './EmptyTabState';

const SANDBOX_TOOLS: Set<string> = new Set([
  'forge_runner',
  'payload_swarm',
  'ai_request_forge',
  'instrument_trace',
  'crypto_padding_oracle',
  'crypto_bleichenbacher',
  'crypto_ecdsa_nonce_reuse',
  'crypto_length_extension',
  'crypto_rsa_low_e',
  'crypto_lattice',
  'crypto_jwt_confusion',
]);

const TOOL_HEADLINE: Record<string, string> = {
  forge_runner:           'Custom script in sandbox',
  payload_swarm:          'Parallel variant fanout',
  ai_request_forge:       'Oracle-backed HTTP probe',
  instrument_trace:       'Live binary instrumentation',
  crypto_padding_oracle:  'CBC padding-oracle attack',
  crypto_bleichenbacher:  'PKCS#1 v1.5 oracle (B\'98)',
  crypto_ecdsa_nonce_reuse: 'ECDSA nonce-reuse recovery',
  crypto_length_extension: 'Hash length-extension forge',
  crypto_rsa_low_e:       'RSA low-exponent attack',
  crypto_lattice:         'Lattice key recovery',
  crypto_jwt_confusion:   'JWT confusion attack',
};

const TOOL_ACCENT: Record<string, string> = {
  forge_runner:           '#4e5ced',
  payload_swarm:          '#7c4dff',
  ai_request_forge:       '#26a69a',
  instrument_trace:       '#ff9800',
  crypto_padding_oracle:  '#ec407a',
  crypto_bleichenbacher:  '#ec407a',
  crypto_ecdsa_nonce_reuse: '#ec407a',
  crypto_length_extension: '#ec407a',
  crypto_rsa_low_e:       '#ec407a',
  crypto_lattice:         '#ec407a',
  crypto_jwt_confusion:   '#ec407a',
};

interface Props {
  toolOutputs: ToolOutput[];
  sessionStatus?: string | null;
  iterationCount?: number;
  hypothesisCount?: number;
}

const VERDICT_COLORS: Record<string, string> = {
  pass: '#4caf50',
  fail: '#f44336',
  partial: '#ff9800',
  no_oracle: '#8a93a6',
};

function safeTime(ts: string): string {
  try { return new Date(ts).toLocaleTimeString(); } catch { return ts; }
}

function copyToClipboard(text: string) {
  if (!text) return;
  try {
    navigator.clipboard?.writeText(text).catch(() => {});
  } catch { /* ignore */ }
}

interface SwarmResultRow {
  name?: string;
  replica?: string;
  exit_code?: number;
  duration_ms?: number;
  stdout_len?: number;
  stdout_head?: string;
  oracle_verdict?: string;
  novelty_score?: number;
  timed_out?: boolean;
}

const VerdictPill: React.FC<{ verdict?: string }> = ({ verdict }) => {
  if (!verdict) return null;
  const v = verdict.toLowerCase();
  const color = VERDICT_COLORS[v] ?? '#8a93a6';
  const Icon = v === 'pass' ? CheckCircleIcon : v === 'fail' ? CancelIcon : HelpOutlineIcon;
  return (
    <Chip
      icon={<Icon sx={{ fontSize: '12px !important', color: `${color} !important` }} />}
      label={`oracle: ${verdict}`}
      size="small"
      sx={{
        height: 20,
        fontSize: '0.62rem',
        fontFamily: 'monospace',
        fontWeight: 700,
        backgroundColor: `${color}1a`,
        color,
        border: `1px solid ${color}55`,
      }}
    />
  );
};

const ForgeCard: React.FC<{ t: ToolOutput; expanded: boolean; onToggle: () => void }> = ({ t, expanded, onToggle }) => {
  const params = (t.params || {}) as Record<string, unknown>;
  const parsed = (t.parsed_output || {}) as Record<string, unknown>;
  const lang = String(params.lang || 'python');
  const code = String(params.code || '');
  const rationale = String(params.rationale || parsed.rationale || '');
  const targetHint = String(params.target_hint || parsed.target_hint || '');
  const verdict = parsed.oracle_verdict as string | undefined;
  const reasons = (parsed.oracle_reasons as string[] | undefined) || [];
  const exitCode = parsed.exit_code as number | undefined;
  const stdout = String(parsed.stdout || '');
  const replica = String(parsed.replica || '');
  return (
    <>
      {rationale && (
        <Typography sx={{ fontSize: '0.84rem', color: '#1a1f2e', mb: 1, fontStyle: 'italic' }}>
          “{rationale}”
        </Typography>
      )}
      <Box sx={{ display: 'flex', gap: 0.75, mb: 1, flexWrap: 'wrap', alignItems: 'center' }}>
        <Chip label={lang} size="small"
          sx={{ height: 20, fontSize: '0.62rem', fontFamily: 'monospace', fontWeight: 700, backgroundColor: 'rgba(78,92,237,0.15)', color: '#4e5ced' }} />
        {targetHint && (
          <Chip label={`target ${targetHint}`} size="small"
            sx={{ height: 20, fontSize: '0.62rem', fontFamily: 'monospace', backgroundColor: '#f4f6fb', color: '#1a1f2e' }} />
        )}
        {replica && (
          <Chip label={`replica ${replica.replace(/^https?:\/\//, '').replace(':3201', '')}`} size="small"
            sx={{ height: 20, fontSize: '0.62rem', fontFamily: 'monospace', backgroundColor: 'rgba(124,77,255,0.10)', color: '#7c4dff' }} />
        )}
        {exitCode != null && (
          <Chip label={`exit ${exitCode}`} size="small"
            sx={{ height: 20, fontSize: '0.62rem', fontFamily: 'monospace',
                  backgroundColor: exitCode === 0 ? 'rgba(76,175,80,0.10)' : 'rgba(244,67,54,0.10)',
                  color: exitCode === 0 ? '#4caf50' : '#f44336' }} />
        )}
        <VerdictPill verdict={verdict} />
      </Box>

      {/* Code preview — collapsible */}
      <Box sx={{ borderRadius: 1.5, overflow: 'hidden', border: '1px solid rgba(30,41,60,0.10)' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', px: 1.25, py: 0.5, backgroundColor: '#1a1f2e' }}>
          <Typography sx={{ flexGrow: 1, fontSize: '0.65rem', color: '#c3cad7', fontFamily: 'monospace', fontWeight: 600 }}>
            {expanded ? '▼ Payload' : '▶ Payload'}  ·  {code.length} chars
          </Typography>
          <Tooltip title="Copy script">
            <IconButton size="small" onClick={(e) => { e.stopPropagation(); copyToClipboard(code); }} sx={{ color: '#c3cad7', p: 0.25 }}>
              <ContentCopyIcon sx={{ fontSize: 13 }} />
            </IconButton>
          </Tooltip>
          <IconButton size="small" onClick={onToggle} sx={{ color: '#c3cad7', p: 0.25 }}>
            {expanded ? <ExpandLessIcon sx={{ fontSize: 16 }} /> : <ExpandMoreIcon sx={{ fontSize: 16 }} />}
          </IconButton>
        </Box>
        <Collapse in={expanded}>
          <Box component="pre" sx={{
            m: 0, px: 1.5, py: 1, backgroundColor: '#0f1320', color: '#dfe3ec',
            fontSize: '0.7rem', fontFamily: 'monospace', overflow: 'auto', maxHeight: 320, whiteSpace: 'pre',
          }}>
            {code || '(no payload captured)'}
          </Box>
        </Collapse>
      </Box>

      {expanded && stdout && (
        <Box sx={{ mt: 1, borderRadius: 1.5, overflow: 'hidden', border: '1px solid rgba(30,41,60,0.10)' }}>
          <Box sx={{ px: 1.25, py: 0.5, backgroundColor: '#f4f6fb' }}>
            <Typography sx={{ fontSize: '0.65rem', color: '#5a6478', fontFamily: 'monospace', fontWeight: 600 }}>
              ▼ stdout · {stdout.length} chars
            </Typography>
          </Box>
          <Box component="pre" sx={{
            m: 0, px: 1.5, py: 1, backgroundColor: '#fafbfc', color: '#1a1f2e',
            fontSize: '0.7rem', fontFamily: 'monospace', overflow: 'auto', maxHeight: 200, whiteSpace: 'pre',
          }}>
            {stdout.substring(0, 4000)}
          </Box>
        </Box>
      )}

      {expanded && reasons.length > 0 && (
        <Box sx={{ mt: 1 }}>
          <Typography sx={{ fontSize: '0.65rem', color: '#5a6478', fontFamily: 'monospace', fontWeight: 600, mb: 0.25 }}>
            Oracle checks:
          </Typography>
          {reasons.map((r, i) => (
            <Typography key={i} sx={{
              fontSize: '0.7rem', fontFamily: 'monospace',
              color: r.startsWith('PASS') ? '#4caf50' : r.startsWith('FAIL') ? '#f44336' : '#5a6478',
            }}>
              {r}
            </Typography>
          ))}
        </Box>
      )}
    </>
  );
};

const SwarmCard: React.FC<{ t: ToolOutput; expanded: boolean; onToggle: () => void }> = ({ t, expanded, onToggle }) => {
  const params = (t.params || {}) as Record<string, unknown>;
  const parsed = (t.parsed_output || {}) as Record<string, unknown>;
  const lang = String(params.lang || 'python');
  const template = String(params.template_code || '');
  const variantsRaw = String(params.variants || '[]');
  const rationale = String(params.rationale || parsed.rationale || '');
  const targetHint = String(params.target_hint || parsed.target_hint || '');
  const variantCount = (parsed.variant_count as number | undefined) ?? 0;
  const interesting = (parsed.interesting_count as number | undefined) ?? 0;
  const totalMs = (parsed.total_ms as number | undefined) ?? 0;
  const parallel = (parsed.parallel as number | undefined) ?? 0;
  const poolSize = (parsed.pool_size as number | undefined) ?? 0;
  const results: SwarmResultRow[] = (parsed.results as SwarmResultRow[]) || [];

  return (
    <>
      {rationale && (
        <Typography sx={{ fontSize: '0.84rem', color: '#1a1f2e', mb: 1, fontStyle: 'italic' }}>
          “{rationale}”
        </Typography>
      )}
      <Box sx={{ display: 'flex', gap: 0.75, mb: 1, flexWrap: 'wrap', alignItems: 'center' }}>
        <Chip icon={<AutoAwesomeIcon sx={{ fontSize: '12px !important', color: '#7c4dff !important' }} />}
          label={`${variantCount} variants`} size="small"
          sx={{ height: 20, fontSize: '0.62rem', fontFamily: 'monospace', fontWeight: 700, backgroundColor: 'rgba(124,77,255,0.15)', color: '#7c4dff' }} />
        <Chip label={`${parallel} parallel · ${poolSize} replicas`} size="small"
          sx={{ height: 20, fontSize: '0.62rem', fontFamily: 'monospace', backgroundColor: '#f4f6fb', color: '#1a1f2e' }} />
        <Chip label={`${totalMs}ms total`} size="small"
          sx={{ height: 20, fontSize: '0.62rem', fontFamily: 'monospace', backgroundColor: 'rgba(78,92,237,0.10)', color: '#4e5ced' }} />
        <Chip label={`${interesting} interesting`} size="small"
          sx={{ height: 20, fontSize: '0.62rem', fontFamily: 'monospace', fontWeight: 700,
                backgroundColor: interesting > 0 ? 'rgba(76,175,80,0.15)' : 'rgba(138,147,166,0.15)',
                color: interesting > 0 ? '#4caf50' : '#8a93a6' }} />
        {targetHint && (
          <Chip label={`target ${targetHint}`} size="small"
            sx={{ height: 20, fontSize: '0.62rem', fontFamily: 'monospace', backgroundColor: '#f4f6fb', color: '#1a1f2e' }} />
        )}
      </Box>

      {/* Top-3 variant strip — shown even when collapsed */}
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5, mb: expanded ? 1 : 0 }}>
        {results.slice(0, expanded ? 12 : 3).map((r, i) => {
          const novelty = r.novelty_score ?? 0;
          const verdictColor = VERDICT_COLORS[(r.oracle_verdict || '').toLowerCase()] ?? '#8a93a6';
          return (
            <Box key={i} sx={{
              display: 'flex', alignItems: 'center', gap: 1, py: 0.5, px: 1,
              borderRadius: 1, backgroundColor: novelty >= 0.5 ? 'rgba(124,77,255,0.06)' : '#fafbfc',
              borderLeft: `3px solid ${novelty >= 1 ? '#7c4dff' : novelty >= 0.5 ? '#bda4ff' : '#dfe3ec'}`,
            }}>
              <Typography sx={{ fontSize: '0.7rem', fontFamily: 'monospace', color: '#1a1f2e', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flexGrow: 1 }}>
                <strong>{r.name || `v${i + 1}`}</strong>
                {r.stdout_head && <span style={{ color: '#5a6478' }}> · {r.stdout_head.replace(/\s+/g, ' ').substring(0, 80)}</span>}
              </Typography>
              <Chip label={`novelty ${novelty.toFixed(2)}`} size="small"
                sx={{ height: 16, fontSize: '0.58rem', fontFamily: 'monospace',
                      backgroundColor: novelty >= 0.5 ? 'rgba(124,77,255,0.15)' : 'rgba(138,147,166,0.10)',
                      color: novelty >= 0.5 ? '#7c4dff' : '#8a93a6', fontWeight: 700 }} />
              {r.oracle_verdict && r.oracle_verdict !== 'no_oracle' && (
                <Chip label={r.oracle_verdict} size="small"
                  sx={{ height: 16, fontSize: '0.58rem', fontFamily: 'monospace',
                        backgroundColor: `${verdictColor}1a`, color: verdictColor, fontWeight: 700 }} />
              )}
              <Typography sx={{ fontSize: '0.6rem', fontFamily: 'monospace', color: '#8a93a6', minWidth: 28, textAlign: 'right' }}>
                {r.stdout_len ?? 0}b
              </Typography>
            </Box>
          );
        })}
        {!expanded && results.length > 3 && (
          <Typography sx={{ fontSize: '0.65rem', color: '#5a6478', fontFamily: 'monospace', pl: 1 }}>
            … and {results.length - 3} more (expand to view)
          </Typography>
        )}
      </Box>

      <Box sx={{ borderRadius: 1.5, overflow: 'hidden', border: '1px solid rgba(30,41,60,0.10)' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', px: 1.25, py: 0.5, backgroundColor: '#1a1f2e' }}>
          <Typography sx={{ flexGrow: 1, fontSize: '0.65rem', color: '#c3cad7', fontFamily: 'monospace', fontWeight: 600 }}>
            {expanded ? '▼ Template' : '▶ Template'} ({lang}) · {template.length} chars
          </Typography>
          <Tooltip title="Copy template">
            <IconButton size="small" onClick={(e) => { e.stopPropagation(); copyToClipboard(template); }} sx={{ color: '#c3cad7', p: 0.25 }}>
              <ContentCopyIcon sx={{ fontSize: 13 }} />
            </IconButton>
          </Tooltip>
          <IconButton size="small" onClick={onToggle} sx={{ color: '#c3cad7', p: 0.25 }}>
            {expanded ? <ExpandLessIcon sx={{ fontSize: 16 }} /> : <ExpandMoreIcon sx={{ fontSize: 16 }} />}
          </IconButton>
        </Box>
        <Collapse in={expanded}>
          <Box component="pre" sx={{
            m: 0, px: 1.5, py: 1, backgroundColor: '#0f1320', color: '#dfe3ec',
            fontSize: '0.7rem', fontFamily: 'monospace', overflow: 'auto', maxHeight: 240, whiteSpace: 'pre',
          }}>
            {template || '(no template captured)'}
          </Box>
          <Box sx={{ px: 1.25, py: 0.5, backgroundColor: '#1a1f2e', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
            <Typography sx={{ fontSize: '0.65rem', color: '#c3cad7', fontFamily: 'monospace', fontWeight: 600 }}>
              ▼ Variants spec
            </Typography>
          </Box>
          <Box component="pre" sx={{
            m: 0, px: 1.5, py: 1, backgroundColor: '#0f1320', color: '#dfe3ec',
            fontSize: '0.65rem', fontFamily: 'monospace', overflow: 'auto', maxHeight: 200, whiteSpace: 'pre',
          }}>
            {variantsRaw}
          </Box>
        </Collapse>
      </Box>
    </>
  );
};

const GenericCard: React.FC<{ t: ToolOutput; expanded: boolean; onToggle: () => void }> = ({ t, expanded, onToggle }) => {
  const params = (t.params || {}) as Record<string, unknown>;
  const parsed = (t.parsed_output || {}) as Record<string, unknown>;
  const verdict = (parsed.oracle_verdict as string | undefined) || (parsed.verdict as string | undefined);
  const ok = parsed.ok as boolean | undefined;
  return (
    <>
      <Box sx={{ display: 'flex', gap: 0.75, mb: 1, flexWrap: 'wrap', alignItems: 'center' }}>
        {ok != null && (
          <Chip
            icon={ok ? <CheckCircleIcon sx={{ fontSize: '12px !important', color: '#4caf50 !important' }} />
                     : <CancelIcon sx={{ fontSize: '12px !important', color: '#f44336 !important' }} />}
            label={ok ? 'ok' : 'failed'} size="small"
            sx={{ height: 20, fontSize: '0.62rem', fontFamily: 'monospace', fontWeight: 700,
                  backgroundColor: ok ? 'rgba(76,175,80,0.15)' : 'rgba(244,67,54,0.15)',
                  color: ok ? '#4caf50' : '#f44336' }} />
        )}
        <VerdictPill verdict={verdict} />
      </Box>
      <Box sx={{ borderRadius: 1.5, overflow: 'hidden', border: '1px solid rgba(30,41,60,0.10)' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', px: 1.25, py: 0.5, backgroundColor: '#1a1f2e' }}>
          <Typography sx={{ flexGrow: 1, fontSize: '0.65rem', color: '#c3cad7', fontFamily: 'monospace', fontWeight: 600 }}>
            {expanded ? '▼ Params' : '▶ Params'}
          </Typography>
          <IconButton size="small" onClick={onToggle} sx={{ color: '#c3cad7', p: 0.25 }}>
            {expanded ? <ExpandLessIcon sx={{ fontSize: 16 }} /> : <ExpandMoreIcon sx={{ fontSize: 16 }} />}
          </IconButton>
        </Box>
        <Collapse in={expanded}>
          <Box component="pre" sx={{
            m: 0, px: 1.5, py: 1, backgroundColor: '#0f1320', color: '#dfe3ec',
            fontSize: '0.7rem', fontFamily: 'monospace', overflow: 'auto', maxHeight: 220, whiteSpace: 'pre',
          }}>
            {JSON.stringify(params, null, 2)}
          </Box>
        </Collapse>
      </Box>
    </>
  );
};

const SandboxPanel: React.FC<Props> = ({ toolOutputs, sessionStatus, iterationCount, hypothesisCount }) => {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState<'all' | 'swarm' | 'forge' | 'wins'>('all');

  const sandboxOutputs = useMemo(() => toolOutputs.filter(t => SANDBOX_TOOLS.has(t.tool_name)), [toolOutputs]);

  const filtered = useMemo(() => {
    return sandboxOutputs.filter(t => {
      if (filter === 'all') return true;
      if (filter === 'swarm') return t.tool_name === 'payload_swarm';
      if (filter === 'forge') return t.tool_name === 'forge_runner';
      if (filter === 'wins') {
        const p = (t.parsed_output || {}) as Record<string, unknown>;
        const v = (p.oracle_verdict as string | undefined) || '';
        if (v.toLowerCase() === 'pass') return true;
        const interesting = (p.interesting_count as number | undefined) ?? 0;
        return interesting > 0;
      }
      return true;
    });
  }, [sandboxOutputs, filter]);

  const counts = useMemo(() => {
    const c = { total: sandboxOutputs.length, swarm: 0, forge: 0, wins: 0, variants: 0 };
    for (const t of sandboxOutputs) {
      if (t.tool_name === 'payload_swarm') c.swarm += 1;
      if (t.tool_name === 'forge_runner') c.forge += 1;
      const p = (t.parsed_output || {}) as Record<string, unknown>;
      const v = (p.oracle_verdict as string | undefined) || '';
      if (v.toLowerCase() === 'pass') c.wins += 1;
      const interesting = (p.interesting_count as number | undefined) ?? 0;
      if (interesting > 0) c.wins += interesting;
      c.variants += (p.variant_count as number | undefined) ?? 0;
    }
    return c;
  }, [sandboxOutputs]);

  const toggle = (id: string) => {
    setExpanded(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  if (sandboxOutputs.length === 0) {
    return (
      <EmptyTabState
        icon={<AutoAwesomeIcon sx={{ fontSize: 36 }} />}
        title="The sandbox is quiet."
        trigger="A card appears here for every forge_runner / payload_swarm / ai_request_forge / instrument_trace / crypto_* invocation. The agent writes them when it wants to test a custom payload — typically once it has gathered enough recon to form a concrete hypothesis."
        sessionStatus={sessionStatus}
        counters={[
          { label: 'iterations', value: iterationCount ?? 0 },
          { label: 'hypotheses', value: hypothesisCount ?? 0 },
          { label: 'tool calls', value: toolOutputs.length },
        ]}
      />
    );
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', flexGrow: 1, minHeight: 0 }}>
      {/* Header strip */}
      <Box sx={{ px: 2, py: 1.25, borderBottom: '1px solid rgba(30,41,60,0.06)', flexShrink: 0 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 1, flexWrap: 'wrap' }}>
          <Box>
            <Typography sx={{ fontSize: '0.7rem', color: '#8a93a6', textTransform: 'uppercase', letterSpacing: 0.5 }}>Invocations</Typography>
            <Typography sx={{ fontSize: '1.4rem', color: '#1a1f2e', fontWeight: 700, lineHeight: 1.1 }}>{counts.total}</Typography>
          </Box>
          <Box>
            <Typography sx={{ fontSize: '0.7rem', color: '#8a93a6', textTransform: 'uppercase', letterSpacing: 0.5 }}>Swarms</Typography>
            <Typography sx={{ fontSize: '1.4rem', color: '#7c4dff', fontWeight: 700, lineHeight: 1.1 }}>{counts.swarm}</Typography>
          </Box>
          <Box>
            <Typography sx={{ fontSize: '0.7rem', color: '#8a93a6', textTransform: 'uppercase', letterSpacing: 0.5 }}>Variants tested</Typography>
            <Typography sx={{ fontSize: '1.4rem', color: '#4e5ced', fontWeight: 700, lineHeight: 1.1 }}>{counts.variants}</Typography>
          </Box>
          <Box>
            <Typography sx={{ fontSize: '0.7rem', color: '#8a93a6', textTransform: 'uppercase', letterSpacing: 0.5 }}>Hits</Typography>
            <Typography sx={{ fontSize: '1.4rem', color: '#4caf50', fontWeight: 700, lineHeight: 1.1 }}>{counts.wins}</Typography>
          </Box>
        </Box>
        <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
          {([
            { key: 'all',   label: `All (${counts.total})` },
            { key: 'swarm', label: `payload_swarm (${counts.swarm})` },
            { key: 'forge', label: `forge_runner (${counts.forge})` },
            { key: 'wins',  label: `Hits (${counts.wins})` },
          ] as const).map(opt => (
            <Chip
              key={opt.key}
              label={opt.label}
              clickable
              onClick={() => setFilter(opt.key)}
              size="small"
              sx={{
                height: 22, fontSize: '0.7rem', fontFamily: 'monospace',
                backgroundColor: filter === opt.key ? 'rgba(78,92,237,0.15)' : '#f4f6fb',
                color: filter === opt.key ? '#4e5ced' : '#5a6478',
                fontWeight: filter === opt.key ? 700 : 400,
                border: filter === opt.key ? '1px solid rgba(78,92,237,0.4)' : '1px solid transparent',
              }}
            />
          ))}
        </Box>
      </Box>

      {/* Cards */}
      <Box sx={{ flexGrow: 1, overflowY: 'auto', backgroundColor: '#fafbfc', p: 2 }}>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5, maxWidth: 880, mx: 'auto' }}>
          {filtered.map((t, idx) => {
            const id = t.id || `${t.tool_name}-${t.timestamp}-${idx}`;
            const isExpanded = expanded.has(id);
            const accent = TOOL_ACCENT[t.tool_name] || '#5a6478';
            const headline = TOOL_HEADLINE[t.tool_name] || t.tool_name;
            return (
              <Box key={id} sx={{
                p: 1.5,
                backgroundColor: '#ffffff',
                borderRadius: 2,
                borderLeft: `3px solid ${accent}`,
                boxShadow: '0 1px 3px rgba(0,0,0,0.04)',
              }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.75 }}>
                  <Typography sx={{ flexGrow: 1, fontSize: '0.85rem', color: '#1a1f2e', fontWeight: 700 }}>
                    {headline}
                  </Typography>
                  <Typography sx={{ fontSize: '0.65rem', color: '#8a93a6', fontFamily: 'monospace' }}>
                    {t.tool_name}
                  </Typography>
                  <Typography sx={{ fontSize: '0.65rem', color: '#8a93a6', fontFamily: 'monospace' }}>
                    {safeTime(t.timestamp)}
                  </Typography>
                  {t.duration_seconds != null && (
                    <Typography sx={{ fontSize: '0.65rem', color: '#8a93a6', fontFamily: 'monospace' }}>
                      {t.duration_seconds.toFixed(1)}s
                    </Typography>
                  )}
                </Box>
                {t.tool_name === 'forge_runner' && (
                  <ForgeCard t={t} expanded={isExpanded} onToggle={() => toggle(id)} />
                )}
                {t.tool_name === 'payload_swarm' && (
                  <SwarmCard t={t} expanded={isExpanded} onToggle={() => toggle(id)} />
                )}
                {t.tool_name !== 'forge_runner' && t.tool_name !== 'payload_swarm' && (
                  <GenericCard t={t} expanded={isExpanded} onToggle={() => toggle(id)} />
                )}
              </Box>
            );
          })}
        </Box>
      </Box>
    </Box>
  );
};

export default SandboxPanel;

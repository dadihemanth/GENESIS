import React, { useEffect, useState, useCallback } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  Button,
  Chip,
  CircularProgress,
  Skeleton,
  Tooltip,
  Snackbar,
  Alert,
  Divider,
} from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import RadarIcon from '@mui/icons-material/Radar';
import LanguageIcon from '@mui/icons-material/Language';
import LockIcon from '@mui/icons-material/Lock';
import KeyIcon from '@mui/icons-material/Key';
import WindowIcon from '@mui/icons-material/Window';
import CodeIcon from '@mui/icons-material/Code';
import ScienceIcon from '@mui/icons-material/Science';
import HubIcon from '@mui/icons-material/Hub';
import MemoryIcon from '@mui/icons-material/Memory';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import AutoAwesomeIcon from '@mui/icons-material/AutoAwesome';
import ShieldIcon from '@mui/icons-material/Shield';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';

import { toolsApi } from '../services/api';
import StatusChip from '../components/StatusChip';
import ToolDetailDialog from '../components/ToolDetailDialog';
import type { ToolInfo } from '../types';

// ── Category definitions ─────────────────────────────────────────────────────

interface Category {
  id: string;
  label: string;
  icon: React.ReactNode;
  tools: string[];
}

const CATEGORIES: Category[] = [
  {
    id: 'recon',
    label: 'Reconnaissance',
    icon: <RadarIcon />,
    tools: ['nmap', 'masscan', 'amass', 'subfinder', 'dnsrecon', 'harvester', 'httpx'],
  },
  {
    id: 'web',
    label: 'Web Scanning',
    icon: <LanguageIcon />,
    tools: ['nikto', 'nuclei', 'whatweb', 'wafw00f', 'gobuster', 'feroxbuster', 'ffuf',
            'wpscan', 'xsstrike', 'sqlmap', 'commix', 'arjun', 'curl_probe'],
  },
  {
    id: 'ssl',
    label: 'SSL / TLS',
    icon: <LockIcon />,
    tools: ['sslscan', 'openssl_check'],
  },
  {
    id: 'auth',
    label: 'Authentication',
    icon: <KeyIcon />,
    tools: ['hydra', 'john'],
  },
  {
    id: 'windows',
    label: 'Windows / Active Directory',
    icon: <WindowIcon />,
    tools: ['enum4linux', 'netexec', 'impacket', 'kerbrute'],
  },
  {
    id: 'static',
    label: 'Static Analysis',
    icon: <CodeIcon />,
    tools: ['semgrep', 'bandit'],
  },
  {
    id: 'novel',
    label: 'Novel Discovery (probes)',
    icon: <AutoAwesomeIcon />,
    tools: ['oob_check', 'differential_probe', 'race_probe', 'session_memory'],
  },
  {
    id: 'http_vuln',
    label: 'HTTP Vulnerability Probes',
    icon: <ShieldIcon />,
    tools: [
      'idor_probe', 'cors_probe', 'jwt_probe', 'graphql_probe', 'ssti_detect',
      'nosql_probe', 'cache_probe', 'prototype_pollution_probe', 'oauth_probe',
      'http_smuggling_probe',
    ],
  },
  {
    id: 'ai_driven',
    label: 'AI-Driven Discovery (v2.0 / Tier-2)',
    icon: <ScienceIcon />,
    tools: [
      'ai_request_forge', 'forge_runner', 'artifact_hunter', 'artifact_pull',
      'cve_patch_pull', 'binary_decompile', 'code_read', 'render_and_see',
      'payload_crafter', 'binary_analyzer', 'code_pattern_search',
    ],
  },
  {
    id: 'frontier',
    label: 'Frontier (v2.5 / Tier-3)',
    icon: <MemoryIcon />,
    tools: ['browser_session', 'fuzz_binary', 'symbolic_exec'],
  },
  {
    id: 'crypto',
    label: 'Crypto Primitive Library (v5.0 / Tier 7 / T26)',
    icon: <VpnKeyIcon />,
    tools: [
      'crypto_padding_oracle', 'crypto_bleichenbacher', 'crypto_ecdsa_nonce_reuse',
      'crypto_length_extension', 'crypto_rsa_low_e', 'crypto_lattice',
      'crypto_jwt_confusion',
    ],
  },
  {
    id: 'graph',
    label: 'Cross-Session Graph (v5.0 / Tier 7 / T21)',
    icon: <HubIcon />,
    tools: ['graph_query'],
  },
  {
    id: 'instrument',
    label: 'Runtime Instrumentation + Differential Fuzz (v5.0 / Tier 7 / T24, T25)',
    icon: <MemoryIcon />,
    tools: ['instrument_trace', 'fuzz_differential'],
  },
  {
    id: 'swarm',
    label: 'Parallel Variant Runner (v5.0 / Tier 7 / T28)',
    icon: <AutoAwesomeIcon />,
    tools: ['payload_swarm'],
  },
  // ── v5.0 Wave 1 — Novelty Engine ─────────────────────────────────────────
  {
    id: 'wave1_novelty',
    label: 'Novelty Engine (v5.0 / T29, T31)',
    icon: <AutoAwesomeIcon />,
    tools: ['http_diff_probe', 'semantic_anomaly_grader'],
  },
  // ── v5.0 Wave 2 — Parser Differential Probes ─────────────────────────────
  {
    id: 'wave2_parser',
    label: 'Parser Differential Probes (v5.0 / T32–T36)',
    icon: <CodeIcon />,
    tools: ['url_parser_diff', 'json_parser_diff', 'unicode_diff_probe', 'multipart_diff_probe', 'charset_confusion_probe'],
  },
  // ── v5.0 Wave 3 — HTTP Modern Protocol Probes ────────────────────────────
  {
    id: 'wave3_http',
    label: 'HTTP Modern Protocol Probes (v5.0 / T37–T39)',
    icon: <LanguageIcon />,
    tools: ['h2_smuggle_probe', 'method_confusion_probe', 'range_trailer_probe'],
  },
  // ── v5.0 Wave 4 — Deserialisation Gadget Arsenal ─────────────────────────
  {
    id: 'wave4_deserial',
    label: 'Deserialisation Gadget Arsenal (v5.0 / T40–T45)',
    icon: <MemoryIcon />,
    tools: ['java_deserial_probe', 'dotnet_deserial_probe', 'php_deserial_probe', 'python_deserial_probe', 'ruby_deserial_probe', 'node_proto_to_gadget'],
  },
  // ── v5.0 Wave 5 — Upload Pipelines & SSRF ────────────────────────────────
  {
    id: 'wave5_upload',
    label: 'Upload Pipelines & SSRF Expansion (v5.0 / T46–T50)',
    icon: <ShieldIcon />,
    tools: ['upload_polyglot_probe', 'image_parser_probe', 'ssrf_scheme_probe', 'cloud_imds_probe', 'dns_rebind_probe'],
  },
  // ── v5.0 Wave 6 — State-Aware Fuzzing ────────────────────────────────────
  {
    id: 'wave6_stateful',
    label: 'State-Aware Fuzzing (v5.0 / T51–T53)',
    icon: <ScienceIcon />,
    tools: ['flow_recorder', 'flow_fuzzer', 'race_probe_h2_singlepacket'],
  },
  // ── v5.0 Wave 7 — Auth / SSO Depth ───────────────────────────────────────
  {
    id: 'wave7_auth',
    label: 'Auth / SSO Depth (v5.0 / T54–T56)',
    icon: <VpnKeyIcon />,
    tools: ['saml_xsw_probe', 'cookie_prefix_probe', 'cswsh_probe'],
  },
  // ── v5.0 Wave 8 — Browser-Side / DOM ─────────────────────────────────────
  {
    id: 'wave8_dom',
    label: 'Browser-Side / DOM (v5.0 / T57–T61)',
    icon: <LanguageIcon />,
    tools: ['dom_clobber_probe', 'postmessage_probe', 'mxss_probe', 'csp_bypass_probe', 'xsleaks_probe'],
  },
  // ── v5.0 Wave 9 — Templates / DB / LDAP ──────────────────────────────────
  {
    id: 'wave9_template',
    label: 'Templates / DB / LDAP Depth (v5.0 / T62–T64)',
    icon: <CodeIcon />,
    tools: ['ssti_gadget_probe', 'ldap_inject_probe', 'second_order_sqli_probe'],
  },
  // ── v5.0 Wave 10 — DoS / Algorithmic Complexity ──────────────────────────
  {
    id: 'wave10_dos',
    label: 'DoS / Algorithmic Complexity (v5.0 / T65–T66)',
    icon: <MemoryIcon />,
    tools: ['redos_probe', 'bomb_probe'],
  },
  // ── v5.0 Wave 11 — LLM / Agentic Endpoints ───────────────────────────────
  {
    id: 'wave11_llm',
    label: 'LLM / Agentic Endpoints (v5.0 / T67–T69)',
    icon: <AutoAwesomeIcon />,
    tools: ['llm_inject_probe', 'indirect_inject_probe', 'rag_poison_probe'],
  },
  // ── v5.0 Wave 12 — Non-HTTP Services ─────────────────────────────────────
  {
    id: 'wave12_nonhttp',
    label: 'Non-HTTP Services (v5.0 / T70–T73)',
    icon: <HubIcon />,
    tools: ['redis_probe', 'grpc_probe', 'db_wire_probe', 'mqtt_amqp_probe'],
  },
  // ── v5.0 Wave 13 — AD / Kill-Chain Completion ────────────────────────────
  {
    id: 'wave13_ad',
    label: 'AD / Kill-Chain Completion (v5.0 / T75–T79)',
    icon: <WindowIcon />,
    tools: ['bloodhound_collect', 'password_spray_cred', 'pivot_socks_pth', 'dlp_exfil_probe', 'killchain_probe'],
  },
  // ── v6.0 Tier-8 Fingerprinting & Replica (T121–T124) ─────────────────────
  {
    id: 'v6_fingerprint',
    label: 'Blackbox Fingerprinting & Replica (v6.0 / Tier 8 / T121–T124)',
    icon: <ScienceIcon />,
    tools: ['behavioral_fingerprint', 'spawn_replica', 'teardown_replica', 'timing_oracle_memory', 'cross_component_diff'],
  },
  // ── v6.0 Tier-8 IoT / Mobile / OT / Embedded Specialists ────────────────
  {
    id: 'v6_iot',
    label: 'IoT Specialist (v6.0 / Tier 8 / T137)',
    icon: <HubIcon />,
    tools: ['upnp_probe', 'ble_probe', 'default_cred_spray'],
  },
  {
    id: 'v6_mobile',
    label: 'Mobile Specialist (v6.0 / Tier 8 / T138)',
    icon: <LanguageIcon />,
    tools: ['apk_analyzer', 'frida_hook_mobile', 'deeplink_probe', 'ssl_pinning_bypass'],
  },
  {
    id: 'v6_ot',
    label: 'OT/ICS Specialist (v6.0 / Tier 8 / T139)',
    icon: <MemoryIcon />,
    tools: ['modbus_probe', 'dnp3_probe', 's7comm_probe', 'bacnet_probe'],
  },
  {
    id: 'v6_embedded',
    label: 'Embedded Specialist (v6.0 / Tier 8 / T140)',
    icon: <CodeIcon />,
    tools: ['secure_boot_analyzer', 'uart_probe'],
  },
];

// ── Status dot colour ─────────────────────────────────────────────────────────

const statusDotColor = (status: string): string => {
  if (status === 'available') return '#4caf50';
  if (status === 'missing') return '#f44336';
  return '#ff9800';
};

// ── Tool card ─────────────────────────────────────────────────────────────────

const ToolCard: React.FC<{ tool: ToolInfo; onClick: () => void }> = ({ tool, onClick }) => (
  <Card
    onClick={onClick}
    sx={{
      height: '100%',
      position: 'relative',
      cursor: 'pointer',
      transition: 'box-shadow 150ms ease, transform 150ms ease, border-color 150ms ease',
      border: '1px solid transparent',
      '&:hover': {
        boxShadow: '0 4px 16px rgba(78,92,237,0.18)',
        borderColor: 'rgba(78,92,237,0.35)',
        transform: 'translateY(-1px)',
      },
    }}
  >
    <Box
      sx={{
        position: 'absolute',
        top: 12,
        right: 12,
        width: 9,
        height: 9,
        borderRadius: '50%',
        backgroundColor: statusDotColor(tool.status),
        boxShadow: tool.status === 'available' ? `0 0 7px ${statusDotColor(tool.status)}` : 'none',
      }}
    />
    {/* Click affordance — the chevron only shows on hover */}
    <OpenInNewIcon
      sx={{
        position: 'absolute', top: 36, right: 12, fontSize: 14, color: '#4e5ced',
        opacity: 0, transition: 'opacity 150ms ease',
        '.MuiCard-root:hover &': { opacity: 0.7 },
      }}
    />

    <CardContent sx={{ p: 2.5 }}>
      <Typography
        variant="subtitle1"
        sx={{
          fontWeight: 700,
          color: '#1a1f2e',
          mb: 0.5,
          fontFamily: 'monospace',
          pr: 2,
          fontSize: '0.9rem',
        }}
      >
        {tool.name}
      </Typography>

      {tool.version && (
        <Chip
          label={tool.version.split('\n')[0].substring(0, 30)}
          size="small"
          sx={{
            backgroundColor: 'rgba(78,92,237,0.10)',
            color: '#4e5ced',
            fontFamily: 'monospace',
            fontSize: '0.6rem',
            height: 18,
            mb: 1,
            maxWidth: '100%',
          }}
        />
      )}

      <Typography
        variant="body2"
        sx={{
          color: '#8a93a6',
          fontSize: '0.78rem',
          lineHeight: 1.5,
          mb: 2,
          minHeight: 36,
          display: '-webkit-box',
          WebkitLineClamp: 2,
          WebkitBoxOrient: 'vertical',
          overflow: 'hidden',
        }}
      >
        {tool.description || 'Security assessment tool'}
      </Typography>

      <StatusChip status={tool.status} />
    </CardContent>
  </Card>
);

const ToolCardSkeleton: React.FC = () => (
  <Card>
    <CardContent sx={{ p: 2.5 }}>
      <Skeleton variant="text" width="60%" height={22} sx={{ mb: 0.5 }} />
      <Skeleton variant="text" width="35%" height={18} sx={{ mb: 1 }} />
      <Skeleton variant="text" width="90%" height={15} />
      <Skeleton variant="text" width="75%" height={15} sx={{ mb: 2 }} />
      <Skeleton variant="rectangular" width={80} height={22} sx={{ borderRadius: 4 }} />
    </CardContent>
  </Card>
);

// ── Main page ─────────────────────────────────────────────────────────────────

const ToolsStatus: React.FC = () => {
  const [tools, setTools] = useState<ToolInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState('');
  const [testing, setTesting] = useState(false);
  const [selectedTool, setSelectedTool] = useState<ToolInfo | null>(null);
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false, message: '', severity: 'success',
  });

  const fetchTools = useCallback(async () => {
    setLoading(true);
    setFetchError('');
    try {
      const result = await toolsApi.list();
      setTools(result);
    } catch (err) {
      setFetchError(err instanceof Error ? err.message : 'Failed to load tools — is the MCP server running?');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchTools(); }, [fetchTools]);

  const handleTestAll = async () => {
    setTesting(true);
    try {
      const result = await toolsApi.testAll();
      setTools(result);
      setSnackbar({ open: true, message: 'All tools tested', severity: 'success' });
    } catch (err) {
      setSnackbar({ open: true, message: err instanceof Error ? err.message : 'Test failed', severity: 'error' });
    } finally {
      setTesting(false);
    }
  };

  const toolMap = Object.fromEntries(tools.map(t => [t.name, t]));
  const available = tools.filter(t => t.status === 'available').length;
  const missing = tools.filter(t => t.status === 'missing').length;
  const errored = tools.filter(t => t.status === 'error').length;

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', mb: 3, flexWrap: 'wrap', gap: 2 }}>
        <Box>
          <Typography variant="h4" sx={{ mb: 0.5, color: '#1a1f2e' }}>
            Tools Status
          </Typography>
          <Typography sx={{ color: '#8a93a6', fontSize: '0.78rem', mb: 1 }}>
            Click any tool to see what it is, why it's used, an example attack, and an analogy.
          </Typography>
          {!loading && tools.length > 0 && (
            <Box sx={{ display: 'flex', gap: 2.5, flexWrap: 'wrap' }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
                <CheckCircleIcon sx={{ color: '#4caf50', fontSize: 17 }} />
                <Typography sx={{ color: '#4caf50', fontWeight: 700, fontFamily: 'monospace', fontSize: '0.9rem' }}>
                  {available}
                </Typography>
                <Typography sx={{ color: '#8a93a6', fontSize: '0.82rem' }}>Operational</Typography>
              </Box>
              {missing > 0 && (
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
                  <Box sx={{ width: 9, height: 9, borderRadius: '50%', backgroundColor: '#f44336' }} />
                  <Typography sx={{ color: '#f44336', fontWeight: 700, fontFamily: 'monospace', fontSize: '0.9rem' }}>
                    {missing}
                  </Typography>
                  <Typography sx={{ color: '#8a93a6', fontSize: '0.82rem' }}>Missing</Typography>
                </Box>
              )}
              {errored > 0 && (
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
                  <Box sx={{ width: 9, height: 9, borderRadius: '50%', backgroundColor: '#ff9800' }} />
                  <Typography sx={{ color: '#ff9800', fontWeight: 700, fontFamily: 'monospace', fontSize: '0.9rem' }}>
                    {errored}
                  </Typography>
                  <Typography sx={{ color: '#8a93a6', fontSize: '0.82rem' }}>Error</Typography>
                </Box>
              )}
              <Typography sx={{ color: '#c3cad7', fontSize: '0.82rem', ml: 'auto' }}>
                {tools.length} total
              </Typography>
            </Box>
          )}
        </Box>

        <Box sx={{ display: 'flex', gap: 1.5 }}>
          <Tooltip title="Refresh tool list">
            <Button
              variant="outlined"
              color="inherit"
              size="small"
              onClick={fetchTools}
              disabled={loading}
              startIcon={<RefreshIcon />}
              sx={{ color: '#8a93a6', borderColor: '#dfe3ec', fontSize: '0.8rem' }}
            >
              Refresh
            </Button>
          </Tooltip>
          <Button
            variant="contained"
            color="primary"
            size="small"
            onClick={handleTestAll}
            disabled={testing || loading}
            startIcon={testing ? <CircularProgress size={14} color="inherit" /> : undefined}
            sx={{ fontSize: '0.8rem' }}
          >
            {testing ? 'Testing...' : 'Test All Tools'}
          </Button>
        </Box>
      </Box>

      {fetchError && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setFetchError('')}>{fetchError}</Alert>
      )}

      {/* Categories */}
      {loading ? (
        <Box>
          {CATEGORIES.map(cat => (
            <Box key={cat.id} sx={{ mb: 4 }}>
              <Skeleton variant="text" width={180} height={28} sx={{ mb: 2 }} />
              <Grid container spacing={2}>
                {[...Array(cat.tools.length > 4 ? 4 : cat.tools.length)].map((_, i) => (
                  <Grid item xs={12} sm={6} md={4} lg={3} key={i}>
                    <ToolCardSkeleton />
                  </Grid>
                ))}
              </Grid>
            </Box>
          ))}
        </Box>
      ) : tools.length === 0 ? (
        <Box sx={{ textAlign: 'center', py: 8 }}>
          <Typography variant="h6" sx={{ color: '#c3cad7', mb: 1 }}>No tools available</Typography>
          <Typography sx={{ color: '#8a93a6', fontSize: '0.875rem' }}>
            Make sure the MCP server is running and configured correctly.
          </Typography>
        </Box>
      ) : (
        CATEGORIES.map((cat, idx) => {
          const catTools = cat.tools
            .map(name => toolMap[name])
            .filter(Boolean) as ToolInfo[];

          if (catTools.length === 0) return null;

          const catAvailable = catTools.filter(t => t.status === 'available').length;
          const catMissing = catTools.filter(t => t.status === 'missing').length;

          return (
            <Box key={cat.id} sx={{ mb: idx < CATEGORIES.length - 1 ? 5 : 0 }}>
              {/* Category header */}
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 2 }}>
                <Box sx={{ color: '#4e5ced', display: 'flex', alignItems: 'center' }}>
                  {cat.icon}
                </Box>
                <Typography variant="h6" sx={{ color: '#1a1f2e', fontWeight: 600, fontSize: '0.95rem' }}>
                  {cat.label}
                </Typography>
                <Chip
                  label={`${catAvailable}/${catTools.length}`}
                  size="small"
                  sx={{
                    backgroundColor: catMissing === 0 ? 'rgba(76,175,80,0.12)' : '#dfe3ec',
                    color: catMissing === 0 ? '#4caf50' : '#5a6478',
                    fontFamily: 'monospace',
                    fontSize: '0.7rem',
                    height: 20,
                  }}
                />
              </Box>
              <Divider sx={{ mb: 2 }} />

              <Grid container spacing={2}>
                {catTools.map(tool => (
                  <Grid item xs={12} sm={6} md={4} lg={3} key={tool.name}>
                    <ToolCard tool={tool} onClick={() => setSelectedTool(tool)} />
                  </Grid>
                ))}
              </Grid>
            </Box>
          );
        })
      )}

      {/* Per-tool detail dialog (what / why / attack / analogy) */}
      <ToolDetailDialog tool={selectedTool} onClose={() => setSelectedTool(null)} />

      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
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

export default ToolsStatus;

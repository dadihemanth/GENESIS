import React from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Chip,
  Grid,
  Divider,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Alert,
} from '@mui/material';
import InfoOutlinedIcon from '@mui/icons-material/InfoOutlined';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import SecurityIcon from '@mui/icons-material/Security';
import PsychologyIcon from '@mui/icons-material/Psychology';
import PsychologyAltIcon from '@mui/icons-material/PsychologyAlt';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import BugReportIcon from '@mui/icons-material/BugReport';
import BuildIcon from '@mui/icons-material/Build';
import StorageIcon from '@mui/icons-material/Storage';
import ShieldIcon from '@mui/icons-material/Shield';
import WhatshotIcon from '@mui/icons-material/Whatshot';
import GroupsIcon from '@mui/icons-material/Groups';
import BusinessIcon from '@mui/icons-material/Business';
import HubIcon from '@mui/icons-material/Hub';

// ── ASCII Flowchart ────────────────────────────────────────────────────────
//
// The diagram intentionally compresses real services into one box per role.
// v7 additions: the Reasoning Loop Layer (between orchestrator and MCP),
// Replica Manager (T122), Threat Intel Daemon (T129–T131), and the
// loop_state MongoDB collection that persists every deliberation tick.

const FLOW = `
  ┌─────────────────────────────────────────────────────────────────────┐
  │                        SECURITY ANALYST                            │
  │        Configure target  ·  Pick scan profile  ·  Set goal         │
  └──────────────────────────────┬──────────────────────────────────────┘
                                 │  HTTPS · X-API-Key  OR  JWT bearer
                                 ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │                       REACT FRONTEND  :3000                        │
  │  Dashboard · Sessions · Vulnerabilities · Intelligence · Loops     │
  │  15-tab Session Viewer streams events live over WebSocket          │
  └──────────────────────────────┬──────────────────────────────────────┘
                                 │  REST  /api/v1  +  WS  /ws/{session}
                                 ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │                    FASTAPI BACKEND  :8000                          │
  │  Auth · Multi-tenant RBAC · Audit log · Budget tracker · Events    │
  └────────┬────────────────────────────────────────────────┬───────────┘
           │  enqueues task                                  │  persists
           ▼                                                ▼
  ┌────────────────────┐ ┌──────────────┐ ┌───────────────────────────┐
  │   REDIS  :6379     │ │  POSTGRESQL  │ │  MONGODB                  │
  │  Celery broker     │ │  sessions    │ │  tool_outputs             │
  │  WS pub/sub        │ │  vulns       │ │  agent_thoughts           │
  │  Findings bus      │ │  users       │ │  hypothesis_market        │
  │                    │ │  audit_log   │ │  loop_state  (NEW v7)     │
  └────────┬───────────┘ └──────────────┘ └───────────────────────────┘
           │  worker picks up task
           ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │                      CELERY WORKER                                  │
  │  Solo OR Multi-agent orchestrator (Recon · Analyst · Exploit · Code)│
  │  + Researcher (v5) + 5 personas (v6) + IoT/Mobile/OT/Embedded specs │
  └──────────────────────────────┬──────────────────────────────────────┘
                                 │
   ┌─────────────────────────────┼──────────────────────────────────────┐
   │            REASONING LOOP LAYER  (v7.0 / Tier-9)                   │
   │  deliberate(loop_type=...) routes to one of 12 deliberation loops:  │
   │   ├ code_intent · invariant_tracker · causal_trace · counterfactual │
   │   ├ hypothesis_decomp · long_context_code                           │
   │   ├ rop_composition · chain_composer · heap_layout · self_correcting│
   │   └ deliberation_framework + tree_of_thought (primitives)           │
   │  Hard token + tick budgets · every tick persisted to loop_state     │
   └──────────────────────────────┬──────────────────────────────────────┘
                                 │  tool calls (JSON-RPC over HTTP)
                                 ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │                    MCP TOOL SERVER  :3001                           │
  │  125+ probes across 8 editions: recon · web · exploit · code        │
  │  v3 crypto · v3 graph · v4 51-probe novelty arsenal · v5 source-aware│
  │  v6 fingerprint + IoT/Mobile/OT/Embedded specialists                │
  └──────────────────────────────┬──────────────────────────────────────┘
                                 │
       ┌─────────────────────────┼────────────────────────────────────┐
       ▼                         ▼                                    ▼
  ┌────────────┐    ┌────────────────────────────┐    ┌──────────────────┐
  │ FORGE      │    │   REPLICA MANAGER  (v6)    │    │  GHIDRA · FUZZER │
  │ SANDBOX×4  │    │  Spawns OSS replicas of    │    │  SYMBEX · CHROME │
  │ python /   │    │  detected stack (T122);    │    │  INSTRUMENTATION │
  │ node / bash│    │  destructive payloads run  │    │  Heavy lifters   │
  │ payload_   │    │  against replica BEFORE    │    │  for binaries +  │
  │ swarm fans │    │  production target.        │    │  artifacts       │
  └────────────┘    │  THREAT INTEL DAEMON       │    └──────────────────┘
                    │  ingests CVE feeds; matches│
                    │  active sessions; sameday  │
                    │  CVE replay against replica│
                    └────────────────────────────┘
                                 │  results back to orchestrator
                                 ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │                       RESULTS ENGINE                                │
  │  Vulnerability rows · Attack chains (T157 topo-sorted) · MITRE map │
  │  Causal exploit traces (T164) · Compliance reports · Patch diffs   │
  │  All events streamed live to browser via WebSocket                 │
  └──────────────────────────────┬──────────────────────────────────────┘
                                 │  on session complete
                                 ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │              INTELLIGENCE LIBRARY  (ChromaDB + Neo4j attack graph)  │
  │  STORE  → confirmed vulns + attack patterns + loop_state corpus     │
  │  RECALL → next session: "seen a target like this? successful path?" │
  │           feeds future v8 training flywheel (T167–T178)             │
  └─────────────────────────────────────────────────────────────────────┘
`;

const FlowChart: React.FC = () => (
  <Box
    component="pre"
    sx={{
      m: 0,
      p: 2.5,
      backgroundColor: '#0d0d0d',
      border: '1px solid rgba(78,92,237,0.15)',
      borderRadius: 1.5,
      overflowX: 'auto',
      fontFamily: "'Courier New', Courier, monospace",
      fontSize: '0.7rem',
      lineHeight: 1.55,
      color: '#c8e6a0',
      whiteSpace: 'pre',
    }}
  >
    {FLOW}
  </Box>
);

// ── Capability cards ───────────────────────────────────────────────────────

const capabilities = [
  {
    icon: <PsychologyAltIcon sx={{ color: '#0f7a55' }} />,
    title: 'Reasoning Loops (v7.0)',
    color: '#0f7a55',
    items: [
      '12 deliberation loops (T155–T166) dispatched via the `deliberate` tool',
      'AlphaZero analogy: loop = MCTS-style search structure, LLM = cheap evaluator',
      'Hard token + tick budgets per loop_type — see Reasoning Loops section',
      'Every tick persisted to MongoDB `loop_state` for replay + v8 training corpus',
      'New "Loops" tab in the Session Viewer streams ticks live',
    ],
  },
  {
    icon: <BugReportIcon sx={{ color: '#f44336' }} />,
    title: 'Blackbox 0-day Engine (v6.0)',
    color: '#f44336',
    items: [
      'Behavioral fingerprinter (T121) profiles target before any active probing',
      'OSS replica spawner (T122) clones the detected stack to a sandbox replica',
      'Timing oracle (T123) confirms blind exploits via response-time deltas',
      'Cross-component diff (T124) flags upstream/downstream version mismatches',
      'Expected ~70% 0-day yield on multi-day blackbox engagements',
    ],
  },
  {
    icon: <WhatshotIcon sx={{ color: '#ff9800' }} />,
    title: 'Threat Intel & Sameday CVE Replay (v6.0)',
    color: '#ff9800',
    items: [
      'Continuous CVE feed ingestion (T129) — NVD, GitHub advisories, vendor RSS',
      'CVE variant matcher (T130) maps each advisory to active sessions automatically',
      'Sameday replay (T131) fires the PoC against the OSS replica and reports verdict',
      'Confirmed-vulnerable findings flow back into the orchestrator within minutes',
    ],
  },
  {
    icon: <GroupsIcon sx={{ color: '#6840cf' }} />,
    title: 'Multi-Persona Adversarial Agents (v6.0)',
    color: '#6840cf',
    items: [
      'Five attacker personas (T135) — opportunistic, cybercrime, APT, insider, hacktivist',
      'Persona-tuned tactics + payload styles + risk tolerance',
      'Conditional specialists (T137–T140) — IoT, Mobile, OT/ICS, Embedded',
      'Specialists activate on Phase-1 surface detection (e.g. UPnP found → IoT spec)',
    ],
  },
  {
    icon: <BusinessIcon sx={{ color: '#0e7c86' }} />,
    title: 'Production-Grade Ops (v6.0)',
    color: '#0e7c86',
    items: [
      'Multi-tenant RBAC + JWT auth (T141/T142) — POST /auth/login, tenant-scoped data',
      'Immutable audit log of every privileged action',
      'SOC integrations (T143) — Slack · Jira · PagerDuty · Splunk · Teams',
      'Compliance reporter (T144) — PCI DSS · HIPAA · SOC2 · ISO27001 · NIST CSF · OWASP ASVS',
      'Budget tracker (T145) per-target USD/token/tool-call caps',
      'Event sourcing (T146) — replay any session from its event stream',
    ],
  },
  {
    icon: <PsychologyIcon sx={{ color: '#ff9800' }} />,
    title: 'Extended Thinking',
    color: '#ff9800',
    items: [
      'Adaptive thinking budget (3k–8k tokens per iteration based on session phase)',
      'Claude reasons about attack surfaces before acting',
      'Deep Thought panel surfaces internal reasoning in real time',
      'Hypothesis-driven approach: form → test → adapt',
    ],
  },
  {
    icon: <AccountTreeIcon sx={{ color: '#4e5ced' }} />,
    title: 'Attack Chain Construction',
    color: '#4e5ced',
    items: [
      'T157 chain_composer topo-sorts confirmed primitives by pre/post-conditions',
      'Persists `attack_chain_id` + `chain_position` onto every Vulnerability row',
      'Visualised as kill-chain in the Chains tab + Neo4j attack graph',
      'Each chain: entry point → exploitation → final impact, with MITRE mapping',
    ],
  },
  {
    icon: <StorageIcon sx={{ color: '#ce93d8' }} />,
    title: 'Cross-Session Intelligence',
    color: '#ce93d8',
    items: [
      'ChromaDB vector store indexes every completed session',
      'Semantic recall — "seen a target like this before?" with successful chains',
      'Neo4j attack graph (T21) — cross-session findings + relationships',
      '`loop_state` ticks are designed as v8 training corpus (T167) from day one',
    ],
  },
  {
    icon: <ShieldIcon sx={{ color: '#4e5ced' }} />,
    title: 'Patch Generation',
    color: '#4e5ced',
    items: [
      'Claude generates exact code fixes for each confirmed vulnerability',
      'Real diffs or config snippets — not generic remediation advice',
      '"View Patch" button on every vulnerability card',
      'Compliance reports map every finding to framework control IDs',
    ],
  },
];

// ── v7 reasoning loops — sourced from registry.py:30-42 ──────────────────

interface ReasoningLoop {
  loop_type: string;
  tBlock: string;
  purpose: string;
  budget: string;
  group: 'code' | 'exploit' | 'primitive';
}

const REASONING_LOOPS: ReasoningLoop[] = [
  // Code / hypothesis loops
  { loop_type: 'code_intent',       tBlock: 'T156', purpose: 'Multi-zoom intent analysis (function → file → module → cross-module → architectural). Discrepancies across zoom levels flag Heartbleed-class smells.', budget: '8k tok / 6 ticks', group: 'code' },
  { loop_type: 'invariant_tracker', tBlock: 'T163', purpose: 'Cross-component invariants graph; flags inconsistencies (e.g. role.toLowerCase() consumer vs producer that allows mixed case).',         budget: '8k tok / 8 ticks', group: 'code' },
  { loop_type: 'causal_trace',      tBlock: 'T164', purpose: 'Builds a causal exploit graph from input bytes → side effects → primitives. Optionally synced to Neo4j for explanation.',                 budget: '6k tok / 6 ticks', group: 'code' },
  { loop_type: 'counterfactual',    tBlock: 'T165', purpose: 'Multi-step "what if I had primitive X, then Y, then Z" tree. Extends the v6 T128 single-step counterfactual reasoner.',                   budget: '8k tok / 6 ticks', group: 'code' },
  { loop_type: 'hypothesis_decomp', tBlock: 'T166', purpose: 'Decomposes vague hypotheses into atomic claims; each child links to the parent in the hypothesis market for evidence accrual.',           budget: '4k tok / 5 ticks', group: 'code' },
  { loop_type: 'long_context_code', tBlock: 'T162', purpose: 'Segment-summarise-recurse harness for 1M+ token codebases. Queries descend the summary tree only into relevant subtrees.',                budget: '20k tok / 15 ticks', group: 'code' },
  // Exploit loops
  { loop_type: 'rop_composition',   tBlock: 'T155', purpose: 'Constraint-aware ROP-chain composition under a byte budget. Search → score → simulate → budget check → rewrite (multi-write strategy).', budget: '15k tok / 12 ticks', group: 'exploit' },
  { loop_type: 'chain_composer',    tBlock: 'T157', purpose: 'Orders confirmed primitives via pre/post-condition topo-sort. Persists attack_chain_id + chain_position onto each Vulnerability row.',    budget: '6k tok / 8 ticks', group: 'exploit' },
  { loop_type: 'heap_layout',       tBlock: 'T158', purpose: 'Allocator-aware shaping (glibc tcache · jemalloc · Windows LFH · musl). Predict → execute in forge_runner → observe → refine.',           budget: '12k tok / 10 ticks', group: 'exploit' },
  { loop_type: 'self_correcting',   tBlock: 'T159', purpose: 'Classifies failure (offset/primitive/allocator/aslr/defence/transport) → proposes correction → replays in sandbox until success/budget.', budget: '10k tok / 8 ticks', group: 'exploit' },
  // Framework primitives
  { loop_type: 'deliberation_framework', tBlock: 'T160', purpose: 'Meta-architecture every other loop composes: state, branching, backtracking, constraint propagation, decomposition delegation.',     budget: 'inherits caller', group: 'primitive' },
  { loop_type: 'tree_of_thought',        tBlock: 'T161', purpose: 'Branching exploration with explicit backtrack. At each decision point, generate N candidates → evaluate → commit → backtrack on dead-end.', budget: 'inherits caller', group: 'primitive' },
];

// ── Tool inventory grouped by edition ────────────────────────────────────

interface ToolEdition {
  version: string;
  tier: string;
  color: string;
  rows: Array<{ category: string; tools: string }>;
}

const TOOL_EDITIONS: ToolEdition[] = [
  {
    version: 'v1.0', tier: 'Tier-1', color: '#4fc3f7',
    rows: [
      { category: 'Recon',         tools: 'nmap · masscan · amass · subfinder · dnsrecon · harvester · httpx' },
      { category: 'Fingerprint',   tools: 'whatweb · wafw00f · sslscan · openssl_check' },
      { category: 'Web Attack',    tools: 'nuclei · nikto · gobuster · feroxbuster · ffuf · wpscan · xsstrike · sqlmap · commix · arjun' },
      { category: 'Exploit',       tools: 'curl_probe · hydra · john · enum4linux · netexec · impacket · kerbrute' },
      { category: 'Code',          tools: 'semgrep · bandit · payload_crafter · binary_analyzer · code_pattern_search' },
    ],
  },
  {
    version: 'v2.0', tier: 'Tier-2', color: '#4e5ced',
    rows: [
      { category: 'AI-Driven',     tools: 'ai_request_forge · forge_runner · artifact_hunter · artifact_pull · cve_patch_pull · binary_decompile · code_read · render_and_see' },
    ],
  },
  {
    version: 'v2.5', tier: 'Tier-3', color: '#4e5ced',
    rows: [
      { category: 'Frontier',      tools: 'browser_session · fuzz_binary · symbolic_exec' },
    ],
  },
  {
    version: 'v3.0', tier: 'Tier-5', color: '#6840cf',
    rows: [
      { category: 'Crypto',        tools: 'crypto_padding_oracle · crypto_bleichenbacher · crypto_ecdsa_nonce_reuse · crypto_length_extension · crypto_rsa_low_e · crypto_lattice · crypto_jwt_confusion' },
      { category: 'Graph (T21)',   tools: 'graph_query' },
      { category: 'Runtime (T25)', tools: 'instrument_trace' },
      { category: 'Diff fuzz (T24)', tools: 'fuzz_differential' },
      { category: 'Swarm (T28)',   tools: 'payload_swarm' },
    ],
  },
  {
    version: 'v4.0', tier: 'Tier-6', color: '#137a4e',
    rows: [
      { category: 'Novelty (51 probes / 13 waves)', tools: 'parser_diff · deserialization_gadget · upload_probe · ssrf_scheme · state_aware_fuzz · dos_probe · llm_probe · ad_killchain · oob_check · differential_probe · race_probe · session_memory · idor · cors · jwt · graphql · ssti · nosql · cache · prototype_pollution · oauth · http_smuggling · …' },
    ],
  },
  {
    version: 'v5.0', tier: 'Tier-7', color: '#0e7c86',
    rows: [
      { category: 'Source-aware (9 probes)', tools: 'repo_ingest · ast_walker · taint_engine · invariant_inferer · adversarial_synthesis · architectural_reasoner · novelty_ab_harness · attack_chain · provenance' },
    ],
  },
  {
    version: 'v6.0', tier: 'Tier-8', color: '#b53030',
    rows: [
      { category: 'Fingerprint (5)', tools: 'behavioral_fingerprinter · oss_replica_spawner · timing_oracle · cross_component_diff · stack_pin' },
      { category: 'Specialist (13)', tools: 'IoT (upnp · ble · modbus · dnp3) · Mobile (apk_analyzer · frida_hooks) · OT (siemens_s7 · ethernet_ip) · Embedded (uart · jtag · spi)' },
    ],
  },
];

// ── Production-grade ops mini-cards (v6.0) ───────────────────────────────

const PROD_OPS_CARDS = [
  {
    title: 'Multi-tenant RBAC + JWT (T141/T142)',
    color: '#0e7c86',
    desc: 'POST /auth/login exchanges email+password for a JWT scoped to a tenant. Every privileged action is appended to an immutable audit log. X-API-Key header still works for headless integrations.',
  },
  {
    title: 'SOC integrations (T143)',
    color: '#4e5ced',
    desc: 'Findings broadcast to Slack, Jira, PagerDuty, Splunk, and Microsoft Teams via the integrations API. Per-tenant routing rules; severity gates configurable per channel.',
  },
  {
    title: 'Compliance reporter (T144)',
    color: '#137a4e',
    desc: 'Generate audit-ready reports against six frameworks: PCI DSS · HIPAA · SOC2 · ISO27001 · NIST CSF · OWASP ASVS. Each finding maps to specific control IDs.',
  },
  {
    title: 'Budget tracker (T145)',
    color: '#9a6d18',
    desc: 'Per-target caps on monthly USD spend, total token consumption, and tool-call counts. Sessions auto-pause when limits are reached; operators see live spend in the Budgets tab.',
  },
  {
    title: 'Event sourcing (T146)',
    color: '#6840cf',
    desc: 'Every session produces an append-only event stream — tool calls, hypotheses, vulnerabilities, agent thoughts. The full session is replayable from events alone for forensic review.',
  },
  {
    title: 'Explainable UX (T147–T149)',
    color: '#0e7c86',
    desc: 'Explanation Panel shows why each tool was chosen + which hypothesis drove it. Hypothesis Tree visualises the confidence-staked market with parent → atomic-claim chains. Agent Chorus shows multi-agent message flow.',
  },
];

const About: React.FC = () => (
  <Box sx={{ p: 3, maxWidth: 1200 }}>
    {/* Header */}
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
      <InfoOutlinedIcon sx={{ color: '#4e5ced', fontSize: 28 }} />
      <Box>
        <Typography variant="h4" sx={{ color: '#1a1f2e', fontSize: '1.4rem', fontWeight: 700, lineHeight: 1.2 }}>
          About GENESIS
        </Typography>
        <Typography variant="caption" sx={{ color: '#8a93a6' }}>
          Autonomous Security Intelligence Platform · v7.0 · Tier 9
        </Typography>
      </Box>
      <Chip label="MYTHOS" size="small" sx={{ backgroundColor: 'rgba(244,67,54,0.15)', color: '#f44336', fontWeight: 700, ml: 1 }} />
    </Box>

    <Alert severity="warning" sx={{ mb: 2, backgroundColor: 'rgba(255,152,0,0.08)', color: '#ff9800', border: '1px solid rgba(255,152,0,0.2)', '& .MuiAlert-icon': { color: '#ff9800' } }}>
      <strong>Authorized use only.</strong> GENESIS is designed exclusively for security assessments on systems you own or have explicit written permission to test. Unauthorized scanning is illegal.
    </Alert>

    <Alert severity="info" sx={{ mb: 1.5, backgroundColor: 'rgba(78,92,237,0.08)', color: '#4e5ced', border: '1px solid rgba(78,92,237,0.20)', '& .MuiAlert-icon': { color: '#4e5ced' } }}>
      <strong>v7.0 (Tier 9) — current.</strong> Reasoning architecture &amp; custom deliberation loops.
      <Box sx={{ mt: 1, display: 'flex', flexDirection: 'column', gap: 0.5, color: '#2a3045', fontSize: '0.85rem' }}>
        <Box>• <strong>New in v7:</strong> 12 reasoning loops (T155–T166) compress search space so a generic Opus model reaches conclusions a much larger monolithic model would otherwise need. AlphaZero-style: loop = search structure, LLM = evaluator. Zero new MCP probes — every gain is reasoning-loop work.</Box>
        <Box>• <strong>Inherited from v6.0 (Tier-8):</strong> blackbox 0-day engine (T121–T124), sameday CVE replay (T129–T131), 5-persona + 4 specialist agents (T135–T140), multi-tenant RBAC (T141/T142), SOC integrations (T143), compliance reporter (T144), budget tracker (T145), event sourcing (T146), explainable UX (T147–T149), model-ops daemons (T151–T154).</Box>
        <Box>• <strong>Default model:</strong> Claude Opus 4.7 with extended thinking (~70% expected 0-day yield on multi-day blackbox engagements).</Box>
      </Box>
    </Alert>

    <Typography sx={{ mb: 3, color: '#4e5ced', fontSize: '0.82rem', fontWeight: 600 }}>
      contributor: Hemanth dadi
    </Typography>

    {/* What is GENESIS */}
    <Card sx={{ mb: 3 }}>
      <CardContent sx={{ p: 3 }}>
        <Typography variant="h6" sx={{ color: '#4e5ced', mb: 1.5, fontSize: '1rem', fontWeight: 700 }}>
          What is GENESIS?
        </Typography>
        <Typography sx={{ color: '#c0c0c0', mb: 2, lineHeight: 1.7, fontSize: '0.9rem' }}>
          GENESIS MYTHOS is an autonomous AI-powered security assessment platform. Unlike script-based scanners, GENESIS
          uses Claude's extended thinking + a 12-loop deliberation framework to reason about attack surfaces, form
          hypotheses, chain tools dynamically, and adapt strategy based on what it discovers — behaving like an elite
          red team operator.
        </Typography>
        <Typography sx={{ color: '#c0c0c0', lineHeight: 1.7, fontSize: '0.9rem' }}>
          Each session runs a free-form autonomous loop: Claude selects from 125+ MCP tools and 12 reasoning loops,
          interprets output, pivots on findings, constructs multi-step attack chains, maps techniques to MITRE ATT&amp;CK,
          and generates exact patch code for every confirmed vulnerability. Findings persist to a cross-session
          intelligence library plus a `loop_state` corpus that will feed v8's training flywheel.
        </Typography>
      </CardContent>
    </Card>

    {/* Architecture Flowchart */}
    <Card sx={{ mb: 3 }}>
      <CardContent sx={{ p: 3 }}>
        <Typography variant="h6" sx={{ color: '#4e5ced', mb: 1, fontSize: '1rem', fontWeight: 700 }}>
          Architecture &amp; Assessment Flow
        </Typography>
        <Typography sx={{ color: '#5a6478', fontSize: '0.82rem', mb: 2 }}>
          Frontend → Backend → Celery → Reasoning Loop Layer → MCP probes → Replicas → Results — with every event streamed live to the browser.
        </Typography>
        <FlowChart />
      </CardContent>
    </Card>

    {/* Capability Grid */}
    <Typography variant="h6" sx={{ color: '#1a1f2e', mb: 2, fontSize: '1rem', fontWeight: 700 }}>
      Capabilities
    </Typography>
    <Grid container spacing={2} sx={{ mb: 3 }}>
      {capabilities.map(cap => (
        <Grid item xs={12} md={6} key={cap.title}>
          <Card sx={{ height: '100%', border: `1px solid ${cap.color}18`, '&:hover': { border: `1px solid ${cap.color}40` }, transition: 'border 0.2s' }}>
            <CardContent sx={{ p: 2.5 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1.5 }}>
                {cap.icon}
                <Typography sx={{ color: '#1a1f2e', fontWeight: 700, fontSize: '0.9rem' }}>{cap.title}</Typography>
              </Box>
              <Box component="ul" sx={{ m: 0, pl: 2.5 }}>
                {cap.items.map(item => (
                  <Box component="li" key={item} sx={{ color: '#5a6478', fontSize: '0.82rem', mb: 0.5 }}>{item}</Box>
                ))}
              </Box>
            </CardContent>
          </Card>
        </Grid>
      ))}
    </Grid>

    {/* Reasoning Loops (v7.0) */}
    <Card sx={{ mb: 3, borderTop: '3px solid #0f7a55' }}>
      <CardContent sx={{ p: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1 }}>
          <PsychologyAltIcon sx={{ color: '#0f7a55' }} />
          <Typography variant="h6" sx={{ color: '#0f7a55', fontSize: '1rem', fontWeight: 700 }}>
            Reasoning Loops (v7.0 / Tier-9)
          </Typography>
          <Chip label="12 loops" size="small" sx={{ ml: 'auto', backgroundColor: 'rgba(15,122,85,0.15)', color: '#0f7a55', fontSize: '0.7rem', fontWeight: 700 }} />
        </Box>
        <Typography sx={{ color: '#5a6478', fontSize: '0.82rem', mb: 2.5 }}>
          A loop that compresses a 10,000-token reasoning task into ten 1,000-token turns lets a generic Opus model reach conclusions a 10× larger monolithic model would otherwise need. AlphaZero-style: <strong style={{ color: '#0f7a55' }}>the loop is the search structure, the LLM is the evaluator</strong>. Every tick persists to MongoDB `loop_state` and broadcasts on the Loops tab.
        </Typography>

        {(['code', 'exploit', 'primitive'] as const).map(group => {
          const groupLabel = group === 'code'      ? 'Code & Hypothesis loops'
                            : group === 'exploit' ? 'Exploit loops'
                            : 'Framework primitives';
          const groupColor = group === 'code'      ? '#0e7c86'
                            : group === 'exploit' ? '#b53030'
                            : '#6840cf';
          const groupLoops = REASONING_LOOPS.filter(l => l.group === group);
          return (
            <Box key={group} sx={{ mb: 2 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1.2 }}>
                <Box sx={{ width: 4, height: 14, backgroundColor: groupColor, borderRadius: 0.5 }} />
                <Typography sx={{ color: groupColor, fontSize: '0.78rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.6 }}>
                  {groupLabel}
                </Typography>
                <Chip label={`${groupLoops.length}`} size="small"
                  sx={{ height: 18, backgroundColor: `${groupColor}15`, color: groupColor, fontSize: '0.65rem', fontWeight: 700 }} />
              </Box>
              <Grid container spacing={1.5}>
                {groupLoops.map(loop => (
                  <Grid item xs={12} sm={6} md={4} key={loop.loop_type}>
                    <Box sx={{ p: 1.5, border: `1px solid ${groupColor}25`, borderRadius: 1.5, backgroundColor: `${groupColor}05`, height: '100%' }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.6 }}>
                        <Chip label={loop.tBlock} size="small"
                          sx={{ height: 16, backgroundColor: `${groupColor}20`, color: groupColor, fontSize: '0.62rem', fontWeight: 700, fontFamily: 'monospace' }} />
                        <Typography sx={{ color: '#1a1f2e', fontWeight: 700, fontSize: '0.78rem', fontFamily: 'monospace' }}>
                          {loop.loop_type}
                        </Typography>
                      </Box>
                      <Typography sx={{ color: '#5a6478', fontSize: '0.74rem', lineHeight: 1.55, mb: 0.6 }}>
                        {loop.purpose}
                      </Typography>
                      <Typography sx={{ color: groupColor, fontSize: '0.68rem', fontFamily: 'monospace', fontWeight: 600 }}>
                        {loop.budget}
                      </Typography>
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </Box>
          );
        })}

        <Box sx={{ mt: 2, p: 1.5, backgroundColor: 'rgba(15,122,85,0.04)', borderRadius: 1, border: '1px solid rgba(15,122,85,0.15)' }}>
          <Typography sx={{ color: '#0f7a55', fontSize: '0.78rem', fontWeight: 700, mb: 0.4 }}>
            Why structured loops beat a single forward pass
          </Typography>
          <Typography sx={{ color: '#5a6478', fontSize: '0.78rem', lineHeight: 1.55 }}>
            AlphaZero plays better Go than any human despite a network that, alone, would be merely strong-amateur — the trick is MCTS-style search exploring branches plus a cheap evaluator scoring each. v7's loops are the same template: the loop is the search structure, the LLM is the evaluator. Loop structure substitutes for reasoning depth within the loop's domain.
          </Typography>
        </Box>
      </CardContent>
    </Card>

    {/* Production Engineering (v6.0) */}
    <Card sx={{ mb: 3, borderTop: '3px solid #0e7c86' }}>
      <CardContent sx={{ p: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1 }}>
          <BusinessIcon sx={{ color: '#0e7c86' }} />
          <Typography variant="h6" sx={{ color: '#0e7c86', fontSize: '1rem', fontWeight: 700 }}>
            Production Engineering (v6.0 / Tier-8)
          </Typography>
          <Chip label="6 systems" size="small" sx={{ ml: 'auto', backgroundColor: 'rgba(14,124,134,0.15)', color: '#0e7c86', fontSize: '0.7rem', fontWeight: 700 }} />
        </Box>
        <Typography sx={{ color: '#5a6478', fontSize: '0.82rem', mb: 2 }}>
          What turns GENESIS from a research engine into something a SOC can actually deploy at scale.
        </Typography>
        <Grid container spacing={1.5}>
          {PROD_OPS_CARDS.map(card => (
            <Grid item xs={12} md={6} key={card.title}>
              <Box sx={{ p: 1.8, border: `1px solid ${card.color}25`, borderRadius: 1.5, height: '100%' }}>
                <Typography sx={{ color: card.color, fontWeight: 700, fontSize: '0.85rem', mb: 0.6 }}>{card.title}</Typography>
                <Typography sx={{ color: '#5a6478', fontSize: '0.78rem', lineHeight: 1.55 }}>{card.desc}</Typography>
              </Box>
            </Grid>
          ))}
        </Grid>
      </CardContent>
    </Card>

    {/* Tool Inventory */}
    <Card sx={{ mb: 3 }}>
      <CardContent sx={{ p: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1 }}>
          <BuildIcon sx={{ color: '#4e5ced' }} />
          <Typography variant="h6" sx={{ color: '#4e5ced', fontSize: '1rem', fontWeight: 700 }}>
            Tool Inventory
          </Typography>
          <Chip label="125+ MCP probes · 8 editions" size="small" sx={{ ml: 'auto', backgroundColor: 'rgba(78,92,237,0.12)', color: '#4e5ced', fontSize: '0.7rem', fontWeight: 700 }} />
        </Box>
        <Typography sx={{ color: '#5a6478', fontSize: '0.78rem', mb: 2 }}>
          v7.0 deliberately adds zero new MCP probes — every gain is reasoning-loop work. Tools below are grouped by the edition that introduced them.
        </Typography>
        {TOOL_EDITIONS.map((edition, i) => (
          <React.Fragment key={`${edition.version}-${edition.tier}`}>
            <Box sx={{ py: 1.5 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.8 }}>
                <Chip label={edition.version} size="small"
                  sx={{ backgroundColor: `${edition.color}15`, color: edition.color, fontSize: '0.7rem', fontWeight: 700, fontFamily: 'monospace' }} />
                <Typography sx={{ color: edition.color, fontSize: '0.7rem', fontWeight: 600 }}>{edition.tier}</Typography>
              </Box>
              {edition.rows.map(row => (
                <Box key={row.category} sx={{ display: 'flex', gap: 2, mb: 0.6, alignItems: 'flex-start' }}>
                  <Typography sx={{ color: '#1a1f2e', fontSize: '0.78rem', fontWeight: 600, minWidth: 200 }}>
                    {row.category}
                  </Typography>
                  <Typography sx={{ color: '#5a6478', fontSize: '0.78rem', fontFamily: 'monospace', lineHeight: 1.7, flexGrow: 1 }}>
                    {row.tools}
                  </Typography>
                </Box>
              ))}
            </Box>
            {i < TOOL_EDITIONS.length - 1 && <Divider sx={{ borderColor: 'rgba(30,41,60,0.06)' }} />}
          </React.Fragment>
        ))}
      </CardContent>
    </Card>

    {/* Scan Profiles */}
    <Card sx={{ mb: 3 }}>
      <CardContent sx={{ p: 3 }}>
        <Typography variant="h6" sx={{ color: '#4e5ced', mb: 2, fontSize: '1rem', fontWeight: 700 }}>
          Scan Profiles
        </Typography>
        <Grid container spacing={1.5}>
          {[
            { name: 'Fast', color: '#4fc3f7', desc: 'Top 1000 ports, httpx, nuclei, curl_probe. No brute-force. ~15 iterations.' },
            { name: 'Deep', color: '#4e5ced', desc: 'Full port scan, all tools. Binary analysis on downloadable executables. ~50 iterations.' },
            { name: 'Stealth', color: '#ff9800', desc: 'Low-and-slow. T1 timing, passive recon first, randomised tool order. ~30 iterations.' },
            { name: 'Full', color: '#f44336', desc: 'No constraints. AD enumeration, binary analysis, credential testing. Simulates 48h APT. ~80 iterations.' },
            { name: 'APT Sim', color: '#ce93d8', desc: 'Phase 1: silent recon. Phase 2: targeted probe. Phase 3: single exploit path. Full MITRE mapping. ~60 iterations.' },
            { name: 'Exhaustive', color: '#0f7a55', desc: 'Idle-stop terminates when the agent runs out of novel ideas. Default for v3.0+ deep engagements. up to 500 iterations.' },
          ].map(p => (
            <Grid item xs={12} sm={6} md={4} key={p.name}>
              <Box sx={{ p: 1.5, border: `1px solid ${p.color}30`, borderRadius: 1.5, backgroundColor: `${p.color}08` }}>
                <Chip label={p.name} size="small" sx={{ backgroundColor: `${p.color}20`, color: p.color, mb: 0.8, fontSize: '0.7rem' }} />
                <Typography sx={{ color: '#5a6478', fontSize: '0.78rem', lineHeight: 1.5 }}>{p.desc}</Typography>
              </Box>
            </Grid>
          ))}
        </Grid>
      </CardContent>
    </Card>

    {/* vs Traditional Pen Testing */}
    <Card sx={{ mb: 3 }}>
      <CardContent sx={{ p: 3 }}>
        <Typography variant="h6" sx={{ color: '#4e5ced', mb: 0.5, fontSize: '1rem', fontWeight: 700 }}>
          GENESIS vs Traditional Penetration Testing
        </Typography>
        <Typography sx={{ color: '#5a6478', fontSize: '0.82rem', mb: 2.5 }}>
          How an autonomous AI security engine compares to a human-led or script-based engagement.
        </Typography>

        <Box sx={{ overflowX: 'auto' }}>
          <Box component="table" sx={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
            <Box component="thead">
              <Box component="tr">
                {['Dimension', 'Traditional Pen Test', 'Script / Scanner', 'GENESIS MYTHOS'].map((h, i) => (
                  <Box component="th" key={h} sx={{
                    p: 1.5, textAlign: 'left', borderBottom: '1px solid #dfe3ec',
                    color: i === 3 ? '#4e5ced' : '#5a6478',
                    fontWeight: i === 3 ? 700 : 500, fontSize: '0.8rem',
                    backgroundColor: i === 3 ? 'rgba(78,92,237,0.04)' : 'transparent',
                  }}>{h}</Box>
                ))}
              </Box>
            </Box>
            <Box component="tbody">
              {[
                ['Reasoning depth', 'Expert intuition, bounded by human fatigue', 'None — fixed rule matching', 'Extended thinking + 12 deliberation loops compress search space'],
                ['Reasoning depth on long horizons', 'Bounded by 1 expert; degrades with fatigue', 'None', '12 deliberation loops compose AlphaZero-style — search structure substitutes for monolithic reasoning'],
                ['Speed', '1–2 weeks for full engagement', 'Minutes, but shallow', 'Hours for deep autonomous sweep'],
                ['Coverage', 'Depends on tester experience', 'Signature database only', '125+ MCP probes + 12 reasoning loops + sandbox swarm + replica spawner'],
                ['Zero-day discovery', 'Yes, if tester is skilled', 'No', 'Yes — reasons about edge cases, logic, chaining; ~70% yield on multi-day blackbox engagements'],
                ['0-day yield (telemetry)', 'Skill-dependent', '0%', '~70% on multi-day blackbox engagements (v6.0+ telemetry)'],
                ['Attack chaining', 'Manual correlation', 'No', 'T157 chain_composer topo-sorts confirmed primitives by pre/post-conditions'],
                ['Patch generation', 'Separate remediation engagement', 'No', 'Exact code diff per confirmed vulnerability'],
                ['Compliance reporting', 'Separate engagement', 'No', 'PCI · HIPAA · SOC2 · ISO27001 · NIST CSF · OWASP ASVS auto-generated'],
                ['Multi-tenancy', 'Single firm engagement', 'N/A', 'JWT-based RBAC; tenant-scoped data; immutable audit log'],
                ['Cost per engagement', 'High (£5k–£50k+)', 'Low (tool license)', 'Low (API token cost; budget tracker per target)'],
                ['Availability', 'Scheduled, limited slots', '24/7', '24/7, unlimited parallel sessions'],
                ['Memory across targets', 'Tribal knowledge / notes', 'None', 'ChromaDB vector DB + Neo4j attack graph + loop_state corpus'],
                ['Report quality', 'Narrative, executive-ready', 'CSV / generic text', 'Structured: severity, CVSS, PoC, MITRE, patch, compliance map'],
                ['Audit trail', 'Manual notes', 'Scan logs', 'Full tool I/O + AI reasoning + per-tick loop state stored per session'],
                ['Multi-agent parallel', 'Multiple testers (expensive)', 'No', 'Recon + Analyst + Exploit + Code + 5 personas + 4 specialist agents'],
              ].map(([dim, trad, script, gen]) => (
                <Box component="tr" key={dim} sx={{ '&:hover td': { backgroundColor: '#f6f8fc' } }}>
                  <Box component="td" sx={{ p: 1.5, borderBottom: '1px solid #dfe3ec', color: '#2a3045', fontWeight: 600, whiteSpace: 'nowrap' }}>{dim}</Box>
                  <Box component="td" sx={{ p: 1.5, borderBottom: '1px solid #dfe3ec', color: '#5a6478' }}>{trad}</Box>
                  <Box component="td" sx={{ p: 1.5, borderBottom: '1px solid #dfe3ec', color: '#5a6478' }}>{script}</Box>
                  <Box component="td" sx={{ p: 1.5, borderBottom: '1px solid #dfe3ec', color: '#1a1f2e', backgroundColor: '#e7eafc', fontWeight: 500 }}>{gen}</Box>
                </Box>
              ))}
            </Box>
          </Box>
        </Box>

        <Divider sx={{ my: 2.5, borderColor: '#dfe3ec' }} />

        <Typography sx={{ color: '#1a1f2e', fontSize: '0.88rem', fontWeight: 700, mb: 1.5 }}>
          Key Differentiators
        </Typography>
        <Grid container spacing={1.5}>
          {[
            { title: 'No Scan Fatigue', color: '#4fc3f7',
              desc: 'A human tester loses focus after hours. GENESIS reasons at full depth on iteration 80 the same as iteration 1, re-reading all prior tool output before each decision.' },
            { title: 'Adaptive Strategy', color: '#4e5ced',
              desc: 'Traditional scripts follow a fixed playbook. GENESIS pivots: if SQL injection hits a WAF, it switches to bypass payloads; if the attack stalls, T165 counterfactual loop maps which hypothetical primitive would unlock the next step.' },
            { title: 'Chained Impact, Not Isolated Findings', color: '#ff9800',
              desc: 'Scanners report individual CVEs. T157 chain_composer topo-sorts primitives by pre/post-conditions and persists chain_id onto every Vulnerability row, producing kill-chains with full business impact.' },
            { title: 'Institutional Memory', color: '#ce93d8',
              desc: 'Successful attack patterns are indexed into ChromaDB + Neo4j. v7 also persists every reasoning-loop tick to MongoDB `loop_state` — the corpus that will feed v8\'s training flywheel.' },
            { title: 'Immediate Patch Delivery', color: '#f44336',
              desc: 'Traditional pen tests separate finding from fixing. GENESIS generates exact patch code at the moment of discovery — closing the gap between "vulnerability found" and "vulnerability fixed".' },
            { title: 'Transparent Reasoning', color: '#0f7a55',
              desc: 'Every decision is visible: Deep Thought panel for extended thinking, Hypothesis Tree for confidence-staked claims, Loops tab for tick-by-tick deliberation. Unlike a black-box scanner, you see exactly why GENESIS chose each tool.' },
          ].map(item => (
            <Grid item xs={12} sm={6} md={4} key={item.title}>
              <Box sx={{ p: 1.5, border: `1px solid ${item.color}25`, borderRadius: 1.5, height: '100%' }}>
                <Typography sx={{ color: item.color, fontSize: '0.82rem', fontWeight: 700, mb: 0.8 }}>{item.title}</Typography>
                <Typography sx={{ color: '#5a6478', fontSize: '0.78rem', lineHeight: 1.55 }}>{item.desc}</Typography>
              </Box>
            </Grid>
          ))}
        </Grid>

        <Box sx={{ mt: 2, p: 1.5, backgroundColor: 'rgba(255,152,0,0.05)', borderRadius: 1, border: '1px solid rgba(255,152,0,0.15)' }}>
          <Typography sx={{ color: '#ff9800', fontSize: '0.78rem', fontWeight: 600, mb: 0.4 }}>Where human testers still lead</Typography>
          <Typography sx={{ color: '#5a6478', fontSize: '0.78rem', lineHeight: 1.55 }}>
            GENESIS excels at breadth, speed, and systematic coverage. Highly complex business-logic flaws requiring deep domain knowledge (e.g., manipulating financial settlement flows), physical security, social engineering, and executive-level report narrative are still best served by experienced human professionals. GENESIS is a force multiplier — not a replacement.
          </Typography>
        </Box>
      </CardContent>
    </Card>

    {/* Cost Optimisations */}
    <Card sx={{ mb: 3 }}>
      <CardContent sx={{ p: 3 }}>
        <Typography variant="h6" sx={{ color: '#4e5ced', mb: 0.5, fontSize: '1rem', fontWeight: 700 }}>
          Cost Optimisations
        </Typography>
        <Typography sx={{ color: '#5a6478', fontSize: '0.82rem', mb: 2.5 }}>
          Four changes that cut cumulative API spend ~60–66% on long sessions without dropping reasoning depth. Stated as relative percentages so the page never drifts when model pricing changes.
        </Typography>

        <Grid container spacing={2}>
          {[
            {
              number: '01', title: 'Prompt Caching', color: '#4fc3f7',
              detail: 'The system prompt and all tool schemas are marked with cache_control. The first call writes them to Anthropic\'s cache; every subsequent call within the 5-minute TTL reads them at ~10% of the write price — a deep discount on tokens that were previously resent on every iteration.',
              saving: '~80% on system-prompt tokens',
            },
            {
              number: '02', title: 'Adaptive Thinking Budget', color: '#ff9800',
              detail: 'Instead of a fixed thinking budget every iteration, the budget adapts by position in the session: high (~8k) for the first 10% (forming initial hypothesis) and last 15% (correlating findings into kill chains), low (~3k) for routine mid-session tool-selection decisions. Average drops from 10k → ~3.8k tokens.',
              saving: '~60% of thinking tokens',
            },
            {
              number: '03', title: 'Message History Compression', color: '#ce93d8',
              detail: 'Every 15 iterations the oldest 12 messages are collapsed into a single bullet-point progress summary. The initial prompt and last 4 messages are always kept verbatim. This prevents quadratic token growth — without compression the history balloons by iter 50.',
              saving: '~70% of context tokens by iter 50',
            },
            {
              number: '04', title: 'Reasoning-Loop Budget Compression (v7)', color: '#0f7a55',
              detail: 'A `deliberate(loop_type=...)` call burns 4k–20k tokens for a structured task that would otherwise consume 50k+ in a single monolithic forward pass. Each loop\'s budget is hard-capped: ROP composition 15k/12 ticks · long-context code 20k/15 ticks · code intent 8k/6 ticks · hypothesis decomp 4k/5 ticks…',
              saving: '~50–80% on heavy reasoning tasks',
            },
          ].map(item => (
            <Grid item xs={12} sm={6} md={3} key={item.number}>
              <Box sx={{ p: 2, border: `1px solid ${item.color}25`, borderRadius: 1.5, height: '100%' }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1.2 }}>
                  <Box sx={{
                    width: 28, height: 28, borderRadius: '50%',
                    backgroundColor: `${item.color}20`, border: `1px solid ${item.color}60`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                  }}>
                    <Typography sx={{ color: item.color, fontSize: '0.7rem', fontWeight: 800, fontFamily: 'monospace' }}>{item.number}</Typography>
                  </Box>
                  <Typography sx={{ color: '#1a1f2e', fontWeight: 700, fontSize: '0.85rem' }}>{item.title}</Typography>
                </Box>
                <Typography sx={{ color: '#5a6478', fontSize: '0.76rem', lineHeight: 1.6, mb: 1.2 }}>{item.detail}</Typography>
                <Box sx={{ display: 'inline-flex', alignItems: 'center', gap: 0.5, backgroundColor: `${item.color}12`, border: `1px solid ${item.color}30`, borderRadius: 1, px: 1, py: 0.4 }}>
                  <Typography sx={{ color: item.color, fontSize: '0.68rem', fontWeight: 700, fontFamily: 'monospace' }}>SAVES {item.saving}</Typography>
                </Box>
              </Box>
            </Grid>
          ))}
        </Grid>

        <Box sx={{ mt: 2, p: 1.5, backgroundColor: 'rgba(78,92,237,0.04)', borderRadius: 1, border: '1px solid rgba(78,92,237,0.1)' }}>
          <Typography sx={{ color: '#5a6478', fontSize: '0.78rem', lineHeight: 1.55 }}>
            <Box component="span" sx={{ color: '#4e5ced', fontWeight: 700 }}>Why not switch to a cheaper model?</Box>
            {' '}Opus 4.7\'s extended thinking is what enables multi-hop chaining, 0-day hypothesis formation, and the structured deliberation loops in v7. Cheaper non-thinking models can\'t reproduce those capabilities. The four optimisations above plus the 12 reasoning loops are how GENESIS affords Opus on long sessions while preserving full reasoning depth.
          </Typography>
        </Box>
      </CardContent>
    </Card>

    {/* Advanced Novel Vulnerability Detection */}
    <Card sx={{ mb: 3 }}>
      <CardContent sx={{ p: 3 }}>
        <Typography variant="h6" sx={{ color: '#4e5ced', mb: 0.5, fontSize: '1rem', fontWeight: 700 }}>
          Advanced Novel Vulnerability Detection
        </Typography>
        <Typography sx={{ color: '#5a6478', fontSize: '0.82rem', mb: 2.5 }}>
          Vulnerability classes that traditional scanners miss — and the GENESIS systems that find them, by edition.
        </Typography>
        <Grid container spacing={2} sx={{ mb: 2.5 }}>
          {[
            {
              title: 'OOB / Differential / Race / Session Memory (v3.0)',
              edition: 'v3.0',
              color: '#6840cf',
              what: 'Four flagship novelty probes from the Tier-5 wave.',
              how: 'oob_check (callback-confirmed blind injection) · differential_probe (response-matrix analysis for blind/IDOR/auth bypass) · race_probe (Promise.all concurrency for TOCTOU) · session_memory (Redis-backed cross-endpoint state).',
              finds: 'Blind SSRF · Blind XXE · Blind SQLi · IDOR · TOCTOU · Multi-step auth bypass',
            },
            {
              title: 'Novelty Arsenal (v4.0)',
              edition: 'v4.0',
              color: '#137a4e',
              what: '51 probes across 13 implementation waves.',
              how: 'Parser-quirk diff · HTTP-modern (smuggling, h2c) · deserialisation gadgets · upload + SSRF schemes · state-aware fuzz · DoS · LLM probe pack · AD kill-chain · template/DB injection · browser-side / DOM probes · non-HTTP services. See manual section "v4.0 / Tier-6" for full breakdown.',
              finds: 'Parser disagreement · Insecure deserialisation · Upload/SSRF · Race-condition state machines · LLM prompt injection · AD kerberoasting + delegation abuse',
            },
            {
              title: 'Source-Aware Reasoning (v5.0)',
              edition: 'v5.0',
              color: '#0e7c86',
              what: '9 probes that read source instead of just probing endpoints.',
              how: 'repo_ingest pulls the codebase · ast_walker indexes structures · taint_engine traces tainted flows · invariant_inferer mines runtime invariants · adversarial_synthesis composes hypothesis-driven exploit candidates · architectural_reasoner extracts trust boundaries.',
              finds: 'Logic flaws not visible from outside · Architectural trust violations · Cross-file taint sinks',
            },
            {
              title: 'Specialist Agents (v6.0)',
              edition: 'v6.0',
              color: '#b53030',
              what: 'IoT · Mobile · OT/ICS · Embedded — activated by Phase-1 surface detection.',
              how: 'IoT (UPnP · BLE · Modbus · DNP3) · Mobile (APK static + Frida hooks) · OT (Siemens S7 · Ethernet/IP) · Embedded (UART · JTAG · SPI). Persona orchestrator routes findings through tactic profiles tuned per agent.',
              finds: 'Industrial control protocol abuse · Mobile cert pinning bypass · BLE characteristic injection · UART/JTAG debug exposure',
            },
          ].map(item => (
            <Grid item xs={12} md={6} key={item.title}>
              <Box sx={{ p: 2, border: `1px solid ${item.color}25`, borderRadius: 1.5, height: '100%' }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                  <Typography sx={{ color: item.color, fontWeight: 700, fontSize: '0.88rem' }}>{item.title}</Typography>
                  <Chip label={item.edition} size="small"
                    sx={{ backgroundColor: `${item.color}15`, color: item.color, fontFamily: 'monospace', fontSize: '0.65rem', height: 16, ml: 'auto' }} />
                </Box>
                <Typography sx={{ color: '#5a6478', fontSize: '0.78rem', lineHeight: 1.55, mb: 0.8 }}>
                  <Box component="span" sx={{ color: '#2a3045', fontWeight: 600 }}>What: </Box>{item.what}
                </Typography>
                <Typography sx={{ color: '#5a6478', fontSize: '0.78rem', lineHeight: 1.55, mb: 0.8 }}>
                  <Box component="span" sx={{ color: '#2a3045', fontWeight: 600 }}>How: </Box>{item.how}
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                  {item.finds.split(' · ').map(f => (
                    <Chip key={f} label={f} size="small"
                      sx={{ backgroundColor: '#dfe3ec', color: '#5a6478', fontSize: '0.62rem', height: 16 }} />
                  ))}
                </Box>
              </Box>
            </Grid>
          ))}
        </Grid>

        {/* Cross-link to Reasoning Loops + Hypothesis systems */}
        <Box sx={{ p: 1.5, backgroundColor: 'rgba(15,122,85,0.04)', borderRadius: 1, border: '1px solid rgba(15,122,85,0.15)', mb: 2.5 }}>
          <Typography sx={{ color: '#0f7a55', fontSize: '0.78rem', fontWeight: 700, mb: 0.4 }}>
            v7.0 — reasoning-side novelty
          </Typography>
          <Typography sx={{ color: '#5a6478', fontSize: '0.78rem', lineHeight: 1.55 }}>
            v7 adds zero new MCP probes — the novelty comes from the 12 reasoning loops above. Code-intent multi-zoom (T156) catches Heartbleed-class smells across function/file/module/architectural views. Cross-component invariant tracker (T163) flags producer/consumer drift. Counterfactual exploration (T165) maps multi-step "what if I had primitive X" trees. See the Reasoning Loops section above.
          </Typography>
        </Box>

        <Divider sx={{ mb: 2.5, borderColor: '#dfe3ec' }} />
        <Typography sx={{ color: '#1a1f2e', fontSize: '0.88rem', fontWeight: 700, mb: 1.5 }}>
          Hypothesis Systems
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} md={4}>
            <Box sx={{ p: 2, border: '1px solid rgba(255,152,0,0.2)', borderRadius: 1.5, height: '100%' }}>
              <Typography sx={{ color: '#ff9800', fontWeight: 700, fontSize: '0.88rem', mb: 0.8 }}>Hypothesis Journal</Typography>
              <Typography sx={{ color: '#5a6478', fontSize: '0.78rem', lineHeight: 1.6 }}>
                Before every tool call, Claude emits a structured <Box component="code" sx={{ color: '#ff9800', backgroundColor: 'rgba(255,152,0,0.08)', px: 0.5, borderRadius: 0.5, fontSize: '0.72rem' }}>HYPOTHESIS</Box> JSON block: statement, confidence, evidence for/against, next planned test, falsification criterion. Stored in MongoDB and broadcast over WebSocket.
              </Typography>
            </Box>
          </Grid>
          <Grid item xs={12} md={4}>
            <Box sx={{ p: 2, border: '1px solid rgba(78,92,237,0.2)', borderRadius: 1.5, height: '100%' }}>
              <Typography sx={{ color: '#4e5ced', fontWeight: 700, fontSize: '0.88rem', mb: 0.8 }}>Hypothesis Market (T89/T166)</Typography>
              <Typography sx={{ color: '#5a6478', fontSize: '0.78rem', lineHeight: 1.6 }}>
                Confidence-staked adversarial hypothesis system. Semantic dedup against ChromaDB before storage. v7 T166 hypothesis_decomp loop breaks vague claims into atomic children with parent_hypothesis_id linkage — each child gets its own evidence stream and resolution status.
              </Typography>
            </Box>
          </Grid>
          <Grid item xs={12} md={4}>
            <Box sx={{ p: 2, border: '1px solid rgba(79,195,247,0.2)', borderRadius: 1.5, height: '100%' }}>
              <Typography sx={{ color: '#4fc3f7', fontWeight: 700, fontSize: '0.88rem', mb: 0.8 }}>Adversarial Critic</Typography>
              <Typography sx={{ color: '#5a6478', fontSize: '0.78rem', lineHeight: 1.6 }}>
                Every unverified vulnerability with confidence ≥ 0.6 is challenged by a secondary Claude call. The critic gets only the title, description, and confidence — no extra context — and independently decides confirmed or disputed. A two-model review layer that filters false positives without human review of every finding.
              </Typography>
            </Box>
          </Grid>
        </Grid>
      </CardContent>
    </Card>

    {/* FAQ */}
    <Typography variant="h6" sx={{ color: '#1a1f2e', mb: 1.5, fontSize: '1rem', fontWeight: 700 }}>
      Frequently Asked Questions
    </Typography>
    {[
      {
        q: 'How does the autonomous loop work?',
        a: 'Each iteration, Claude receives the accumulated message history and uses extended thinking (adaptive 3k–8k token budget) to decide its next action. It calls a tool — either an MCP probe or, in v7+, a reasoning loop via the `deliberate` tool — observes the result, and repeats. The loop ends when Claude emits a FINAL_REPORT block, the iteration limit is reached, or (in Exhaustive profile) the agent runs out of novel ideas.',
      },
      {
        q: 'What are reasoning loops and when do they fire?',
        a: 'Reasoning loops are domain-specific deliberation harnesses that compress a hard task into many small tractable turns (AlphaZero-style: loop = search structure, LLM = evaluator). Claude opts into them by emitting a `deliberate(loop_type=..., inputs=...)` tool call — they are NOT auto-fired by the orchestrator. Each loop has a hard token + tick budget. Every tick is persisted to MongoDB `loop_state` and visible in the Loops tab.',
      },
      {
        q: 'How does the OSS replica spawner work?',
        a: 'T122 fingerprints the target stack (server software, framework versions, observable routes), then spawns a matched OSS image (e.g. matching nginx + WordPress + PHP version) via the replica_manager sidecar service. Destructive payloads — SQLi, RCE, deserialisation gadgets, fuzzing, ROP chains — run against the replica BEFORE any production target. v6 T131 also uses replicas for sameday CVE replay: as new advisories ingest, their PoCs are fired against the replica automatically.',
      },
      {
        q: 'Is GENESIS multi-tenant?',
        a: 'Yes. JWT-based authentication via POST /api/v1/auth/login (T141) plus tenant-scoped data isolation. Every privileged action — session creation, vulnerability confirmation, integration changes, settings updates — appends to an immutable audit log (T142). The X-API-Key header still works for headless/CI integrations.',
      },
      {
        q: 'Can I generate compliance reports?',
        a: 'Yes. The Compliance tab in the Session Viewer generates audit-ready reports against six frameworks: PCI DSS, HIPAA, SOC2, ISO27001, NIST CSF, OWASP ASVS. Each finding maps to specific control IDs. Reports are downloadable from /api/v1/compliance/sessions/{id}/{framework}.',
      },
      {
        q: 'What is multi-agent mode?',
        a: 'Multi-agent mode spawns four parallel sub-agents — Recon (port/service discovery), Analyst (fingerprinting, SSL, WAF), Exploit (web attacks, credential testing), Code (static analysis) — plus up to four conditional specialists (IoT, Mobile, OT, Embedded) activated by Phase-1 surface detection, plus five attacker personas (T135). A Strategist agent correlates cross-agent findings into unified attack chains via T157 chain_composer.',
      },
      {
        q: 'How does the Intelligence Library work?',
        a: 'After every completed session, GENESIS indexes confirmed vulnerabilities and attack patterns into a ChromaDB vector store, plus relationships into a Neo4j attack graph (T21). Before a new session, you can query the library with a target fingerprint to recall similar past assessments and their successful chains. The v7 `loop_state` MongoDB collection adds a third layer — every reasoning-loop tick is preserved as future training corpus for v8\'s flywheel.',
      },
      {
        q: 'Are the generated payloads and exploits safe to run?',
        a: 'GENESIS never runs destructive payloads against production automatically — they go to the OSS replica first. Exploit code in vulnerability cards is generated for documentation and manual review. The AI is instructed never to execute --delete, DROP, DoS, or format operations against the target. Always review exploit_code before running it in a real environment.',
      },
      {
        q: 'Where are findings stored?',
        a: 'Structured vulnerabilities are stored in PostgreSQL (queryable, persistent). Real-time session events (tool outputs, thoughts, deep thinking, hypotheses, loop ticks) are stored in MongoDB. Cross-session attack-pattern vectors are stored in ChromaDB. The Neo4j attack graph holds cross-session relationships. All data is local to your deployment.',
      },
    ].map(item => (
      <Accordion key={item.q} sx={{ backgroundColor: '#ffffff', border: '1px solid #dfe3ec', mb: 1, '&:before': { display: 'none' } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: '#5a6478' }} />}>
          <Typography sx={{ color: '#2a3045', fontSize: '0.88rem', fontWeight: 500 }}>{item.q}</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Typography sx={{ color: '#5a6478', fontSize: '0.83rem', lineHeight: 1.65 }}>{item.a}</Typography>
        </AccordionDetails>
      </Accordion>
    ))}

    {/* Edition history */}
    <Box sx={{ mt: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1.5 }}>
        <HubIcon sx={{ color: '#4e5ced', fontSize: 18 }} />
        <Typography variant="h6" sx={{ color: '#1a1f2e', fontSize: '1rem', fontWeight: 700 }}>
          Edition history (v1.0 → v7.0)
        </Typography>
        <Chip label="8 editions" size="small" sx={{ ml: 'auto', backgroundColor: 'rgba(78,92,237,0.1)', color: '#4e5ced', fontSize: '0.7rem', fontWeight: 700 }} />
      </Box>
      {[
        { v: 'v1.0', tier: 'Tier-1', built: true, theme: 'Make the autonomous loop trustworthy and coherent.',
          detail: 'U1 Evidence rules · U2 Loop-breaker · U3 Chain suggestions · U4 Technique recall · U5 Multi-agent messaging.' },
        { v: 'v2.0', tier: 'Tier-2', built: true, theme: 'Move from orchestrator-of-scanners to AI doing original work.',
          detail: 'T1 Target Intent Brief · T2 AI Payload Forge · T3 Artifact Hunter · T4 Binary Decompiler · T5 Sandbox Runner · T6 Vision · T7 CVE Patch Reader · T8 Session Reflections.' },
        { v: 'v2.5', tier: 'Tier-3', built: true, theme: 'Go deeper into native code; longer in horizon; engine pluggable.',
          detail: 'T9 Coverage fuzzer · T10 Symbolic execution · T11 Plan-tree · T12 Agentic browser · T13 Model-swap hook.' },
        { v: 'v3.0', tier: 'Tier-5', built: true, theme: 'Cross-session reasoning · specialist depth · parallel novelty hunting · operator UI.',
          detail: 'T21 Neo4j attack graph · T22 5 specialist agents · T23 Multi-host + MinIO · T24 Grammar fuzz · T25 Frida / DynamoRIO · T26 Crypto primitives · T27 Live observability · T28 Sandbox swarm.' },
        { v: 'v4.0', tier: 'Tier-6', built: true, theme: 'Novel-vulnerability research platform — differential testing, coverage feedback, 51 new probes across 13 waves.',
          detail: 'Wave 1 Novelty engine (T29-T31) · Wave 2 Parser diff (T32-T36) · Wave 3 HTTP-modern (T37-T39) · Wave 4 Deserialisation (T40-T45) · Wave 5 Upload+SSRF (T46-T50) · Wave 6 State-aware fuzz (T51-T53) · Wave 7 Auth depth (T54-T56) · Wave 8 Browser-side (T57-T61) · Wave 9 Templates/DB (T62-T64) · Wave 10 DoS (T65-T66) · Wave 11 LLM (T67-T69) · Wave 12 Non-HTTP (T70-T73) · Wave 13 AD/Kill-Chain (T74-T79).' },
        { v: 'v5.0', tier: 'Tier-7', built: true, theme: 'Source-aware reasoning · adversarial synthesis · self-improving tooling · long-horizon Researcher.',
          detail: 'Theme 1 Source-aware (T80-T86) · Theme 2 Adversarial (T87-T92) · Theme 3 Synthetic envs (T93-T96) · Theme 4 Self-improving (T97-T101) · Theme 5 Long-horizon (T102-T105) · Theme 6 Binary & memory (T106-T109) · Theme 7 New surfaces (T110-T116) · Theme 8 Output (T117-T120).' },
        { v: 'v6.0', tier: 'Tier-8', built: true, theme: 'Sophistication + blackbox 0-day — replica spawning · curiosity RL · real-time threat intel · multi-persona · production engineering.',
          detail: 'Theme A Blackbox (T121-T124) · Theme B Curiosity RL (T125-T128) · Theme C Threat intel (T129-T131) · Theme D Goal planning (T132-T134) · Theme E Personas (T135-T140) · Theme F Production (T141-T146) · Theme G Explainable UX (T147-T150) · Theme H Model ops (T151-T154). Expected ~70% 0-day yield on multi-day blackbox engagements.' },
        { v: 'v7.0', tier: 'Tier-9', built: true, theme: 'Reasoning loops — twelve domain-specific deliberation harnesses that compress search space.',
          detail: 'T155 rop_composition · T156 code_intent · T157 chain_composer · T158 heap_layout · T159 self_correcting · T160 deliberation_framework · T161 tree_of_thought · T162 long_context_code · T163 cross_component_invariant_tracker · T164 causal_exploit_trace · T165 counterfactual_exploration_deep · T166 hypothesis_decomposition. AlphaZero-style: loop = search structure, LLM = evaluator. Zero new MCP probes; every gain is reasoning-loop work.' },
      ].map(ed => (
        <Accordion key={ed.v} sx={{ backgroundColor: '#ffffff', border: '1px solid #dfe3ec', mb: 0.8, '&:before': { display: 'none' } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: '#5a6478' }} />}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, flex: 1 }}>
              <Chip label={ed.v} size="small" sx={{ backgroundColor: 'rgba(78,92,237,0.12)', color: '#4e5ced', fontFamily: 'monospace', fontSize: '0.7rem', fontWeight: 700 }} />
              <Typography sx={{ color: '#5a6478', fontSize: '0.7rem', fontWeight: 600, minWidth: 56 }}>{ed.tier}</Typography>
              <Typography sx={{ color: '#2a3045', fontSize: '0.85rem', fontWeight: 500, flex: 1 }}>{ed.theme}</Typography>
              <Chip label={ed.built ? 'Built' : 'Planned'} size="small"
                sx={{ backgroundColor: ed.built ? 'rgba(19,122,78,0.12)' : 'rgba(154,109,24,0.12)',
                      color: ed.built ? '#137a4e' : '#9a6d18',
                      fontSize: '0.65rem', fontWeight: 700, height: 20 }} />
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Typography sx={{ color: '#5a6478', fontSize: '0.82rem', lineHeight: 1.65 }}>{ed.detail}</Typography>
          </AccordionDetails>
        </Accordion>
      ))}
    </Box>

    <Box sx={{ mt: 3, p: 2, backgroundColor: 'rgba(78,92,237,0.04)', borderRadius: 2, border: '1px solid rgba(78,92,237,0.1)' }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
        <SecurityIcon sx={{ color: '#4e5ced', fontSize: 16 }} />
        <Typography sx={{ color: '#4e5ced', fontSize: '0.82rem', fontWeight: 700 }}>GENESIS MYTHOS</Typography>
      </Box>
      <Typography sx={{ color: '#8a93a6', fontSize: '0.75rem' }}>
        Powered by Claude Opus 4.7 with extended thinking + 12-loop deliberation framework. Built for authorized penetration testing and security research.
      </Typography>
    </Box>
  </Box>
);

export default About;

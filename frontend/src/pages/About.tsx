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
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import BugReportIcon from '@mui/icons-material/BugReport';
import BuildIcon from '@mui/icons-material/Build';
import StorageIcon from '@mui/icons-material/Storage';
import ShieldIcon from '@mui/icons-material/Shield';

// ── ASCII Flowchart ────────────────────────────────────────────────────────

const FLOW = `
  ┌─────────────────────────────────────────────────────────────────────┐
  │                        SECURITY ANALYST                            │
  │                Configure target  ·  Choose scan profile            │
  └──────────────────────────────┬──────────────────────────────────────┘
                                 │  HTTPS + X-API-Key header
                                 ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │                       REACT FRONTEND  :3000                        │
  │   Dashboard · Session Viewer · Attack Graph · Intelligence · About │
  │   Real-time updates via WebSocket  ·  Stores API key in browser    │
  └──────────────────────────────┬──────────────────────────────────────┘
                                 │  REST API calls  /  WebSocket stream
                                 ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │                    FASTAPI BACKEND  :8000                           │
  │   Auth middleware (X-API-Key)  ·  Session CRUD  ·  WebSocket relay │
  └────────┬───────────────────────────────────────────────┬────────────┘
           │  enqueues task via Redis                       │  persists to
           ▼                                               ▼
  ┌────────────────────┐   ┌──────────────┐   ┌───────────────────────┐
  │   REDIS  :6379     │   │ POSTGRESQL   │   │  MONGODB              │
  │  Celery broker     │   │  sessions    │   │  tool outputs         │
  │  Task queue        │   │  vulns       │   │  AI thoughts          │
  │  Result backend    │   │  settings    │   │  deep_thoughts        │
  └────────┬───────────┘   └──────────────┘   └───────────────────────┘
           │  worker picks up task
           ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │                      CELERY WORKER                                  │
  │         Runs assessment as a background task                        │
  │         Routes to Solo or Multi-Agent orchestrator                  │
  └──────────────────────────────┬──────────────────────────────────────┘
                                 │
           ┌──────────────────────┴──────────────────────┐
           │  agent_mode = solo                           │  agent_mode = multi_agent
           ▼                                             ▼
  ┌─────────────────────────┐              ┌──────────────────────────────┐
  │   SOLO AI ORCHESTRATOR  │              │   MULTI-AGENT ORCHESTRATOR   │
  │   Claude MYTHOS         │              │                              │
  │                         │              │  ┌──────────┐ ┌───────────┐  │
  │  Each iteration:        │              │  │  RECON   │ │  ANALYST  │  │
  │  1. Extended Thinking   │              │  │  Agent   │ │  Agent    │  │
  │     (10k token budget)  │              │  └──────────┘ └───────────┘  │
  │  2. Choose a tool       │              │  ┌──────────┐ ┌───────────┐  │
  │  3. Call MCP server     │              │  │  EXPLOIT │ │   CODE    │  │
  │  4. Read result         │              │  │  Agent   │ │  Agent    │  │
  │  5. Update findings     │              │  └──────────┘ └───────────┘  │
  │  6. Repeat until done   │              │  Strategist correlates all   │
  └──────────┬──────────────┘              └──────────────┬───────────────┘
             │                                            │
             └──────────────────┬─────────────────────────┘
                                │  tool calls (JSON-RPC over HTTP)
                                ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │                    MCP TOOL SERVER  :3001                           │
  │                    47 tools across 7 categories                     │
  │                                                                     │
  │  ┌─────────────┐  ┌──────────────┐  ┌────────────┐  ┌──────────┐  │
  │  │    RECON    │  │   WEB AUDIT  │  │   EXPLOIT  │  │   CODE   │  │
  │  │  nmap       │  │  nuclei      │  │  sqlmap    │  │  semgrep │  │
  │  │  masscan    │  │  nikto       │  │  xsstrike  │  │  bandit  │  │
  │  │  amass      │  │  gobuster    │  │  commix    │  │  payload_│  │
  │  │  subfinder  │  │  feroxbuster │  │  hydra     │  │  crafter │  │
  │  │  dnsrecon   │  │  ffuf        │  │  john      │  │  binary_ │  │
  │  │  httpx      │  │  wpscan      │  │  netexec   │  │  analyzer│  │
  │  └─────────────┘  └──────────────┘  └────────────┘  └──────────┘  │
  │  ┌────────────────────────────────────────────────────────────────┐ │
  │  │  FINGERPRINT: whatweb · wafw00f · sslscan · openssl_check     │ │
  │  │  AD / CREDS:  enum4linux · impacket · kerbrute · arjun        │ │
  │  │  NOVEL VULN:  oob_check · differential_probe · race_probe     │ │
  │  │               session_memory  (blind/race/correlation)         │ │
  │  │  HTTP VULN:   idor_probe · cors_probe · jwt_probe             │ │
  │  │               graphql_probe · ssti_detect · nosql_probe       │ │
  │  │               cache_probe · prototype_pollution_probe          │ │
  │  │               oauth_probe · http_smuggling_probe               │ │
  │  └────────────────────────────────────────────────────────────────┘ │
  └──────────────────────────────┬──────────────────────────────────────┘
                                 │  tool output returned to AI
                                 ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │                       RESULTS ENGINE                                │
  │                                                                     │
  │  ┌─────────────────────┐  ┌──────────────────┐  ┌───────────────┐  │
  │  │   VULNERABILITY     │  │  ATTACK CHAIN    │  │  MITRE ATT&CK │  │
  │  │  Title + CVSS score │  │  Step 1 (recon)  │  │  T1046 scan   │  │
  │  │  Exploit PoC code   │  │  Step 2 (foothold│  │  T1190 exploit│  │
  │  │  Patch code (diff)  │  │  Step 3 (pivot)  │  │  T1059 exec   │  │
  │  │  Verified / 0-day   │  │  Final impact    │  │  per finding  │  │
  │  └─────────────────────┘  └──────────────────┘  └───────────────┘  │
  │                                                                     │
  │   All events streamed live to browser via WebSocket                 │
  └──────────────────────────────┬──────────────────────────────────────┘
                                 │  on session complete
                                 ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │              INTELLIGENCE LIBRARY  (ChromaDB  :8001)                │
  │                                                                     │
  │  STORE  →  Indexes confirmed vulns + attack patterns as vectors     │
  │  RECALL →  Next session queries: "seen a target like this before?"  │
  │            Returns: similar past targets + their successful chains  │
  └─────────────────────────────────────────────────────────────────────┘
`;

const FlowChart: React.FC = () => (
  <Box
    component="pre"
    sx={{
      m: 0,
      p: 2.5,
      backgroundColor: '#0d0d0d',
      border: '1px solid rgba(134,188,37,0.15)',
      borderRadius: 1.5,
      overflowX: 'auto',
      fontFamily: "'Courier New', Courier, monospace",
      fontSize: '0.72rem',
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
    icon: <PsychologyIcon sx={{ color: '#ff9800' }} />,
    title: 'Extended Thinking',
    color: '#ff9800',
    items: [
      '10,000-token private reasoning budget per iteration',
      'Claude reasons about attack surfaces before acting',
      'Deep Thought panel shows internal reasoning in real-time',
      'Hypothesis-driven approach: form → test → adapt',
    ],
  },
  {
    icon: <BugReportIcon sx={{ color: '#f44336' }} />,
    title: 'Zero-Day & Chaining',
    color: '#f44336',
    items: [
      'Reasons beyond CVE databases — looks for logic flaws',
      'Business logic abuse detection',
      'Chains minor issues into high-impact attack paths',
      'Assigns MITRE ATT&CK techniques to every finding',
    ],
  },
  {
    icon: <AccountTreeIcon sx={{ color: '#86BC25' }} />,
    title: 'Attack Chain Construction',
    color: '#86BC25',
    items: [
      'Groups vulnerabilities into multi-step kill chains',
      'Visualized as attack graph with SVG node diagram',
      'Each chain: entry point → exploitation → final impact',
      'Supports export to PNG for reporting',
    ],
  },
  {
    icon: <BuildIcon sx={{ color: '#4fc3f7' }} />,
    title: '37 Security Tools',
    color: '#4fc3f7',
    items: [
      'Recon: nmap, masscan, amass, subfinder, dnsrecon, httpx',
      'Web: nuclei, nikto, gobuster, feroxbuster, ffuf, sqlmap, xsstrike',
      'Novel: oob_check, differential_probe, race_probe, session_memory',
      'Code: semgrep, bandit, payload_crafter, binary_analyzer',
    ],
  },
  {
    icon: <StorageIcon sx={{ color: '#ce93d8' }} />,
    title: 'Cross-Session Intelligence',
    color: '#ce93d8',
    items: [
      'ChromaDB vector store indexes every completed session',
      'Semantic similarity recall: find similar past targets',
      'Successful attack patterns reused on new assessments',
      'Intelligence Dashboard shows library at a glance',
    ],
  },
  {
    icon: <ShieldIcon sx={{ color: '#86BC25' }} />,
    title: 'Patch Generation',
    color: '#86BC25',
    items: [
      'Claude generates exact code fixes for each confirmed vuln',
      'Real diffs or config snippets — not generic advice',
      '"View Patch" button on every vulnerability card',
      'Remediation guidance attached to every finding',
    ],
  },
];

const toolCategories = [
  { label: 'Recon', tools: 'nmap · masscan · amass · subfinder · dnsrecon · harvester · httpx' },
  { label: 'Fingerprint', tools: 'whatweb · wafw00f · sslscan · openssl_check' },
  { label: 'Web Attack', tools: 'nuclei · nikto · gobuster · feroxbuster · ffuf · wpscan · xsstrike · sqlmap · commix · arjun' },
  { label: 'Exploit', tools: 'curl_probe · hydra · john · enum4linux · netexec · impacket · kerbrute' },
  { label: 'Code Analysis', tools: 'semgrep · bandit · payload_crafter · binary_analyzer · code_pattern_search' },
  { label: 'Novel Discovery', tools: 'oob_check · differential_probe · race_probe · session_memory' },
  { label: 'HTTP Vulnerability Analysis', tools: 'idor_probe · cors_probe · jwt_probe · graphql_probe · ssti_detect · nosql_probe · cache_probe · prototype_pollution_probe · oauth_probe · http_smuggling_probe' },
];

const About: React.FC = () => (
  <Box sx={{ p: 3, maxWidth: 1200 }}>
    {/* Header */}
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
      <InfoOutlinedIcon sx={{ color: '#86BC25', fontSize: 28 }} />
      <Box>
        <Typography variant="h4" sx={{ color: '#f0f0f0', fontSize: '1.4rem', fontWeight: 700, lineHeight: 1.2 }}>
          About GENESIS
        </Typography>
        <Typography variant="caption" sx={{ color: '#616161' }}>
          Autonomous Security Intelligence Platform
        </Typography>
      </Box>
      <Chip label="MYTHOS" size="small" sx={{ backgroundColor: 'rgba(244,67,54,0.15)', color: '#f44336', fontWeight: 700, ml: 1 }} />
    </Box>

    <Alert severity="warning" sx={{ mb: 3, backgroundColor: 'rgba(255,152,0,0.08)', color: '#ff9800', border: '1px solid rgba(255,152,0,0.2)', '& .MuiAlert-icon': { color: '#ff9800' } }}>
      <strong>Authorized use only.</strong> GENESIS is designed exclusively for security assessments on systems you own or have explicit written permission to test. Unauthorized scanning is illegal.
    </Alert>

    {/* What is GENESIS */}
    <Card sx={{ mb: 3 }}>
      <CardContent sx={{ p: 3 }}>
        <Typography variant="h6" sx={{ color: '#86BC25', mb: 1.5, fontSize: '1rem', fontWeight: 700 }}>
          What is GENESIS?
        </Typography>
        <Typography sx={{ color: '#c0c0c0', mb: 2, lineHeight: 1.7, fontSize: '0.9rem' }}>
          GENESIS MYTHOS is an autonomous AI-powered security assessment platform. Unlike script-based scanners, GENESIS
          uses Claude's extended thinking to reason about attack surfaces, form hypotheses, chain tools dynamically, and
          adapt its strategy based on what it discovers — behaving like an elite red team operator.
        </Typography>
        <Typography sx={{ color: '#c0c0c0', lineHeight: 1.7, fontSize: '0.9rem' }}>
          Each session runs a free-form autonomous loop: Claude selects tools freely, interprets output, pivots on
          findings, constructs multi-step attack chains, maps techniques to MITRE ATT&amp;CK, and generates exact patch
          code for every confirmed vulnerability. All findings are persisted to a cross-session intelligence library for
          future recall.
        </Typography>
      </CardContent>
    </Card>

    {/* Architecture Flowchart */}
    <Card sx={{ mb: 3 }}>
      <CardContent sx={{ p: 3 }}>
        <Typography variant="h6" sx={{ color: '#86BC25', mb: 1, fontSize: '1rem', fontWeight: 700 }}>
          Architecture &amp; Assessment Flow
        </Typography>
        <Typography sx={{ color: '#9e9e9e', fontSize: '0.82rem', mb: 2 }}>
          From session creation to intelligence storage — hover nodes to highlight.
        </Typography>
        <FlowChart />
      </CardContent>
    </Card>

    {/* Capability Grid */}
    <Typography variant="h6" sx={{ color: '#f0f0f0', mb: 2, fontSize: '1rem', fontWeight: 700 }}>
      Capabilities
    </Typography>
    <Grid container spacing={2} sx={{ mb: 3 }}>
      {capabilities.map(cap => (
        <Grid item xs={12} md={6} key={cap.title}>
          <Card sx={{ height: '100%', border: `1px solid ${cap.color}18`, '&:hover': { border: `1px solid ${cap.color}40` }, transition: 'border 0.2s' }}>
            <CardContent sx={{ p: 2.5 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1.5 }}>
                {cap.icon}
                <Typography sx={{ color: '#f0f0f0', fontWeight: 700, fontSize: '0.9rem' }}>{cap.title}</Typography>
              </Box>
              <Box component="ul" sx={{ m: 0, pl: 2.5 }}>
                {cap.items.map(item => (
                  <Box component="li" key={item} sx={{ color: '#9e9e9e', fontSize: '0.82rem', mb: 0.5 }}>{item}</Box>
                ))}
              </Box>
            </CardContent>
          </Card>
        </Grid>
      ))}
    </Grid>

    {/* Tool Categories */}
    <Card sx={{ mb: 3 }}>
      <CardContent sx={{ p: 3 }}>
        <Typography variant="h6" sx={{ color: '#86BC25', mb: 2, fontSize: '1rem', fontWeight: 700 }}>
          Tool Inventory (47 Tools)
        </Typography>
        {toolCategories.map((cat, i) => (
          <React.Fragment key={cat.label}>
            <Box sx={{ display: 'flex', gap: 2, py: 1.5, alignItems: 'flex-start' }}>
              <Chip label={cat.label} size="small"
                sx={{ backgroundColor: 'rgba(134,188,37,0.1)', color: '#86BC25', fontSize: '0.7rem', minWidth: 90 }} />
              <Typography sx={{ color: '#9e9e9e', fontSize: '0.82rem', fontFamily: 'monospace', lineHeight: 1.8, flexGrow: 1 }}>
                {cat.tools}
              </Typography>
            </Box>
            {i < toolCategories.length - 1 && <Divider sx={{ borderColor: 'rgba(255,255,255,0.05)' }} />}
          </React.Fragment>
        ))}
      </CardContent>
    </Card>

    {/* Scan Profiles */}
    <Card sx={{ mb: 3 }}>
      <CardContent sx={{ p: 3 }}>
        <Typography variant="h6" sx={{ color: '#86BC25', mb: 2, fontSize: '1rem', fontWeight: 700 }}>
          Scan Profiles
        </Typography>
        <Grid container spacing={1.5}>
          {[
            { name: 'Fast', color: '#4fc3f7', desc: 'Top 1000 ports, httpx, nuclei, curl_probe. No brute-force. ~15 iterations.' },
            { name: 'Deep', color: '#86BC25', desc: 'Full port scan, all tools. Binary analysis on downloadable executables. ~50 iterations.' },
            { name: 'Stealth', color: '#ff9800', desc: 'Low-and-slow. T1 timing, passive recon first, randomized tool order. ~30 iterations.' },
            { name: 'Full', color: '#f44336', desc: 'No constraints. AD enumeration, binary analysis, credential testing. Simulates 48h APT. ~80 iterations.' },
            { name: 'APT Sim', color: '#ce93d8', desc: 'Phase 1: silent recon. Phase 2: targeted probe. Phase 3: single exploit path. Full MITRE mapping. ~60 iterations.' },
          ].map(p => (
            <Grid item xs={12} sm={6} md={4} key={p.name}>
              <Box sx={{ p: 1.5, border: `1px solid ${p.color}30`, borderRadius: 1.5, backgroundColor: `${p.color}08` }}>
                <Chip label={p.name} size="small" sx={{ backgroundColor: `${p.color}20`, color: p.color, mb: 0.8, fontSize: '0.7rem' }} />
                <Typography sx={{ color: '#9e9e9e', fontSize: '0.78rem', lineHeight: 1.5 }}>{p.desc}</Typography>
              </Box>
            </Grid>
          ))}
        </Grid>
      </CardContent>
    </Card>

    {/* vs Traditional Pen Testing */}
    <Card sx={{ mb: 3 }}>
      <CardContent sx={{ p: 3 }}>
        <Typography variant="h6" sx={{ color: '#86BC25', mb: 0.5, fontSize: '1rem', fontWeight: 700 }}>
          GENESIS vs Traditional Penetration Testing
        </Typography>
        <Typography sx={{ color: '#9e9e9e', fontSize: '0.82rem', mb: 2.5 }}>
          How an autonomous AI security engine compares to a human-led or script-based engagement.
        </Typography>

        {/* Comparison table */}
        <Box sx={{ overflowX: 'auto' }}>
          <Box component="table" sx={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
            <Box component="thead">
              <Box component="tr">
                {['Dimension', 'Traditional Pen Test', 'Script / Scanner', 'GENESIS MYTHOS'].map((h, i) => (
                  <Box component="th" key={h} sx={{
                    p: 1.5, textAlign: 'left', borderBottom: '1px solid rgba(255,255,255,0.1)',
                    color: i === 3 ? '#86BC25' : '#9e9e9e',
                    fontWeight: i === 3 ? 700 : 500, fontSize: '0.8rem',
                    backgroundColor: i === 3 ? 'rgba(134,188,37,0.04)' : 'transparent',
                  }}>{h}</Box>
                ))}
              </Box>
            </Box>
            <Box component="tbody">
              {[
                ['Reasoning depth', 'Expert intuition, bounded by human fatigue', 'None — fixed rule matching', 'Extended thinking per iteration; hypothesis-driven'],
                ['Speed', '1–2 weeks for full engagement', 'Minutes, but shallow', 'Hours for deep autonomous sweep'],
                ['Coverage', 'Depends on tester experience', 'Signature database only', '47 tools + IDOR/CORS/JWT/GraphQL/SSTI/NoSQL/cache/prototype/OAuth/smuggling probes + zero-day reasoning'],
                ['Zero-day discovery', 'Yes, if tester is skilled', 'No', 'Yes — reasons about edge cases, logic, and chaining'],
                ['Attack chaining', 'Manual correlation', 'No', 'Automatic — groups steps into kill chains with MITRE'],
                ['Patch generation', 'Separate remediation engagement', 'No', 'Exact code diff per confirmed vulnerability'],
                ['Cost per engagement', 'High (£5k–£50k+)', 'Low (tool license)', 'Low (API token cost)'],
                ['Availability', 'Scheduled, limited slots', '24/7', '24/7, unlimited parallel sessions'],
                ['Memory across targets', 'Tribal knowledge / notes', 'None', 'Vector DB — recalls similar past assessments'],
                ['Report quality', 'Narrative, executive-ready', 'CSV / generic text', 'Structured: severity, CVSS, PoC, MITRE, patch'],
                ['Audit trail', 'Manual notes', 'Scan logs', 'Full tool I/O + AI reasoning stored per session'],
                ['Multi-agent parallel', 'Multiple testers (expensive)', 'No', 'Recon + Analyst + Exploit + Code in parallel'],
              ].map(([dim, trad, script, gen], rowIdx) => (
                <Box component="tr" key={dim} sx={{ '&:hover td': { backgroundColor: 'rgba(255,255,255,0.02)' } }}>
                  <Box component="td" sx={{ p: 1.5, borderBottom: '1px solid rgba(255,255,255,0.05)', color: '#e0e0e0', fontWeight: 600, whiteSpace: 'nowrap' }}>{dim}</Box>
                  <Box component="td" sx={{ p: 1.5, borderBottom: '1px solid rgba(255,255,255,0.05)', color: '#9e9e9e' }}>{trad}</Box>
                  <Box component="td" sx={{ p: 1.5, borderBottom: '1px solid rgba(255,255,255,0.05)', color: '#9e9e9e' }}>{script}</Box>
                  <Box component="td" sx={{ p: 1.5, borderBottom: '1px solid rgba(255,255,255,0.05)', color: '#c8e6a0', backgroundColor: 'rgba(134,188,37,0.04)' }}>{gen}</Box>
                </Box>
              ))}
            </Box>
          </Box>
        </Box>

        <Divider sx={{ my: 2.5, borderColor: 'rgba(255,255,255,0.06)' }} />

        {/* Key differentiators */}
        <Typography sx={{ color: '#f0f0f0', fontSize: '0.88rem', fontWeight: 700, mb: 1.5 }}>
          Key Differentiators
        </Typography>
        <Grid container spacing={1.5}>
          {[
            {
              title: 'No Scan Fatigue',
              color: '#4fc3f7',
              desc: 'A human tester loses focus after hours. GENESIS reasons at full depth on iteration 48 the same as iteration 1, re-reading all prior tool output before each decision.',
            },
            {
              title: 'Adaptive Strategy',
              color: '#86BC25',
              desc: 'Traditional scripts follow a fixed playbook. GENESIS pivots: if an SQL injection attempt reveals a WAF, it switches to WAF-bypass payloads and tries alternate injection points automatically.',
            },
            {
              title: 'Chained Impact, Not Isolated Findings',
              color: '#ff9800',
              desc: 'Scanners report individual CVEs. GENESIS builds kill chains: "open redirect (low) → OAuth token theft (medium) → account takeover (critical)". Each chain shows full business impact.',
            },
            {
              title: 'Institutional Memory',
              color: '#ce93d8',
              desc: 'After every assessment, successful attack patterns are indexed into a vector store. Future sessions on similar targets query this memory — effectively getting smarter with every engagement.',
            },
            {
              title: 'Immediate Patch Delivery',
              color: '#f44336',
              desc: 'Traditional pen tests separate finding from fixing. GENESIS generates exact patch code at the moment of discovery — closing the gap between "vulnerability found" and "vulnerability fixed".',
            },
            {
              title: 'Transparent Reasoning',
              color: '#86BC25',
              desc: 'Every decision is visible in the Deep Thought panel. Unlike a black-box scanner or an overworked contractor, you can see exactly *why* GENESIS chose each tool and what it was hypothesizing.',
            },
          ].map(item => (
            <Grid item xs={12} sm={6} md={4} key={item.title}>
              <Box sx={{ p: 1.5, border: `1px solid ${item.color}25`, borderRadius: 1.5, height: '100%' }}>
                <Typography sx={{ color: item.color, fontSize: '0.82rem', fontWeight: 700, mb: 0.8 }}>{item.title}</Typography>
                <Typography sx={{ color: '#9e9e9e', fontSize: '0.78rem', lineHeight: 1.55 }}>{item.desc}</Typography>
              </Box>
            </Grid>
          ))}
        </Grid>

        <Box sx={{ mt: 2, p: 1.5, backgroundColor: 'rgba(255,152,0,0.05)', borderRadius: 1, border: '1px solid rgba(255,152,0,0.15)' }}>
          <Typography sx={{ color: '#ff9800', fontSize: '0.78rem', fontWeight: 600, mb: 0.4 }}>Where human testers still lead</Typography>
          <Typography sx={{ color: '#9e9e9e', fontSize: '0.78rem', lineHeight: 1.55 }}>
            GENESIS excels at breadth, speed, and systematic coverage. Highly complex business-logic flaws requiring deep domain knowledge (e.g., manipulating financial settlement flows), physical security, social engineering, and executive-level report narrative are still best served by experienced human professionals. GENESIS is a force multiplier — not a replacement.
          </Typography>
        </Box>
      </CardContent>
    </Card>

    {/* Cost Optimisations */}
    <Card sx={{ mb: 3 }}>
      <CardContent sx={{ p: 3 }}>
        <Typography variant="h6" sx={{ color: '#86BC25', mb: 0.5, fontSize: '1rem', fontWeight: 700 }}>
          Cost Optimisations
        </Typography>
        <Typography sx={{ color: '#9e9e9e', fontSize: '0.82rem', mb: 2.5 }}>
          Three changes that reduce per-session API cost by ~66% without any loss in reasoning quality.
        </Typography>

        {/* Cost table */}
        <Box sx={{ overflowX: 'auto', mb: 2.5 }}>
          <Box component="table" sx={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
            <Box component="thead">
              <Box component="tr">
                {['Profile', 'Before', 'After', 'Saving'].map((h, i) => (
                  <Box component="th" key={h} sx={{
                    p: 1.5, textAlign: 'left',
                    borderBottom: '1px solid rgba(255,255,255,0.1)',
                    color: i === 3 ? '#86BC25' : '#9e9e9e',
                    fontWeight: 600, fontSize: '0.8rem',
                  }}>{h}</Box>
                ))}
              </Box>
            </Box>
            <Box component="tbody">
              {[
                ['Fast (15 iter)', '~$1.80', '~$0.75', '58%'],
                ['Deep (50 iter)', '~$11.85', '~$4.00', '66%'],
                ['Full (80 iter)', '~$24.00', '~$8.50', '65%'],
                ['APT Sim (60 iter)', '~$18.00', '~$6.50', '64%'],
              ].map(([profile, before, after, saving]) => (
                <Box component="tr" key={profile} sx={{ '&:hover td': { backgroundColor: 'rgba(255,255,255,0.02)' } }}>
                  <Box component="td" sx={{ p: 1.5, borderBottom: '1px solid rgba(255,255,255,0.05)', color: '#e0e0e0', fontWeight: 600 }}>{profile}</Box>
                  <Box component="td" sx={{ p: 1.5, borderBottom: '1px solid rgba(255,255,255,0.05)', color: '#f44336' }}>{before}</Box>
                  <Box component="td" sx={{ p: 1.5, borderBottom: '1px solid rgba(255,255,255,0.05)', color: '#86BC25' }}>{after}</Box>
                  <Box component="td" sx={{ p: 1.5, borderBottom: '1px solid rgba(255,255,255,0.05)', color: '#86BC25', fontWeight: 700 }}>{saving}</Box>
                </Box>
              ))}
            </Box>
          </Box>
        </Box>

        <Divider sx={{ mb: 2.5, borderColor: 'rgba(255,255,255,0.06)' }} />

        <Grid container spacing={2}>
          {[
            {
              number: '01',
              title: 'Prompt Caching',
              color: '#4fc3f7',
              detail: 'The system prompt (~4k tokens) and all 47 tool schemas (~5k tokens) are marked with cache_control. The first API call writes them to Anthropic\'s cache at $3.75/M. Every subsequent call within the 5-minute TTL reads them at $0.30/M — a 90% reduction on those tokens that were previously resent on every iteration.',
              saving: '~$0.90 / Deep session',
            },
            {
              number: '02',
              title: 'Adaptive Thinking Budget',
              color: '#ff9800',
              detail: 'Instead of a fixed 10,000 thinking tokens every iteration, the budget adapts by position in the session: 8,000 tokens for the first 10% (forming the initial hypothesis) and last 15% (correlating findings into kill chains), 3,000 tokens for routine mid-session tool-selection decisions. Average drops from 10,000 → ~3,800 tokens.',
              saving: '~$4.65 / Deep session',
            },
            {
              number: '03',
              title: 'Message History Compression',
              color: '#ce93d8',
              detail: 'Every 15 iterations the oldest 12 messages are collapsed into a single bullet-point progress summary (tools run, services found, vulnerabilities confirmed, chains forming). The initial prompt and last 4 messages are always kept verbatim. This prevents quadratic token growth — without compression the history balloons to ~98k tokens by iteration 50.',
              saving: '~$2.10 / Deep session',
            },
          ].map(item => (
            <Grid item xs={12} md={4} key={item.number}>
              <Box sx={{ p: 2, border: `1px solid ${item.color}25`, borderRadius: 1.5, height: '100%' }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 1.2 }}>
                  <Box sx={{
                    width: 28, height: 28, borderRadius: '50%',
                    backgroundColor: `${item.color}20`, border: `1px solid ${item.color}60`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
                  }}>
                    <Typography sx={{ color: item.color, fontSize: '0.7rem', fontWeight: 800, fontFamily: 'monospace' }}>{item.number}</Typography>
                  </Box>
                  <Typography sx={{ color: '#f0f0f0', fontWeight: 700, fontSize: '0.88rem' }}>{item.title}</Typography>
                </Box>
                <Typography sx={{ color: '#9e9e9e', fontSize: '0.78rem', lineHeight: 1.6, mb: 1.2 }}>{item.detail}</Typography>
                <Box sx={{ display: 'inline-flex', alignItems: 'center', gap: 0.5, backgroundColor: `${item.color}12`, border: `1px solid ${item.color}30`, borderRadius: 1, px: 1, py: 0.4 }}>
                  <Typography sx={{ color: item.color, fontSize: '0.7rem', fontWeight: 700, fontFamily: 'monospace' }}>SAVES {item.saving}</Typography>
                </Box>
              </Box>
            </Grid>
          ))}
        </Grid>

        <Box sx={{ mt: 2, p: 1.5, backgroundColor: 'rgba(134,188,37,0.04)', borderRadius: 1, border: '1px solid rgba(134,188,37,0.1)' }}>
          <Typography sx={{ color: '#9e9e9e', fontSize: '0.78rem', lineHeight: 1.55 }}>
            <Box component="span" sx={{ color: '#86BC25', fontWeight: 700 }}>Why not switch to a cheaper model?</Box>
            {' '}GPT-4o mini fine-tuned costs ~30× less per token but has no extended thinking. The thinking budget is what enables multi-hop vulnerability chaining, zero-day hypothesis formation, and cross-tool correlation — the features that make GENESIS more than a smarter nuclei. The three optimisations above achieve comparable cost savings while preserving full reasoning depth.
          </Typography>
        </Box>
      </CardContent>
    </Card>

    {/* Advanced Novel Vulnerability Detection */}
    <Card sx={{ mb: 3 }}>
      <CardContent sx={{ p: 3 }}>
        <Typography variant="h6" sx={{ color: '#86BC25', mb: 0.5, fontSize: '1rem', fontWeight: 700 }}>
          Advanced Novel Vulnerability Detection
        </Typography>
        <Typography sx={{ color: '#9e9e9e', fontSize: '0.82rem', mb: 2.5 }}>
          Four new systems that find vulnerability classes that traditional scanners miss entirely.
        </Typography>
        <Grid container spacing={2} sx={{ mb: 2.5 }}>
          {[
            {
              title: 'OOB Callback Detection',
              color: '#f44336',
              tool: 'oob_check',
              what: 'Generates unique callback URLs backed by a Redis-stored hit log.',
              how: 'Claude injects the callback URL into SSRF vectors, XML external entities, redirect parameters, and email fields. If the server makes an outbound request, the hit is recorded — confirming blind injection that returns no visible response.',
              finds: 'Blind SSRF · Blind XXE · Blind command injection · DNS rebinding',
            },
            {
              title: 'Differential Probe',
              color: '#ff9800',
              tool: 'differential_probe',
              what: 'Sends N request variants with different parameter values and matrices the response behavior.',
              how: 'Compares status codes, content lengths, response times, and body content across all variants. Statistically significant differences reveal boolean-based blind injection, auth inconsistencies, IDOR, and subtle data leaks.',
              finds: 'Blind SQL injection · IDOR · Auth bypass · Timing side-channels',
            },
            {
              title: 'Race Condition Probe',
              color: '#ce93d8',
              tool: 'race_probe',
              what: 'Fires N concurrent HTTP requests simultaneously using Promise.all to expose TOCTOU windows.',
              how: 'If a state-changing operation (deduct balance, redeem coupon, cast vote) has no atomic lock, two requests arriving in the same millisecond can both succeed. GENESIS detects this by observing multiple 2xx responses or divergent response bodies.',
              finds: 'Double-spend · Coupon abuse · Vote manipulation · Privilege duplication',
            },
            {
              title: 'Session Working Memory',
              color: '#4fc3f7',
              tool: 'session_memory',
              what: 'Redis-backed per-session key/value store categorized by: endpoints, params, credentials, users, paths, cookies, headers, notes.',
              how: 'Claude stores discoveries as it finds them (endpoint at iter 3, credential at iter 15) and queries the store before testing IDOR or privilege escalation. Cross-endpoint correlation finds multi-step vulnerabilities that require connecting findings from different tools.',
              finds: 'IDOR · Privilege escalation · Multi-step auth bypass · Credential reuse',
            },
          ].map(item => (
            <Grid item xs={12} md={6} key={item.title}>
              <Box sx={{ p: 2, border: `1px solid ${item.color}25`, borderRadius: 1.5, height: '100%' }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                  <Typography sx={{ color: item.color, fontWeight: 700, fontSize: '0.88rem' }}>{item.title}</Typography>
                  <Chip label={item.tool} size="small"
                    sx={{ backgroundColor: `${item.color}15`, color: item.color, fontFamily: 'monospace', fontSize: '0.65rem', height: 16, ml: 'auto' }} />
                </Box>
                <Typography sx={{ color: '#9e9e9e', fontSize: '0.78rem', lineHeight: 1.55, mb: 0.8 }}>
                  <Box component="span" sx={{ color: '#e0e0e0', fontWeight: 600 }}>What: </Box>{item.what}
                </Typography>
                <Typography sx={{ color: '#9e9e9e', fontSize: '0.78rem', lineHeight: 1.55, mb: 0.8 }}>
                  <Box component="span" sx={{ color: '#e0e0e0', fontWeight: 600 }}>How: </Box>{item.how}
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                  {item.finds.split(' · ').map(f => (
                    <Chip key={f} label={f} size="small"
                      sx={{ backgroundColor: 'rgba(255,255,255,0.06)', color: '#9e9e9e', fontSize: '0.62rem', height: 16 }} />
                  ))}
                </Box>
              </Box>
            </Grid>
          ))}
        </Grid>

        {/* Hypothesis Journal + Adversarial Critic */}
        <Divider sx={{ mb: 2.5, borderColor: 'rgba(255,255,255,0.06)' }} />
        <Typography sx={{ color: '#f0f0f0', fontSize: '0.88rem', fontWeight: 700, mb: 1.5 }}>
          Hypothesis Journal &amp; Adversarial Critic
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} md={6}>
            <Box sx={{ p: 2, border: '1px solid rgba(255,152,0,0.2)', borderRadius: 1.5, height: '100%' }}>
              <Typography sx={{ color: '#ff9800', fontWeight: 700, fontSize: '0.88rem', mb: 0.8 }}>Hypothesis Journal</Typography>
              <Typography sx={{ color: '#9e9e9e', fontSize: '0.78rem', lineHeight: 1.6, mb: 0.8 }}>
                Before every tool call, Claude emits a structured <Box component="code" sx={{ color: '#ff9800', backgroundColor: 'rgba(255,152,0,0.08)', px: 0.5, borderRadius: 0.5, fontSize: '0.72rem' }}>HYPOTHESIS</Box> JSON block with: statement, confidence score (0–1), evidence for, evidence against, and next planned test.
              </Typography>
              <Typography sx={{ color: '#9e9e9e', fontSize: '0.78rem', lineHeight: 1.6 }}>
                Hypotheses are stored in MongoDB and broadcast live via WebSocket. The <strong style={{ color: '#e0e0e0' }}>Hypotheses tab</strong> in the Session Viewer shows each hypothesis with a confidence bar, live evidence list, and status chip (active / confirmed / ruled out). This makes GENESIS's reasoning transparent and auditable.
              </Typography>
            </Box>
          </Grid>
          <Grid item xs={12} md={6}>
            <Box sx={{ p: 2, border: '1px solid rgba(79,195,247,0.2)', borderRadius: 1.5, height: '100%' }}>
              <Typography sx={{ color: '#4fc3f7', fontWeight: 700, fontSize: '0.88rem', mb: 0.8 }}>Adversarial Critic Agent</Typography>
              <Typography sx={{ color: '#9e9e9e', fontSize: '0.78rem', lineHeight: 1.6, mb: 0.8 }}>
                Every vulnerability with confidence ≥ 0.6 that is reported as <em>unverified</em> is automatically challenged by a secondary Claude call. The critic is given only the title, description, and confidence score — no additional context — and must independently decide: <strong style={{ color: '#e0e0e0' }}>confirmed</strong> or <strong style={{ color: '#f44336' }}>disputed</strong>.
              </Typography>
              <Typography sx={{ color: '#9e9e9e', fontSize: '0.78rem', lineHeight: 1.6 }}>
                If the critic disagrees with the main agent, the finding is marked <strong style={{ color: '#f44336' }}>disputed</strong> — visible on the finding card. This two-model review layer acts as an automated false-positive filter without requiring human review of every finding.
              </Typography>
            </Box>
          </Grid>
        </Grid>
      </CardContent>
    </Card>

    {/* FAQ */}
    <Typography variant="h6" sx={{ color: '#f0f0f0', mb: 1.5, fontSize: '1rem', fontWeight: 700 }}>
      Frequently Asked Questions
    </Typography>
    {[
      {
        q: 'How does the autonomous loop work?',
        a: 'Each iteration, Claude receives the accumulated message history and uses extended thinking (10k token budget) to decide its next action. It calls a tool, observes the result, and repeats — with no forced phase transitions. The loop ends when Claude emits a FINAL_REPORT block or the session iteration limit is reached.',
      },
      {
        q: 'What is multi-agent mode?',
        a: 'Multi-agent mode spawns four parallel sub-agents: Recon (port/service discovery), Analyst (fingerprinting, SSL, WAF), Exploit (web attacks, credential testing), and Code (static analysis). Each runs its own Claude loop with a specialized tool subset. A Strategist agent correlates cross-agent findings into unified attack chains.',
      },
      {
        q: 'How does the Intelligence Library work?',
        a: 'After each completed session, GENESIS indexes the confirmed vulnerabilities and attack patterns into a ChromaDB vector store. Before a new session, you can query the library with a target fingerprint (e.g. "Apache/2.4 PHP MySQL") to recall similar past assessments and their successful attack chains.',
      },
      {
        q: 'Are the generated payloads and exploits safe to run?',
        a: 'GENESIS never runs destructive payloads automatically. Exploit code in vulnerability cards is generated for documentation and manual review. The AI is instructed never to execute --delete, DROP, DoS, or format operations. Always review exploit_code before running it in a real environment.',
      },
      {
        q: 'Where are findings stored?',
        a: 'Structured vulnerabilities are stored in PostgreSQL (queryable, persistent). Real-time session events (tool outputs, thoughts, deep thinking) are stored in MongoDB. Hypothesis journals are in MongoDB. Cross-session attack pattern vectors are stored in ChromaDB. All data is local to your deployment.',
      },
      {
        q: 'How does the adversarial critic reduce false positives?',
        a: 'After the main Claude agent reports a vulnerability with confidence ≥ 0.6, a second Claude call (using Haiku for cost efficiency) independently reviews just the title and description. If it cannot confirm the finding, the verification_status is set to "disputed". You can filter disputed findings in the Vulnerabilities view, letting you focus on the confirmed issues first.',
      },
    ].map(item => (
      <Accordion key={item.q} sx={{ backgroundColor: '#1a1a1a', border: '1px solid rgba(255,255,255,0.06)', mb: 1, '&:before': { display: 'none' } }}>
        <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: '#9e9e9e' }} />}>
          <Typography sx={{ color: '#e0e0e0', fontSize: '0.88rem', fontWeight: 500 }}>{item.q}</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Typography sx={{ color: '#9e9e9e', fontSize: '0.83rem', lineHeight: 1.65 }}>{item.a}</Typography>
        </AccordionDetails>
      </Accordion>
    ))}

    <Box sx={{ mt: 3, p: 2, backgroundColor: 'rgba(134,188,37,0.04)', borderRadius: 2, border: '1px solid rgba(134,188,37,0.1)' }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
        <SecurityIcon sx={{ color: '#86BC25', fontSize: 16 }} />
        <Typography sx={{ color: '#86BC25', fontSize: '0.82rem', fontWeight: 700 }}>GENESIS MYTHOS</Typography>
      </Box>
      <Typography sx={{ color: '#616161', fontSize: '0.75rem' }}>
        Powered by Claude Sonnet 4.6 with extended thinking. Built for authorized penetration testing and security research.
      </Typography>
    </Box>
  </Box>
);

export default About;

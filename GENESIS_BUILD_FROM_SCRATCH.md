# GENESIS — Build From Scratch

**Goal:** rebuild the entire GENESIS platform (FastAPI backend + Celery worker + Node/TypeScript MCP server + React/MUI frontend + Postgres/MongoDB/Redis/ChromaDB + nginx) from an empty directory.

**Audience:** an engineer who has shipped web apps before but has never seen this codebase. Every step tells you *what to type, what file to create, and why it exists*. Follow sequentially — later steps assume earlier ones are done.

**Estimated time:** 6–8 hours the first time; 2–3 hours with this guide at hand.

This guide is deliberately step-numbered. When a step says "create `path/to/file.py`", create exactly that file with exactly the content below. When it says "paste the implementation from [file.py](file.py)", copy the code from the existing repo file — the full source is the source of truth; this guide is the build order.

---

## Table of Contents

0. [Prerequisites](#0-prerequisites)
1. [Project scaffolding](#1-project-scaffolding)
2. [Infrastructure first — Docker Compose](#2-infrastructure-first--docker-compose)
3. [Backend — FastAPI control plane](#3-backend--fastapi-control-plane)
4. [Backend — orchestrator engine](#4-backend--orchestrator-engine)
5. [MCP server — Node/TypeScript tool executor](#5-mcp-server--nodetypescript-tool-executor)
6. [Frontend — React / MUI / Vite](#6-frontend--react--mui--vite)
7. [First run and verification](#7-first-run-and-verification)
8. [Extending GENESIS](#8-extending-genesis)

---

## 0. Prerequisites

Install once on the build host:

| Tool | Version | Why |
|---|---|---|
| Docker Desktop (or Docker Engine + Compose v2) | 24+ | Every service runs in a container |
| Node.js | 20 LTS | MCP server + frontend build |
| Python | 3.11 | Only needed if you plan to run the backend *outside* Docker for debugging |
| An Anthropic API key | — | Claude Opus / Sonnet / Haiku are the LLMs GENESIS orchestrates |
| A target to scan | — | A deliberately-vulnerable lab (Juice Shop, DVWA, Metasploitable). **Never** point this at production or third-party property. |

Verify:

```bash
docker --version          # 24.x.x
docker compose version    # v2.x.x
node --version            # v20.x.x
```

---

## 1. Project scaffolding

### Step 1.1 — Create the root directory

```bash
mkdir GENESIS && cd GENESIS
```

### Step 1.2 — Lay out the tree

```bash
mkdir -p backend/app/{api/routes,database,models,schemas,services,websocket}
mkdir -p backend/alembic/versions
mkdir -p mcp-server/src/tools
mkdir -p frontend/src/{components,pages,services,store,types}
mkdir -p memory
touch backend/app/__init__.py
touch backend/app/api/__init__.py
touch backend/app/api/routes/__init__.py
touch backend/app/database/__init__.py
touch backend/app/models/__init__.py
touch backend/app/schemas/__init__.py
touch backend/app/services/__init__.py
touch backend/app/websocket/__init__.py
```

You should now have the same top-level shape as the reference repo:

```
GENESIS/
├── backend/          FastAPI + Celery
├── mcp-server/       Node tool executor (security-tool HTTP bridge)
├── frontend/         React SPA
├── memory/           Runtime state (Redis/Mongo volumes mount here in dev)
├── docker-compose.yml
└── .env
```

### Step 1.3 — Create `.env.example`

This is the canonical secrets template. Check it in. The real `.env` (next step) stays gitignored.

```dotenv
# backend
POSTGRES_USER=admin
POSTGRES_PASSWORD=CHANGE_ME
POSTGRES_DB=security_research
MONGODB_USER=admin
MONGODB_PASSWORD=CHANGE_ME
SECRET_KEY=CHANGE_ME_32_chars_random
API_KEY=CHANGE_ME_32_chars_random
MCP_API_KEY=CHANGE_ME_32_chars_random

# derived URLs (Docker-internal hostnames)
DATABASE_URL=postgresql+asyncpg://admin:CHANGE_ME@postgres:5432/security_research
MONGODB_URL=mongodb://admin:CHANGE_ME@mongodb:27017/security_research?authSource=admin
REDIS_URL=redis://redis:6379/0
CHROMA_HOST=chromadb
CHROMA_PORT=8000
MCP_HOST=mcp_server
MCP_PORT=3001

# llm defaults (user can override per-session via Settings UI)
ANTHROPIC_API_KEY=
LLM_MAX_TOKENS=16000
LLM_TEMPERATURE=0.7
MAX_ITERATIONS=50
SCAN_TIMEOUT=3600
```

### Step 1.4 — Create `.env` from the template

```bash
cp .env.example .env
```

Then edit it: generate real secrets (`python -c 'import secrets; print(secrets.token_urlsafe(32))'`) and replace every `CHANGE_ME`. Add your Anthropic key if you want it seeded by default.

### Step 1.5 — Create `.gitignore`

```gitignore
.env
node_modules/
__pycache__/
*.pyc
dist/
build/
.venv/
.vscode/
.idea/
*.log
memory/
```

---

## 2. Infrastructure first — Docker Compose

Build the service topology before writing any application code. Everything in §3–§6 will target these service hostnames.

### Step 2.1 — Create `docker-compose.yml`

```yaml
services:
  postgres:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER}"]
      interval: 5s

  mongodb:
    image: mongo:7
    restart: unless-stopped
    environment:
      MONGO_INITDB_ROOT_USERNAME: ${MONGODB_USER}
      MONGO_INITDB_ROOT_PASSWORD: ${MONGODB_PASSWORD}
    volumes:
      - mongodb_data:/data/db

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    volumes:
      - redis_data:/data

  chromadb:
    image: chromadb/chroma:0.5.18
    restart: unless-stopped
    volumes:
      - chroma_data:/chroma/chroma
    ports:
      - "8001:8000"   # expose for admin/debug only; not required

  mcp_server:
    build: ./mcp-server
    restart: unless-stopped
    environment:
      MCP_API_KEY: ${MCP_API_KEY}
      PORT: 3001
    ports:
      - "3001:3001"
    networks:
      - default
      - vuln-lab

  backend:
    build: ./backend
    restart: unless-stopped
    depends_on: [postgres, mongodb, redis, chromadb, mcp_server]
    env_file: .env
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000
    ports:
      - "8000:8000"
    networks:
      - default
      - vuln-lab

  worker:
    build: ./backend
    restart: unless-stopped
    depends_on: [postgres, mongodb, redis, chromadb, mcp_server]
    env_file: .env
    command: celery -A app.services.celery_app.celery_app worker -Q research --loglevel=info --concurrency=2
    networks:
      - default
      - vuln-lab

  frontend:
    build: ./frontend
    restart: unless-stopped
    depends_on: [backend]
    ports:
      - "3000:80"

networks:
  vuln-lab:
    name: genesis_vuln-lab
    driver: bridge

volumes:
  postgres_data:
  mongodb_data:
  redis_data:
  chroma_data:
```

**Why two networks?** `default` keeps DBs private. `vuln-lab` is where you attach deliberately-vulnerable target containers so GENESIS can reach them by hostname without exposing them on the host.

### Step 2.2 — Stub each Dockerfile

Create placeholder files so Compose parses — real contents arrive in their owning sections.

```bash
touch backend/Dockerfile mcp-server/Dockerfile frontend/Dockerfile
```

---

## 3. Backend — FastAPI control plane

### Step 3.1 — `backend/requirements.txt`

```
fastapi==0.115.0
uvicorn[standard]==0.32.0
sqlalchemy[asyncio]==2.0.36
asyncpg==0.30.0
psycopg2-binary==2.9.10
motor==3.6.0
redis==5.2.0
chromadb==0.5.18
anthropic==0.49.0
celery[redis]==5.4.0
alembic==1.14.0
pydantic-settings==2.6.1
httpx==0.28.0
python-multipart==0.0.12
python-dotenv==1.0.1
greenlet==3.1.1
```

### Step 3.2 — `backend/Dockerfile`

```dockerfile
FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Step 3.3 — `backend/app/config.py`

Pydantic settings — one source of truth for env vars.

```python
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str
    mongodb_url: str
    redis_url: str = "redis://redis:6379/0"
    chroma_host: str = "chromadb"
    chroma_port: int = 8000
    mcp_host: str = "mcp_server"
    mcp_port: int = 3001
    api_key: str = ""
    mcp_api_key: str = ""
    secret_key: str = ""
    anthropic_api_key: str = ""
    claude_model: str = "claude-opus-4-7"
    llm_max_tokens: int = 16000
    llm_temperature: float = 0.7
    max_iterations: int = 50
    scan_timeout: int = 3600

    @property
    def mcp_base_url(self) -> str:
        return f"http://{self.mcp_host}:{self.mcp_port}"

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")

settings = Settings()
```

### Step 3.4 — Database clients

Create four files, one per data store. Full implementations live in the reference repo — what matters is that each exposes async-safe accessors.

**`backend/app/database/postgres.py`** — SQLAlchemy async engine, `get_db()` dependency, `create_tables()` on startup, `init_default_settings()` to seed the `app_settings` table.

**`backend/app/database/mongodb.py`** — motor client with lazy `_get_db()`, accessors per collection (`get_agent_thoughts_collection`, `get_tool_outputs_collection`, `get_deep_thoughts_collection`, `get_hypothesis_journals_collection`, `get_vulnerability_metadata_collection`), and an `init_indexes()` coroutine called at startup. Index every collection on `session_id`.

**`backend/app/database/redis_client.py`** — async redis client + `publish_session_message(session_id, data)` helper (uses pub/sub on channel `genesis:session:{id}`).

**`backend/app/database/chroma_client.py`** — HTTP client pointing at the chromadb service; two collections (`attack_patterns`, `attack_techniques`, plus `vulnerability_embeddings` for search-by-description).

Copy the exact file bodies from [backend/app/database/](backend/app/database/).

### Step 3.5 — Models

**`backend/app/models/base.py`** — SQLAlchemy `Base`, `TimestampMixin` (`created_at`, `updated_at`), `UUIDMixin` (`id = UUID(as_uuid=True), default=uuid4`).

**`backend/app/models/session.py`** — `ResearchSession`: `id`, `target_ip`, `target_hostname`, `status` (`pending|running|paused|completed|failed|stopped`), `phase`, `scan_profile`, `agent_mode`, `iteration`, `vulnerability_count`, `critical_count`, `high_count`, `network_topology` (JSON), `config` (JSON), `summary`, `completed_at`. Plus `AppSettings` (key / value / value_type).

**`backend/app/models/vulnerability.py`** — see [backend/app/models/vulnerability.py](backend/app/models/vulnerability.py). Critical columns for Tier-1: `verification_status`, `verification_output` (audit text), `attack_chain_id`, `chain_position`, `mitre_techniques` (JSON), `is_zero_day`, `confidence`, `exploit_code`, `patch_code`.

### Step 3.6 — Schemas (Pydantic request/response)

Under `backend/app/schemas/`: `session.py` (SessionCreate, SessionRead, SessionList, AgentThoughtRead, ToolOutputRead), `vulnerability.py` (VulnerabilityRead, VulnerabilityList), `settings.py` (TestConnectionResult). Keep them thin — just mirror the SQLAlchemy shapes for the JSON API.

### Step 3.7 — Alembic

```bash
cd backend
alembic init alembic
```

Edit `alembic.ini` and `alembic/env.py` to pull the URL from `app.config.settings.database_url` and import `Base.metadata` from `app.models.base`. Then:

```bash
alembic revision --autogenerate -m "initial schema"
alembic upgrade head   # run this against the live Postgres container
```

### Step 3.8 — Routes

Create these files under `backend/app/api/routes/`. Each one is a small `APIRouter`; details in [backend/app/api/routes/](backend/app/api/routes/).

| File | Prefix | What it does |
|---|---|---|
| `health.py` | `/health`, `/health/detailed` | Liveness + per-service probe (postgres, mongo, redis, chroma, mcp). Public — no API key. |
| `sessions.py` | `/sessions` | CRUD + `/start`, `/pause`, `/resume`, `/stop`. `/start` dispatches the Celery task. |
| `vulnerabilities.py` | `/vulnerabilities` | List, get, search (ChromaDB similarity). |
| `settings.py` | `/settings` | Get/update, `/test-llm`, `/test-mcp`. **Redact `llm_api_key` in the GET response.** |
| `tools.py` | `/tools` | Proxy to MCP `/tools` and `/tools/test-all`. |
| `intelligence.py` | `/intelligence` | List patterns, search patterns. |
| `session_memory.py` | `/session-memory` | Per-session KV store (Redis-backed, category-scoped). |
| `callback.py` | `/callback` | OOB token generate/hit/check. The `/hit/{token}` endpoint stays unauthenticated (targets can't sign requests). |

Then `backend/app/api/router.py` collects them:

```python
from fastapi import APIRouter
from app.api.routes import (health, sessions, vulnerabilities, settings,
                            tools, intelligence, session_memory, callback)

router = APIRouter()
router.include_router(health.router, prefix="/health", tags=["health"])
router.include_router(sessions.router, prefix="/sessions", tags=["sessions"])
router.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["vulnerabilities"])
router.include_router(settings.router, prefix="/settings", tags=["settings"])
router.include_router(tools.router, prefix="/tools", tags=["tools"])
router.include_router(intelligence.router, prefix="/intelligence", tags=["intelligence"])
router.include_router(session_memory.router, prefix="/session-memory", tags=["session-memory"])
router.include_router(callback.router, prefix="/callback", tags=["callback"])
```

### Step 3.9 — WebSocket

**`backend/app/websocket/manager.py`** — `ConnectionManager` with a dict of `session_id -> [WebSocket]`. On connect, subscribe to Redis channel `genesis:session:{id}` and relay messages to every socket for that session.

**`backend/app/websocket/router.py`** — one endpoint `/ws/{session_id}` that accepts the socket, calls `manager.connect()`, and blocks on `receive_text()` until disconnect (the server-to-client direction is fully server-pushed).

### Step 3.10 — `backend/app/main.py`

Tie everything together. The file [backend/app/main.py](backend/app/main.py) has the canonical version; the critical shape:

```python
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import hmac, os, logging
from contextlib import asynccontextmanager

from app.api.router import router as api_router
from app.websocket.router import router as ws_router

_API_KEY = os.getenv("API_KEY", "")

@asynccontextmanager
async def lifespan(app):
    # startup: create tables, init mongo indexes, ping redis
    from app.database.postgres import create_tables, init_default_settings
    from app.database.mongodb import init_indexes
    from app.database.redis_client import get_redis
    await create_tables()
    await init_default_settings()
    await init_indexes()
    await (await get_redis()).ping()
    yield
    # shutdown: dispose pools

app = FastAPI(title="GENESIS", lifespan=lifespan,
              docs_url=None if _API_KEY else "/docs")

app.add_middleware(CORSMiddleware,
                   allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
                   allow_credentials=False,
                   allow_methods=["GET", "POST", "PUT", "OPTIONS"],
                   allow_headers=["Content-Type", "X-API-Key"])

_UNAUTH_PATHS = {"/", "/health", "/api/v1/health"}
_UNAUTH_PREFIXES = ("/api/v1/callback/hit/",)

@app.middleware("http")
async def api_key_mw(request: Request, call_next):
    if not _API_KEY:
        return await call_next(request)
    if request.url.path in _UNAUTH_PATHS: return await call_next(request)
    if any(request.url.path.startswith(p) for p in _UNAUTH_PREFIXES):
        return await call_next(request)
    if request.url.path.startswith("/ws/"):
        token = request.query_params.get("token", "")
        if token and hmac.compare_digest(token.encode(), _API_KEY.encode()):
            return await call_next(request)
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
    provided = request.headers.get("X-API-Key", "")
    if provided and hmac.compare_digest(provided.encode(), _API_KEY.encode()):
        return await call_next(request)
    return JSONResponse(status_code=401, content={"detail": "Invalid or missing X-API-Key header"})

app.include_router(api_router, prefix="/api/v1")
app.include_router(ws_router)
```

**Boot smoke test:**

```bash
docker compose up -d postgres mongodb redis chromadb
docker compose up --build backend
# visit http://localhost:8000/health — should return {"status": "healthy"}
```

---

## 4. Backend — orchestrator engine

This is the heart of GENESIS. It runs inside the Celery worker.

### Step 4.1 — `backend/app/services/celery_app.py`

```python
from celery import Celery
from app.config import settings

celery_app = Celery(
    "genesis",
    broker=settings.redis_url,
    backend=settings.redis_url,
)
celery_app.conf.task_routes = {
    "app.services.tasks.run_research_session": {"queue": "research"},
}
celery_app.conf.worker_prefetch_multiplier = 1
celery_app.conf.task_acks_late = True
```

### Step 4.2 — `backend/app/services/tasks.py`

```python
import asyncio
from app.services.celery_app import celery_app

@celery_app.task(
    bind=True,
    name="app.services.tasks.run_research_session",
    queue="research",
    max_retries=0,
    time_limit=3700,
    soft_time_limit=3600,
)
def run_research_session(self, session_id: str, target_ip: str) -> dict:
    from app.services.ai_orchestrator import AIOrchestrator
    orch = AIOrchestrator()
    asyncio.run(orch.run_session(session_id, target_ip))
    return {"session_id": session_id, "status": "done"}
```

### Step 4.3 — `backend/app/services/mcp_client.py`

Thin HTTP client. One method: `execute_tool(name, params) -> {"output": str, "parsed": dict}`. Talks to `settings.mcp_base_url + "/tools/execute"`, sets `X-API-Key: settings.mcp_api_key`, handles httpx timeouts.

### Step 4.4 — `backend/app/services/intelligence_library.py`

Two ChromaDB collections (`attack_patterns` for session aggregates, `attack_techniques` for per-vuln techniques with `success` flag). Full implementation at [backend/app/services/intelligence_library.py](backend/app/services/intelligence_library.py). Key methods:

- `recall_patterns(target, n=5)` — session-level similarity
- `recall_techniques(target, n=8)` — per-technique similarity with positive/negative split
- `store_session_patterns(session_id, db)` — called at session complete; reads `vulnerabilities` table + `vulnerability_metadata` Mongo collection and writes both collections

### Step 4.5 — `backend/app/services/attack_chain.py`

Post-session service that groups confirmed vulnerabilities into `AttackChain` dataclasses by shared `attack_chain_id`, port/service proximity, and ChromaDB similarity. Exposes `AttackChainService.get_chains(session_id)` used by the frontend AttackGraph page.

### Step 4.6 — `backend/app/services/ai_orchestrator.py`

**The heart of the system.** Roughly 1600 lines once complete. Build it in layers.

**Layer 1 — constants:**

- `MYTHOS_SYSTEM_PROMPT` — the multi-thousand-character directive prompt covering hypothesis format, OOB usage, differential testing, zero-day reasoning, attack-chain tracking, MITRE mapping, patch generation, vulnerability output format with evidence rules, the `## Rules` block. Full text in the reference file.
- `SCAN_PROFILES` — dict mapping profile name (`fast|deep|stealth|full|apt_sim`) to `{"max_iter": int, "instructions": str}`.
- `TOOL_SCHEMAS` — a list of ~47 tool schema dicts in Anthropic tool-use format. Each has `name`, `description`, `input_schema` (JSON Schema). Keep this list in the same file for caching purposes.
- `_BLIND_VULN_KEYWORDS` — tuple of strings used to detect blind-class vulns (`blind`, `oob`, `time-based`, etc).
- `_CHAIN_SUGGESTIONS` — list of `(keyword, suggestion_text)` tuples for the chain nudge system (SQLi → dump schema, SSRF → metadata endpoints, etc).
- `_thinking_budget(iteration, max_iter)` — 8000 tokens at the 10% and 85% bookends, 3000 in the middle.
- `_is_blind_vuln(title, description)` + `_match_chain_suggestion(title, description)` — pure helpers.

**Layer 2 — the `AIOrchestrator` class:**

```python
class AIOrchestrator:
    def __init__(self):
        self._critic_client = None
        self._critic_model = "claude-haiku-4-5-20251001"

    async def run_session(self, session_id, target_ip):
        # 1. load app_settings, build Anthropic client, read scan_profile / agent_mode
        # 2. if agent_mode == "multi_agent": delegate to MultiAgentOrchestrator and return
        # 3. build system_prompt (MYTHOS + profile + intelligence recall)
        # 4. enable prompt caching (cache_control on system + last tool schema)
        # 5. enter the while loop:
        #    - poll session status (pause/stop)
        #    - if iteration == int(max_iter * 0.9): inject wrap-up prompt
        #    - every 15 iters: _compress_history()
        #    - call client.messages.create(thinking=..., tools=..., messages=...)
        #    - append assistant content to messages
        #    - extract thinking blocks -> _store_deep_thought + ws publish
        #    - extract text -> store_thought + extract_vulnerabilities + extract_hypotheses + extract_topology_updates
        #    - if FINAL_REPORT in text: break
        #    - if stop_reason == "tool_use": execute each via MCPClient,
        #         track sig ring-buffer (U2), build tool_result_blocks + chain nudges + wedge nudges,
        #         append as next user turn
        #    - if stop_reason == "end_turn": inject "continue your assessment" user turn (+ nudges)
        # 6. _finalize_session + _store_intelligence + publish session_complete
```

**Layer 3 — the helpers:**

- `_recall_intelligence(target)` — calls both `recall_patterns` and `recall_techniques`, formats as `### What worked` and `### Dead ends` bullets.
- `_store_intelligence(session_id)` — delegates to `IntelligenceLibrary.store_session_patterns`.
- `_extract_topology_updates()`, `_update_topology()` — parse `TOPOLOGY_UPDATE` JSON blocks, persist to `research_sessions.network_topology`.
- `_store_thought`, `_store_tool_output`, `_store_deep_thought` — Mongo inserts.
- `_extract_and_save_vulnerabilities(session_id, text) -> List[str]` — parse each `VULNERABILITY` block, call `_save_vulnerability`, collect and return chain nudges.
- `_extract_and_save_hypotheses()`, `_save_hypothesis()` — upsert on `hyp_id`, publish WS event.
- `_has_oob_hit(evidence_for)` — scans strings for 32-hex tokens, checks Redis `genesis:oob:{token}` for `hits`.
- `_adversarial_critique(title, description, confidence, evidence_for, starting_status)` — calls Haiku with strict critic-prompt, returns `confirmed|disputed|unverified`.
- `_save_vulnerability(session_id, vuln_data) -> Optional[str]` — this is where Tier-1 rules live:
    1. extract all fields including `evidence_for`, `endpoint`, `technique_tag`
    2. downgrade if rule 1 (no evidence) or rule 2 (blind without OOB hit) fires
    3. always-on critic (may promote or downgrade)
    4. write audit string to `verification_output`
    5. insert into Postgres, update session counters
    6. upsert per-vuln metadata into Mongo `vulnerability_metadata`
    7. add embedding to ChromaDB vulnerability collection
    8. if confirmed/exploited + match in `_CHAIN_SUGGESTIONS`: return the formatted nudge string; else None
- `_compress_history()` — every 15 iterations, summarize the oldest 12 messages with a Haiku call, keep the first user prompt + compressed summary + last 4 turns.

**Layer 4 — utilities at module-end:**

`_now_iso()`, `_safe_int`, `_safe_float`, `_extract_vulnerability_blocks(text)`, `_extract_hypothesis_blocks(text)`. The extractors use a bracket-matching parser (not regex) because the JSON can be deeply nested.

The full working source is [backend/app/services/ai_orchestrator.py](backend/app/services/ai_orchestrator.py). Don't hand-type it — copy it and make sure the helper function names match.

### Step 4.7 — `backend/app/services/multi_agent_orchestrator.py`

Four `SubAgent`s (recon / analyst / exploit / code), each with its own tool subset and system prompt. Phase 1 runs recon+analyst in parallel via `asyncio.gather`; Phase 2 runs exploit+code with `prior_findings` seeded from Phase 1 summaries plus the shared Redis findings list. Each `SubAgent` also publishes `SHARED_FINDING` blocks to the list during runtime and consumes fresh ones on each tool-result turn. Full source at [backend/app/services/multi_agent_orchestrator.py](backend/app/services/multi_agent_orchestrator.py).

**Boot test — start a session:**

```bash
docker compose up -d
# wait ~60s for health checks
curl -X POST http://localhost:8000/api/v1/sessions \
     -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
     -d '{"target_ip": "10.10.0.11", "scan_profile": "fast"}'
# returns {"id": "...", ...}
curl -X POST http://localhost:8000/api/v1/sessions/<id>/start \
     -H "X-API-Key: $API_KEY"
```

Watch `docker compose logs -f worker` — you should see the orchestrator loop and tool calls go out.

---

## 5. MCP server — Node/TypeScript tool executor

The MCP server is the only component that actually shells out to `nmap`, `nuclei`, etc. Keep it separate from the backend so the orchestrator never runs untrusted commands in-process.

### Step 5.1 — `mcp-server/package.json`

```json
{
  "name": "genesis-mcp-server",
  "version": "1.0.0",
  "main": "dist/index.js",
  "scripts": {
    "build": "tsc",
    "start": "node dist/index.js",
    "dev": "tsc --watch & node --watch dist/index.js"
  },
  "dependencies": {
    "express": "^4.21.0",
    "cors": "^2.8.5"
  },
  "devDependencies": {
    "@types/express": "^4.17.21",
    "@types/node": "^20.11.0",
    "typescript": "^5.7.0"
  }
}
```

### Step 5.2 — `mcp-server/tsconfig.json`

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "commonjs",
    "outDir": "dist",
    "rootDir": "src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true
  },
  "include": ["src/**/*"]
}
```

### Step 5.3 — `mcp-server/Dockerfile`

```dockerfile
FROM python:3.12-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap masscan hydra john sqlmap nikto whatweb dnsrecon \
    curl wget git build-essential \
    gobuster ffuf \
    openssl ca-certificates \
    nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# python-based tools
RUN pip install --no-cache-dir \
    theharvester bandit semgrep impacket \
    arjun xsstrike

# node mcp app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

EXPOSE 3001
CMD ["node", "dist/index.js"]
```

You can trim the apt install to the tools you actually want. Each tool corresponds to a wrapper in `src/tools/`.

### Step 5.4 — Core types and executor

**`mcp-server/src/types.ts`:**

```typescript
export interface ToolDefinition {
  name: string;
  description: string;
  category: string;
  execute: (params: Record<string, unknown>) => Promise<ToolResult>;
  availability?: () => Promise<boolean>;
}
export interface ToolResult {
  output: string;          // human-readable text
  parsed?: unknown;        // structured JSON payload consumed by the LLM
  exitCode?: number;
  durationMs?: number;
  error?: string;
}
```

**`mcp-server/src/executor.ts`:**

```typescript
import { spawn } from "node:child_process";

export function execute(
  cmd: string, args: string[], opts: { timeoutMs?: number } = {}
): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, {
      stdio: ["pipe", "pipe", "pipe"],
      shell: false,            // NEVER true — injection safety
      windowsHide: true,
    });
    const out: string[] = []; const err: string[] = [];
    child.stdout.on("data", (d) => out.push(d.toString()));
    child.stderr.on("data", (d) => err.push(d.toString()));
    const timer = setTimeout(() => child.kill("SIGTERM"), opts.timeoutMs ?? 600_000);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ stdout: out.join(""), stderr: err.join(""), code: code ?? -1 });
    });
  });
}
```

**Rule: `shell: false` always.** Never pass user input into a shell string.

### Step 5.5 — Registry

**`mcp-server/src/registry.ts`** — keeps a `Map<string, ToolDefinition>` and an `availability()` probe (tries `--help` or `-h` with a 10-second timeout). Exposes `list()`, `get(name)`, `execute(name, params)`.

### Step 5.6 — First real tool: nmap

**`mcp-server/src/tools/nmap.ts`:**

```typescript
import { ToolDefinition } from "../types";
import { execute } from "../executor";

export const nmap: ToolDefinition = {
  name: "nmap_scan",
  description: "Run an nmap port scan. Returns open ports, services, OS fingerprint.",
  category: "reconnaissance",
  async execute(params) {
    const target = String(params.target ?? "");
    if (!target) return { output: "target required", error: "invalid_params" };
    const ports = String(params.ports ?? "1-1000");
    const timing = String(params.timing ?? "T3");
    const args = ["-sV", "-O", `-${timing}`, "-p", ports, target];
    const { stdout, stderr, code } = await execute("nmap", args, { timeoutMs: 300_000 });
    return {
      output: stdout || stderr,
      parsed: { target, ports, timing, exitCode: code,
                open_ports: parseOpenPorts(stdout) },
      exitCode: code,
    };
  },
};

function parseOpenPorts(out: string): Array<{ port: number; service: string }> {
  const lines = out.split("\n");
  return lines
    .filter((l) => /\d+\/tcp\s+open/.test(l))
    .map((l) => {
      const m = l.match(/^(\d+)\/tcp\s+open\s+(\S+)/);
      return m ? { port: parseInt(m[1], 10), service: m[2] } : null;
    })
    .filter(Boolean) as Array<{ port: number; service: string }>;
}
```

Repeat the pattern for every other CLI tool (masscan, nikto, nuclei, gobuster, ffuf, sqlmap, etc.). The real repo has ~47 — start with 5–6 and grow.

### Step 5.7 — A differential probe (no CLI wrapper)

These are GENESIS's secret weapon — real TypeScript implementations using `fetch()` / `node:net`. Example skeleton for IDOR:

**`mcp-server/src/tools/idor_probe.ts`:**

```typescript
import { ToolDefinition } from "../types";

export const idorProbe: ToolDefinition = {
  name: "idor_probe",
  description: "Enumerate sequential/UUID IDs and cross-validate with two tokens to detect IDOR/BOLA.",
  category: "vulnerability-probe",
  async execute(params) {
    const base = String(params.url_template ?? "");   // "https://host/api/users/{id}"
    const ownToken = String(params.own_token ?? "");
    const altToken = String(params.alt_token ?? "");
    const startId = Number(params.start_id ?? 1);
    const range = Number(params.range ?? 10);

    const results: Array<Record<string, unknown>> = [];
    for (let i = startId; i < startId + range; i++) {
      const url = base.replace("{id}", String(i));
      const own = await fetchWith(url, ownToken);
      const alt = await fetchWith(url, altToken);
      results.push({
        id: i,
        own_status: own.status, alt_status: alt.status,
        body_differs: own.body !== alt.body,
      });
    }
    const confirmed = results.some((r) =>
      r.own_status === 200 && r.alt_status === 200 && r.body_differs);
    return {
      output: JSON.stringify(results, null, 2),
      parsed: { results, confirmed_idor: confirmed },
    };
  },
};

async function fetchWith(url: string, token: string) {
  const r = await fetch(url, { headers: { authorization: `Bearer ${token}` } });
  return { status: r.status, body: (await r.text()).slice(0, 2000) };
}
```

The shape is the same for `race_probe`, `jwt_probe`, `graphql_probe`, `cache_probe`, `cors_probe`, `http_smuggling_probe` (this one uses `node:net` raw sockets), `nosql_probe`, `prototype_pollution_probe`, `oauth_probe`, `ssti_detect`, `differential_probe`, `oob_check`. Copy from [mcp-server/src/tools/](mcp-server/src/tools/).

### Step 5.8 — The server

**`mcp-server/src/server.ts`:**

```typescript
import express from "express";
import { timingSafeEqual } from "node:crypto";
import { registry } from "./registry";
import "./tools";   // side-effect: register everything

const apiKey = process.env.MCP_API_KEY || "";
const app = express();
app.use(express.json({ limit: "10mb" }));

app.use((req, res, next) => {
  if (req.path === "/health" || !apiKey) return next();
  const provided = req.header("x-api-key") || "";
  const a = Buffer.from(provided); const b = Buffer.from(apiKey);
  if (a.length === b.length && timingSafeEqual(a, b)) return next();
  return res.status(401).json({ error: "unauthorized" });
});

app.get("/health", (_req, res) =>
  res.json({ status: "ok", tools: registry.list().length })
);

app.get("/tools", (_req, res) => res.json(registry.list()));

app.post("/tools/execute", async (req, res) => {
  const { tool, params } = req.body ?? {};
  if (typeof tool !== "string")
    return res.status(400).json({ error: "tool required" });
  const result = await registry.execute(tool, params ?? {});
  res.json(result);
});

export { app };
```

**`mcp-server/src/index.ts`:**

```typescript
import { app } from "./server";
const port = Number(process.env.PORT ?? 3001);
app.listen(port, () => console.log(`MCP server listening on :${port}`));
```

**Boot test:**

```bash
docker compose up --build mcp_server
curl -H "X-API-Key: $MCP_API_KEY" http://localhost:3001/tools
```

---

## 6. Frontend — React / MUI / Vite

### Step 6.1 — Scaffolding

```bash
cd frontend
npm create vite@latest . -- --template react-ts
npm install @mui/material @emotion/react @emotion/styled \
            @mui/icons-material react-router-dom zustand axios
```

Replace the generated `src/` with the structure below.

### Step 6.2 — `frontend/package.json` scripts

```json
"scripts": {
  "dev": "vite --host",
  "build": "tsc && vite build",
  "preview": "vite preview"
}
```

### Step 6.3 — `frontend/Dockerfile`

```dockerfile
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
```

### Step 6.4 — `frontend/nginx.conf`

```nginx
server {
  listen 80;
  location / { root /usr/share/nginx/html; try_files $uri $uri/ /index.html; }
  location /api/ { proxy_pass http://backend:8000; }
  location /ws/ {
    proxy_pass http://backend:8000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_read_timeout 86400;
  }
}
```

### Step 6.5 — API client

**`frontend/src/services/api.ts`:**

```typescript
import axios from "axios";

export const api = axios.create({ baseURL: "/api/v1", timeout: 60000 });

api.interceptors.request.use((config) => {
  const key = sessionStorage.getItem("genesis_api_key");
  if (key) config.headers["X-API-Key"] = key;
  return config;
});
```

Prefer `sessionStorage` over `localStorage` — same tab lifecycle, clears on close, reduces XSS blast radius.

### Step 6.6 — WebSocket client

**`frontend/src/services/websocket.ts`:**

```typescript
type Handler = (msg: any) => void;

export function openSessionSocket(sessionId: string, onMessage: Handler) {
  const key = sessionStorage.getItem("genesis_api_key") ?? "";
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(
    `${proto}://${window.location.host}/ws/${sessionId}?token=${encodeURIComponent(key)}`
  );
  ws.onmessage = (ev) => { try { onMessage(JSON.parse(ev.data)); } catch {} };
  ws.onerror = (e) => console.error("ws error", e);
  return () => ws.close();
}
```

Handle these event `type` values in the UI: `agent_thought`, `deep_thought`, `tool_execution`, `vulnerability_found`, `hypothesis_update`, `topology_update`, `chain_suggestion`, `loop_break`, `shared_finding`, `phase_transition`, `session_complete`, `error`.

### Step 6.7 — Pages

Scaffold one file per page in `frontend/src/pages/`:

- `LoginScreen.tsx` — one password field, stores the API key in `sessionStorage`, routes to `/dashboard`.
- `SetupWizard.tsx` — multi-step form for LLM provider, key, model, MCP host; calls `/settings`, `/settings/test-llm`, `/settings/test-mcp`; sets `setup_complete=true`.
- `Dashboard.tsx` — session list + "new session" form (target IP, scan profile, agent mode).
- `SessionViewer.tsx` — the real-time UI. Four tabs: Thoughts / Tool Outputs / Hypotheses / Attack Chains. Opens a WS, renders each event type in its own lane. Show `chain_suggestion` / `loop_break` / `shared_finding` / `phase_transition` with distinct badges.
- `Vulnerabilities.tsx` — filter + table, with `verification_status` chip (confirmed=green, disputed=orange, unverified=grey, exploited=red).
- `ToolsStatus.tsx` — health ping per tool.
- `Settings.tsx` — edit settings; the `llm_api_key` field is write-only (the GET endpoint redacts it).
- `AttackGraph.tsx` — force-directed graph from `/api/v1/sessions/{id}/attack-chains`.
- `IntelligenceDashboard.tsx` — list cross-session patterns.
- `About.tsx` — static.

### Step 6.8 — App shell

**`frontend/src/App.tsx`:** BrowserRouter; on mount fetch `/settings` — if `setup_complete !== "true"` route to `/setup`, else render the main layout (Sidebar + TopBar + `<Outlet/>`) with the routes above. If `/settings` returns 401, route to `/login`.

### Step 6.9 — Boot test

```bash
docker compose up --build frontend
# open http://localhost:3000
# login with API_KEY from .env
```

---

## 7. First run and verification

### Step 7.1 — Bring everything up

```bash
docker compose up -d
docker compose logs -f backend worker mcp_server
```

Wait ~90 seconds for all health checks to go green. Hit `http://localhost:8000/health` → `{"status":"healthy"}`.

### Step 7.2 — Spin up a legitimate target

Attach a deliberately-vulnerable container to the `vuln-lab` network:

```bash
docker run -d --rm --name juice --network genesis_vuln-lab bkimminich/juice-shop
# it's now reachable from the backend as http://juice:3000
```

### Step 7.3 — Run a session

From the UI: **New Session → Target `juice` → profile `fast` → Solo → Start**. Or via API:

```bash
curl -X POST http://localhost:8000/api/v1/sessions \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"target_ip": "juice", "scan_profile": "fast", "agent_mode": "solo"}'
# capture the returned id, then:
curl -X POST http://localhost:8000/api/v1/sessions/<id>/start -H "X-API-Key: $API_KEY"
```

### Step 7.4 — Watch the Tier-1 features fire

Open the session in the UI and confirm in the event stream:

| Feature | What to look for |
|---|---|
| **Evidence rule 1** | Any `VULNERABILITY` without `evidence_for` in the text stream should end up `unverified` in the vulnerabilities tab — check `verification_output`. |
| **Evidence rule 2** | Ask the model to run an SSRF OOB test. If it claims `confirmed` without a Redis hit on the token, it downgrades. |
| **Always-on critic** | Even `confirmed` findings get a Haiku critic pass — watch Celery logs for `_adversarial_critique`. |
| **Loop guard** | If the model retries the same tool three times, a `loop_break` event appears in the WS stream. |
| **Chain suggestion** | On any confirmed vuln matching the suggestion table, a `chain_suggestion` WS event fires and the next tool call should be on the suggested follow-up. |
| **Multi-agent `phase_transition`** | Start a session with `agent_mode=multi_agent`. Between Phase 1 and Phase 2 you'll see the `phase_transition` event containing `prior_findings`. |
| **Cross-session recall** | Run two sessions against similar Node apps. On run 2, inspect the first `agent_thought` — the system prompt addendum should show positive/negative technique bullets. |

### Step 7.5 — Smoke-test checklist

- [ ] `http://localhost:8000/health` returns `healthy`
- [ ] `http://localhost:8000/api/v1/tools` (with `X-API-Key`) returns > 30 tools
- [ ] `http://localhost:3001/health` returns `{status: "ok", tools: <n>}`
- [ ] Frontend login works, dashboard renders
- [ ] New session completes within its iteration budget
- [ ] At least one `vulnerability_found` event has `verification_status: "confirmed"`
- [ ] At least one `chain_suggestion` or `loop_break` event appears in a longer run

---

## 8. Extending GENESIS

### Adding a new CLI-backed tool

1. Write `mcp-server/src/tools/mytool.ts` exporting a `ToolDefinition`.
2. Register it in `mcp-server/src/tools/index.ts`.
3. Add the tool schema (name, description, input_schema) to `TOOL_SCHEMAS` in `backend/app/services/ai_orchestrator.py` so Claude can call it.
4. If it belongs in a specific multi-agent role, add the name to the appropriate set in `_AGENT_TOOL_SETS` in `backend/app/services/multi_agent_orchestrator.py`.
5. Rebuild both containers: `docker compose up -d --build mcp_server worker backend`.

### Adding a new vulnerability probe (differential test)

Same path as above, but the tool implementation is pure TypeScript — `fetch()` loops with response diffing, the way `idor_probe` and `jwt_probe` do. Add a sentence to `MYTHOS_SYSTEM_PROMPT` under "Advanced HTTP Vulnerability Testing" so the model knows when to reach for it.

### Adding a new chain-suggestion playbook

Append a `(keyword, suggestion_text)` tuple to `_CHAIN_SUGGESTIONS` in `ai_orchestrator.py`. First match wins, so put more specific keywords before more generic ones. Tier-1 already ships entries for SQLi, SSRF, file upload, IDOR, JWT, GraphQL, CORS, XXE, RCE, command injection, prototype pollution, SSTI, open redirect, OAuth, auth bypass.

### Rebuilding the manual

The HTML manual is generated from `GENESIS_TECHNICAL_REFERENCE.md`:

```bash
node build_manual.js
```

Edit the MD, rebuild, open `GENESIS_Manual.html`.

### Database migrations

After any change to `backend/app/models/`:

```bash
docker compose exec backend alembic revision --autogenerate -m "describe change"
docker compose exec backend alembic upgrade head
```

Review the generated SQL before running it against anything you care about.

### Where things break most often

| Symptom | Cause | Fix |
|---|---|---|
| `401 Invalid or missing X-API-Key` on `/ws/` | Token in query string doesn't match `API_KEY` env var | Ensure frontend reads from the same `API_KEY` the backend boots with |
| Orchestrator hangs with `ConnectionRefused` to `mcp_server` | MCP container not healthy yet | Add `depends_on` with `condition: service_healthy` — or wait |
| `verification_status` always `unverified` | Tier-1 evidence enforcement doing its job — Claude isn't citing concrete evidence | Verify prompt updates from §6.2 of the manual landed in `MYTHOS_SYSTEM_PROMPT` |
| Celery task silently exits | `time_limit` hit, or unhandled exception in `run_session` | `docker compose logs worker` and look for the traceback |
| ChromaDB queries return 0 results | Collection empty (first session) | Run a session end-to-end, then re-query |

---

That's the full build. The plan from zero to a running GENESIS instance is roughly: scaffold (§1) → infra (§2) → FastAPI shell (§3) → orchestrator engine (§4) → MCP server (§5) → frontend (§6) → smoke test (§7). Skip none of them — each later step expects the earlier step's hostnames, schemas, or volumes to exist.

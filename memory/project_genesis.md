---
name: GENESIS
description: GENESIS — Generative Engine for Novel Exploitation & Security Intelligence Study. Full-stack AI security research platform at C:/Users/AI-SEC-LAB/Desktop/claude/
type: project
---

**GENESIS** — Generative Engine for Novel Exploitation & Security Intelligence Study

86-file platform at `C:/Users/AI-SEC-LAB/Desktop/claude/`.

**Why:** User built this as an AI-powered autonomous vulnerability assessment platform.

**How to apply:** Use as context when user asks about this codebase or the GENESIS project.

## Stack
- Backend: FastAPI (port 8000), SQLAlchemy async, Motor, aioredis, ChromaDB, Anthropic SDK, Celery
- MCP Server: Express/TypeScript (port 3001), 15 security tools
- Frontend: React 18 + MUI v5 + Vite (port 3000)
- DBs: PostgreSQL 16 (db: security_research), MongoDB 7, Redis 7.2, ChromaDB

## Key architecture decisions
- Claude tool use agentic loop in `backend/app/services/ai_orchestrator.py`
- 5 research phases: reconnaissance → service_analysis → vulnerability_scan → exploitation → reporting
- Real-time updates: Celery worker → Redis pub/sub `session:{id}` → FastAPI WebSocket → React
- Tool name mapping in mcp_client.py: `nmap_scan` (Claude schema) → `nmap` (MCP server)
- Settings stored in PostgreSQL AppSettings table, loaded at runtime so live updates work
- Alembic migrations: `backend/alembic/versions/001_initial_schema.py`
- GENESIS identity embedded in Claude system prompt in ai_orchestrator.py

## Start commands
- Docker: `start.bat`
- Dev mode: `dev-start.bat`
- First run: open http://localhost:3000/setup

## Post-generation fixes applied
- `backend/app/services/mcp_client.py`: Fixed execute_tool to POST /tools/execute with {tool, params} body; added tool name mapping dict (_TOOL_NAME_MAP)
- `backend/requirements.txt`: Added psycopg2-binary==2.9.10

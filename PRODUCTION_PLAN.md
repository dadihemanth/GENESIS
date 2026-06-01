# GENESIS — Production Readiness Project Plan
**Generated:** 2026-05-13  
**Target Go-Live:** 2026-07-14  
**Current State:** Feature-complete v7.0, not production-hardened

---

## Executive Summary

GENESIS is architecturally complete. The blocker for production is a cluster of security and operational gaps: hardcoded credentials, no HTTPS, no rate limiting, no structured logging, and no automated test suite. This plan resolves all of them across 5 phases over 9 weeks, ending with a validated go-live.

---

## Phase Overview

| Phase | Dates | Focus | Owner |
|-------|-------|-------|-------|
| 0 | May 13–19 | Critical security fixes | Backend |
| 1 | May 20 – Jun 2 | Infrastructure hardening | DevOps |
| 2 | Jun 3–16 | Vulnerable image + test environment | QA / Backend |
| 3 | Jun 17–30 | Testing, bug triage, fixes | Full team |
| 4 | Jul 1–14 | Pre-prod review + go-live | All |

---

## Phase 0 — Critical Security Fixes
**Dates: May 13–19, 2026**  
**Blockers that prevent ANY production deployment**

### 0.1 — Secrets hardening (May 13–14)
**Files:** `.env`, `backend/app/middleware/auth.py`, `backend/alembic.ini`

- [ ] Replace all `Genesis@1234` passwords with cryptographically random 32-char values
  - `POSTGRES_PASSWORD`, `MONGODB_PASSWORD`, `NEO4J_PASSWORD`, `MINIO_ROOT_PASSWORD`
- [ ] Set `JWT_SECRET` to a 64-char random hex string (currently empty — falls back to hardcoded dev default)
- [ ] Replace `API_KEY=Gen@1234` with a strong random key
- [ ] Replace `MCP_API_KEY=Mcp@gen` with a strong random key
- [ ] Replace hardcoded `SecureP%40ssw0rd` in `backend/alembic.ini` line 62 with `%(DATABASE_URL)s`
- [ ] Verify `.env` is in `.gitignore` and has never been committed — if it has, rotate all secrets immediately
- [ ] Create `.env.production.example` documenting every required variable with generation instructions

**Test:** Start stack, confirm `warnings.warn` for JWT_SECRET no longer fires in logs.

---

### 0.2 — HTTPS / TLS (May 14–15)
**Files:** `frontend/nginx.conf`, `docker-compose.yml`

- [ ] Add TLS certificate mount to frontend nginx container (self-signed for staging, real cert for prod)
- [ ] Update `frontend/nginx.conf` to listen on 443, redirect 80 → 443
- [ ] Add HSTS header: `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- [ ] Add `X-Frame-Options: DENY`
- [ ] Add `X-Content-Type-Options: nosniff`
- [ ] Add `Referrer-Policy: strict-origin-when-cross-origin`
- [ ] Add `Content-Security-Policy` header
- [ ] Enable gzip in nginx for JSON/JS

**Test:** `curl -I https://<host>` shows all security headers. HTTP redirects to HTTPS.

---

### 0.3 — CORS production config (May 15)
**File:** `backend/app/main.py` lines 119–128

- [ ] Change `allow_origins` hardcoded list to `os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")`
- [ ] Document `CORS_ORIGINS` in `.env.production.example`

**Test:** Frontend on production domain can reach API. `curl` from unauthorized origin gets 403.

---

### 0.4 — Rate limiting (May 15–16)
**File:** `backend/app/main.py`

- [ ] Install `fastapi-limiter` (Redis-backed)
- [ ] Apply 10 req/min limit to `/api/v1/auth/login`
- [ ] Apply 60 req/min limit to all other `/api/v1/` endpoints
- [ ] Apply 5 req/min limit to session-start endpoints (expensive operations)
- [ ] Return `429 Too Many Requests` with `Retry-After` header

**Test:** Hammer `/api/v1/auth/login` 15 times in a minute, confirm 429 on attempt 11.

---

### 0.5 — Docker non-root users (May 16–17)
**Files:** `backend/Dockerfile`, `frontend/Dockerfile`, `mcp-server/Dockerfile`

- [ ] Add `adduser` + `USER` directive to each Dockerfile (no container runs as root)
- [ ] Add SHA256 checksum verification for the Docker CLI binary download in `backend/Dockerfile`
- [ ] Add `mem_limit` + `cpus` to backend, frontend, mcp_server in `docker-compose.yml`

**Test:** `docker inspect <container> | grep User` shows non-root UID.

---

### Phase 0 Exit Criteria
- Zero hardcoded secrets in any file
- JWT_SECRET set and warning suppressed
- HTTPS working with security headers
- Rate limiting active on auth endpoints
- No container running as root

---

## Phase 1 — Infrastructure Hardening
**Dates: May 20 – Jun 2, 2026**

### 1.1 — Structured JSON logging (May 20–21)
**File:** `backend/app/main.py`

- [ ] Install `python-json-logger`
- [ ] Replace `logging.basicConfig` with JSON formatter
- [ ] Add `request_id` correlation header (generate UUID per request, propagate to all log lines)
- [ ] Mask sensitive fields: API keys, passwords, token values in log output
- [ ] Configure log level from env: `LOG_LEVEL=INFO` (default), `DEBUG` for dev

**Test:** `docker logs genesis_backend | python -m json.tool` parses without error.

---

### 1.2 — Token revocation & session management (May 21–22)
**File:** `backend/app/middleware/auth.py`

- [ ] Implement Redis-backed JWT blacklist for logout
- [ ] Add `POST /api/v1/auth/logout` endpoint that blacklists the current token
- [ ] Add idle session timeout: invalidate JWT if no API call in `SESSION_IDLE_TIMEOUT` minutes (default 60)
- [ ] Add configurable `JWT_EXPIRE_HOURS` env var (document in example)

**Test:** Login, logout, confirm subsequent requests with same token return 401.

---

### 1.3 — Monitoring & metrics (May 22–26)
**Files:** new `backend/app/api/routes/metrics.py`, `docker-compose.yml`

- [ ] Add Prometheus metrics endpoint (`/metrics`) using `prometheus-fastapi-instrumentator`
  - Request count by route, latency p50/p95/p99, error rate
  - Active sessions count
  - LLM token usage counter
  - Tool call success/failure rates
- [ ] Add Prometheus + Grafana containers to `docker-compose.yml`
- [ ] Create Grafana dashboard: service health, API latency, error rate, session activity
- [ ] Add alerting rules: service down > 1 min → alert; error rate > 5% → alert

**Test:** `curl localhost:8000/metrics` shows Prometheus text format. Grafana dashboard loads.

---

### 1.4 — Database backups (May 26–27)
**Files:** new `scripts/backup.sh`, `docker-compose.yml`

- [ ] Write `scripts/backup.sh`:
  - `pg_dump` → MinIO bucket `backups/postgres/`
  - `mongodump` → MinIO bucket `backups/mongo/`
  - Neo4j online backup → MinIO
  - Run as Celery Beat task every 24h
- [ ] Add retention policy: keep 7 daily, 4 weekly, 3 monthly
- [ ] Document restore procedure in `scripts/RESTORE.md`

**Test:** Run backup script manually, confirm files appear in MinIO. Restore to new DB, verify row counts match.

---

### 1.5 — `.env.production.example` completion (May 27–28)
**File:** `.env.production.example` (new)

- [ ] Document every env variable with:
  - Description
  - Default value (or `REQUIRED`)
  - How to generate (e.g., `openssl rand -hex 32`)
- [ ] Add startup validation in `backend/app/config.py`: fail fast if any `REQUIRED` variable is empty
- [ ] Add `CORS_ORIGINS`, `JWT_SECRET`, `API_KEY`, `MCP_API_KEY`, `NEO4J_PASSWORD`, `MINIO_ROOT_USER/PASSWORD` as REQUIRED

**Test:** Start backend with a missing REQUIRED var, confirm it exits with a clear error message.

---

### 1.6 — Audit log retention & SIEM prep (May 28 – Jun 2)
**Files:** `backend/app/database/`, Celery beat tasks

- [ ] Add `audit_log` archival: rows older than 90 days move to `audit_log_archive` table
- [ ] Add `POST /api/v1/audit/export` (admin only) — JSON export of audit logs for SIEM ingestion
- [ ] Add Celery Beat task to run archival weekly

**Test:** Insert 100 audit records with old timestamps, run archival, confirm moved to archive table.

---

### Phase 1 Exit Criteria
- Structured JSON logs with correlation IDs
- Token revocation working
- Prometheus + Grafana live with alerts configured
- Database backup running on schedule
- All required env vars validated at startup

---

## Phase 2 — Test Environment & Vulnerable Target Image
**Dates: Jun 3–16, 2026**

This is the most important validation phase: build a purpose-made vulnerable Docker image, run GENESIS against it, and verify GENESIS finds the bugs that are known to exist.

---

### 2.1 — Vulnerable target image (Jun 3–6)
**New file:** `test-targets/Dockerfile.vuln-lab`

Build a single Docker image containing a stack of known, documented vulnerabilities that GENESIS should find:

```
test-targets/
  Dockerfile.vuln-lab          # main vulnerable image
  docker-compose.vuln-lab.yml  # spin up the target network
  KNOWN_VULNS.md               # ground truth: list of bugs + CVEs
  expected_results.json        # expected GENESIS findings JSON
```

**Vulnerabilities to bake in (all documented, intentional):**

| # | Vulnerability | Type | Severity |
|---|---------------|------|----------|
| 1 | SQLi in `/login` (no parameterization) | SQLI | Critical |
| 2 | Reflected XSS in `/search?q=` | XSS | High |
| 3 | Insecure Direct Object Reference on `/api/user/{id}` | IDOR | High |
| 4 | Hardcoded admin credentials in source | CWE-798 | Critical |
| 5 | Unauthenticated file read at `/files?path=../` | Path Traversal | Critical |
| 6 | SSRF via `/fetch?url=` (no allowlist) | SSRF | High |
| 7 | Weak JWT secret `secret123` | JWT | High |
| 8 | Command injection in `/ping?host=` | RCE | Critical |
| 9 | Outdated component: Flask 1.1.2 (CVE-2023-30861) | CVE | High |
| 10 | Missing rate limiting on login (brute-forceable) | Auth | Medium |
| 11 | CORS `Access-Control-Allow-Origin: *` with credentials | CORS | Medium |
| 12 | Directory listing enabled on `/static/` | Info Disclosure | Low |

**Stack:** Python Flask app + PostgreSQL + nginx reverse proxy (a realistic 3-tier target)

**Steps:**
- [ ] Write `test-targets/vulnapp/app.py` with all 12 bugs intentionally embedded
- [ ] Write `test-targets/Dockerfile.vuln-lab`
- [ ] Write `docker-compose.vuln-lab.yml` that puts vuln target on isolated network `genesis_vuln_test`
- [ ] Write `KNOWN_VULNS.md` documenting each bug with location, CVE reference, expected GENESIS tool that should find it
- [ ] Build image: `docker build -t genesis-vuln-lab:1.0 -f test-targets/Dockerfile.vuln-lab test-targets/`
- [ ] Smoke test: confirm all 12 endpoints respond before running GENESIS

**Test:** `curl http://vuln-lab:5000/health` returns 200. Manual SQLi `' OR 1=1--` in login works.

---

### 2.2 — Automated test runner (Jun 6–9)
**New file:** `tests/e2e/test_vuln_lab.py`

```python
# End-to-end test: start a GENESIS session against vuln-lab, 
# wait for completion, assert minimum finding set is present.
```

- [ ] Write pytest fixture that starts a GENESIS scan session via REST API
- [ ] Wait for session to reach `status=completed` (poll `/api/v1/sessions/{id}`)
- [ ] Assert that findings include at minimum:
  - At least 1 SQLi finding with `severity=critical`
  - At least 1 XSS finding
  - The path traversal at `/files`
  - The command injection at `/ping`
  - CVE-2023-30861 (Flask version)
- [ ] Assert `verified=true` on critical findings (oracle required)
- [ ] Assert session completed in < 30 minutes
- [ ] Assert no unhandled exceptions in session logs

**Run:** `pytest tests/e2e/test_vuln_lab.py -v --timeout=1800`

---

### 2.3 — Unit tests for core services (Jun 9–13)
**New files:** `tests/unit/`

Priority order based on audit risk:

| File | Tests to write |
|------|---------------|
| `tests/unit/test_auth.py` | JWT generation, expiry, blacklist, rate limit |
| `tests/unit/test_config.py` | Required var validation, startup failure on missing vars |
| `tests/unit/test_adversarial.py` | Red-blocked / blue-blocked handling (the 429 fix from last week) |
| `tests/unit/test_hypothesis_market.py` | Submit, vote, stake, accept |
| `tests/unit/test_llm_providers.py` | Rate limit retry, semaphore concurrency |

- [ ] Target 80% coverage on `backend/app/middleware/auth.py`
- [ ] Target 70% coverage on `backend/app/services/adversarial_agents.py`
- [ ] Add `pytest.ini` with `--cov` configuration
- [ ] Add coverage badge threshold: fail CI if < 60% overall

**Run:** `pytest tests/unit/ -v --cov=app --cov-report=term-missing`

---

### 2.4 — MCP tool smoke tests (Jun 13–16)
**New file:** `tests/smoke/test_mcp_tools.py`

- [ ] For each MCP tool in the registry: call with known-good parameters, assert non-error response
- [ ] Test against `vuln-lab` target for tools that need a live target (nmap, httpx, nikto)
- [ ] Test tool timeout handling: call with unreachable target, assert graceful timeout within 30s
- [ ] Test tool error sanitization: assert no stack traces leak in tool error responses

**Run:** `pytest tests/smoke/ -v` (requires vuln-lab network up)

---

### Phase 2 Exit Criteria
- `genesis-vuln-lab:1.0` Docker image built and documented
- GENESIS finds ≥ 8 of 12 known vulnerabilities in automated test run
- All critical findings (SQLi, path traversal, command injection) detected
- Unit test suite passing with ≥ 60% coverage
- MCP tool smoke tests all passing

---

## Phase 3 — Testing, Bug Triage & Fixes
**Dates: Jun 17–30, 2026**

### 3.1 — Full GENESIS scan against vuln-lab (Jun 17–18)
**Manual validation run**

- [ ] Start fresh GENESIS session targeting `vuln-lab` in multi-agent mode
- [ ] Run to completion, export full findings report
- [ ] Compare findings against `KNOWN_VULNS.md` ground truth
- [ ] For each missed vulnerability: create GitHub issue with label `bug/missed-finding`
- [ ] For each false positive: create issue with label `bug/false-positive`
- [ ] Document time-to-first-finding, total session duration, token cost

**Acceptance threshold:**
- Recall ≥ 80% (≥ 10/12 bugs found)
- Precision ≥ 70% (≤ 30% false positives)
- All 4 critical vulns found and verified

---

### 3.2 — Regression bug fixes (Jun 18–23)
Based on Phase 2 test failures and vuln-lab scan gaps:

**Known bugs to fix (from audit):**

- [ ] **`health.py` lazy import** — Move `__import__("sqlalchemy")` to top-level import
- [ ] **MCP server error leak** — Sanitize `String(err)` stack traces in `mcp-server/src/server.ts`
- [ ] **`replica_manager` network** — Wire up `genesis_replica_net` so spawned replicas are actually isolated
- [ ] **`dedup_threshold` unused** — Verify and wire up `DEDUP_THRESHOLD` config in orchestrator
- [ ] **`alembic.ini` credentials** — Replace hardcoded DB URL with env variable interpolation
- [ ] **ChromaDB error leaking** — Sanitize error detail in `vulnerabilities.py` line 65 before sending to client
- [ ] **WebSocket token in query param** — Move `?token=` to `Sec-WebSocket-Protocol` subprotocol header

---

### 3.3 — Performance baseline & load test (Jun 23–25)
**New file:** `tests/load/locustfile.py`

- [ ] Write Locust load test simulating 10 concurrent users:
  - Create session → start scan → poll status → retrieve findings
- [ ] Baseline targets:
  - API response time p95 < 500ms for read endpoints
  - Session start response < 2s
  - WebSocket events delivered within 1s of emission
- [ ] Run 30-minute soak test at 10 users, confirm no memory leaks or DB connection pool exhaustion
- [ ] Document results as baseline for production monitoring

**Run:** `locust -f tests/load/locustfile.py --host=http://localhost:8000 --users=10 --spawn-rate=2 --run-time=30m`

---

### 3.4 — Security scan of GENESIS itself (Jun 25–27)

Run security tooling against the GENESIS codebase and container images:

- [ ] **Trivy** container scan: `trivy image genesis_backend:latest` — fix CRITICAL CVEs
- [ ] **Bandit** Python scan: `bandit -r backend/app/` — fix HIGH severity findings
- [ ] **npm audit**: `cd mcp-server && npm audit --audit-level=high` — fix high/critical
- [ ] **OWASP Dependency-Check** on Python requirements
- [ ] **Semgrep** static analysis: `semgrep --config=p/owasp-top-ten backend/`
- [ ] Accept/document any false positives with justification

**Pass criteria:** Zero CRITICAL findings, < 5 HIGH findings with documented risk acceptance.

---

### 3.5 — User acceptance testing (Jun 27–30)

- [ ] Deploy full stack to staging environment (isolated from production network)
- [ ] Run complete scan session end-to-end on `vuln-lab` from staging URL
- [ ] Verify all UI components render correctly (Adversarial tab, Hypothesis Market, Session Viewer)
- [ ] Test multi-user scenario: 2 operators running simultaneous sessions
- [ ] Test RBAC: reviewer role cannot start sessions, read_only cannot see sensitive findings
- [ ] Test session export / PDF report generation
- [ ] Test WebSocket reconnection after 60s disconnect

---

### Phase 3 Exit Criteria
- All known bugs fixed and verified
- Vuln-lab scan recall ≥ 80%
- Load test passes with p95 < 500ms
- Zero CRITICAL CVEs in container images
- UAT sign-off from operator

---

## Phase 4 — Pre-Production Review & Go-Live
**Dates: Jul 1–14, 2026**

### 4.1 — Pre-production hardening checklist (Jul 1–3)

- [ ] All Phase 0 critical items verified in staging
- [ ] `docker-compose.prod.yml` created (differs from dev: no exposed DB ports, no debug volumes)
- [ ] All secrets loaded from environment, not from files
- [ ] Network ACLs: databases accessible only from backend containers
- [ ] Firewall rules: only ports 443 (frontend) and 22 (SSH management) exposed externally
- [ ] Backup tested: restore from yesterday's backup to new DB, verify row counts
- [ ] Runbook written: common failure scenarios with recovery steps
- [ ] Incident response contacts documented

---

### 4.2 — Final penetration test (Jul 3–7)

Self-penetration test using GENESIS against its own staging deployment:

- [ ] Run GENESIS scan against staging URL (dogfooding)
- [ ] Manually test: SQLi on all form inputs, XSS in session names, IDOR on session IDs
- [ ] Test JWT forgery: attempt to craft token with known dev secret
- [ ] Test CORS: attempt cross-origin request from unauthorized domain
- [ ] Test rate limiting: script 20 login attempts in 60s
- [ ] Test auth bypass: attempt access to admin routes with reviewer JWT
- [ ] Document all findings — fix before go-live, or accept risk in writing

---

### 4.3 — Go-live (Jul 8–14)

- [ ] **Jul 8:** Final image builds tagged as `genesis:v7.0.0-prod`
- [ ] **Jul 9:** Deploy to production, run health checks on all services
- [ ] **Jul 9:** Run `test_vuln_lab.py` against production to confirm pipeline is live
- [ ] **Jul 10:** Monitor Grafana dashboards for 24 hours, watch for anomalies
- [ ] **Jul 10:** Enable alerting (PagerDuty / email) for service health failures
- [ ] **Jul 11:** Invite first operator users, monitor audit logs
- [ ] **Jul 14:** First week post-mortem — document any issues, plan remediation

---

### Phase 4 Exit Criteria
- All services healthy in production
- E2E vuln-lab test passes against production URL
- 24-hour monitoring shows no anomalies
- Runbook in place
- Alerting configured and tested

---

## Test Plan: Vulnerable Image Scanning (Detailed)

### Target Image Specification

**Image:** `genesis-vuln-lab:1.0`  
**Base:** `python:3.11-slim` + nginx reverse proxy  
**Purpose:** Ground-truth validation of GENESIS detection capabilities

### Pre-Scan Checklist
1. Start vuln-lab: `docker-compose -f docker-compose.vuln-lab.yml up -d`
2. Verify target responds: `curl http://vuln-lab:5000/health`
3. Verify GENESIS stack healthy: `curl http://localhost:8000/api/v1/health`
4. Start fresh GENESIS session via UI or API: `POST /api/v1/sessions` with `target_ip=vuln-lab`

### Detection Matrix

| Bug | Expected GENESIS Tool | Expected Finding Type | Pass Criteria |
|-----|----------------------|----------------------|---------------|
| SQL injection `/login` | sqlmap, nuclei | `sqli_authentication_bypass` | `severity=critical, verified=true` |
| Reflected XSS `/search` | XSStrike, nuclei | `reflected_xss` | `severity=high` |
| IDOR `/api/user/{id}` | Custom IDOR probe | `idor_horizontal_priv_esc` | `severity=high` |
| Hardcoded creds | Source analysis, artifact_pull | `hardcoded_credentials` | `severity=critical` |
| Path traversal `/files` | nuclei, custom probe | `path_traversal_lfi` | `severity=critical, verified=true` |
| SSRF `/fetch` | Custom SSRF probe | `ssrf_internal_access` | `severity=high` |
| Weak JWT | JWT confusion tool | `jwt_weak_secret` | `severity=high` |
| Command injection `/ping` | Custom cmd-inject | `rce_command_injection` | `severity=critical, verified=true` |
| CVE-2023-30861 (Flask) | nuclei CVE template | `outdated_component_cve` | `cve_id=CVE-2023-30861` |
| No rate limiting | Login brute force | `missing_rate_limiting` | `severity=medium` |
| CORS misconfiguration | CORS probe | `cors_misconfiguration` | `severity=medium` |
| Directory listing | httpx, gobuster | `directory_listing_enabled` | `severity=low` |

### Pass / Fail Definition
- **PASS:** ≥ 10/12 bugs found, all 4 critical bugs found and `verified=true`, no false positives on `/health` endpoint
- **FAIL:** Any critical bug missed, or > 3 false positives, or session crashes before completion

### Debugging Guide (when a finding is missed)

1. **Check tool was called:** Search `agent_thoughts` collection for tool name (`sqlmap`, `XSStrike`, etc.)
2. **Check tool output:** If called, inspect `tool_outputs` for error or empty result
3. **Check hypothesis market:** Was a hypothesis proposed for this vuln class? If yes but not verified, oracle failed
4. **Check logs:** `docker logs genesis_backend 2>&1 | grep ERROR`
5. **Re-run tool manually via MCP:** `POST /api/v1/tools/execute` with tool and target params
6. **Common fixes:**
   - Tool timed out → increase `TOOL_TIMEOUT` env var
   - Tool not in agent's allowed set → update `_AGENT_TOOL_SETS` in `multi_agent_orchestrator.py`
   - Target network unreachable → verify `genesis_vuln_test` network is shared between GENESIS and vuln-lab
   - 429 during scan → reduce `AZURE_OAI_CONCURRENCY` (already fixed) or increase delay between agent spawns

---

## Bug Tracking

All bugs found during testing to be filed in project tracker with:
- **Severity:** Critical / High / Medium / Low
- **Phase found:** Which phase surfaced it
- **Component:** Backend / Frontend / MCP / Infrastructure
- **Repro steps:** Exact steps to reproduce
- **Expected vs actual:** What should happen vs what does
- **Fix owner + due date**

### Known bugs to fix (pre-scheduled)

| Bug | Severity | File | Target Fix Date |
|-----|----------|------|-----------------|
| JWT_SECRET empty in .env | Critical | `.env` | May 13 |
| Hardcoded `Genesis@1234` passwords | Critical | `.env` | May 13 |
| `health.py` lazy `__import__` | Low | `health.py:18` | Jun 18 |
| MCP error stack trace leak | Medium | `mcp-server/src/server.ts:75` | Jun 18 |
| `alembic.ini` hardcoded DB URL | High | `alembic.ini:62` | May 13 |
| ChromaDB error detail in response | Medium | `vulnerabilities.py:65` | Jun 19 |
| WebSocket token in query param | High | `main.py` | Jun 20 |
| `replica_manager` network isolation | Medium | `docker-compose.yml` | Jun 21 |
| `dedup_threshold` config unused | Low | `ai_orchestrator.py` | Jun 22 |
| CORS hardcoded localhost | High | `main.py:119` | May 15 |

---

## Milestone Summary

| Milestone | Date | Definition of Done |
|-----------|------|--------------------|
| M0: Security baseline | May 19 | No hardcoded secrets, HTTPS live, rate limiting active |
| M1: Infrastructure complete | Jun 2 | Monitoring live, backups running, startup validation in place |
| M2: Vuln-lab image ready | Jun 6 | Image built, 12 bugs documented, smoke test passing |
| M3: Test suite passing | Jun 16 | E2E + unit + smoke tests all green, ≥60% coverage |
| M4: Bug fixes complete | Jun 30 | All pre-scheduled bugs fixed, UAT sign-off |
| M5: Go-live | Jul 14 | Production deployed, monitored 24h, runbook live |

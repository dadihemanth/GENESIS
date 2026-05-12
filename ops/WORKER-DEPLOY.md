# Deploying an additional GENESIS worker host (T23)

GENESIS v3.0 lets the `celery_worker` service run on hosts other than the one
running the compose stack. This document is the operator runbook for
standing up a second worker host.

**Before you start:** verify single-host multi-agent is healthy on your
primary host. Multi-host deployments amplify infrastructure problems;
fix single-host first.

## What you get

- Campaigns (T18) against many targets fan out across all available workers.
- Artifacts pulled on one host are readable by every other worker, streamed
  via MinIO.
- Capability-tagged workers: a worker on a big box with Ghidra + the fuzzer
  advertises those tags; a worker on a small box advertises only what it has.

## What stays single-node in v3.0

- The broker (Redis), Postgres, MongoDB, ChromaDB, and Neo4j all live on
  the primary host. Workers connect across the network.
- MinIO lives on the primary host too. No cross-region replication.
- Autoscaling: manual only. Add / remove worker hosts by hand.

## Prerequisites on the worker host

1. Docker + docker-compose installed.
2. Network path open to the primary host on:
   - Redis (default `6379`) — broker + capability registry
   - MinIO (default `9000`) — artifact bytes
   - Postgres (`5432`), MongoDB (`27017`), ChromaDB (`8000`), Neo4j (`7687`)
3. A clone of this repo on the worker host.
4. The same `.env` used on the primary host, **plus**:
   - `REDIS_URL`, `DATABASE_URL`, `MONGODB_URL`, `CHROMA_HOST`, `NEO4J_URI`
     pointed at the primary host's reachable IP/DNS.
   - `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`,
     `MINIO_BUCKET` set to the primary host's MinIO (same credentials).
   - `WORKER_CAPABILITIES` — comma-separated tag list advertising what this
     worker has. Examples:
     - Full-featured box: `ghidra,fuzzer,instrumentation,forge_sandbox`
     - Fuzz-only box: `fuzzer`
     - GPU box for binary analysis: `ghidra,symbex,instrumentation`
     Leaving this empty means the worker still serves the default queue but
     does not appear in the capability registry.

## Minimal worker-only compose file

Create `docker-compose.worker.yml` on the secondary host:

```yaml
version: '3.8'

services:
  celery_worker:
    build: ./backend
    command: celery -A app.services.celery_app worker --loglevel=info -c 4 -Q research,has-ghidra,has-fuzzer,has-instrumentation
    env_file: .env
    environment:
      REDIS_URL: ${REDIS_URL}
      CELERY_BROKER_URL: ${REDIS_URL}/0
      CELERY_RESULT_BACKEND: ${REDIS_URL}/1
      DATABASE_URL: ${DATABASE_URL}
      MONGODB_URL: ${MONGODB_URL}
      CHROMA_HOST: ${CHROMA_HOST}
      CHROMA_PORT: ${CHROMA_PORT:-8000}
      NEO4J_URI: ${NEO4J_URI}
      NEO4J_USER: ${NEO4J_USER:-neo4j}
      NEO4J_PASSWORD: ${NEO4J_PASSWORD}
      MINIO_ENDPOINT: ${MINIO_ENDPOINT}
      MINIO_ACCESS_KEY: ${MINIO_ACCESS_KEY}
      MINIO_SECRET_KEY: ${MINIO_SECRET_KEY}
      MINIO_BUCKET: ${MINIO_BUCKET:-genesis-artifacts}
      WORKER_CAPABILITIES: ${WORKER_CAPABILITIES}
      MCP_API_KEY: ${MCP_API_KEY:-}
      ARTIFACT_ROOT: /data/security/artifacts
    volumes:
      # Local scratch only. The primary artifact volume is NOT shared across
      # hosts — the worker pulls artifact bytes from MinIO on demand.
      - worker_scratch:/data/security

volumes:
  worker_scratch:
```

Tune the `-Q` list to match your `WORKER_CAPABILITIES`. A worker that
advertises `fuzzer` should serve `has-fuzzer`; a worker without Ghidra
should **not** serve `has-ghidra`.

## Bring it up

```sh
docker compose -f docker-compose.worker.yml up -d --build
docker compose -f docker-compose.worker.yml logs -f celery_worker
```

Expected startup log line:

```
worker_ready: advertising capabilities=['ghidra', 'fuzzer'] as celery@worker-host-2 (heartbeat every 30s, ttl 90s)
```

## Verify from the primary host

```sh
# 1. Broker sees the new worker.
docker exec -it genesis_redis_1 redis-cli KEYS 'genesis:workers:*'

# 2. Capability registry entry is fresh.
docker exec -it genesis_redis_1 redis-cli GET 'genesis:workers:celery@worker-host-2:capabilities'

# 3. MinIO bucket has artefacts pulled on host A.
docker exec -it genesis_minio_1 mc ls local/genesis-artifacts
```

## Smoke test — artifact published on A, consumed on B

1. On the primary host: run a session that pulls a binary artifact (any
   target with a downloadable file).
2. On the primary host Mongo:
   ```
   docker exec -it genesis_mongodb_1 mongosh -u admin \
     --eval "db.getSiblingDB('security_research').artifacts.findOne({session_id:'<SESSION>'})"
   ```
   Confirm both `path` and `s3_key` fields are populated.
3. On the worker host: submit a `binary_decompile` task targeting that
   artifact by sha256. The worker should fetch the bytes from MinIO into
   `/data/security/artifacts/_resolved/<sha256>.bin` and hand the path to
   Ghidra.
4. Compare Ghidra output to a run on the primary host — identical.

## Troubleshooting

**Worker registers but no tasks arrive.** Check that `-Q` includes
`research` — the dispatcher only sends capability-specific tasks to
capability queues; everything else goes to `research`.

**Artifact resolve returns 404 on worker B.** Either:

- Mongo record has no `s3_key` field (artifact was registered *before*
  MinIO was enabled — re-register or re-pull), or
- MinIO upload failed at pull time (check backend logs on host A for
  `MinIO publish failed for <sid>/<sha>`), or
- The worker has no MinIO credentials (check `MINIO_ACCESS_KEY` is set in
  its environment).

**Worker says `heartbeat: cannot connect to redis`.** `REDIS_URL` must be
reachable from the worker. Firewall, Docker network, or missing
`network_mode: host` are the usual culprits.

**Sessions fail with "Event loop is closed" on the worker.** The same bug
fixed on the primary host — ensure the worker is on v3.0+, which resets
the async-client singletons per Celery task.

## Rolling back

To remove a worker host: `docker compose -f docker-compose.worker.yml down`
on that host. The capability heartbeat key expires from Redis within 90s
and the worker simply disappears from the dispatcher's view. No data is
lost — artifacts remain in MinIO, sessions keep running on other workers.

## Residual notes

- MinIO credentials are static env vars in v3.0. A secrets-manager layer is
  on the v5.0 (cost-router) roadmap.
- Broker HA is out of scope for v3.0. If the primary host goes down, the
  broker is unavailable and workers stall. Single-site + cold-failover is
  the intended operating mode.
- `code_read` (which walks whole source directories) is NOT yet remote-worker
  compatible — those tasks should be routed to a worker that has direct
  filesystem access to the artifact, or routed to the primary host.

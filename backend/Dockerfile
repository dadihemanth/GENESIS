FROM python:3.11-slim
WORKDIR /app
# v7.x — docker CLI (static binary) is needed by celery_worker so the
# orchestrator's `_cleanup_session_containers` helper can `docker rm -f`
# orphaned replica_manager-spawned compose containers
# (compose_<session_id>-app-1) at session finalize. Without it the helper
# silently no-ops and the containers accumulate forever. The static binary
# from download.docker.com is ~50MB, deterministic, and doesn't pull a
# daemon (we only need the client; the host's docker socket is mounted).
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc libpq-dev curl ca-certificates \
 && curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-27.3.1.tgz \
    | tar -xzC /tmp \
 && mv /tmp/docker/docker /usr/local/bin/docker \
 && chmod +x /usr/local/bin/docker \
 && rm -rf /tmp/docker /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# GENESIS forge_sandbox — runs LLM-authored Python/Node/Bash scripts under
# strict resource + egress limits. Target IP + OOB domain only.
#
# Defensive layering:
#   - Rootless (USER sandbox, UID 1000)
#   - Read-only rootfs at runtime (set in docker-compose)
#   - /tmp is the only writable scratch mount
#   - 256 MB memory cap (docker-compose), 60s default wall-time (enforced in server)
#   - No egress except target IP + OOB host (enforced by Docker network config)
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive

# Node.js 20 LTS for the `node` lang path
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates gnupg \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# A narrow allow-list of Python libs useful for exploit scripting.
# Deliberately excludes things that would enable arbitrary exploitation
# beyond HTTP-class probing (paramiko, impacket, etc.).
RUN pip install --no-cache-dir \
    requests==2.32.3 \
    httpx==0.27.2 \
    pyjwt==2.9.0 \
    cryptography==43.0.1 \
    beautifulsoup4==4.12.3 \
    lxml==5.3.0

RUN useradd --create-home --shell /bin/bash --uid 1000 sandbox \
    && mkdir -p /app /scripts /tmp/work \
    && chown -R sandbox:sandbox /app /scripts /tmp/work

# T26 — install the GENESIS crypto primitive library into site-packages so
# driver scripts launched with `python -I` (which ignores PYTHONPATH) can
# `import genesis_crypto.padding_oracle` etc.
COPY --chown=sandbox:sandbox genesis_crypto /opt/genesis_crypto
RUN pip install --no-cache-dir /opt/genesis_crypto

WORKDIR /app
COPY --chown=sandbox:sandbox server.py /app/server.py

USER sandbox

EXPOSE 3201
CMD ["python", "-u", "/app/server.py"]

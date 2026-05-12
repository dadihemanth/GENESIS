# GENESIS symbex (Tier-3 · T10) — symbolic-execution container.
#
# Wraps angr behind an HTTP API so the orchestrator can pose bounded
# reachability / constraint-solver questions against a binary artifact
# (pulled via T3). Use cases:
#   - "Can this decompiled function reach its 'system()' call? Under what input?"
#   - "Which branch conditions must hold to reach address 0xABCD?"
#   - "Produce a minimal byte string that sets flag X when parsed."
#
# angr is heavy. The container runs as unprivileged `symbex`, has a wall-clock
# cap per request, and only sees /data/security/artifacts as a read-only mount.

FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
        libxml2-dev \
        libxslt1-dev \
        zlib1g-dev \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 1000 symbex
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /app/requirements.txt

COPY server.py /app/server.py
RUN chown -R symbex:symbex /app

USER symbex

EXPOSE 3501
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -sf http://127.0.0.1:3501/health || exit 1

CMD ["python3", "/app/server.py"]

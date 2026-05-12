# GENESIS instrumentation (Tier-5 · T25) — dynamic instrumentation container.
#
# Wraps Frida (spawn-mode) and DynamoRIO behind a small HTTP API so the AI
# can point at a pulled artifact, inject a hook / run a DR client, and get
# function traces, coverage bitmaps, or syscall logs back as structured
# evidence.
#
# Intel Pin is intentionally NOT installed in v1 — its licence forbids
# redistribution without Intel's consent. DynamoRIO covers the same
# x86/x64 user-mode surface.
#
# This container is firewalled to the default docker network only (no
# vuln-lab egress): the instrumented binary runs inside this container
# against its own /tmp, not against the target.

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        ca-certificates curl file binutils strace \
        libpython3.12 \
    && rm -rf /var/lib/apt/lists/*

# DynamoRIO 10.0.0 binary release. Failure is non-fatal — if the download
# is unreachable from the build environment the server falls back to
# "dynamorio unavailable" at runtime.
ARG DYNAMORIO_VERSION=10.0.0
ARG DYNAMORIO_URL=https://github.com/DynamoRIO/dynamorio/releases/download/release_10.0.0/DynamoRIO-Linux-10.0.0.tar.gz
RUN set -e; \
    if curl -fsSL -o /tmp/dr.tar.gz "${DYNAMORIO_URL}"; then \
        mkdir -p /opt/dynamorio \
        && tar xzf /tmp/dr.tar.gz -C /opt \
        && mv /opt/DynamoRIO-* /opt/dynamorio.tmp \
        && rm -rf /opt/dynamorio \
        && mv /opt/dynamorio.tmp /opt/dynamorio \
        && echo "DynamoRIO ${DYNAMORIO_VERSION} installed"; \
    else \
        echo "[instrumentation] DynamoRIO download failed — dynamorio mode will report unavailable"; \
        mkdir -p /opt/dynamorio; \
    fi; \
    rm -f /tmp/dr.tar.gz

ENV PATH="/opt/dynamorio/bin64:${PATH}"

# App venv with Frida + Flask
RUN python3 -m venv /app/venv \
    && /app/venv/bin/pip install --no-cache-dir --upgrade pip

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN /app/venv/bin/pip install --no-cache-dir -r /app/requirements.txt

COPY server.py /app/server.py

RUN useradd --create-home instrument \
    && mkdir -p /tmp/instwork \
    && chown -R instrument:instrument /app /tmp/instwork

USER instrument

ENV PATH="/app/venv/bin:/opt/dynamorio/bin64:${PATH}" \
    INSTWORK=/tmp/instwork

EXPOSE 3601
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -sf http://127.0.0.1:3601/health || exit 1

CMD ["python3", "/app/server.py"]

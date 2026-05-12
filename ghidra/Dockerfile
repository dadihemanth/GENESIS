# Ghidra-headless decompiler service for GENESIS T4.
#
# Builds on the official Eclipse Temurin JRE 21 base, downloads the official
# Ghidra release, and exposes a small HTTP server (server.py) that runs
# analyzeHeadless + a Post-Script to dump pseudo-C for top-N functions.
#
# The artifact volume (/data/security/artifacts) is mounted read-only at
# runtime so decompilation can never mutate pulled binaries.
FROM eclipse-temurin:21-jre-jammy

ENV DEBIAN_FRONTEND=noninteractive \
    GHIDRA_VERSION=11.2.1_PUBLIC_20241105 \
    GHIDRA_SHA256=ce4db5117da0fbaf8f33863fec4f40902f754f06b68945a59fb1c0f9b1bc461c \
    GHIDRA_HOME=/opt/ghidra \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 python3-pip unzip wget ca-certificates fontconfig \
    && wget -qO /tmp/ghidra.zip \
        https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2.1_build/ghidra_${GHIDRA_VERSION}.zip \
    && echo "${GHIDRA_SHA256}  /tmp/ghidra.zip" | sha256sum -c - \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_* /opt/ghidra \
    && rm /tmp/ghidra.zip \
    && apt-get purge -y wget unzip \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash --uid 1000 ghidra \
    && mkdir -p /work /scripts \
    && chown -R ghidra:ghidra /work /scripts

COPY ghidra_scripts/DumpPseudoC.java /scripts/DumpPseudoC.java
COPY server.py /app/server.py

RUN chown -R ghidra:ghidra /app /scripts

USER ghidra
WORKDIR /app

EXPOSE 3101
CMD ["python3", "-u", "/app/server.py"]

# GENESIS fuzzer (Tier-3 · T9) — coverage-guided fuzzing container.
#
# Wraps AFL++ and honggfuzz behind a small HTTP API so the orchestrator can
# point at an artifact (a binary pulled via T3 and decompiled by T4) with a
# corpus directory and trigger a bounded fuzz run. Crashes are minimized
# and reported back with stdout/stderr fingerprints.
#
# This container is firewalled to the `vuln-lab` docker network only and
# never receives inbound internet. It reads artifacts from `/data/security`
# (mounted read-only) and writes crashes + minimized corpora to its own
# writable volume.

FROM aflplusplus/aflplusplus:latest AS afl

# AFL++ only. honggfuzz was originally included as a secondary engine
# but is no longer packaged in the distros we target (Ubuntu 24.04 noble
# dropped it; jammy universe dropped it; Debian bookworm main does not
# carry it either). AFL++ is the primary engine for coverage-guided
# fuzzing and is sufficient on its own.
#
# Ubuntu 24.04 (noble) is the base because AFL++ binaries from the
# upstream image are dynamically linked against libpython3.12 — noble
# ships Python 3.12, while Debian bookworm only has 3.11 and would
# produce a "libpython3.12.so.1.0 not found" runtime error.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        libpython3.12 \
        binutils file strace \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Copy AFL++ binaries from the upstream image. The upstream image lays
# its artefacts out under /AFLplusplus/ (not /out/ — /out/ was the layout
# in older AFL++ images but the current `:latest` tag places everything
# under the project directory). The afl-compiler-rt object files and the
# SanitizerCoverage LTO/PCGUARD libraries live alongside them but are
# only needed for instrumented compilation, which we don't do here.
COPY --from=afl /AFLplusplus/afl-fuzz    /usr/local/bin/afl-fuzz
COPY --from=afl /AFLplusplus/afl-showmap /usr/local/bin/afl-showmap
COPY --from=afl /AFLplusplus/afl-cmin    /usr/local/bin/afl-cmin
COPY --from=afl /AFLplusplus/afl-tmin    /usr/local/bin/afl-tmin

# App-level Python server
RUN python3 -m venv /app/venv && \
    /app/venv/bin/pip install --no-cache-dir --upgrade pip

# Ubuntu 24.04 already ships a user at UID 1000 (`ubuntu`); let useradd
# allocate any free UID for the fuzzer account. The read-only artifact
# mount does not require UID parity with the host.
RUN useradd --create-home fuzzer
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN /app/venv/bin/pip install --no-cache-dir -r /app/requirements.txt

COPY server.py /app/server.py
# T24 — grammar-aware dictionaries for AFL++ (-x). One subdir per format,
# each contains dict.afl. Missing grammars fall back to pure random mutation.
COPY grammars /app/grammars
RUN chown -R fuzzer:fuzzer /app

USER fuzzer

ENV PATH="/app/venv/bin:${PATH}" \
    AFL_SKIP_CPUFREQ=1 \
    AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1

EXPOSE 3401
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -sf http://127.0.0.1:3401/health || exit 1

CMD ["python3", "/app/server.py"]

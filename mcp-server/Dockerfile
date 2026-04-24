FROM python:3.12-slim

WORKDIR /app

# ── Node.js 20 ────────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates gnupg \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# ── System packages ───────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    masscan \
    hydra \
    whatweb \
    sslscan \
    john \
    ruby \
    ruby-dev \
    build-essential \
    libffi-dev \
    libcurl4-openssl-dev \
    libxml2 \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    curl \
    openssl \
    perl \
    wget \
    unzip \
    git \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# ── WPScan (Ruby gem — needs build-essential + libffi-dev for native exts) ────
RUN gem install wpscan --no-document \
    || echo "[warn] wpscan gem install failed — continuing"

# ── Wordlists ─────────────────────────────────────────────────────────────────
RUN mkdir -p /usr/share/wordlists && \
    printf '%s\n' password admin 123456 password123 admin123 letmein \
    qwerty 12345678 1234567890 master password1 iloveyou sunshine \
    princess dragon monkey shadow welcome 666666 abc123 football \
    baseball superman batman trustno1 starwars passw0rd changeme \
    secret 111111 000000 root toor test guest default login pass \
    > /usr/share/wordlists/rockyou.txt

# ── Nikto (Perl script + required Perl modules) ───────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    libjson-perl \
    libxml-writer-perl \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl

# ── Python security tools ─────────────────────────────────────────────────────
RUN pip install --no-cache-dir \
    sqlmap \
    dnsrecon \
    semgrep \
    bandit \
    impacket \
    wafw00f \
    arjun \
    git+https://github.com/laramies/theHarvester.git

# ── Create impacket console-script wrappers (pip doesn't always do this) ──────
RUN python3 -c "import os; names=['secretsdump','GetUserSPNs','GetNPUsers','lookupsid','smbclient','rpcdump','atexec','wmiexec','reg']; [open('/usr/local/bin/impacket-'+n,'w').write('#!/usr/bin/env python3\nimport sys, runpy\nrunpy.run_module(\"impacket.examples.'+n+'\", run_name=\"__main__\")\n') for n in names]" \
    && chmod +x /usr/local/bin/impacket-* \
    || echo "[warn] impacket wrapper creation failed"

# ── enum4linux-ng and netexec (install from source) ───────────────────────────
RUN pip install --no-cache-dir \
    git+https://github.com/cddmp/enum4linux-ng.git \
    2>/dev/null || echo "[warn] enum4linux-ng install failed"

RUN pip install --no-cache-dir \
    git+https://github.com/Pennyw0rth/NetExec.git \
    2>/dev/null || echo "[warn] netexec install failed"

# ── commix (OS command injection, not on PyPI) ────────────────────────────────
RUN git clone --depth 1 https://github.com/commixproject/commix.git /opt/commix \
    && chmod +x /opt/commix/commix.py \
    && ln -sf /opt/commix/commix.py /usr/local/bin/commix \
    || echo "[warn] commix install failed"

# ── XSStrike (Python, not on PyPI) ───────────────────────────────────────────
RUN git clone --depth 1 https://github.com/s0md3v/XSStrike.git /opt/xsstrike \
    && pip install --no-cache-dir \
       -r /opt/xsstrike/requirements.txt \
    && chmod +x /opt/xsstrike/xsstrike.py \
    && ln -sf /opt/xsstrike/xsstrike.py /usr/local/bin/xsstrike \
    || echo "[warn] xsstrike install failed"

# ── Go-based security tools (linux/amd64) ─────────────────────────────────────
RUN wget -qO /tmp/gobuster.tar.gz \
      https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz \
    && tar -xzf /tmp/gobuster.tar.gz -C /usr/local/bin gobuster \
    && chmod +x /usr/local/bin/gobuster \
    && rm /tmp/gobuster.tar.gz

RUN wget -qO /tmp/ffuf.tar.gz \
      https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz \
    && tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin ffuf \
    && chmod +x /usr/local/bin/ffuf \
    && rm /tmp/ffuf.tar.gz

RUN wget -qO /tmp/feroxbuster.zip \
      https://github.com/epi052/feroxbuster/releases/download/v2.10.4/x86_64-linux-feroxbuster.zip \
    && unzip -j /tmp/feroxbuster.zip feroxbuster -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/feroxbuster \
    && rm /tmp/feroxbuster.zip

RUN wget -qO /tmp/amass.zip \
      https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_amd64.zip \
    && unzip -j /tmp/amass.zip 'amass_Linux_amd64/amass' -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/amass \
    && rm /tmp/amass.zip

RUN wget -qO /tmp/nuclei.zip \
      https://github.com/projectdiscovery/nuclei/releases/download/v3.3.8/nuclei_3.3.8_linux_amd64.zip \
    && unzip -j /tmp/nuclei.zip nuclei -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

RUN wget -qO /tmp/subfinder.zip \
      https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip \
    && unzip -j /tmp/subfinder.zip subfinder -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/subfinder \
    && rm /tmp/subfinder.zip

# httpx — HTTP probing and web asset discovery
RUN wget -qO /tmp/httpx.zip \
      https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip \
    && unzip -j /tmp/httpx.zip httpx -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/httpx \
    && rm /tmp/httpx.zip \
    || echo "[warn] httpx install failed"

# kerbrute — Kerberos user enumeration and brute-force
RUN wget -qO /usr/local/bin/kerbrute \
      https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 \
    && chmod +x /usr/local/bin/kerbrute \
    || echo "[warn] kerbrute install failed"

# ── Node.js app ───────────────────────────────────────────────────────────────
COPY package*.json ./
RUN npm install
COPY tsconfig.json .
COPY src ./src
RUN npm run build

EXPOSE 3001
CMD ["node", "dist/index.js"]

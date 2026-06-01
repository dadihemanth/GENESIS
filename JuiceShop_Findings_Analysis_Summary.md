# OWASP Juice Shop Scan Comparison Summary

Scope:
- Scan files analyzed: `Findings-v14.5.1.csv` and `Findings-v20.csv`
- Official baseline used: tagged OWASP Juice Shop `data/static/challenges.yml` for `v14.5.1` and `v20.0.0`
- Important caveat: neither CSV marks any row as `novel=yes`. The "candidate novel" section below means "not clearly represented by an official Juice Shop challenge and worth manual validation", not confirmed zero-day.

## 1. CSV Inventory

| File | Raw rows | Unique finding titles | Critical | High | Medium | Low | Info | `novel=yes` rows |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `Findings-v14.5.1.csv` | 802 | 702 | 309 | 245 | 217 | 30 | 1 | 0 |
| `Findings-v20.csv` | 1787 | 1482 | 656 | 596 | 475 | 53 | 7 | 0 |

Data quality notes:
- Both CSVs contain many duplicate or near-duplicate titles for the same vulnerability class.
- Both CSVs also contain target strings that mention other versions or adjacent services. I treated the filename as the primary session identifier, but flagged environment/service findings separately.
- `Findings-v14.5.1.csv` includes 419 rows explicitly mentioning 14.5.1, 25 mentioning 20.0.0, 17 mentioning 6.2.0-SNAPSHOT, and 341 without a version string.
- `Findings-v20.csv` includes 693 rows explicitly mentioning 20.0.0, 43 mentioning 14.5.1, 80 mentioning 6.2.0-SNAPSHOT, and 971 without a version string.

## 2. Official Challenge Catalog

| Version | Official challenges | Official categories | Official tags |
|---|---:|---:|---:|
| v14.5.1 | 101 | 15 | 10 |
| v20.0.0 | 112 | 16 | 12 |

Category counts:

| Category | v14.5.1 | v20.0.0 |
|---|---:|---:|
| Broken Access Control | 10 | 12 |
| Broken Anti Automation | 4 | 4 |
| Broken Authentication | 9 | 9 |
| Cryptographic Issues | 5 | 5 |
| Improper Input Validation | 10 | 12 |
| Injection | 11 | 13 |
| Insecure Deserialization | 2 | 3 |
| Miscellaneous | 5 | 6 |
| Observability Failures | 0 | 4 |
| Security Misconfiguration | 4 | 4 |
| Security through Obscurity | 3 | 3 |
| Sensitive Data Exposure | 16 | 16 |
| Unvalidated Redirects | 2 | 2 |
| Vulnerable Components | 9 | 8 |
| XSS | 9 | 9 |
| XXE | 2 | 2 |

Version deltas from v14.5.1 to v20.0.0:
- Added in v20: `AI Debugging`, `Chatbot Prompt Injection`, `Empty User Registration`, `Exposed credentials`, `Greedy Chatbot Manipulation`, `Leaked API Key`, `Memory Bomb`, `Mint the Honey Pot`, `NFT Takeover`, `Password Hash Leak`, `Security Advisory`, `Wallet Depletion`, `Web3 Sandbox`.
- Removed since v14.5.1: `Bully Chatbot`, `Kill Chatbot`.
- Category changes: `Access Log`, `Exposed Metrics`, `Leaked Access Logs`, and `Misplaced Signature File` moved from `Sensitive Data Exposure` to `Observability Failures`.

## 3. Official Challenge Coverage by Scan

Coverage method:
- A challenge is counted as "identified" when at least one scan finding semantically maps to the official challenge objective or vulnerability class.
- This is not the same as proving the challenge was solved in the Juice Shop scoreboard.
- Conservative mapping was used for OSINT, UI-only, joke, tutorial, and contraption challenges; many of those are intentionally hard for scanners to detect.

| Version | Official challenges | Identified by scan | Coverage |
|---|---:|---:|---:|
| v14.5.1 | 101 | 33 | 32.7% |
| v20.0.0 | 112 | 32 | 28.6% |

### v14.5.1 Category Coverage

| Category | Identified / Official |
|---|---:|
| Broken Access Control | 5 / 10 |
| Broken Anti Automation | 2 / 4 |
| Broken Authentication | 3 / 9 |
| Cryptographic Issues | 2 / 5 |
| Improper Input Validation | 3 / 10 |
| Injection | 4 / 11 |
| Insecure Deserialization | 0 / 2 |
| Miscellaneous | 0 / 5 |
| Security Misconfiguration | 2 / 4 |
| Security through Obscurity | 0 / 3 |
| Sensitive Data Exposure | 4 / 16 |
| Unvalidated Redirects | 1 / 2 |
| Vulnerable Components | 3 / 9 |
| XSS | 3 / 9 |
| XXE | 1 / 2 |

v14.5.1 official challenges identified:
`API-only XSS`, `Admin Registration`, `Allowlist Bypass`, `Arbitrary File Write`, `CAPTCHA Bypass`, `Change Bender's Password`, `Confidential Document`, `DOM XSS`, `Deluxe Fraud`, `Deprecated Interface`, `Error Handling`, `Exposed Metrics`, `Extra Language`, `Forged Coupon`, `Forged Review`, `Forged Signed JWT`, `Forgotten Developer Backup`, `Forgotten Sales Backup`, `Login Admin`, `Manipulate Basket`, `NoSQL Exfiltration`, `Password Strength`, `Poison Null Byte`, `Product Tampering`, `Reflected XSS`, `Reset Jim's Password`, `SSRF`, `SSTi`, `Unsigned JWT`, `User Credentials`, `View Basket`, `Weird Crypto`, `XXE Data Access`.

High-signal missed areas in v14.5.1:
- OSINT and puzzle-style challenges: `Bjoern's Favorite Pet`, `Login Amy`, `Login MC SafeSearch`, geo-stalking, steganography.
- UI/navigation/tutorial challenges: `Score Board`, `Privacy Policy`, `Security Policy`, `Mass Dispel`.
- Several XSS variants: `CSP Bypass`, `HTTP-Header XSS`, `Video XSS`, `Server-side XSS Protection`.
- Insecure deserialization RCE/DoS challenges.
- Chatbot-era challenges: `Bully Chatbot`, `Kill Chatbot`.

### v20.0.0 Category Coverage

| Category | Identified / Official |
|---|---:|
| Broken Access Control | 4 / 12 |
| Broken Anti Automation | 2 / 4 |
| Broken Authentication | 4 / 9 |
| Cryptographic Issues | 2 / 5 |
| Improper Input Validation | 5 / 12 |
| Injection | 3 / 13 |
| Insecure Deserialization | 0 / 3 |
| Miscellaneous | 0 / 6 |
| Observability Failures | 1 / 4 |
| Security Misconfiguration | 2 / 4 |
| Security through Obscurity | 0 / 3 |
| Sensitive Data Exposure | 4 / 16 |
| Unvalidated Redirects | 0 / 2 |
| Vulnerable Components | 3 / 8 |
| XSS | 1 / 9 |
| XXE | 1 / 2 |

v20.0.0 official challenges identified:
`API-only XSS`, `Admin Registration`, `CAPTCHA Bypass`, `Change Bender's Password`, `Confidential Document`, `Database Schema`, `Deluxe Fraud`, `Deprecated Interface`, `Error Handling`, `Exposed Metrics`, `Extra Language`, `Forged Coupon`, `Forged Review`, `Forged Signed JWT`, `Forgotten Developer Backup`, `Forgotten Sales Backup`, `Login Admin`, `Manipulate Basket`, `Password Hash Leak`, `Password Strength`, `Payback Time`, `Poison Null Byte`, `Product Tampering`, `Reset Jim's Password`, `Two Factor Authentication`, `Unsigned JWT`, `Upload Type`, `User Credentials`, `View Basket`, `Vulnerable Library`, `Weird Crypto`, `XXE Data Access`.

High-signal missed areas in v20.0.0:
- New AI challenges: `Chatbot Prompt Injection`, `Greedy Chatbot Manipulation`, `AI Debugging`.
- New Web3/business challenges: `NFT Takeover`, `Mint the Honey Pot`, `Wallet Depletion`, `Web3 Sandbox`.
- New metadata/secrets challenges: `Exposed credentials`, `Leaked API Key`, `Security Advisory`.
- Most XSS subtypes beyond API/product-description XSS.
- Insecure deserialization challenges: `Blocked RCE DoS`, `Successful RCE DoS`, `Memory Bomb`.
- Observability items except `Exposed Metrics`: `Access Log`, `Leaked Access Logs`, `Misplaced Signature File`.

## 4. Scanner Strengths and Weaknesses

Scanner strengths:
- Strong at classic web/API issues: SQL injection, JWT verification weaknesses, mass assignment, basket IDOR/BOLA, product tampering, XXE file disclosure, FTP/null-byte artifact exposure, default credentials, weak coupon/crypto artifacts, metrics exposure.
- Strong at repeating exploit evidence across variants, which explains the high row counts for a smaller number of vulnerability classes.

Scanner weaknesses:
- Weak at OSINT, tutorial, "find a hidden page", puzzle, and UI-only challenges.
- Weak at challenge-specific proof conditions. Example: finding an XSS class is not always equivalent to identifying the exact official `CSP Bypass`, `HTTP-Header XSS`, or `Video XSS` challenge.
- Weak at LLM/Web3 challenge semantics in v20. It saw some chatbot/Web3 endpoints, but did not demonstrate the official prompt-injection, greedy-coupon, AI-debugging, NFT, minting, wallet, or sandbox objectives.

## 5. Candidate Novel / Non-Official Findings

None of the CSV rows are marked novel. The items below are candidate non-official findings because they do not cleanly map to an official Juice Shop challenge, or they describe impact beyond the official challenge objective.

Top app-specific candidates:

| Candidate class | Seen in | Why it matters |
|---|---|---|
| JWT `kid` path traversal / arbitrary key selection | v20 | This is not an official JWT challenge name/objective. If exploitable, it is a distinct token-forgery primitive beyond `alg=none` and RS256-to-HS256 confusion. |
| JWT payload/session hygiene: password hashes, TOTP/deluxe tokens, missing expiration, no revocation after password change | v14.5.1, v20 | Some overlap exists with `Password Hash Leak`, but long-lived JWTs, TOTP leakage, and no revocation after password changes are broader than the official challenge catalog. |
| Bulk authentication-details/user metadata disclosure | v14.5.1, v20 | Repeated findings show low-privilege access to user records, auth metadata, reusable JWTs, TOTP secrets, and/or admin user objects. This goes beyond the official basket-focused access control challenges. |
| Public KeePass / incident-support vault exposure | v14.5.1, v20 | The scans report `.kdbx`/incident-support vault exposure. This is not clearly the same as v20 `Exposed credentials`, which is about hardcoded client-side test credentials. |
| B2B `orderLinesData` eval / unsafe YAML-JavaScript import | v14.5.1, v20 | This may be official-adjacent to RCE/deserialization challenges, but the scan evidence describes parser/eval behavior and verbose stack disclosure in B2B flows. Validate separately. |
| Web3 listener/control endpoint creation via GET | v20 | The official Web3 challenges are NFT takeover, minting, wallet depletion, and sandbox discovery. Unauthenticated listener creation looks like a separate API control issue. |
| Chatbot/LLM backend metadata/error leakage | v20 | The official AI challenges are prompt-injection/manipulation/debugging. Backend error and configuration leakage is adjacent, but not the same objective. |

Environment/control-plane candidates:

| Candidate class | Seen in | Scope note |
|---|---|---|
| Unauthenticated ChromaDB exposure/read-write/session memory leakage | v14.5.1, v20 | Appears to target GENESIS/lab infrastructure, not Juice Shop itself. Treat as environment risk. |
| Unauthenticated Redis with command/RCE primitives | v20 | Environment/internal service exposure, not an official Juice Shop challenge. |
| Unauthenticated Chromium renderer SSRF / file-read primitive | v14.5.1, v20 | Environment renderer service exposure. This can be high impact if reachable from the tested network. |
| GENESIS Replica Manager unauthenticated replica creation/topology disclosure | v14.5.1 | Environment control-plane issue. Not part of Juice Shop's official challenge catalog. |

Manual validation priority:
1. Validate v20 JWT `kid` path traversal with a minimal proof: attacker-controlled `kid`, chosen key path, forged admin token accepted by a protected endpoint.
2. Validate auth metadata exposure with a low-privilege account and record exact endpoints, fields returned, and whether reusable tokens/TOTP secrets are present.
3. Validate public KeePass exposure by confirming unauthenticated download path and whether the file is intentionally shipped for a challenge or newly exposed.
4. Validate B2B parser eval/YAML behavior with safe non-destructive payloads and distinguish stack disclosure from actual code execution.
5. Validate environment findings separately from Juice Shop scoring, because ChromaDB/Redis/renderer/Replica Manager are outside the official Juice Shop challenge catalog.

## 6. Bottom Line

The scans found a large volume of high-impact web/API weaknesses, but official challenge coverage is moderate: about one-third for v14.5.1 and under one-third for v20.0.0. That is expected because many Juice Shop challenges are intentionally human, OSINT, UI, or puzzle driven.

The most important result is not the raw row count. It is the split between:
- Confirmed official-challenge coverage: SQLi, JWT, mass assignment, basket IDOR, file/FTP/null-byte, XXE, metrics, weak/default credentials, and product tampering.
- Non-official candidates needing triage: JWT `kid` traversal, broad auth metadata leakage, JWT lifecycle/secret leakage, public KeePass artifacts, B2B parser eval, Web3 listener control, chatbot metadata leakage, and adjacent GENESIS service exposure.

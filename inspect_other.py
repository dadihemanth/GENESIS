import csv
import re
from collections import Counter

CLUSTER_PATTERNS = [
    (r"sql.inject|sqli|union.select|blind.sql|error.based.sql|time.based.sql|login.bypass.*sql", "SQL Injection"),
    (r"nosql.inject|nosqli|mongodb.inject", "NoSQL Injection"),
    (r"command.inject|os.inject|rce|remote.code.exec|shell.inject", "Command Injection / RCE"),
    (r"ssti|template.inject|server.side.template", "Template Injection"),
    (r"alg.*none|algorithm.*none|jwt.*none|none.*algorithm", "JWT alg:none Bypass"),
    (r"jwt.*weak|weak.*jwt|jwt.*secret|jwt.*brute|jwt.*crack|jwt.*forge|jwt.*tamper|jwt.*sign", "JWT Weak Secret"),
    (r"\bjwt\b|json.web.token", "JWT Misc"),
    (r"stored.xss|persistent.xss", "Stored XSS"),
    (r"reflected.xss", "Reflected XSS"),
    (r"dom.xss|dom.based", "DOM XSS"),
    (r"\bxss\b|cross.site.script", "XSS generic"),
    (r"ssrf|server.side.request.forg", "SSRF"),
    (r"path.travers|directory.travers|lfi|local.file.inclus|dot.dot", "Path Traversal"),
    (r"bola|idor|insecure.direct.object|broken.object.level", "BOLA/IDOR"),
    (r"bfla|broken.function.level|privilege.escal", "BFLA"),
    (r"broken.access.control|unauth.*access|missing.authori|access.control", "Broken Access Control"),
    (r"auth.*bypass|bypass.*auth|login.*bypass", "Auth Bypass"),
    (r"no.auth|missing.auth|unauthenticated.*endpoint|weak.auth|default.cred", "Weak/Missing Auth"),
    (r"session.fixat|session.hijack|insecure.cookie|cookie.*secure|cookie.*httponly|\bcsrf\b|cross.site.request", "Session/Cookie/CSRF"),
    (r"account.takeover|account.*hijack|inactive.account|disabled.account", "Account Takeover"),
    (r"weak.password|password.policy|brute.force.*password|password.*brute|rate.limit.*auth", "Password/Brute Force"),
    (r"sensitive.data|information.disclosure|data.exposure|data.leak|secret.*expos|api.key.*expos|token.*expos", "Sensitive Data"),
    (r"error.message|stack.trace|verbose.error|debug.info|exception.detail", "Error Disclosure"),
    (r"user.enum|account.enum|email.enum|username.enum|user.disclosure|enumerat", "Enumeration"),
    (r"crypto|hash.*weak|md5.*weak|sha1.*weak|insecure.random|weak.cipher|length.extension|hmac.bypass", "Crypto Issues"),
    (r"vulnerable.depend|outdated.dep|cve-|ghsa-|known.vuln.*package|npm.audit", "Vulnerable Deps"),
    (r"prototype.pollut|proto.pollut|__proto__", "Prototype Pollution"),
    (r"missing.*header|security.header|content.security.policy|\bcsp\b|x-frame|hsts|x-content.type", "Missing Headers"),
    (r"misconfigur|default.config|exposed.config|admin.*expos|debug.*expos|admin.panel.*unauth|exposed.admin", "Misconfiguration"),
    (r"file.upload|unrestricted.upload|malicious.upload", "File Upload"),
    (r"graphql|introspect.*graphql", "GraphQL"),
    (r"open.redirect|unvalidated.redirect", "Open Redirect"),
    (r"\bdos\b|denial.of.service|redos|regex.dos", "DoS"),
    (r"clickjack|x-frame-options", "Clickjacking"),
    (r"business.logic|logic.flaw|workflow.bypass|payment.*bypass|coupon.*bypass|negative.price|membership.*bypass|deluxe.*token", "Business Logic"),
    (r"chromadb|chroma|celery|\bredis\b|chromium|vector.store|renderer", "Infrastructure"),
]

def get_cluster(t):
    for pattern, label in CLUSTER_PATTERNS:
        if re.search(pattern, t, re.IGNORECASE):
            return label
    return None

def inspect_other(filepath, label, sample_n=30):
    other_findings = []
    with open(filepath, newline='', encoding='utf-8-sig', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            finding = row.get('finding', '')
            if get_cluster(finding) is None:
                other_findings.append(finding)

    print(f"\n{'='*70}")
    print(f"{label}: {len(other_findings)} uncategorized rows")
    print(f"Sample of unique uncategorized findings:")
    print("-"*70)

    # Show top N unique (by prefix)
    seen = set()
    count = 0
    for f in other_findings:
        key = f[:80]
        if key not in seen:
            seen.add(key)
            print(f"  [{count+1}] {f[:120]}")
            count += 1
            if count >= sample_n:
                break

inspect_other(
    r"c:\Users\AI-SEC-LAB\Desktop\Claude\GENESIS\Findings-v14.5.1.csv",
    "v14.5.1 Other bucket"
)

inspect_other(
    r"c:\Users\AI-SEC-LAB\Desktop\Claude\GENESIS\Findings-v20.csv",
    "v20.0.0 Other bucket"
)

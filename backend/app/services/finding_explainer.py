from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Sequence


PlainLanguageFinding = Dict[str, str]


def _get(obj: Any, key: str, default: Any = "") -> Any:
    if isinstance(obj, Mapping):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _clean(value: Any, *, max_len: int = 480) -> str:
    text = str(value or "").strip()
    text = re.sub(r"\s+", " ", text)
    if len(text) > max_len:
        return text[: max_len - 1].rstrip() + "..."
    return text


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _target(vulnerability: Any, metadata: Mapping[str, Any]) -> str:
    endpoint = _clean(metadata.get("endpoint"), max_len=160)
    service = _clean(_get(vulnerability, "affected_service"), max_len=220)
    port = _get(vulnerability, "port", None)
    if endpoint and service:
        return f"{service} at {endpoint}"
    if endpoint:
        return endpoint
    if service and port:
        return f"{service}:{port}"
    if service:
        return service
    return "the assessed target"


def _determine_class(vulnerability: Any, metadata: Mapping[str, Any]) -> str:
    text = " ".join(
        [
            str(_get(vulnerability, "title", "")),
            str(_get(vulnerability, "description", "")),
            str(metadata.get("technique_tag", "")),
            " ".join(str(x) for x in _as_list(_get(vulnerability, "mitre_techniques", []))),
        ]
    ).lower()
    checks = [
        ("sqli", ("sql injection", "sqli", "union", "sqlite", "database query")),
        ("xss", ("xss", "cross-site scripting", "cross site scripting", "script injection")),
        ("ssrf", ("ssrf", "server-side request", "metadata service", "imds")),
        ("lfi", ("lfi", "local file", "path traversal", "directory traversal", "arbitrary file read", "/etc/passwd", "/etc/shadow")),
        ("cmdi", ("command injection", "os command", "shell=true", "rce", "remote code execution")),
        ("idor", ("idor", "object level", "insecure direct object", "any account", "any authenticated user")),
        ("jwt", ("jwt", "json web token", "alg=none", "hs256", "token forgery", "hardcoded secret")),
        ("auth", ("authentication", "auth bypass", "unauthenticated", "login", "admin token")),
        ("package", ("cve-", "out-of-bounds", "buffer overflow", "use-after-free", "advisory", "package")),
        ("info", ("banner", "swagger", "openapi", "information disclosure", "source code disclosure")),
    ]
    for label, needles in checks:
        if any(needle in text for needle in needles):
            return label
    if _as_list(_get(vulnerability, "cve_ids", [])):
        return "package"
    return "generic"


_IMPACT_BY_CLASS = {
    "sqli": "An attacker may be able to read, change, or delete application data by changing database queries through user input.",
    "xss": "An attacker may be able to run script in a user's browser, steal session data, or perform actions as that user.",
    "ssrf": "An attacker may be able to make the server contact internal systems that should not be reachable from the internet.",
    "lfi": "An attacker may be able to read files from the server, including configuration files or secrets.",
    "cmdi": "An attacker may be able to run operating system commands on the server.",
    "idor": "A user may be able to access another user's data because the application does not enforce ownership checks.",
    "jwt": "An attacker may be able to forge or misuse tokens and gain privileges they should not have.",
    "auth": "An attacker may be able to access protected functionality without proper authentication or authorization.",
    "package": "If the vulnerable component is reachable, attackers may be able to trigger the published weakness described by the advisory.",
    "info": "This exposes information that can help an attacker understand the system and plan stronger attacks.",
    "generic": "This weakness can reduce the security of the target and may become more serious when combined with other findings.",
}


_DESCRIPTION_BY_CLASS = {
    "sqli": "The application appears to handle user input in a way that can change a database query.",
    "xss": "The application appears to place user input into a web page without safely encoding it first.",
    "ssrf": "The server appears to accept a user-controlled URL or host and make a request on the user's behalf.",
    "lfi": "The application appears to let a user influence which file the server reads.",
    "cmdi": "The application appears to pass user-controlled input into an operating system command.",
    "idor": "The application appears to let one user request another user's object or account data.",
    "jwt": "The application appears to accept or issue JSON Web Tokens in an unsafe way.",
    "auth": "The application appears to expose protected functionality without a strong authentication or authorization check.",
    "package": "The detected component appears to match a known vulnerable package or version.",
    "info": "The target exposes information that is usually not needed by normal users.",
    "generic": "GENESIS identified behavior that may weaken the target's security.",
}


_SOLUTION_BY_CLASS = {
    "sqli": "Use parameterized queries or a safe ORM, and never place user input directly into SQL strings.",
    "xss": "Escape output before placing user input into HTML, validate input, and consider a Content Security Policy.",
    "ssrf": "Allow only approved outbound destinations, resolve DNS on the server, and block private, loopback, and metadata IP ranges.",
    "lfi": "Restrict file access to an approved directory, normalize paths, and reject any path that escapes that directory.",
    "cmdi": "Avoid shell execution for user-controlled values. Use argument lists, strict allow-lists, and least-privilege service accounts.",
    "idor": "Check that the authenticated user owns the requested object, or has an explicit role that permits access.",
    "jwt": "Use a vetted JWT library, require approved algorithms, rotate weak secrets, and enforce token expiry.",
    "auth": "Require real authentication, derive privileges server-side, and audit every privileged token or session issuance path.",
    "package": "Upgrade the affected package to a fixed version or apply the vendor security update.",
    "info": "Remove or restrict the exposed information in production, and require authentication where appropriate.",
    "generic": "Validate the affected code or configuration, remove the unsafe behavior, and retest the target.",
}


def _proof_text(
    vulnerability: Any,
    evidence_for: Sequence[Any],
    verification_output: Any,
) -> str:
    status = str(_get(vulnerability, "verification_status", "unverified") or "unverified").lower()
    if status in {"confirmed", "exploited"}:
        if evidence_for:
            snippet = _clean(evidence_for[0], max_len=320)
            return f"GENESIS tested this and recorded proof evidence: {snippet}"
        if verification_output:
            snippet = _clean(verification_output, max_len=320)
            return f"GENESIS tested this and recorded verification output: {snippet}"
        return "GENESIS marked this as proven, but the compact proof text was not available in the summary response."
    if status in {"disputed", "refuted"}:
        return "GENESIS has not accepted this as proven because validation disputed or refuted the evidence."
    return "GENESIS has not completed a passing proof run for this item yet. Treat it as a lead until validation is completed."


def _validation_note(vulnerability: Any, evidence_for: Sequence[Any]) -> str:
    status = str(_get(vulnerability, "verification_status", "unverified") or "unverified").lower()
    confidence = _get(vulnerability, "confidence", None)
    conf_text = ""
    try:
        conf_text = f" Confidence is {round(float(confidence) * 100)}%."
    except Exception:
        conf_text = ""
    if status == "exploited":
        return f"Status is exploited, meaning GENESIS produced evidence that the issue can be triggered on the target.{conf_text}"
    if status == "confirmed":
        return f"Status is confirmed, meaning GENESIS promoted this after proof or auditable operator validation.{conf_text}"
    if status == "disputed":
        return f"Status is disputed, meaning a validator found an unresolved concern. Review the evidence before acting.{conf_text}"
    if evidence_for:
        return f"Status is {status}. Evidence exists, but this should not be treated as a confirmed vulnerability until proof passes.{conf_text}"
    return f"Status is {status}. This is not yet a confirmed vulnerability.{conf_text}"


def build_plain_language_finding(
    vulnerability: Any,
    metadata: Mapping[str, Any] | None = None,
) -> PlainLanguageFinding:
    """Build a deterministic, Nessus-like simple-English explanation.

    This is a presentation helper only. It does not change the stored finding,
    validation state, or proof policy.
    """
    metadata = metadata or {}
    cves = [str(c) for c in _as_list(_get(vulnerability, "cve_ids", [])) if str(c or "").strip()]
    target = _target(vulnerability, metadata)
    vuln_class = _determine_class(vulnerability, metadata)
    severity = str(_get(vulnerability, "severity", "info") or "info").lower()
    title = _clean(_get(vulnerability, "title", "security finding"), max_len=260)
    evidence_for = _as_list(metadata.get("evidence_for") or [])

    if cves:
        description = (
            f"{target} appears to be affected by {', '.join(cves[:3])}. "
            f"This means the detected component or service matches a known security issue. "
            f"{_DESCRIPTION_BY_CLASS.get(vuln_class, _DESCRIPTION_BY_CLASS['package'])}"
        )
    else:
        description = (
            f"GENESIS found a {severity} target-specific issue: {title}. "
            f"The affected area is {target}. "
            f"{_DESCRIPTION_BY_CLASS.get(vuln_class, _DESCRIPTION_BY_CLASS['generic'])}"
        )

    remediation = _clean(_get(vulnerability, "remediation", ""), max_len=520)
    solution = remediation or _SOLUTION_BY_CLASS.get(vuln_class, _SOLUTION_BY_CLASS["generic"])

    return {
        "description": description,
        "why_it_matters": _IMPACT_BY_CLASS.get(vuln_class, _IMPACT_BY_CLASS["generic"]),
        "proof": _proof_text(vulnerability, evidence_for, _get(vulnerability, "verification_output", "")),
        "solution": solution,
        "validation_note": _validation_note(vulnerability, evidence_for),
    }

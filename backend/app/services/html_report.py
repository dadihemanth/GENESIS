from __future__ import annotations

import html
import re
import uuid
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Dict, Iterable, List, Mapping, Sequence


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
ACTIVE_STATUSES = {"confirmed", "exploited"}
REVIEW_STATUSES = {"disputed", "unverified", "refuted"}


def escape_html(value: Any) -> str:
    return html.escape(str(value or ""), quote=True)


def redact_sensitive(value: Any) -> str:
    text = str(value or "")
    replacements = [
        (r"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._\-+/=]+", r"\1[REDACTED]"),
        (r"(?i)(api[_-]?key['\"\s:=]+)[A-Za-z0-9._\-+/=]{12,}", r"\1[REDACTED]"),
        (r"(?i)(access[_-]?token['\"\s:=]+)[A-Za-z0-9._\-+/=]{12,}", r"\1[REDACTED]"),
        (r"(?i)(password['\"\s:=]+)[^\s,'\"]{4,}", r"\1[REDACTED]"),
        (r"(?i)(secret['\"\s:=]+)[A-Za-z0-9._\-+/=]{6,}", r"\1[REDACTED]"),
        (r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b", "[JWT_REDACTED]"),
        (r"\bAKIA[0-9A-Z]{16}\b", "[AWS_KEY_REDACTED]"),
    ]
    for pattern, repl in replacements:
        text = re.sub(pattern, repl, text)
    return text


def safe_text(value: Any, *, max_chars: int = 1200) -> str:
    text = redact_sensitive(value)
    if max_chars > 0 and len(text) > max_chars:
        return text[:max_chars].rstrip() + f"\n\n[truncated: showing first {max_chars} characters]"
    return text


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _norm(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip()).lower()


def _status(value: Any) -> str:
    return _norm(value) or "unverified"


def _severity(value: Any) -> str:
    sev = _norm(value) or "info"
    return sev if sev in SEVERITY_ORDER else "info"


def classify_areas(
    tool_names: Iterable[str],
    finding_texts: Iterable[str] = (),
    candidate_texts: Iterable[str] = (),
) -> Dict[str, Dict[str, Any]]:
    """Infer readable areas probed from tools plus finding/candidate text."""
    categories: Dict[str, Dict[str, Any]] = {
        "Reconnaissance": {"keywords": ("nmap", "dns", "subdomain", "whois", "banner", "fingerprint", "port", "dir", "crawl"), "count": 0, "signals": set()},
        "Web and API": {"keywords": ("http", "curl", "request", "swagger", "openapi", "graphql", "rest", "endpoint", "browser"), "count": 0, "signals": set()},
        "Authentication and Identity": {"keywords": ("auth", "login", "jwt", "oauth", "saml", "idor", "session", "token", "cors"), "count": 0, "signals": set()},
        "Injection": {"keywords": ("sql", "sqli", "nosql", "injection", "ssti", "template", "command", "xss"), "count": 0, "signals": set()},
        "SSRF and Cloud Metadata": {"keywords": ("ssrf", "metadata", "imds", "cloud", "aws", "azure", "gcp", "oob"), "count": 0, "signals": set()},
        "File and Path Access": {"keywords": ("lfi", "file", "path", "traversal", "download", "upload", "directory"), "count": 0, "signals": set()},
        "Source and Artifact Analysis": {"keywords": ("source", "repo", "artifact", "semgrep", "ast", "taint", "code", "sourcemap"), "count": 0, "signals": set()},
        "Binary, Fuzzing, and Instrumentation": {"keywords": ("binary", "ghidra", "fuzz", "symbolic", "symbex", "instrument", "trace", "asan"), "count": 0, "signals": set()},
        "Crypto and Transport": {"keywords": ("crypto", "tls", "ssl", "rsa", "ecdsa", "jwt", "certificate"), "count": 0, "signals": set()},
        "Infrastructure and Network": {"keywords": ("ssh", "smb", "ldap", "kerberos", "ad", "rdp", "network", "tcp", "udp"), "count": 0, "signals": set()},
    }
    blobs: List[tuple[str, str]] = []
    blobs.extend((str(name or ""), str(name or "")) for name in tool_names)
    blobs.extend(("finding", text) for text in finding_texts)
    blobs.extend(("candidate", text) for text in candidate_texts)

    for source, text in blobs:
        low = _norm(text)
        if not low:
            continue
        for area, data in categories.items():
            if any(keyword in low for keyword in data["keywords"]):
                data["count"] += 1
                if source and source not in {"finding", "candidate"}:
                    data["signals"].add(source)
                else:
                    data["signals"].add(low[:80])

    return {
        area: {"count": data["count"], "signals": sorted(data["signals"])[:8]}
        for area, data in categories.items()
        if data["count"] > 0
    }


def _badge(text: str, kind: str = "neutral") -> str:
    return f'<span class="badge {kind}">{escape_html(text)}</span>'


def _fmt_time(value: Any) -> str:
    if not value:
        return "-"
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _filename_target(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value or "session").strip("-")
    return cleaned[:80] or "session"


def _finding_meta(meta_by_vid: Mapping[str, Mapping[str, Any]], vuln: Any) -> Mapping[str, Any]:
    return meta_by_vid.get(str(getattr(vuln, "id", "")), {})


def _finding_text(vuln: Any, meta: Mapping[str, Any]) -> str:
    fields = [
        getattr(vuln, "title", ""),
        getattr(vuln, "description", ""),
        getattr(vuln, "affected_service", ""),
        " ".join(str(x) for x in _as_list(getattr(vuln, "cve_ids", []))),
        " ".join(str(x) for x in _as_list(getattr(vuln, "mitre_techniques", []))),
        meta.get("endpoint", ""),
        meta.get("technique_tag", ""),
    ]
    return " ".join(str(x) for x in fields if x)


def _executive_recommendation(vuln: Any) -> str:
    sev = _severity(getattr(vuln, "severity", "info"))
    status = _status(getattr(vuln, "verification_status", "unverified"))
    if status in ACTIVE_STATUSES and sev in {"critical", "high"}:
        return "Prioritize immediate remediation and retest after the fix is deployed."
    if status in ACTIVE_STATUSES:
        return "Schedule remediation based on exposure and business owner priority."
    if status == "disputed":
        return "Assign an engineer or security reviewer to resolve the disputed evidence before committing remediation work."
    return "Treat as a lead until more proof is collected or the owner confirms the risk."


def _technical_recommendation(vuln: Any, plain: Mapping[str, str]) -> str:
    patch = getattr(vuln, "patch_code", None)
    remediation = getattr(vuln, "remediation", None)
    if patch:
        return "Review the suggested patch, apply an equivalent fix in source control, deploy to a test environment, and rerun GENESIS against the affected endpoint."
    if remediation:
        return str(remediation)
    return plain.get("solution", "Validate the affected code or configuration, remove the unsafe behavior, and rerun the scan.")


def _table(rows: Sequence[Sequence[Any]], headers: Sequence[str]) -> str:
    head = "".join(f"<th>{escape_html(h)}</th>" for h in headers)
    body = []
    for row in rows:
        body.append("<tr>" + "".join(f"<td>{escape_html(cell)}</td>" for cell in row) + "</tr>")
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(body) or '<tr><td colspan=\"99\">No data.</td></tr>'}</tbody></table>"


def _finding_card(vuln: Any, meta: Mapping[str, Any], plain: Mapping[str, str], *, max_evidence_chars: int, include_raw: bool) -> str:
    sev = _severity(getattr(vuln, "severity", "info"))
    status = _status(getattr(vuln, "verification_status", "unverified"))
    cves = [str(c) for c in _as_list(getattr(vuln, "cve_ids", [])) if str(c or "").strip()]
    mitre = [str(m) for m in _as_list(getattr(vuln, "mitre_techniques", [])) if str(m or "").strip()]
    evidence = _as_list(meta.get("evidence_for") or [])
    endpoint = meta.get("endpoint") or ""
    technique = meta.get("technique_tag") or ""

    meta_rows = [
        ("Severity", sev.upper()),
        ("Status", status),
        ("CVSS", f"{getattr(vuln, 'cvss_score', None):.1f}" if getattr(vuln, "cvss_score", None) is not None else "-"),
        ("Affected service", getattr(vuln, "affected_service", "") or "-"),
        ("Endpoint", endpoint or "-"),
        ("CVE", ", ".join(cves) if cves else "-"),
        ("MITRE", ", ".join(mitre) if mitre else "-"),
        ("Technique", technique or "-"),
        ("Confidence", f"{float(getattr(vuln, 'confidence', 0) or 0) * 100:.0f}%"),
    ]
    evidence_items = "".join(
        f"<li><code>{escape_html(safe_text(e, max_chars=max_evidence_chars))}</code></li>"
        for e in evidence[:12]
    ) or "<li>No compact evidence items were attached.</li>"

    raw_sections = ""
    if include_raw:
        if getattr(vuln, "description", ""):
            raw_sections += (
                "<details><summary>Raw technical description</summary>"
                f"<pre>{escape_html(safe_text(getattr(vuln, 'description', ''), max_chars=max_evidence_chars))}</pre></details>"
            )
        if getattr(vuln, "verification_output", ""):
            raw_sections += (
                "<details><summary>Verification output</summary>"
                f"<pre>{escape_html(safe_text(getattr(vuln, 'verification_output', ''), max_chars=max_evidence_chars))}</pre></details>"
            )
        if getattr(vuln, "exploit_code", ""):
            raw_sections += (
                "<details><summary>Exploit / proof appendix</summary>"
                f"<pre>{escape_html(safe_text(getattr(vuln, 'exploit_code', ''), max_chars=max_evidence_chars))}</pre></details>"
            )
        if getattr(vuln, "patch_code", ""):
            raw_sections += (
                "<details open><summary>Suggested patch</summary>"
                f"<pre>{escape_html(safe_text(getattr(vuln, 'patch_code', ''), max_chars=max_evidence_chars))}</pre></details>"
            )

    return f"""
    <article class="finding {sev} {status}">
      <div class="finding-title">
        <h3>{escape_html(getattr(vuln, "title", ""))}</h3>
        <div>{_badge(sev.upper(), sev)} {_badge(status, status)}</div>
      </div>
      {_table(meta_rows, ["Field", "Value"])}
      <div class="two-col">
        <section><h4>Description</h4><p>{escape_html(plain.get("description", ""))}</p></section>
        <section><h4>Why It Matters</h4><p>{escape_html(plain.get("why_it_matters", ""))}</p></section>
      </div>
      <section><h4>Evidence Summary</h4><p>{escape_html(plain.get("proof", ""))}</p><ul>{evidence_items}</ul></section>
      <div class="two-col">
        <section><h4>Executive Recommendation</h4><p>{escape_html(_executive_recommendation(vuln))}</p></section>
        <section><h4>Technical Recommendation / Remediation</h4><p>{escape_html(_technical_recommendation(vuln, plain))}</p></section>
      </div>
      <section><h4>Validation Note</h4><p>{escape_html(plain.get("validation_note", ""))}</p></section>
      {raw_sections}
    </article>
    """


def _recommendation_buckets(vulns: Sequence[Any]) -> Dict[str, List[Any]]:
    buckets: Dict[str, List[Any]] = {"Fix now": [], "Schedule": [], "Monitor": [], "Review manually": []}
    for vuln in vulns:
        sev = _severity(getattr(vuln, "severity", "info"))
        status = _status(getattr(vuln, "verification_status", "unverified"))
        if status in ACTIVE_STATUSES and sev in {"critical", "high"}:
            buckets["Fix now"].append(vuln)
        elif status in ACTIVE_STATUSES and sev in {"medium", "low"}:
            buckets["Schedule"].append(vuln)
        elif sev == "info" and status in ACTIVE_STATUSES:
            buckets["Monitor"].append(vuln)
        else:
            buckets["Review manually"].append(vuln)
    return buckets


async def render_session_html_report(
    session_id: uuid.UUID,
    db: Any,
    *,
    audience: str = "combined",
    include_raw: bool = True,
    max_evidence_chars: int = 1200,
) -> tuple[str, str]:
    from sqlalchemy import select

    from app.database.mongodb import (
        get_benchmark_reports_collection,
        get_candidate_findings_collection,
        get_finding_clusters_collection,
        get_hypothesis_journals_collection,
        get_proof_runs_collection,
        get_target_surface_graph_collection,
        get_tool_outputs_collection,
        get_validation_verdicts_collection,
        get_vulnerability_metadata_collection,
    )
    from app.models.session import ResearchSession
    from app.models.vulnerability import Vulnerability
    from app.services.finding_explainer import build_plain_language_finding

    sid = str(session_id)
    session = (await db.execute(select(ResearchSession).where(ResearchSession.id == session_id))).scalar_one_or_none()
    if session is None:
        raise KeyError("session not found")

    rows = (await db.execute(select(Vulnerability).where(Vulnerability.session_id == session_id))).scalars().all()
    vulns = sorted(
        list(rows),
        key=lambda v: (
            SEVERITY_ORDER.get(_severity(getattr(v, "severity", "info")), 9),
            0 if _status(getattr(v, "verification_status", "")) in ACTIVE_STATUSES else 1,
            getattr(v, "created_at", None) or datetime.min,
        ),
    )

    meta_by_vid: Dict[str, Dict[str, Any]] = {}
    async for doc in get_vulnerability_metadata_collection().find({"session_id": sid}):
        vid = str(doc.get("vuln_id", ""))
        if vid:
            meta_by_vid[vid] = doc

    tool_docs = await get_tool_outputs_collection().find({"session_id": sid}, {"tool_name": 1, "timestamp": 1}).to_list(length=5000)
    tool_counts = Counter(str(doc.get("tool_name") or "?") for doc in tool_docs)

    candidates = await get_candidate_findings_collection().find({"session_id": sid}).to_list(length=1000)
    verdicts = await get_validation_verdicts_collection().find({"session_id": sid}).to_list(length=1000)
    proofs = await get_proof_runs_collection().find({"session_id": sid}).to_list(length=1000)
    clusters = await get_finding_clusters_collection().find({"session_id": sid}).to_list(length=1000)
    benchmarks = await get_benchmark_reports_collection().find({"session_id": sid}).sort("created_at", -1).to_list(length=20)
    surface_graph = await get_target_surface_graph_collection().find_one({"session_id": sid}) or {}

    hyp_cursor = get_hypothesis_journals_collection().find({"session_id": sid}).sort("updated_at", -1)
    latest_hyps: Dict[str, Dict[str, Any]] = {}
    async for doc in hyp_cursor:
        hid = str(doc.get("hyp_id", "")).strip()
        if hid and hid not in latest_hyps:
            latest_hyps[hid] = doc
    confirmed_hyps = [h for h in latest_hyps.values() if h.get("status") == "confirmed"]

    severity_counts = Counter(_severity(getattr(v, "severity", "info")) for v in vulns)
    status_counts = Counter(_status(getattr(v, "verification_status", "unverified")) for v in vulns)
    chain_ids = {str(getattr(v, "attack_chain_id", "")) for v in vulns if getattr(v, "attack_chain_id", None)}
    cves = sorted({str(c) for v in vulns for c in _as_list(getattr(v, "cve_ids", [])) if str(c or "").strip()})
    zero_day_count = sum(1 for v in vulns if bool(getattr(v, "is_zero_day", False)))
    passed_proof_count = sum(1 for p in proofs if p.get("passed"))
    disputed_or_unverified = [v for v in vulns if _status(getattr(v, "verification_status", "")) in REVIEW_STATUSES]
    confirmed = [v for v in vulns if _status(getattr(v, "verification_status", "")) in ACTIVE_STATUSES]
    top_risks = sorted(
        confirmed,
        key=lambda v: (SEVERITY_ORDER.get(_severity(getattr(v, "severity", "info")), 9), -(float(getattr(v, "confidence", 0) or 0))),
    )[:5]

    finding_texts = [_finding_text(v, _finding_meta(meta_by_vid, v)) for v in vulns]
    candidate_texts = [
        " ".join(str(c.get(k, "")) for k in ("title", "attack_class", "affected_surface", "hypothesis", "endpoint", "sink"))
        for c in candidates
    ]
    areas = classify_areas(tool_counts.keys(), finding_texts, candidate_texts)

    target = session.target_hostname or session.target_ip or "unknown-target"
    report_kind = "Final session report" if session.status == "completed" else "Partial session report"
    report_class = "final" if session.status == "completed" else "partial"
    filename = f"genesis-{_filename_target(target)}-{sid[:8]}.html"
    generated_at = datetime.utcnow().isoformat() + "Z"

    severity_rows = [[sev.title(), severity_counts.get(sev, 0)] for sev in ("critical", "high", "medium", "low", "info")]
    status_rows = [[status, count] for status, count in sorted(status_counts.items())]
    cve_rows = [[cve] for cve in cves]
    area_rows = [[area, info["count"], ", ".join(info["signals"]) or "-"] for area, info in areas.items()]
    tool_rows = [[name, count] for name, count in tool_counts.most_common(25)]
    benchmark_rows = [
        [
            b.get("label", "scorecard"),
            b.get("lane", "-"),
            b.get("recall", "n/a"),
            b.get("confirmed_vulnerability_count", 0),
            b.get("proof_coverage", 0),
            b.get("duplicate_rate", 0),
        ]
        for b in benchmarks
    ]
    proof_rows = [
        [
            p.get("candidate_id", "-"),
            p.get("proof_tool", "-"),
            "pass" if p.get("passed") else "fail",
            p.get("proof_class", "-"),
            safe_text(p.get("pass_fail_reason") or p.get("result") or "", max_chars=240),
        ]
        for p in proofs[:100]
    ]
    verdict_rows = [
        [
            v.get("candidate_id", "-"),
            v.get("validator", "-"),
            v.get("verdict", "-"),
            safe_text(v.get("reasoning", ""), max_chars=240),
        ]
        for v in verdicts[:100]
    ]
    candidate_rows = [
        [
            c.get("title", "-"),
            c.get("severity", "-"),
            c.get("status", "-"),
            c.get("endpoint", c.get("affected_surface", "-")),
            safe_text(c.get("hypothesis", ""), max_chars=240),
        ]
        for c in candidates[:100]
    ]

    finding_cards = []
    for vuln in confirmed:
        meta = _finding_meta(meta_by_vid, vuln)
        plain = build_plain_language_finding(vuln, meta)
        finding_cards.append(_finding_card(vuln, meta, plain, max_evidence_chars=max_evidence_chars, include_raw=include_raw))
    review_cards = []
    for vuln in disputed_or_unverified:
        meta = _finding_meta(meta_by_vid, vuln)
        plain = build_plain_language_finding(vuln, meta)
        review_cards.append(_finding_card(vuln, meta, plain, max_evidence_chars=max_evidence_chars, include_raw=include_raw))

    buckets = _recommendation_buckets(vulns)
    bucket_html = []
    for name, items in buckets.items():
        rows_for_bucket = [[getattr(v, "severity", "info"), getattr(v, "verification_status", "unverified"), getattr(v, "title", "")] for v in items[:20]]
        bucket_html.append(f"<section><h3>{escape_html(name)}</h3>{_table(rows_for_bucket, ['Severity', 'Status', 'Finding'])}</section>")

    top_risk_rows = [
        [
            getattr(v, "severity", "info").upper(),
            getattr(v, "title", ""),
            getattr(v, "affected_service", "") or _finding_meta(meta_by_vid, v).get("endpoint", "-"),
            _executive_recommendation(v),
        ]
        for v in top_risks
    ]
    hyp_rows = [
        [
            h.get("hyp_id", "-"),
            f"{float(h.get('confidence') or 0) * 100:.0f}%",
            safe_text(h.get("statement", ""), max_chars=260),
        ]
        for h in confirmed_hyps[:25]
    ]
    chain_rows = []
    for cid in sorted(chain_ids):
        members = [v for v in vulns if str(getattr(v, "attack_chain_id", "")) == cid]
        members.sort(key=lambda v: getattr(v, "chain_position", None) or 0)
        chain_rows.append([cid, len(members), " -> ".join(getattr(v, "title", "")[:80] for v in members)])

    css = """
    :root { --ink:#172033; --muted:#637086; --line:#dde3ee; --bg:#f6f8fb; --card:#fff; --blue:#365cff; --red:#c62828; --orange:#ef6c00; --green:#137a4e; --purple:#6a35b8; }
    * { box-sizing: border-box; }
    body { margin:0; background:var(--bg); color:var(--ink); font-family: Inter, Segoe UI, Arial, sans-serif; line-height:1.5; }
    main { max-width: 1180px; margin: 0 auto; padding: 28px; }
    header { background:#101828; color:white; padding:34px 28px; border-bottom:5px solid var(--blue); }
    header h1 { margin:0 0 8px; font-size:30px; }
    header p { margin:4px 0; color:#d6ddeb; }
    section, article { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:18px; margin:16px 0; box-shadow:0 1px 2px rgba(16,24,40,.04); }
    h2 { font-size:20px; margin:0 0 12px; }
    h3 { font-size:16px; margin:0 0 10px; }
    h4 { font-size:13px; margin:0 0 6px; text-transform:uppercase; letter-spacing:.04em; color:var(--muted); }
    .banner { display:inline-block; padding:6px 10px; border-radius:999px; font-size:12px; font-weight:700; margin-bottom:10px; }
    .banner.final { background:#e8f5ee; color:var(--green); }
    .banner.partial { background:#fff4e5; color:#9a5b00; }
    .metric-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:10px; }
    .metric { padding:14px; border:1px solid var(--line); border-radius:8px; background:#fbfcff; }
    .metric strong { display:block; font-size:24px; }
    .two-col { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:12px; }
    table { width:100%; border-collapse:collapse; margin:8px 0; font-size:13px; }
    th, td { text-align:left; border-bottom:1px solid var(--line); padding:8px; vertical-align:top; }
    th { background:#f1f4f9; color:#344054; }
    .badge { display:inline-block; border-radius:999px; padding:3px 8px; font-size:11px; font-weight:800; margin:2px; background:#eef1f6; color:#344054; }
    .badge.critical, .badge.exploited { background:#fdeaea; color:var(--red); }
    .badge.high { background:#fff0e3; color:#b45100; }
    .badge.medium, .badge.disputed { background:#fff8dd; color:#8a6200; }
    .badge.low { background:#e9f0ff; color:#284a9f; }
    .badge.confirmed { background:#e8f5ee; color:var(--green); }
    .badge.unverified { background:#edf0f5; color:#4e5969; }
    .finding-title { display:flex; justify-content:space-between; align-items:flex-start; gap:12px; flex-wrap:wrap; }
    .finding { border-left:5px solid #8a93a6; }
    .finding.critical { border-left-color:var(--red); }
    .finding.high { border-left-color:#ef6c00; }
    .finding.medium { border-left-color:#ffb020; }
    .finding.confirmed { box-shadow:inset 0 0 0 1px rgba(19,122,78,.12); }
    code, pre { font-family: Consolas, SFMono-Regular, Menlo, monospace; white-space:pre-wrap; word-break:break-word; }
    pre { background:#0f172a; color:#dce7ff; padding:12px; border-radius:6px; overflow:auto; }
    details { margin:10px 0; }
    summary { cursor:pointer; font-weight:700; color:#334155; }
    .muted { color:var(--muted); }
    .print-note { font-size:12px; color:var(--muted); }
    @media print { body { background:white; } main { max-width:none; padding:0; } section, article { box-shadow:none; break-inside:avoid; } header { margin:-8px -8px 18px; } }
    """

    html_doc = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>GENESIS HTML Report - {escape_html(target)}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>{css}</style>
</head>
<body>
<header>
  <span class="banner {report_class}">{escape_html(report_kind)}</span>
  <h1>GENESIS Security Assessment Report</h1>
  <p><strong>Target:</strong> {escape_html(target)} | <strong>Session:</strong> {escape_html(sid)}</p>
  <p><strong>Status:</strong> {escape_html(session.status)} | <strong>Profile:</strong> {escape_html(session.scan_profile)} | <strong>Agent mode:</strong> {escape_html(session.agent_mode)}</p>
  <p><strong>Started:</strong> {escape_html(_fmt_time(session.started_at))} | <strong>Completed:</strong> {escape_html(_fmt_time(session.completed_at))} | <strong>Generated:</strong> {escape_html(generated_at)}</p>
</header>
<main>
  <section>
    <h2>Executive Summary</h2>
    <div class="metric-grid">
      <div class="metric"><strong>{len(vulns)}</strong>Total findings</div>
      <div class="metric"><strong>{len(confirmed)}</strong>Confirmed / exploited</div>
      <div class="metric"><strong>{len(disputed_or_unverified)}</strong>Need review</div>
      <div class="metric"><strong>{severity_counts.get('critical', 0) + severity_counts.get('high', 0)}</strong>Critical / high</div>
      <div class="metric"><strong>{len(cves)}</strong>CVEs found</div>
      <div class="metric"><strong>{zero_day_count}</strong>Novel / zero-day flags</div>
    </div>
    <p>GENESIS assessed the target with automated agents and security tools, then classified findings using evidence checks and critic review. Confirmed findings are suitable for remediation planning; disputed or unverified items should be reviewed before they become tickets.</p>
    <h3>Top Risks</h3>
    {_table(top_risk_rows, ['Severity', 'Title', 'Affected area', 'Executive recommendation'])}
  </section>

  <section>
    <h2>Risk Dashboard</h2>
    <div class="two-col">
      <section><h3>Severity</h3>{_table(severity_rows, ['Severity', 'Count'])}</section>
      <section><h3>Verification Status</h3>{_table(status_rows, ['Status', 'Count'])}</section>
    </div>
    <div class="two-col">
      <section><h3>CVEs Found</h3>{_table(cve_rows, ['CVE'])}</section>
      <section><h3>Other Signals</h3>{_table([['Attack chains', len(chain_ids)], ['Confirmed hypotheses', len(confirmed_hyps)], ['Tool calls', sum(tool_counts.values())], ['Validation candidates', len(candidates)], ['Passed proof runs', passed_proof_count], ['Surface links', surface_graph.get('link_count', 0)]], ['Signal', 'Count'])}</section>
    </div>
  </section>

  <section>
    <h2>Areas Probed</h2>
    {_table(area_rows, ['Area', 'Signal count', 'Representative signals'])}
  </section>

  {'<section><h2>Confirmed Vulnerabilities</h2>' + ''.join(finding_cards or ['<p>No confirmed or exploited findings recorded.</p>']) + '</section>' if audience in {'combined', 'technical', 'executive'} else ''}
  {'<section><h2>Disputed and Unverified Findings</h2><p>These items are not confirmed. They require more proof, owner review, or validation.</p>' + ''.join(review_cards or ['<p>No disputed or unverified findings recorded.</p>']) + '</section>' if audience in {'combined', 'technical'} else ''}

  <section>
    <h2>Recommendations</h2>
    {''.join(bucket_html)}
    <p class="print-note">Retest after remediation, especially for critical/high findings and any finding tied to authentication, command execution, file access, or SSRF.</p>
  </section>

  <section>
    <h2>Methodology</h2>
    <p>Scan profile: <strong>{escape_html(session.scan_profile)}</strong>. Agent mode: <strong>{escape_html(session.agent_mode)}</strong>. GENESIS used tool automation, hypothesis tracking, evidence checks, critic review, and optional Validation Lab artifacts when candidates or proof runs were present.</p>
    <div class="two-col">
      <section><h3>Top Tools Used</h3>{_table(tool_rows, ['Tool', 'Calls'])}</section>
      <section><h3>Benchmark Scorecards</h3>{_table(benchmark_rows, ['Label', 'Lane', 'Recall', 'Confirmed', 'Proof coverage', 'Duplicate rate'])}</section>
    </div>
  </section>

  {'<section><h2>Technical Appendix</h2><h3>Attack Chains</h3>' + _table(chain_rows, ['Chain', 'Steps', 'Path']) + '<h3>Confirmed Hypotheses</h3>' + _table(hyp_rows, ['ID', 'Confidence', 'Statement']) + '<h3>Validation Lab Candidates</h3>' + _table(candidate_rows, ['Title', 'Severity', 'Status', 'Endpoint / surface', 'Hypothesis']) + '<h3>Validation Verdicts</h3>' + _table(verdict_rows, ['Candidate', 'Validator', 'Verdict', 'Reasoning']) + '<h3>Proof Runs</h3>' + _table(proof_rows, ['Candidate', 'Tool', 'Result', 'Class', 'Reason']) + '<h3>Clusters</h3>' + _table([[c.get('cluster_id', '-'), c.get('canonical_title', c.get('canonical_finding', '-')), len(c.get('duplicates', []) or [])] for c in clusters[:100]], ['Cluster', 'Canonical finding', 'Duplicates']) + '</section>' if audience in {'combined', 'technical'} else ''}
</main>
</body>
</html>"""

    return filename, html_doc

"""validation milestone 2 — commit_analyzer: git history attack surface derivation.

Analyzes recent git commit history to identify security-sensitive changes
and derive a prioritized scan surface. The validated scanner Prepare stage draws attack
surface and threat models by analyzing past commits; this module implements
that capability for GENESIS.

Security-sensitive commits (ownership changes, auth modifications, new
allocation sites, recently-added IPC/network paths) are high-value scan
targets because they represent code under active change — where the risk of
introducing bugs is highest and where recent CVEs cluster.

Results are stored in MongoDB `security_commits` per session, and a
prioritized surface list is returned for injection into architectural_reasoner.
"""
from __future__ import annotations

import hashlib
import logging
import re
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.database.mongodb import get_security_commits_collection

logger = logging.getLogger(__name__)

# Maximum commits to scan (performance guard)
_MAX_COMMITS = 500
# Max diff size per commit to feed to keyword extraction
_MAX_DIFF_CHARS = 8_000

# Security-sensitive keywords — presence in a diff raises the risk score.
# Organized as (pattern, risk_delta, label).
_SECURITY_PATTERNS: List[Tuple[re.Pattern, float, str]] = [
    # Memory management — ownership/lifetime violations are UAF/double-free territory
    (re.compile(r"\bfree\s*\("),              0.25, "memory_free"),
    (re.compile(r"\bkfree\s*\("),             0.25, "memory_free"),
    (re.compile(r"\bdelete\s+"),              0.20, "memory_free"),
    (re.compile(r"\bmalloc\s*\("),            0.15, "memory_alloc"),
    (re.compile(r"\bkmalloc\s*\("),           0.15, "memory_alloc"),
    (re.compile(r"\bnew\s+\w"),               0.10, "memory_alloc"),
    (re.compile(r"\bmemcpy\s*\("),            0.20, "unsafe_copy"),
    (re.compile(r"\bstrcpy\s*\("),            0.25, "unsafe_copy"),
    (re.compile(r"\bsprintf\s*\("),           0.15, "format_string"),
    # Reference counting — incorrect decrement order is UAF
    (re.compile(r"\bObDeref\w+"),             0.30, "refcount"),
    (re.compile(r"\bkref_put\b"),             0.25, "refcount"),
    (re.compile(r"\bAtomic\w*Dec\b"),         0.20, "refcount"),
    # Locking — missed unlock is deadlock; wrong order is privilege escalation
    (re.compile(r"\b(?:spin_lock|mutex_lock|AcquireSpin)\b"),  0.20, "locking"),
    (re.compile(r"\b(?:spin_unlock|mutex_unlock|ReleaseSpin)\b"), 0.15, "locking"),
    (re.compile(r"\bIoAcquireCancelSpinLock\b"),              0.30, "kernel_lock"),
    # Authentication and authorization — new auth paths are high value
    (re.compile(r"\bauth(?:enticate|oriz\w+)?\b", re.I),      0.25, "auth"),
    (re.compile(r"\bpermission\b", re.I),                      0.20, "auth"),
    (re.compile(r"\bprivilege\b", re.I),                       0.20, "privilege"),
    (re.compile(r"\brole\b", re.I),                            0.10, "rbac"),
    (re.compile(r"\btoken\b", re.I),                           0.15, "token"),
    # IPC and network — new entry points
    (re.compile(r"\bsocket\s*\("),            0.20, "network"),
    (re.compile(r"\bsend\s*\(|recv\s*\("),   0.15, "network"),
    (re.compile(r"\bIRP\b|IRP_MJ_"),         0.30, "kernel_irp"),
    (re.compile(r"\bRpcServer\w+\b"),         0.25, "rpc"),
    (re.compile(r"\bOpenProcess|NtCreate\w+"), 0.20, "kernel_api"),
    # Cryptographic
    (re.compile(r"\bAES|RSA|ECDSA|HMAC\b"),  0.15, "crypto"),
    (re.compile(r"\bssl_|SSL_\w+"),           0.20, "tls"),
    # Validation bypass patterns
    (re.compile(r"\bbypass|skip.*check|disable.*valid\w+", re.I), 0.30, "bypass"),
    (re.compile(r"\bTODO.*security|FIXME.*auth|HACK.*bypass", re.I), 0.25, "todo_security"),
]

# File extension risk multipliers — kernel/native code > web
_EXT_MULTIPLIERS: Dict[str, float] = {
    ".c": 1.5, ".cpp": 1.5, ".cc": 1.5, ".h": 1.3,
    ".rs": 1.3, ".go": 1.1,
    ".py": 0.9, ".js": 0.9, ".ts": 0.9,
    ".java": 1.0, ".cs": 1.0,
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _run_git(args: List[str], cwd: str, timeout: int = 60) -> Optional[str]:
    try:
        result = subprocess.run(
            ["git"] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        if result.returncode == 0:
            return result.stdout
    except Exception as exc:
        logger.debug("commit_analyzer git command failed: %s", exc)
    return None


def _score_diff(diff_text: str) -> Tuple[float, List[str]]:
    """Return (risk_score 0–1, [matched_labels]) for a diff snippet."""
    score = 0.0
    labels: List[str] = []
    seen_labels: set = set()
    for pattern, delta, label in _SECURITY_PATTERNS:
        if pattern.search(diff_text):
            score += delta
            if label not in seen_labels:
                labels.append(label)
                seen_labels.add(label)
    # Apply max extension multiplier found in diff file headers
    max_mult = 1.0
    for ext, mult in _EXT_MULTIPLIERS.items():
        if ext in diff_text:
            max_mult = max(max_mult, mult)
    score *= max_mult
    return min(1.0, score), labels


def _extract_changed_functions(diff_text: str) -> List[str]:
    """Extract function/method signatures from unified diff context lines."""
    funcs: List[str] = []
    # @@ -N,N +N,N @@ <function_name> pattern
    for m in re.finditer(r"@@[^@]*@@\s*(.+)", diff_text):
        ctx = m.group(1).strip()
        if ctx and len(ctx) < 200:
            funcs.append(ctx[:100])
    return funcs[:20]


def _extract_changed_files(diff_text: str) -> List[str]:
    files: List[str] = []
    for m in re.finditer(r"^(?:\+\+\+|---)\s+b?/(.+)$", diff_text, re.M):
        f = m.group(1).strip()
        if f and f != "/dev/null":
            files.append(f)
    return list(dict.fromkeys(files))[:20]  # deduplicate preserving order


async def analyze_commits(
    session_id: str,
    repo_path: str,
    max_commits: int = _MAX_COMMITS,
) -> Dict[str, Any]:
    """Analyze git history at *repo_path* for security-sensitive changes.

    Returns a summary dict:
      {
        "commits_scanned": int,
        "high_risk_commits": int,
        "prioritized_surface": [{"file": str, "risk_score": float, "labels": [...]}],
        "stored": int,
      }

    Also persists per-commit documents to MongoDB `security_commits` collection
    so architectural_reasoner can query them with `get_high_risk_commits()`.
    """
    repo_dir = str(repo_path)

    # Verify this is a git repository
    if not _run_git(["rev-parse", "--git-dir"], repo_dir):
        logger.info("commit_analyzer: %s is not a git repository — skipping", repo_dir)
        return {"commits_scanned": 0, "high_risk_commits": 0, "prioritized_surface": [], "stored": 0}

    # Get the commit list: hash, date, author, subject
    log_out = _run_git(
        ["log", f"-{max_commits}", "--pretty=format:%H\t%ai\t%ae\t%s", "--diff-filter=MA"],
        repo_dir,
        timeout=30,
    )
    if not log_out:
        return {"commits_scanned": 0, "high_risk_commits": 0, "prioritized_surface": [], "stored": 0}

    col = get_security_commits_collection()

    commits_scanned = 0
    high_risk_commits = 0
    file_risk_map: Dict[str, Dict[str, Any]] = {}
    stored = 0

    for line in log_out.strip().splitlines():
        parts = line.split("\t", 3)
        if len(parts) < 4:
            continue
        commit_hash, date_str, author_email, subject = parts
        commits_scanned += 1

        # Pull the diff for this commit (truncated to avoid huge context)
        diff_out = _run_git(
            ["show", "--unified=2", "--no-color", commit_hash, "--", "*.c", "*.cpp",
             "*.h", "*.py", "*.go", "*.java", "*.ts", "*.js", "*.cs", "*.rs"],
            repo_dir,
            timeout=20,
        )
        if not diff_out:
            continue
        diff_snippet = diff_out[:_MAX_DIFF_CHARS]

        risk_score, labels = _score_diff(diff_snippet)
        if risk_score < 0.1:
            continue

        high_risk_commits += 1
        changed_files = _extract_changed_files(diff_snippet)
        changed_functions = _extract_changed_functions(diff_snippet)

        # Accumulate file-level risk (a file touched in many high-risk commits is higher priority)
        for f in changed_files:
            if f not in file_risk_map:
                file_risk_map[f] = {"file": f, "risk_score": 0.0, "labels": set(), "commit_count": 0}
            file_risk_map[f]["risk_score"] = min(1.0, file_risk_map[f]["risk_score"] + risk_score * 0.5)
            file_risk_map[f]["labels"].update(labels)
            file_risk_map[f]["commit_count"] += 1

        # Store the commit document
        commit_id = f"seccom-{session_id[:8]}-{commit_hash[:12]}"
        doc = {
            "_id": commit_id,
            "session_id": str(session_id),
            "commit_hash": commit_hash,
            "author_email": author_email[:100],
            "date": date_str[:30],
            "subject": subject[:300],
            "risk_score": risk_score,
            "security_keywords_hit": labels,
            "files_changed": changed_files,
            "functions_changed": changed_functions,
            "analyzed_at": _now(),
        }
        try:
            await col.replace_one({"_id": commit_id}, doc, upsert=True)
            stored += 1
        except Exception as exc:
            logger.debug("commit_analyzer: mongo upsert failed: %s", exc)

    # Build prioritized surface (top files by cumulative risk, de-duped)
    surface = sorted(
        [
            {
                "file": v["file"],
                "risk_score": round(v["risk_score"], 3),
                "labels": sorted(v["labels"]),
                "commit_count": v["commit_count"],
            }
            for v in file_risk_map.values()
        ],
        key=lambda x: x["risk_score"],
        reverse=True,
    )[:50]

    logger.info(
        "commit_analyzer: session=%s commits=%d high_risk=%d surface_files=%d stored=%d",
        session_id, commits_scanned, high_risk_commits, len(surface), stored,
    )
    return {
        "commits_scanned": commits_scanned,
        "high_risk_commits": high_risk_commits,
        "prioritized_surface": surface,
        "stored": stored,
    }


async def get_high_risk_commits(
    session_id: str,
    min_risk: float = 0.3,
    limit: int = 20,
) -> List[Dict[str, Any]]:
    """Return the top high-risk commits for a session from MongoDB."""
    col = get_security_commits_collection()
    try:
        cursor = (
            col.find({"session_id": str(session_id), "risk_score": {"$gte": min_risk}})
            .sort("risk_score", -1)
            .limit(limit)
        )
        return [doc async for doc in cursor]
    except Exception as exc:
        logger.warning("get_high_risk_commits failed: %s", exc)
        return []

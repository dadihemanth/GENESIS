"""T80 — repo_ingest: deep-clone source, build symbol table, chunk and embed.

Clones a git repository (or ingests a local path) into the MinIO artifact
store, detects languages, labels entry points, then chunks source files into
~512-token segments and stores their embeddings in the `source_corpus`
ChromaDB collection so T81–T85 can perform semantic source-code recall.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.database.chroma_client import get_source_corpus_collection
from app.services.artifact_resolver import ArtifactResolver

logger = logging.getLogger(__name__)

# Maximum characters per chunk before we split (≈512 tokens at ~4 chars/token)
_CHUNK_SIZE = 2048
# Languages we recognise; value = typical entry-point filename patterns
_LANG_MAP: Dict[str, List[str]] = {
    "python": ["main.py", "app.py", "wsgi.py", "asgi.py", "manage.py", "setup.py"],
    "javascript": ["index.js", "server.js", "app.js", "main.js"],
    "typescript": ["index.ts", "server.ts", "app.ts", "main.ts"],
    "java": ["Main.java", "Application.java", "App.java"],
    "go": ["main.go"],
    "php": ["index.php", "app.php"],
    "ruby": ["app.rb", "config.ru"],
    "csharp": ["Program.cs", "Startup.cs"],
    "cpp": ["main.cpp", "main.cc"],
    "c": ["main.c"],
}
_EXT_TO_LANG: Dict[str, str] = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".java": "java", ".go": "go", ".php": "php", ".rb": "ruby",
    ".cs": "csharp", ".cpp": "cpp", ".cc": "cpp", ".c": "c",
}
# Files / directories to skip during ingestion
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".tox"}
_SKIP_EXTS = {".pyc", ".class", ".o", ".so", ".dll", ".exe", ".bin", ".jpg",
              ".jpeg", ".png", ".gif", ".pdf", ".zip", ".tar", ".gz"}


def _detect_language(file_path: Path) -> str:
    return _EXT_TO_LANG.get(file_path.suffix.lower(), "unknown")


def _is_entry_point(file_path: Path, language: str) -> bool:
    patterns = _LANG_MAP.get(language, [])
    return file_path.name in patterns


def _chunk_text(text: str, chunk_size: int = _CHUNK_SIZE) -> List[str]:
    """Split *text* into overlapping chunks of at most *chunk_size* chars."""
    if len(text) <= chunk_size:
        return [text]
    chunks: List[str] = []
    start = 0
    overlap = chunk_size // 8
    while start < len(text):
        end = min(start + chunk_size, len(text))
        chunks.append(text[start:end])
        start = end - overlap
    return chunks


def _sanitize_git_url(url: str) -> bool:
    """Reject obviously unsafe git URLs (local paths, file://, etc.)."""
    url = url.strip()
    if re.match(r"^(https?|git|ssh)://", url):
        return True
    if re.match(r"^git@[\w.]+:", url):
        return True
    return False


async def ingest_repository(
    session_id: str,
    repo_url: Optional[str] = None,
    local_path: Optional[str] = None,
    max_files: int = 500,
) -> Dict[str, Any]:
    """Clone / read a repository and embed its source into ChromaDB.

    Returns a summary dict with file count, languages detected, and entry
    points found. All failures are caught and returned in an `errors` list so
    a single bad file never aborts the whole ingestion.
    """
    if not repo_url and not local_path:
        return {"error": "Either repo_url or local_path is required"}

    work_dir: Optional[str] = None
    cleanup_work = False

    try:
        if repo_url:
            if not _sanitize_git_url(repo_url):
                return {"error": "Unsupported or unsafe repo_url scheme"}
            work_dir = tempfile.mkdtemp(prefix="genesis_repo_")
            cleanup_work = True
            result = subprocess.run(
                ["git", "clone", "--depth", "1", "--quiet", repo_url, work_dir],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode != 0:
                return {"error": f"git clone failed: {result.stderr[:500]}"}
        else:
            work_dir = local_path

        source_dir = Path(work_dir)
        collection = await get_source_corpus_collection()

        file_count = 0
        lang_counts: Dict[str, int] = {}
        entry_points: List[str] = []
        errors: List[str] = []
        add_ids: List[str] = []
        add_docs: List[str] = []
        add_metas: List[Dict[str, Any]] = []

        for file_path in source_dir.rglob("*"):
            if file_count >= max_files:
                break
            if not file_path.is_file():
                continue
            if any(p in file_path.parts for p in _SKIP_DIRS):
                continue
            if file_path.suffix.lower() in _SKIP_EXTS:
                continue

            lang = _detect_language(file_path)
            if lang == "unknown":
                continue

            try:
                text = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception as exc:
                errors.append(f"{file_path}: {exc}")
                continue

            file_count += 1
            lang_counts[lang] = lang_counts.get(lang, 0) + 1
            is_entry = _is_entry_point(file_path, lang)
            if is_entry:
                rel = str(file_path.relative_to(source_dir))
                entry_points.append(rel)

            rel_path = str(file_path.relative_to(source_dir))
            repo_name = (
                repo_url.rstrip("/").rsplit("/", 1)[-1].replace(".git", "")
                if repo_url
                else Path(local_path).name
            )

            for chunk_idx, chunk in enumerate(_chunk_text(text)):
                chunk_hash = hashlib.sha256(chunk.encode()).hexdigest()[:16]
                doc_id = f"src-{session_id}-{chunk_hash}-{chunk_idx}"
                add_ids.append(doc_id)
                add_docs.append(chunk)
                add_metas.append({
                    "session_id": session_id,
                    "repo": repo_name,
                    "language": lang,
                    "file_path": rel_path,
                    "symbol": "",
                    "kind": "entry_point" if (is_entry and chunk_idx == 0) else "source",
                })

            # Batch insert every 200 chunks to avoid oversized requests
            if len(add_ids) >= 200:
                try:
                    await collection.add(ids=add_ids, documents=add_docs, metadatas=add_metas)
                except Exception as exc:
                    errors.append(f"chroma batch add: {exc}")
                add_ids, add_docs, add_metas = [], [], []

        if add_ids:
            try:
                await collection.add(ids=add_ids, documents=add_docs, metadatas=add_metas)
            except Exception as exc:
                errors.append(f"chroma final batch add: {exc}")

        summary = {
            "session_id": session_id,
            "file_count": file_count,
            "languages": lang_counts,
            "entry_points": entry_points[:20],
            "chunks_stored": len(add_ids),
            "errors": errors[:10],
        }
        logger.info("repo_ingest: session=%s files=%d chunks=%d", session_id, file_count, len(add_ids))
        return summary

    except Exception as exc:
        logger.warning("repo_ingest failed: %s", exc)
        return {"error": str(exc)}
    finally:
        if cleanup_work and work_dir and os.path.exists(work_dir):
            import shutil
            shutil.rmtree(work_dir, ignore_errors=True)


async def search_source_corpus(
    session_id: str,
    query: str,
    n_results: int = 10,
    language: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Semantic search over ingested source for the given session."""
    try:
        collection = await get_source_corpus_collection()
        where: Optional[Dict[str, Any]] = {"session_id": session_id}
        if language:
            where = {"$and": [{"session_id": session_id}, {"language": language}]}
        results = await collection.query(
            query_texts=[query],
            where=where,
            n_results=n_results,
            include=["documents", "metadatas", "distances"],
        )
        items: List[Dict[str, Any]] = []
        if results and results.get("ids"):
            for i, doc_id in enumerate(results["ids"][0]):
                items.append({
                    "id": doc_id,
                    "document": results["documents"][0][i] if results.get("documents") else "",
                    "metadata": results["metadatas"][0][i] if results.get("metadatas") else {},
                    "similarity": 1.0 - (results["distances"][0][i] if results.get("distances") else 1.0),
                })
        return items
    except Exception as exc:
        logger.warning("search_source_corpus failed: %s", exc)
        return []

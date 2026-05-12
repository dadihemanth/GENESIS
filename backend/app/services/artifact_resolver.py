"""T23 — Shared-artifact resolver for multi-host Celery deployments.

On a single-host deployment all workers share the ``security_data`` bind mount,
so every artifact is addressable by its local filesystem path. For a
multi-host deployment we need the same artifact reachable from a worker on
host B that was pulled on host A — so we mirror pulled bytes into MinIO
(``minio_bucket``) and store the object key alongside the on-disk path in
the Mongo ``artifacts`` collection.

The resolver exposes two idempotent operations:

    publish(local_path, session_id, sha256)  → s3_key
    resolve(session_id, sha256)              → LocalPath   (cached under /tmp)

When ``MINIO_ENDPOINT`` is empty (default — single-host v2.5 deployment) both
operations degrade gracefully to a local-filesystem stat on the shared mount,
which is exactly today's behaviour. Nothing breaks for operators who don't
opt in to the multi-host path.
"""
from __future__ import annotations

import hashlib
import logging
import os
import shutil
from pathlib import Path
from typing import Optional

from app.config import settings

logger = logging.getLogger(__name__)

_ARTIFACT_ROOT = Path(os.environ.get("ARTIFACT_ROOT", "/data/security/artifacts")).resolve()
# Scratch dir for MinIO-fetched objects on remote workers. Kept under /tmp
# because the artifact-root bind mount is typically read-only on remote hosts.
_CACHE_ROOT = Path(os.environ.get("ARTIFACT_CACHE_ROOT", "/tmp/artifacts_cache"))
_CACHE_ROOT.mkdir(parents=True, exist_ok=True)


def _s3_key(session_id: str, sha256: str, basename: str = "") -> str:
    safe_base = "".join(c if c.isalnum() or c in "._-" else "_" for c in basename)[:80] or "artifact"
    return f"{session_id}/{sha256}-{safe_base}"


class ArtifactResolverError(RuntimeError):
    pass


class ArtifactResolver:
    """Singleton-ish MinIO gateway. Construct via ``get_resolver()``."""

    def __init__(self) -> None:
        self._client = None
        self._bucket = settings.minio_bucket
        self._enabled = bool(settings.minio_endpoint and settings.minio_access_key)

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _ensure_client(self):
        if not self._enabled:
            raise ArtifactResolverError("MinIO is not configured (MINIO_ENDPOINT empty)")
        if self._client is None:
            try:
                from minio import Minio
                from minio.error import S3Error  # noqa: F401 — imported for side effect
            except ImportError as exc:  # pragma: no cover — dep declared in requirements.txt
                raise ArtifactResolverError(f"minio client not installed: {exc}") from exc
            self._client = Minio(
                settings.minio_endpoint,
                access_key=settings.minio_access_key,
                secret_key=settings.minio_secret_key,
                secure=settings.minio_secure,
            )
            # Create the bucket on first use — idempotent.
            try:
                if not self._client.bucket_exists(self._bucket):
                    self._client.make_bucket(self._bucket)
                    logger.info("Created MinIO bucket %s", self._bucket)
            except Exception as exc:  # noqa: BLE001
                raise ArtifactResolverError(f"bucket init failed: {exc}") from exc
        return self._client

    def publish(self, local_path: Path | str, session_id: str, sha256: str) -> Optional[str]:
        """Upload ``local_path`` to MinIO under a session-scoped key. Returns the
        object key on success, or ``None`` when MinIO is disabled (callers
        should still register the local path in Mongo and proceed).

        Idempotent: repeated uploads of the same (session_id, sha256) overwrite
        the same key, which is cheap and avoids stale copies.
        """
        path = Path(local_path)
        if not path.is_file():
            raise ArtifactResolverError(f"local_path does not exist: {path}")
        if not self._enabled:
            return None
        client = self._ensure_client()
        key = _s3_key(session_id, sha256, path.name)
        try:
            client.fput_object(self._bucket, key, str(path))
        except Exception as exc:  # noqa: BLE001
            raise ArtifactResolverError(f"upload failed: {exc}") from exc
        return key

    def resolve_from_s3(self, s3_key: str, expected_sha256: Optional[str] = None) -> Path:
        """Fetch ``s3_key`` into the local cache and return the path.

        Uses ``expected_sha256`` (if given) as a cache key — if the cached file
        already hashes to ``expected_sha256`` we skip the network round-trip.
        """
        if not self._enabled:
            raise ArtifactResolverError("MinIO is not configured (MINIO_ENDPOINT empty)")

        safe_name = s3_key.replace("/", "__")[:120]
        cache_path = _CACHE_ROOT / safe_name

        if expected_sha256 and cache_path.is_file():
            if _sha256_file(cache_path) == expected_sha256:
                return cache_path

        client = self._ensure_client()
        try:
            client.fget_object(self._bucket, s3_key, str(cache_path))
        except Exception as exc:  # noqa: BLE001
            raise ArtifactResolverError(f"download failed: {exc}") from exc

        if expected_sha256:
            got = _sha256_file(cache_path)
            if got != expected_sha256:
                raise ArtifactResolverError(
                    f"sha256 mismatch: expected {expected_sha256}, got {got}"
                )
        return cache_path

    def resolve(self, session_id: str, sha256: str) -> Path:
        """Return a local path for an artifact identified by (session, sha256).

        Resolution order:
          1. Look up the artifact metadata in Mongo.
          2. If ``path`` is set and the file is present on this host's artifact
             root, return it (the single-host / shared-mount case).
          3. Otherwise, if ``s3_key`` is set AND MinIO is configured, fetch to
             the local cache and return that.
          4. Otherwise, raise — the artifact isn't reachable from this worker.
        """
        # This method is sync by design — it's called from tool handlers that
        # may already be inside an asyncio loop. Mongo lookup is delegated to
        # a separate async helper (``resolve_artifact``) below.
        raise NotImplementedError("use resolve_artifact() from async code")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# ── Module-level singleton + async entry point ────────────────────────────
_resolver: Optional[ArtifactResolver] = None


def get_resolver() -> ArtifactResolver:
    global _resolver
    if _resolver is None:
        _resolver = ArtifactResolver()
    return _resolver


def reset_resolver() -> None:
    """Drop the cached resolver + MinIO client.

    Called from ``tasks._reset_async_singletons`` so a fresh Celery task spins
    up a new connection pool. MinIO's urllib3 pool is loop-agnostic (sync),
    so this is defensive more than strictly necessary — but mirrors the
    pattern of the other ``reset_*`` hooks.
    """
    global _resolver
    _resolver = None


async def resolve_artifact(session_id: str, sha256: str) -> Path:
    """Async wrapper that joins the Mongo lookup + MinIO fetch."""
    from app.database.mongodb import get_artifacts_collection

    doc = await get_artifacts_collection().find_one(
        {"session_id": session_id, "sha256": sha256}
    )
    if not doc:
        raise ArtifactResolverError(
            f"artifact ({session_id}, {sha256}) not registered"
        )

    local_path = doc.get("path", "")
    s3_key = doc.get("s3_key", "")

    # 1. Local-first (single-host / shared mount).
    if local_path:
        p = Path(local_path)
        try:
            p.resolve().relative_to(_ARTIFACT_ROOT)
            if p.is_file():
                return p
        except ValueError:
            pass  # Outside artifact root — ignore and try MinIO.

    # 2. MinIO fallback.
    resolver = get_resolver()
    if resolver.enabled and s3_key:
        return resolver.resolve_from_s3(s3_key, expected_sha256=sha256)

    raise ArtifactResolverError(
        f"artifact ({session_id}, {sha256}) not reachable: "
        f"local_path={local_path or '(none)'}, s3_key={s3_key or '(none)'}, "
        f"minio_enabled={resolver.enabled}"
    )

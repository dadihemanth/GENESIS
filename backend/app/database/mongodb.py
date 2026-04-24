from __future__ import annotations

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection, AsyncIOMotorDatabase

from app.config import settings

_client: AsyncIOMotorClient | None = None
_db: AsyncIOMotorDatabase | None = None


def _get_client() -> AsyncIOMotorClient:
    global _client
    if _client is None:
        _client = AsyncIOMotorClient(settings.mongodb_url)
    return _client


def _get_db() -> AsyncIOMotorDatabase:
    global _db
    if _db is None:
        _db = _get_client()["security_research"]
    return _db


def get_tool_outputs_collection() -> AsyncIOMotorCollection:
    return _get_db()["tool_outputs"]


def get_agent_thoughts_collection() -> AsyncIOMotorCollection:
    return _get_db()["agent_thoughts"]


def get_session_logs_collection() -> AsyncIOMotorCollection:
    return _get_db()["session_logs"]


def get_hypothesis_journals_collection() -> AsyncIOMotorCollection:
    return _get_db()["hypothesis_journals"]


def get_deep_thoughts_collection() -> AsyncIOMotorCollection:
    return _get_db()["deep_thoughts"]


def get_vulnerability_metadata_collection() -> AsyncIOMotorCollection:
    """Per-vulnerability technique metadata (endpoint, payload, technique_tag, evidence).

    Populated by the orchestrator when a VULNERABILITY block is saved. Consumed by
    the IntelligenceLibrary at session completion to build fine-grained cross-session
    recall entries.
    """
    return _get_db()["vulnerability_metadata"]


def get_session_errors_collection() -> AsyncIOMotorCollection:
    """Structured error log for a session.

    Every exception captured in the orchestrator, sub-agents, Celery task, or MCP
    tool call lands here with phase, iteration, traceback, and free-form context
    so operators can diagnose why a session failed.
    """
    return _get_db()["session_errors"]


def get_target_briefs_collection() -> AsyncIOMotorCollection:
    """Pre-scan Target Intent Brief (tier-2 T1).

    One document per session, written once at session start by the pre-scan
    reasoning agent. Captures predicted_stack, attack_surface_hypotheses,
    novel_vuln_class_hypotheses, suggested_artifact_targets, payload_seed_ideas
    and expected_dead_ends so the main loop tests specific hypotheses instead of
    discovering blindly.
    """
    return _get_db()["target_briefs"]


def get_artifacts_collection() -> AsyncIOMotorCollection:
    """Artifact acquisition metadata (tier-2 T3).

    One document per pulled artifact (binary, source tree, config blob) with
    sha256, size, mime, source_url, session_id, on-disk path and pull timestamp.
    The actual bytes live under /data/security/artifacts/{session}/... so they
    can be fed to binary_decompile (T4) or code_read (T4).
    """
    return _get_db()["artifacts"]


def get_motor_client() -> AsyncIOMotorClient:
    return _get_client()


async def init_indexes() -> None:
    db = _get_db()

    # tool_outputs indexes
    await db["tool_outputs"].create_index("session_id")
    await db["tool_outputs"].create_index("timestamp")
    await db["tool_outputs"].create_index([("session_id", 1), ("timestamp", -1)])

    # agent_thoughts indexes
    await db["agent_thoughts"].create_index("session_id")
    await db["agent_thoughts"].create_index("timestamp")
    await db["agent_thoughts"].create_index([("session_id", 1), ("iteration", 1)])

    # session_logs indexes
    await db["session_logs"].create_index("session_id")
    await db["session_logs"].create_index("timestamp")
    await db["session_logs"].create_index([("session_id", 1), ("level", 1)])

    # hypothesis_journals indexes
    await db["hypothesis_journals"].create_index("session_id")
    await db["hypothesis_journals"].create_index([("session_id", 1), ("hyp_id", 1)], unique=False)

    # vulnerability_metadata indexes
    await db["vulnerability_metadata"].create_index("session_id")
    await db["vulnerability_metadata"].create_index([("session_id", 1), ("vuln_id", 1)], unique=True)

    # session_errors indexes
    await db["session_errors"].create_index("session_id")
    await db["session_errors"].create_index([("session_id", 1), ("timestamp", 1)])

    # target_briefs indexes (tier-2 T1)
    await db["target_briefs"].create_index("session_id", unique=True)
    await db["target_briefs"].create_index("target")

    # artifacts indexes (tier-2 T3)
    await db["artifacts"].create_index("session_id")
    await db["artifacts"].create_index([("session_id", 1), ("sha256", 1)], unique=True)
    await db["artifacts"].create_index("source_url")


async def close_mongo() -> None:
    global _client, _db
    if _client is not None:
        _client.close()
        _client = None
        _db = None


def reset_mongo_client() -> None:
    """Drop the module-level Motor client so the next access re-creates it.

    Motor's AsyncIOMotorClient binds to the event loop it was first used on;
    reusing it across the fresh loop that each Celery task's `asyncio.run()`
    creates can hang or raise. Call this at the start of every Celery task
    to guarantee a loop-local client.
    """
    global _client, _db
    try:
        if _client is not None:
            _client.close()
    except Exception:
        pass
    _client = None
    _db = None

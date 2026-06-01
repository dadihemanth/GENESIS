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


def get_plan_trees_collection() -> AsyncIOMotorCollection:
    """Persistent plan tree for long-horizon engagements (tier-3 T11).

    One document per session (upserted as the tree rebalances). Root holds the
    strategic plan; phase-level sub-plans decompose into action nodes each with
    their own goal, evidence_required, status (pending|in_progress|done|abandoned),
    and outcome. The orchestrator reads the tree at each iteration to keep
    state coherent across context compression.
    """
    return _get_db()["plan_trees"]


def get_threat_intel_collection() -> AsyncIOMotorCollection:
    """v6 T129/T130: CVE feed entries and matched targets.

    One document per CVE/advisory with: cve_id, source, affected_components[],
    severity, poc_url, ingested_at, matched_targets[{target_ip, service, confidence}].
    """
    return _get_db()["threat_intel_entries"]


def get_goal_trees_collection() -> AsyncIOMotorCollection:
    """v6 T132: compiled goal attack trees.

    One document per session with: session_id, root, phases[], open_questions[].
    """
    return _get_db()["goal_trees"]


def get_goal_progress_collection() -> AsyncIOMotorCollection:
    """Per-session derived progress for the operator goal tree.

    One doc per session: {session_id, progress: {"<phase_idx>.<sg_idx>": {status,
    evidence_count, last_tool, last_finding_id}}, last_updated}. Recomputed by
    `app.services.goal_progress` on tool_execution / vulnerability_found /
    hypothesis_update events; merged into goal GET responses so reload shows
    current state without waiting for the next WS push.
    """
    return _get_db()["goal_progress"]


def get_replay_sessions_collection() -> AsyncIOMotorCollection:
    """v6 T131: sameday CVE replay results against T122 replicas.

    One document per replay attempt with: session_id, cve_id, replica_id, result, ts.
    """
    return _get_db()["replay_sessions"]


def get_target_performance_collection() -> AsyncIOMotorCollection:
    """v7.x — per-target high-water mark of finding count + duration.

    Used by the orchestrator to (a) inject 'match or beat the prior best'
    into the intel context at session start, and (b) flag in the
    Reproducibility Report whether this run hit the bar. Schema:

      {
        "target_ip": "10.10.0.14",
        "best_findings": 451,
        "best_duration_minutes": 667,
        "best_iterations": 222,
        "best_session_id": "<uuid>",
        "best_seen_at": ISODate,
        "session_count": 7
      }
    """
    return _get_db()["target_performance"]


def get_target_specialist_memory_collection() -> AsyncIOMotorCollection:
    """v7.x — per-target specialist replay memory.

    One document per target_ip:
      {
        "target_ip": "10.10.0.14",
        "specialists": ["crypto","auth","network","reveng","exploitdev","mobile"],
        "specialists_with_findings": ["crypto","reveng"],
        "session_count": 7,
        "last_seen": ISODate
      }

    The MultiAgentOrchestrator unions `specialists` into `specialists_ordered`
    at session start so subsequent scans of the same target NEVER lose
    coverage that prior scans surfaced. At session-finalize the orchestrator
    upserts the union of (this run's specialists) ∪ (prior set) and records
    which specialists produced confirmed VULNERABILITY rows so the operator
    can see persistent value over time.
    """
    return _get_db()["target_specialist_memory"]


def get_reproducibility_reports_collection() -> AsyncIOMotorCollection:
    """v7.x — per-session reproducibility report.

    One document per session capturing the deterministic shape of the run:
    specialist baseline / detected / inherited / actually-ran, Phase-1 stats,
    attack-class checklist coverage, first-time-target floors used, and the
    intel context size injected from prior runs. Surfaced via
    GET /api/v1/sessions/{id}/reproducibility and rendered atop RoutingPanel.
    """
    return _get_db()["reproducibility_reports"]


def get_llm_usage_collection() -> AsyncIOMotorCollection:
    """v7.x — per-LLM-call token usage records for the session Costs tab.

    One document per `client.messages.create` call across the orchestrator,
    critic, multi-agent sub-agents, and adversarial agents. Doc shape:
      {
        session_id, iteration, source,        # solo|critic|red_blue|philosopher|subagent
        model, input_tokens, output_tokens,
        cache_create_tokens, cache_read_tokens,
        ts: datetime,
      }
    Pricing is computed at read time from the operator-configured per-model
    rates (model_pricing JSON in AppSettings) so historical sessions reflect
    the current rate card unless the operator pins one.
    """
    return _get_db()["llm_usage"]


def get_adversarial_reasoning_collection() -> AsyncIOMotorCollection:
    """v7.x — full red/blue dialectic and philosopher exchange transcripts.

    One document per round (RedBlueDialectic) or per generation (PhilosopherAgent).
    Captures the raw LLM text from each agent so the operator can read the full
    reasoning, not just the final accepted hypothesis. Doc shape:

      kind: "red_blue" — has red.{raw,parsed}, blue.{raw,parsed}, verdict, round
      kind: "philosopher" — has anomalies_summary, raw, parsed{bug_class,...}

    Both kinds carry session_id + created_at + linked_hypothesis_id(s) so the UI
    can join back to the hypothesis market.
    """
    return _get_db()["adversarial_reasoning"]


def get_judge_verdicts_collection() -> AsyncIOMotorCollection:
    """v8 — SessionJudge verdict documents, one per judge evaluation round.

    Schema:
      {_id: "jv-<hex12>", session_id, round_idx (-1=terminal),
       overall_score, coverage_pct, killchain_phase_scores,
       goals_met, goals_not_met, hypothesis_resolution_rate,
       finding_quality_summary, gap_list, coverage_gate_passed,
       verdict ("pass"|"needs_work"|"critical_gaps"), created_at}
    """
    return _get_db()["judge_verdicts"]


def get_supervisor_directives_collection() -> AsyncIOMotorCollection:
    """v8 — SessionSupervisor directive documents, one per dispatched directive.

    Schema:
      {_id: "dir-<hex12>", session_id, round_triggered_by, verdict_id,
       agent_type, phase, attack_class, instruction, priority,
       created_at, consumed_at, consumed_by_iteration}
    """
    return _get_db()["supervisor_directives"]


def get_candidate_findings_collection() -> AsyncIOMotorCollection:
    """validated_dynamic — scanner candidate findings.

    Candidate findings are pre-promotion vulnerability claims emitted by
    agents during the multi-stage pipeline. They preserve leads, evidence, and
    proposed proof actions without creating final Vulnerability rows until the
    validation/proof gate promotes them.
    """
    return _get_db()["candidate_findings"]


def get_validation_verdicts_collection() -> AsyncIOMotorCollection:
    """validated_dynamic — independent validator/debater verdicts."""
    return _get_db()["validation_verdicts"]


def get_proof_runs_collection() -> AsyncIOMotorCollection:
    """validated_dynamic — normalized deterministic proof attempts."""
    return _get_db()["proof_runs"]


def get_validation_proof_jobs_collection() -> AsyncIOMotorCollection:
    """Validation Lab background proof/promotion jobs."""
    return _get_db()["validation_proof_jobs"]


def get_finding_clusters_collection() -> AsyncIOMotorCollection:
    """validated_dynamic — semantic/dedup clusters of candidate findings."""
    return _get_db()["finding_clusters"]


def get_benchmark_reports_collection() -> AsyncIOMotorCollection:
    """validated_dynamic — benchmark/scorecard reports for scanner runs."""
    return _get_db()["benchmark_reports"]


def get_source_ingest_summaries_collection() -> AsyncIOMotorCollection:
    """validated_dynamic hybrid — source/repo ingest summaries per session."""
    return _get_db()["source_ingest_summaries"]


def get_target_surface_graph_collection() -> AsyncIOMotorCollection:
    """validated_dynamic hybrid — endpoint/source/artifact surface graph."""
    return _get_db()["target_surface_graphs"]


def get_security_commits_collection() -> AsyncIOMotorCollection:
    """validation milestone 2 — security-sensitive git commits analyzed per session.

    One document per commit per session with: commit_hash, author_email, date,
    subject, risk_score, security_keywords_hit[], files_changed[],
    functions_changed[]. Produced by commit_analyzer.analyze_commits() and
    consumed by architectural_reasoner to seed prioritized scan hypotheses.
    """
    return _get_db()["security_commits"]


def get_dedup_clusters_collection() -> AsyncIOMotorCollection:
    """validation milestone 5 — patch-semantic dedup clusters across promoted findings.

    Groups findings whose remediation patches are semantically equivalent.
    One document per cluster: {cluster_id, session_id, finding_ids[], patch_summary,
    created_at}. Prevents duplicate CVE-assignment for the same root cause.
    """
    return _get_db()["dedup_clusters"]


def get_benchmark_scorecards_collection() -> AsyncIOMotorCollection:
    """validation milestone 7 — historical CVE recall benchmark scorecards.

    One document per benchmark run: {target, cve_ids_tested[], recall, precision,
    f1, run_at}. Produced by benchmark_recall Celery task. Surfaced at
    GET /api/v1/benchmarks/recall.
    """
    return _get_db()["benchmark_scorecards"]


def get_motor_client() -> AsyncIOMotorClient:
    return _get_client()


async def get_db() -> AsyncIOMotorDatabase:
    """Public async accessor for the Motor database used by v5 service modules."""
    return _get_db()


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

    # plan_trees indexes (tier-3 T11)
    await db["plan_trees"].create_index("session_id", unique=True)
    await db["plan_trees"].create_index("updated_at")

    # threat_intel_entries indexes (v6 T129/T130)
    await db["threat_intel_entries"].create_index("cve_id", unique=True)
    await db["threat_intel_entries"].create_index("ingested_at")
    await db["threat_intel_entries"].create_index("affected_components")

    # goal_trees indexes (v6 T132)
    await db["goal_trees"].create_index("session_id", unique=True)

    # goal_progress indexes (live subtask-progress tracking)
    await db["goal_progress"].create_index("session_id", unique=True)

    # replay_sessions indexes (v6 T131)
    await db["replay_sessions"].create_index("session_id")
    await db["replay_sessions"].create_index([("cve_id", 1), ("replica_id", 1)])

    # adversarial_reasoning indexes (v7.x — red/blue + philosopher transcripts)
    await db["adversarial_reasoning"].create_index([("session_id", 1), ("created_at", -1)])
    await db["adversarial_reasoning"].create_index([("kind", 1), ("created_at", -1)])

    # llm_usage indexes (v7.x — Costs tab)
    await db["llm_usage"].create_index([("session_id", 1), ("ts", 1)])
    await db["llm_usage"].create_index([("session_id", 1), ("iteration", 1)])

    # target_specialist_memory (v7.x — replay specialist set across runs)
    await db["target_specialist_memory"].create_index("target_ip", unique=True)

    # target_performance (v7.x — high-water mark per target)
    await db["target_performance"].create_index("target_ip", unique=True)

    # reproducibility_reports (v7.x — one doc per session)
    await db["reproducibility_reports"].create_index("session_id", unique=True)
    await db["reproducibility_reports"].create_index([("target_ip", 1), ("created_at", -1)])

    # judge_verdicts (v8 — SessionJudge per-round verdicts)
    await db["judge_verdicts"].create_index([("session_id", 1), ("created_at", -1)])
    await db["judge_verdicts"].create_index([("session_id", 1), ("round_idx", 1)])

    # supervisor_directives (v8 — SessionSupervisor agent directives)
    await db["supervisor_directives"].create_index([("session_id", 1), ("created_at", -1)])
    await db["supervisor_directives"].create_index([("session_id", 1), ("agent_type", 1)])
    await db["supervisor_directives"].create_index([("session_id", 1), ("consumed_at", 1)])

    # validated_dynamic — multi-stage candidate / validation / proof pipeline
    await db["candidate_findings"].create_index([("session_id", 1), ("created_at", -1)])
    await db["candidate_findings"].create_index([("session_id", 1), ("candidate_id", 1)], unique=True)
    await db["candidate_findings"].create_index([("session_id", 1), ("dedup_key", 1)])
    await db["candidate_findings"].create_index([("session_id", 1), ("status", 1)])
    await db["validation_verdicts"].create_index([("session_id", 1), ("candidate_id", 1)])
    await db["validation_verdicts"].create_index([("session_id", 1), ("verdict", 1)])
    await db["proof_runs"].create_index([("session_id", 1), ("candidate_id", 1)])
    await db["proof_runs"].create_index([("session_id", 1), ("passed", 1)])
    await db["validation_proof_jobs"].create_index([("session_id", 1), ("created_at", -1)])
    await db["validation_proof_jobs"].create_index([("session_id", 1), ("job_id", 1)], unique=True)
    await db["validation_proof_jobs"].create_index([("session_id", 1), ("status", 1)])
    await db["finding_clusters"].create_index([("session_id", 1), ("cluster_id", 1)], unique=True)
    await db["benchmark_reports"].create_index([("session_id", 1), ("created_at", -1)])
    await db["source_ingest_summaries"].create_index([("session_id", 1), ("created_at", -1)])
    await db["target_surface_graphs"].create_index("session_id", unique=True)
    await db["target_surface_graphs"].create_index("updated_at")


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

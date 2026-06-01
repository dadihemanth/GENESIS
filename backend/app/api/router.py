from __future__ import annotations

from fastapi import APIRouter

from app.api.routes import (
    adversarial,
    agents,
    artifacts,
    audit,
    auth,
    benchmarks,
    budgets,
    callback,
    compliance,
    containers,
    costs,
    events,
    goals,
    graph,
    health,
    hypotheses,
    integrations,
    intelligence,
    judge,
    loops,
    provenance,
    session_memory,
    sessions,
    settings,
    source,
    tools,
    validated,
    vulnerabilities,
)

router = APIRouter()

router.include_router(health.router, prefix="/health", tags=["health"])
# v6 routes
router.include_router(auth.router, prefix="/auth", tags=["auth"])
router.include_router(audit.router, prefix="/audit", tags=["audit"])
router.include_router(goals.router, prefix="/goals", tags=["goals"])
router.include_router(integrations.router, prefix="/integrations", tags=["integrations"])
router.include_router(sessions.router, prefix="/sessions", tags=["sessions"])
router.include_router(vulnerabilities.router, prefix="/vulnerabilities", tags=["vulnerabilities"])
router.include_router(settings.router, prefix="/settings", tags=["settings"])
router.include_router(tools.router, prefix="/tools", tags=["tools"])
router.include_router(intelligence.router, prefix="/intelligence", tags=["intelligence"])
router.include_router(compliance.router, prefix="/compliance", tags=["compliance"])
router.include_router(budgets.router, prefix="/budgets", tags=["budgets"])
router.include_router(events.router, prefix="/events", tags=["events"])
router.include_router(callback.router, prefix="/callback", tags=["callback"])
router.include_router(session_memory.router, prefix="/session-memory", tags=["session-memory"])
router.include_router(artifacts.router, prefix="/artifacts", tags=["artifacts"])
router.include_router(graph.router, prefix="/graph", tags=["graph"])
router.include_router(agents.router, prefix="/agents", tags=["agents"])
router.include_router(containers.router, prefix="/containers", tags=["containers"])
# v5 routes
router.include_router(source.router, prefix="/source", tags=["source"])
router.include_router(hypotheses.router, prefix="/hypotheses", tags=["hypotheses"])
router.include_router(provenance.router, prefix="/provenance", tags=["provenance"])
# v7 routes
router.include_router(loops.router, prefix="/loops", tags=["loops"])
router.include_router(adversarial.router, prefix="/adversarial", tags=["adversarial"])
router.include_router(costs.router, prefix="/sessions", tags=["costs"])
# v8 routes
router.include_router(judge.router, prefix="/judge", tags=["judge"])
# validated_dynamic routes
router.include_router(validated.router, prefix="/validated", tags=["validated"])
# validation milestone 7 — recall benchmark routes
router.include_router(benchmarks.router, prefix="/benchmarks", tags=["benchmarks"])

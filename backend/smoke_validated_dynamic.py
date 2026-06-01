#!/usr/bin/env python3
"""AST/text smoke checks for the validated_dynamic scanner pipeline."""
from __future__ import annotations

import ast
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


CHECKS: list[tuple[str, bool]] = []


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def parse(rel: str) -> ast.AST:
    return ast.parse(read(rel), filename=rel)


def check(name: str, ok: bool) -> None:
    CHECKS.append((name, ok))


def has_function(tree: ast.AST, name: str) -> bool:
    return any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name for n in ast.walk(tree))


def main() -> int:
    files = [
        "backend/app/services/validated_scanner.py",
        "backend/app/services/validation_completion.py",
        "backend/app/api/routes/validated.py",
        "backend/app/services/ai_orchestrator.py",
        "backend/app/services/multi_agent_orchestrator.py",
        "backend/app/database/mongodb.py",
        "backend/app/api/router.py",
        "backend/app/services/llm_routing.py",
    ]
    for rel in files:
        try:
            parse(rel)
            check(f"{rel} parses", True)
        except SyntaxError as exc:
            check(f"{rel} parses ({exc})", False)

    svc_tree = parse("backend/app/services/validated_scanner.py")
    svc_text = read("backend/app/services/validated_scanner.py")
    for fn in (
        "normalize_candidate",
        "store_candidate",
        "store_candidates_from_text",
        "extract_source_candidate_blocks",
        "candidate_from_source_candidate",
        "record_source_ingest_summary",
        "rebuild_target_surface_graph",
        "create_validation_verdict",
        "record_proof_run",
        "rebuild_clusters",
        "promote_ready_candidates",
        "build_benchmark_report",
    ):
        check(f"validated_scanner.{fn} present", has_function(svc_tree, fn))

    orchestrator = read("backend/app/services/ai_orchestrator.py")
    check("validated_dynamic scan profile registered", '"validated_dynamic": {' in orchestrator)
    check("reasoning loop count prompt matches registry", "The 11 available loops" in orchestrator)
    check("candidate extraction helper wired", "_extract_and_save_candidates" in orchestrator)
    check("source candidate prompt wired", "SOURCE_CANDIDATE_FINDING" in orchestrator)
    check("strict validation flag is opt-in", "strict_validation_pipeline_enabled" in orchestrator)
    check("VULNERABILITY blocks can become candidates in strict mode", "store_vulnerability_blocks_as_candidates" in orchestrator)
    check("strict proof gate marker present", "strict validation gate requires a passing proof oracle" in orchestrator)
    check("final promotion hook wired", "promote_ready_candidates" in orchestrator)
    check("surface graph rebuild wired", "rebuild_target_surface_graph" in orchestrator)
    check("hypothesis bridge routes into candidates", "_bridge_hypotheses_to_candidates" in orchestrator)

    multi_agent = read("backend/app/services/multi_agent_orchestrator.py")
    check("multi-agent candidate hint wired", "_CANDIDATE_EMISSION_HINT" in multi_agent)
    check("multi-agent source candidate hint wired", "SOURCE_CANDIDATE_FINDING" in multi_agent)
    check("multi-agent candidate capture wired", "_extract_and_save_candidates" in multi_agent)

    mongo = read("backend/app/database/mongodb.py")
    for accessor in (
        "get_candidate_findings_collection",
        "get_validation_verdicts_collection",
        "get_proof_runs_collection",
        "get_validation_proof_jobs_collection",
        "get_finding_clusters_collection",
        "get_benchmark_reports_collection",
        "get_source_ingest_summaries_collection",
        "get_target_surface_graph_collection",
    ):
        check(f"mongodb.{accessor} present", accessor in mongo)

    router = read("backend/app/api/router.py")
    check("validated API router registered", "validated.router" in router and 'prefix="/validated"' in router)

    routing = read("backend/app/services/llm_routing.py")
    check("validator role registered", '"validator"' in routing and "candidate reachability" in routing)
    check("hybrid validator roles registered", all(role in routing for role in ("endpoint_validator", "source_validator", "counter_validator")))
    check("proof planner role registered", "proof_planner" in routing)
    check("counter validator support does not promote alone", '"validator": {"$ne": "counter_validator"}' in svc_text)
    check("proof tool names normalized before classing", 'proof_tool_name = str(proof_tool or "").strip()' in svc_text)
    check("source verified state protected from static proof fallback failures", "protected_statuses.extend([\"source_verified_needs_replay\", \"source_verified_unreachable\"])" in svc_text)

    validated_routes = read("backend/app/api/routes/validated.py")
    source_routes = read("backend/app/api/routes/source.py")
    check("surface graph API route present", "/surface-graph" in validated_routes)
    check("complete validation API route present", "/complete-validation" in validated_routes and "/proof-jobs/" in validated_routes)
    check("source ingest records validated summary", "record_source_ingest_summary" in source_routes)

    api_ts = read("frontend/src/services/api.ts")
    viewer_tsx = read("frontend/src/pages/SessionViewer.tsx")
    dashboard_tsx = read("frontend/src/pages/Dashboard.tsx")
    types_ts = read("frontend/src/types/index.ts")
    check("frontend validatedApi client present", "validatedApi" in api_ts)
    check("frontend surface graph client present", "getSurfaceGraph" in api_ts)
    check("frontend Validation Lab panel renders", "ValidatedScannerPanel" in viewer_tsx and 'label="Validation Lab"' in viewer_tsx)
    panel_tsx = read("frontend/src/components/ValidatedScannerPanel.tsx")
    check("frontend surface tab present", "Surface (" in panel_tsx and "source_verified_needs_replay" in panel_tsx)
    check("dashboard can start validated_dynamic", 'value="validated_dynamic"' in dashboard_tsx)
    check("types include validated_dynamic", "'validated_dynamic'" in types_ts)
    check("types include hybrid source contexts", "CandidateSourceContext" in types_ts and "TargetSurfaceGraph" in types_ts)
    cross_compare = read("backend/app/services/reasoning/cross_file_compare.py")
    check("cross-file compare normalizes string snippet input", "isinstance(comparison_snippets, str)" in cross_compare and "isinstance(comparisons, str)" in cross_compare)

    passed = sum(1 for _, ok in CHECKS if ok)
    failed = len(CHECKS) - passed
    print("validated_dynamic smoke")
    for name, ok in CHECKS:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    print(f"\nPASS: {passed} passed, {failed} failed" if failed == 0 else f"\nFAIL: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

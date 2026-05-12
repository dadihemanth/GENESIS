"""v7.0 smoke test — AST-only static integrity check.

Run from the backend/ directory:
    python smoke_v7.py

Backend deps (httpx/sqlalchemy/pydantic/fastapi/motor) aren't installed in
the host Python — they live inside the Docker image. So this test pulls
information by parsing the source ASTs alone, which is enough to catch:

  1. Every loop class file parses (no syntax errors)
  2. _BUDGETS keys match _build_class_map keys (no registry desync)
  3. Each loop class declares `loop_type = "..."` matching its registry key
  4. Each loop class subclasses DeliberationLoop and defines an `async def tick`
  5. The `deliberate` tool is registered in TOOL_SCHEMAS
  6. The orchestrator's tool dispatch routes loop_type=="deliberate" to the registry
  7. /api/v1/loops route is registered
"""
from __future__ import annotations

import ast
import pathlib
import re
import sys
from typing import Dict, List, Optional, Set, Tuple

ROOT = pathlib.Path(__file__).parent
REASONING_DIR = ROOT / "app" / "services" / "reasoning"

CHECKS_PASSED = 0
CHECKS_FAILED: List[str] = []


def _ok(msg: str) -> None:
    global CHECKS_PASSED
    CHECKS_PASSED += 1
    print(f"  [PASS] {msg}")


def _fail(msg: str) -> None:
    CHECKS_FAILED.append(msg)
    print(f"  [FAIL] {msg}")


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

def parse_file(path: pathlib.Path) -> Optional[ast.Module]:
    try:
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError as exc:
        _fail(f"{path.name}: SyntaxError {exc}")
        return None


def find_classes(mod: ast.Module) -> List[ast.ClassDef]:
    return [n for n in mod.body if isinstance(n, ast.ClassDef)]


def find_class_attr_str(cls: ast.ClassDef, name: str) -> Optional[str]:
    """Return the string value of a class-level `name = "..."` assignment."""
    for node in cls.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            tgt = node.targets[0]
            if isinstance(tgt, ast.Name) and tgt.id == name:
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    return node.value.value
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                return node.value.value
    return None


def has_async_method(cls: ast.ClassDef, name: str) -> bool:
    return any(
        isinstance(n, ast.AsyncFunctionDef) and n.name == name
        for n in cls.body
    )


def base_names(cls: ast.ClassDef) -> List[str]:
    out: List[str] = []
    for b in cls.bases:
        if isinstance(b, ast.Name):
            out.append(b.id)
        elif isinstance(b, ast.Attribute):
            out.append(b.attr)
    return out


# ---------------------------------------------------------------------------
# 1. Parse the registry to extract _BUDGETS keys and class_map keys
# ---------------------------------------------------------------------------

def parse_registry() -> Tuple[Set[str], Dict[str, str]]:
    """Return (budget_keys, class_map: loop_type -> class_name)."""
    path = REASONING_DIR / "registry.py"
    mod = parse_file(path)
    if mod is None:
        return set(), {}

    budget_keys: Set[str] = set()
    class_map: Dict[str, str] = {}

    def _extract_dict_keys(dict_node: ast.Dict) -> List[str]:
        out: List[str] = []
        for k in dict_node.keys:
            if isinstance(k, ast.Constant) and isinstance(k.value, str):
                out.append(k.value)
        return out

    for node in ast.walk(mod):
        # _BUDGETS = {...}  OR  _BUDGETS: Dict[str, LoopBudget] = {...}
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            tgt = node.targets[0]
            if (isinstance(tgt, ast.Name) and tgt.id == "_BUDGETS"
                    and isinstance(node.value, ast.Dict)):
                budget_keys.update(_extract_dict_keys(node.value))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if (node.target.id == "_BUDGETS"
                    and node.value is not None
                    and isinstance(node.value, ast.Dict)):
                budget_keys.update(_extract_dict_keys(node.value))

        # def _build_class_map(): ... return { "code_intent": CodeIntentLoop, ... }
        if isinstance(node, ast.FunctionDef) and node.name == "_build_class_map":
            for sub in ast.walk(node):
                if isinstance(sub, ast.Return) and isinstance(sub.value, ast.Dict):
                    for k, v in zip(sub.value.keys, sub.value.values):
                        if (isinstance(k, ast.Constant) and isinstance(k.value, str)
                                and isinstance(v, ast.Name)):
                            class_map[k.value] = v.id

    return budget_keys, class_map


# ---------------------------------------------------------------------------
# 2. For each loop module, find the DeliberationLoop subclass and its loop_type
# ---------------------------------------------------------------------------

def find_loop_classes_in_dir() -> Dict[str, Dict[str, object]]:
    """Walk reasoning/*.py, return {class_name: {file, loop_type, has_tick, has_setup, bases}}."""
    found: Dict[str, Dict[str, object]] = {}
    for py in sorted(REASONING_DIR.glob("*.py")):
        if py.name in ("__init__.py", "registry.py", "framework.py", "loop_state.py",
                       "tree_of_thought.py"):
            continue
        mod = parse_file(py)
        if mod is None:
            continue
        for cls in find_classes(mod):
            bases = base_names(cls)
            if "DeliberationLoop" not in bases:
                continue
            found[cls.name] = {
                "file": py.name,
                "loop_type": find_class_attr_str(cls, "loop_type"),
                "has_tick": has_async_method(cls, "tick"),
                "has_setup": has_async_method(cls, "setup"),
                "bases": bases,
            }
    return found


# ---------------------------------------------------------------------------
# 3. Verify orchestrator wiring
# ---------------------------------------------------------------------------

def check_orchestrator() -> None:
    print("\n[5/7] Verifying ai_orchestrator.py wiring...")
    path = ROOT / "app" / "services" / "ai_orchestrator.py"
    if not path.exists():
        _fail("ai_orchestrator.py missing")
        return
    src = path.read_text(encoding="utf-8")

    if re.search(r'"name"\s*:\s*"deliberate"', src):
        _ok("`deliberate` tool registered in TOOL_SCHEMAS")
    else:
        _fail("`deliberate` tool NOT found in TOOL_SCHEMAS")

    if 'tool_name == "deliberate"' in src:
        _ok("orchestrator dispatches `deliberate` separately from MCP")
    else:
        _fail("orchestrator does NOT branch on tool_name == 'deliberate'")

    if "from app.services.reasoning import registry" in src:
        _ok("orchestrator imports reasoning.registry")
    else:
        _fail("orchestrator does NOT import reasoning.registry")

    if re.search(r"def\s+_make_llm_call_adapter", src):
        _ok("AIOrchestrator._make_llm_call_adapter helper present")
    else:
        _fail("AIOrchestrator._make_llm_call_adapter helper MISSING")


def check_routes() -> None:
    print("\n[6/7] Verifying API route registration...")
    router_path = ROOT / "app" / "api" / "router.py"
    if not router_path.exists():
        _fail("api/router.py missing")
        return
    src = router_path.read_text(encoding="utf-8")
    if "loops" in src and 'prefix="/loops"' in src:
        _ok("/loops router registered in api/router.py")
    else:
        _fail("/loops router NOT registered")

    loops_path = ROOT / "app" / "api" / "routes" / "loops.py"
    if loops_path.exists():
        loops_src = loops_path.read_text(encoding="utf-8")
        for ep in ('"/types"', '"/detail/{loop_id}"', '"/{session_id}"'):
            if ep in loops_src:
                _ok(f"endpoint {ep} declared")
            else:
                _fail(f"endpoint {ep} MISSING from routes/loops.py")
    else:
        _fail("api/routes/loops.py missing")


def check_main_lifespan() -> None:
    print("\n[7/7] Verifying main.py boots loop_state indexes...")
    path = ROOT / "app" / "main.py"
    if not path.exists():
        _fail("main.py missing")
        return
    src = path.read_text(encoding="utf-8")
    if "from app.services.reasoning.loop_state import init_indexes" in src:
        _ok("main.py imports loop_state.init_indexes")
    else:
        _fail("main.py does NOT import loop_state.init_indexes")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    print("=" * 72)
    print("GENESIS v7.0 smoke test (AST-only — no backend deps required)")
    print("=" * 72)

    # 1. Parse every reasoning/*.py
    print("\n[1/7] Parsing reasoning/*.py...")
    parse_failed = False
    for py in sorted(REASONING_DIR.glob("*.py")):
        if parse_file(py) is None:
            parse_failed = True
        else:
            _ok(f"{py.name} parsed")
    if parse_failed:
        print("\nAborting — fix syntax errors first.")
        return 1

    # 2. Registry symmetry
    print("\n[2/7] Verifying _BUDGETS == _build_class_map keys...")
    budget_keys, class_map = parse_registry()
    if not budget_keys or not class_map:
        _fail("could not extract _BUDGETS or class_map from registry")
    elif budget_keys == set(class_map):
        _ok(f"both have {len(budget_keys)} keys: {sorted(budget_keys)}")
    else:
        only_b = budget_keys - set(class_map)
        only_c = set(class_map) - budget_keys
        _fail(f"asymmetric — only in _BUDGETS: {sorted(only_b)}; only in class_map: {sorted(only_c)}")

    # 3. Each loop class has matching loop_type, tick, base
    print("\n[3/7] Verifying each loop class structure...")
    found = find_loop_classes_in_dir()
    # Reverse map class_name -> loop_type for lookup
    cls_to_key: Dict[str, str] = {v: k for k, v in class_map.items()}
    expected_classes = set(class_map.values())
    found_classes = set(found.keys())

    missing = expected_classes - found_classes
    extra = found_classes - expected_classes
    if missing:
        _fail(f"loop classes referenced by registry but not found in source: {sorted(missing)}")
    if extra:
        # Extra subclasses are allowed but worth surfacing.
        print(f"  [INFO] extra DeliberationLoop subclasses (not registered): {sorted(extra)}")

    for cls_name, info in sorted(found.items()):
        if cls_name not in expected_classes:
            continue
        expected_loop_type = cls_to_key.get(cls_name)
        actual_loop_type = info["loop_type"]
        if expected_loop_type != actual_loop_type:
            _fail(f"{cls_name} ({info['file']}): registry key '{expected_loop_type}' != class loop_type '{actual_loop_type}'")
        elif not info["has_tick"]:
            _fail(f"{cls_name} ({info['file']}): missing `async def tick`")
        else:
            _ok(f"{cls_name:30s} loop_type='{actual_loop_type}' tick={info['has_tick']} setup={info['has_setup']}")

    # 4. Framework — confirm DeliberationLoop is the abstract base and tick is abstract
    print("\n[4/7] Verifying DeliberationLoop base is intact...")
    fw_path = REASONING_DIR / "framework.py"
    fw_mod = parse_file(fw_path)
    if fw_mod is None:
        _fail("framework.py failed to parse")
    else:
        base = next((c for c in find_classes(fw_mod) if c.name == "DeliberationLoop"), None)
        if base is None:
            _fail("DeliberationLoop class missing from framework.py")
        else:
            has_run = has_async_method(base, "run")
            has_tick = any(isinstance(n, ast.AsyncFunctionDef) and n.name == "tick" for n in base.body)
            if has_run:
                _ok("DeliberationLoop.run defined")
            else:
                _fail("DeliberationLoop.run MISSING")
            if has_tick:
                _ok("DeliberationLoop.tick declared (abstract)")
            else:
                _fail("DeliberationLoop.tick declaration MISSING")

    # 5-7. Orchestrator + routes + main
    check_orchestrator()
    check_routes()
    check_main_lifespan()
    check_v7x_floor_dedup_backstop()
    check_v7x_adversarial_wiring()
    check_v7x_costs_wiring()
    check_v7x_routing_wiring()
    check_v7x_robustness_pass()
    check_v7x_coverage_and_novel()

    # Summary
    print("\n" + "=" * 72)
    status = "PASS" if not CHECKS_FAILED else "FAIL"
    print(f"{status}: {CHECKS_PASSED} passed, {len(CHECKS_FAILED)} failed")
    if CHECKS_FAILED:
        print("\nFailures:")
        for msg in CHECKS_FAILED:
            print(f"  - {msg}")
    print("=" * 72)
    return 1 if CHECKS_FAILED else 0


def check_v7x_robustness_pass() -> None:
    """v7.x — verify the full robustness-pass wiring is in place."""
    print("\n[12/12] Verifying v7.x robustness-pass wiring...")

    ma = (ROOT / "app" / "services" / "multi_agent_orchestrator.py").read_text(encoding="utf-8")
    for needle, label in [
        ("_BASELINE_SPECIALISTS", "A: baseline specialists constant"),
        ("_memory_specialists", "B: per-target specialist memory state"),
        ("[SPECIALIST_MEMORY]", "B: memory load/persist log"),
        ("[P1_COVERAGE_GATE]", "D: Phase-1 coverage gate"),
        ("[SPAWN]", "E: spawn diagnostics"),
        ("[FINISHED]", "E: finished diagnostics"),
        ("[DEDUP_OVERRIDE]", "H: per-agent dedup_threshold override"),
    ]:
        if needle in ma:
            _ok(f"multi_agent_orchestrator.py: {label}")
        else:
            _fail(f"multi_agent_orchestrator.py: missing {label}")

    ao = (ROOT / "app" / "services" / "ai_orchestrator.py").read_text(encoding="utf-8")
    for needle, label in [
        ("[CROSS-SESSION INTELLIGENCE]", "C: intel reframing block"),
        ("[FIRST_TIME]", "G: first-time-target log"),
        ("min_probes_per_class", "F: per-class probe-count check"),
        ("min_classes_required: int = 14", "F: bumped checklist threshold to 14"),
        ("_attack_class_probe_counts", "F: probe-count helper"),
        ("_write_reproducibility_report", "I: reproducibility writer"),
        ("[REPRO_REPORT]", "I: reproducibility log"),
    ]:
        if needle in ao:
            _ok(f"ai_orchestrator.py: {label}")
        else:
            _fail(f"ai_orchestrator.py: missing {label}")

    mongo = (ROOT / "app" / "database" / "mongodb.py").read_text(encoding="utf-8")
    for needle, label in [
        ("get_target_specialist_memory_collection", "B: memory collection accessor"),
        ("get_reproducibility_reports_collection", "I: reports collection accessor"),
    ]:
        if needle in mongo:
            _ok(f"mongodb.py: {label}")
        else:
            _fail(f"mongodb.py: missing {label}")

    sess = (ROOT / "app" / "api" / "routes" / "sessions.py").read_text(encoding="utf-8")
    if "/{session_id}/reproducibility" in sess:
        _ok("sessions.py: /reproducibility endpoint registered")
    else:
        _fail("sessions.py: missing /reproducibility endpoint")


def check_v7x_coverage_and_novel() -> None:
    """v7.x — verify Coverage matrix + Novel vulnerabilities tabs are wired."""
    print("\n[13/13] Verifying v7.x coverage-matrix + novel-tab wiring...")

    sess = (ROOT / "app" / "api" / "routes" / "sessions.py").read_text(encoding="utf-8")
    if "/{session_id}/coverage-matrix" in sess:
        _ok("sessions.py: /coverage-matrix endpoint registered")
    else:
        _fail("sessions.py: missing /coverage-matrix endpoint")

    vulns = (ROOT / "app" / "api" / "routes" / "vulnerabilities.py").read_text(encoding="utf-8")
    if '"/novel"' in vulns or "'/novel'" in vulns:
        _ok("vulnerabilities.py: /novel endpoint registered")
    else:
        _fail("vulnerabilities.py: missing /novel endpoint")

    # Frontend checks: only run when the frontend tree is reachable on disk.
    # Inside a backend container the frontend isn't mounted, so skip silently.
    fe_root = None
    for candidate in (ROOT.parent / "frontend" / "src", ROOT / "frontend" / "src"):
        if candidate.exists():
            fe_root = candidate
            break
    if fe_root is None:
        _ok("frontend: tree not reachable — skipping FE checks (run smoke from repo root for full coverage)")
        return

    cov_panel = fe_root / "components" / "CoverageMatrixPanel.tsx"
    if cov_panel.exists():
        _ok("frontend: CoverageMatrixPanel.tsx present")
    else:
        _fail("frontend: CoverageMatrixPanel.tsx missing")

    novel_panel = fe_root / "components" / "NovelVulnerabilitiesPanel.tsx"
    if novel_panel.exists():
        _ok("frontend: NovelVulnerabilitiesPanel.tsx present")
    else:
        _fail("frontend: NovelVulnerabilitiesPanel.tsx missing")

    sv = (fe_root / "pages" / "SessionViewer.tsx").read_text(encoding="utf-8")
    for needle, label in [
        ("CoverageMatrixPanel", "SessionViewer imports CoverageMatrixPanel"),
        ("NovelVulnerabilitiesPanel", "SessionViewer imports NovelVulnerabilitiesPanel"),
        ("rightTab === 18", "SessionViewer renders Coverage tab"),
        ("rightTab === 19", "SessionViewer renders Novel tab"),
    ]:
        if needle in sv:
            _ok(f"frontend: {label}")
        else:
            _fail(f"frontend: missing {label}")

    api = (fe_root / "services" / "api.ts").read_text(encoding="utf-8")
    for needle, label in [
        ("getCoverageMatrix", "api.ts: getCoverageMatrix client"),
        ("listNovel", "api.ts: listNovel client"),
    ]:
        if needle in api:
            _ok(f"frontend: {label}")
        else:
            _fail(f"frontend: missing {label}")


def check_v7x_routing_wiring() -> None:
    """v7.x — verify multi-model role-based routing wiring is in place."""
    print("\n[11/11] Verifying v7.x multi-model routing wiring...")

    routing = ROOT / "app" / "services" / "llm_routing.py"
    if routing.exists():
        _ok("services/llm_routing.py present")
    else:
        _fail("services/llm_routing.py missing")
        return
    rt = routing.read_text(encoding="utf-8")
    for needle, label in [
        ("def get_client_and_model_for_role", "helper signature"),
        ("model_profiles", "reads model_profiles setting"),
        ("role_assignments", "reads role_assignments setting"),
        ("_legacy_fallback_profile", "legacy fallback profile builder"),
        ('"primary"', "primary role default"),
        ('mode == "single"', "honours llm_mode=single override"),
    ]:
        if needle in rt:
            _ok(f"llm_routing.py: {label}")
        else:
            _fail(f"llm_routing.py: missing {label}")

    providers = (ROOT / "app" / "services" / "llm_providers.py").read_text(encoding="utf-8")
    if '"foundry_serverless"' in providers:
        _ok("llm_providers.py: foundry_serverless provider branch")
    else:
        _fail("llm_providers.py: missing foundry_serverless branch")

    ao = (ROOT / "app" / "services" / "ai_orchestrator.py").read_text(encoding="utf-8")
    for needle, label in [
        ("get_client_and_model_for_role", "orchestrator imports routing helper"),
        ("self._app_settings = dict(app_settings)", "orchestrator stashes app_settings"),
        ("await self._get_red_blue", "red_blue resolution awaits routing"),
        ("await self._get_philosopher", "philosopher resolution awaits routing"),
        ("get_client_and_model_for_role(\n                \"critic\"", "critic resolved via routing"),
    ]:
        if needle in ao:
            _ok(f"ai_orchestrator.py: {label}")
        else:
            _fail(f"ai_orchestrator.py: missing {label}")


def check_v7x_costs_wiring() -> None:
    """v7.x — verify session-cost tracking is wired end-to-end."""
    print("\n[10/10] Verifying v7.x costs wiring...")

    if (ROOT / "app" / "services" / "llm_usage.py").exists():
        _ok("services/llm_usage.py present")
    else:
        _fail("services/llm_usage.py missing")

    mongo = (ROOT / "app" / "database" / "mongodb.py").read_text(encoding="utf-8")
    if "get_llm_usage_collection" in mongo:
        _ok("mongodb.py: llm_usage collection accessor")
    else:
        _fail("mongodb.py: missing get_llm_usage_collection")

    ao = (ROOT / "app" / "services" / "ai_orchestrator.py").read_text(encoding="utf-8")
    ao_checks = [
        ("source=\"orchestrator\"", "main loop records usage as source=orchestrator"),
        ("source=\"brief\"", "brief generation records usage"),
        ("source=\"critic\"", "critic records usage"),
        ("source=\"history_compress\"", "compressor records usage"),
    ]
    for needle, label in ao_checks:
        if needle in ao:
            _ok(f"ai_orchestrator.py: {label}")
        else:
            _fail(f"ai_orchestrator.py: missing {label}")

    ma = (ROOT / "app" / "services" / "multi_agent_orchestrator.py").read_text(encoding="utf-8")
    if "source=f\"subagent:{self.agent_type}\"" in ma:
        _ok("multi_agent_orchestrator.py: subagent records usage")
    else:
        _fail("multi_agent_orchestrator.py: missing subagent usage record")

    adv = (ROOT / "app" / "services" / "adversarial_agents.py").read_text(encoding="utf-8")
    for needle, label in [
        ("source=\"red_agent\"", "red agent records usage"),
        ("source=\"blue_agent\"", "blue agent records usage"),
        ("source=\"philosopher\"", "philosopher records usage"),
    ]:
        if needle in adv:
            _ok(f"adversarial_agents.py: {label}")
        else:
            _fail(f"adversarial_agents.py: missing {label}")

    if (ROOT / "app" / "api" / "routes" / "costs.py").exists():
        _ok("routes/costs.py present")
    else:
        _fail("routes/costs.py missing")
    router = (ROOT / "app" / "api" / "router.py").read_text(encoding="utf-8")
    if "costs.router" in router:
        _ok("router.py: costs router registered")
    else:
        _fail("router.py: costs router not registered")


def check_v7x_adversarial_wiring() -> None:
    """v7.x — verify adversarial reasoning (red/blue + philosopher) is wired."""
    print("\n[9/9] Verifying v7.x adversarial-reasoning wiring...")

    mongo = (ROOT / "app" / "database" / "mongodb.py").read_text(encoding="utf-8")
    if "get_adversarial_reasoning_collection" in mongo:
        _ok("mongodb.py: adversarial_reasoning collection accessor")
    else:
        _fail("mongodb.py: missing get_adversarial_reasoning_collection")
    if "adversarial_reasoning" in mongo and "create_index" in mongo:
        _ok("mongodb.py: adversarial_reasoning indexes init")

    adv = (ROOT / "app" / "services" / "adversarial_agents.py").read_text(encoding="utf-8")
    adv_checks = [
        ("publish_fn: Optional[PublishFn]", "RedBlueDialectic.synthesize accepts publish_fn"),
        ("trigger: str = \"seed\"", "RedBlueDialectic.synthesize accepts trigger"),
        ("get_adversarial_reasoning_collection", "agents persist into adversarial_reasoning"),
        ("adversarial_round_complete", "WS event type emitted"),
        ("trigger_hypothesis_id", "trigger_hypothesis_id propagated"),
    ]
    for needle, label in adv_checks:
        if needle in adv:
            _ok(f"adversarial_agents.py: {label}")
        else:
            _fail(f"adversarial_agents.py: missing {label}")

    ao = (ROOT / "app" / "services" / "ai_orchestrator.py").read_text(encoding="utf-8")
    ao_checks = [
        ("def _get_red_blue", "AIOrchestrator._get_red_blue helper"),
        ("def _get_philosopher", "AIOrchestrator._get_philosopher helper"),
        ("\"red_blue_seeded\"", "iter-5 red/blue seed guarded"),
        ("\"philosopher_fired\"", "philosopher fire-once guard"),
        ("[ADVERSARIAL]", "ADVERSARIAL log emitted"),
        ("trigger=\"confirmed_hypothesis\"", "per-hyp red/blue follow-up wired"),
    ]
    for needle, label in ao_checks:
        if needle in ao:
            _ok(f"ai_orchestrator.py: {label}")
        else:
            _fail(f"ai_orchestrator.py: missing {label}")

    ma = (ROOT / "app" / "services" / "multi_agent_orchestrator.py").read_text(encoding="utf-8")
    ma_checks = [
        ("[ADVERSARIAL]", "multi-agent ADVERSARIAL log"),
        ("self._ai._get_red_blue", "multi-agent invokes red/blue via _ai helper"),
        ("self._ai._get_philosopher", "multi-agent invokes philosopher via _ai helper"),
        ("philosopher_fired", "multi-agent philosopher fire-once flag"),
        ("adversarial_seen", "multi-agent per-hyp dedup set"),
    ]
    for needle, label in ma_checks:
        if needle in ma:
            _ok(f"multi_agent_orchestrator.py: {label}")
        else:
            _fail(f"multi_agent_orchestrator.py: missing {label}")

    routes_dir = ROOT / "app" / "api" / "routes"
    if (routes_dir / "adversarial.py").exists():
        _ok("routes/adversarial.py present")
    else:
        _fail("routes/adversarial.py missing")
    router = (ROOT / "app" / "api" / "router.py").read_text(encoding="utf-8")
    if "adversarial.router" in router:
        _ok("router.py: adversarial router registered")
    else:
        _fail("router.py: adversarial router not registered")


def check_v7x_floor_dedup_backstop() -> None:
    """v7.x — verify the iteration-floor / dedup / reasoning-loop-backstop
    wiring is present in the source. Static checks only — runtime behaviour
    requires a live backend (see integration_test_v7.py)."""
    print("\n[8/8] Verifying v7.x floor / dedup / backstop wiring...")

    # config.py
    cfg = (ROOT / "app" / "config.py").read_text(encoding="utf-8")
    if 'alias="MIN_ITERATIONS"' in cfg and "min_iterations" in cfg:
        _ok("config.py declares min_iterations field with MIN_ITERATIONS alias")
    else:
        _fail("config.py missing min_iterations field / alias")
    if 'alias="DEDUP_THRESHOLD"' in cfg:
        _ok("config.py declares dedup_threshold field")
    else:
        _fail("config.py missing dedup_threshold field")
    if 'alias="LOOP_BACKSTOP_ITER"' in cfg:
        _ok("config.py declares loop_backstop_iter field")
    else:
        _fail("config.py missing loop_backstop_iter field")

    # ai_orchestrator.py
    ao = (ROOT / "app" / "services" / "ai_orchestrator.py").read_text(encoding="utf-8")
    checks = [
        ("def _compute_call_signature(", "AIOrchestrator._compute_call_signature helper"),
        ("def _build_continuation_message(", "AIOrchestrator._build_continuation_message helper"),
        ("def _dedup_exhaustion_satisfied(", "AIOrchestrator._dedup_exhaustion_satisfied helper"),
        ("async def _run_backstop_loop(", "AIOrchestrator._run_backstop_loop helper"),
        ("async def _fetch_top_hypothesis_text(", "AIOrchestrator._fetch_top_hypothesis_text helper"),
        ("async def _goal_progress_blocks_termination(", "AIOrchestrator._goal_progress_blocks_termination helper"),
        ("[FLOOR_GATE]", "FLOOR_GATE log emitted from main loop"),
        ("[BACKSTOP]", "BACKSTOP log emitted from main loop"),
        ("[DEDUP]", "DEDUP log emitted from main loop"),
        ("ALREADY_EXECUTED", "ALREADY_EXECUTED synthetic tool_result wired"),
        ("deliberate_backstop_fired", "backstop nudge_key registered to fire-once"),
        ("if max_iter < min_iter:", "max_iter clamp to min_iter present"),
        ("func.greatest(", "monotonic iteration write (GREATEST clamp)"),
        ("from sqlalchemy import func", "sqlalchemy.func imported"),
        ("goal_incomplete:", "goal-progress reason wired into continuation"),
    ]
    for needle, label in checks:
        if needle in ao:
            _ok(f"ai_orchestrator.py: {label}")
        else:
            _fail(f"ai_orchestrator.py: missing {label} (needle={needle!r})")

    # multi_agent_orchestrator.py
    ma = (ROOT / "app" / "services" / "multi_agent_orchestrator.py").read_text(encoding="utf-8")
    ma_checks = [
        ('if tool_name == "deliberate":', "multi-agent deliberate dispatch branch"),
        ("min_iter_per_agent", "multi-agent per-agent min-iter floor"),
        ("ALREADY_EXECUTED", "multi-agent dedup short-circuit"),
        ("[FLOOR_GATE]", "multi-agent FLOOR_GATE log"),
        ('"deliberate" not in _agent_tool_list', "multi-agent injects deliberate into every role"),
        ("session_iter_total", "multi-agent session-wide iteration aggregate"),
        ("[MA_ROUND]", "multi-agent rounds-loop log"),
        ("max_rounds", "multi-agent rounds cap"),
        ("_iteration_used", "SubAgent exposes iteration count"),
        ("_goal_progress_blocks_termination", "multi-agent goal-progress gate hookup"),
        ("backstop_dispatched", "multi-agent reasoning-loop backstop flag"),
        ("phase2_round", "multi-agent round-aware phase_transition events"),
    ]
    for needle, label in ma_checks:
        if needle in ma:
            _ok(f"multi_agent_orchestrator.py: {label}")
        else:
            _fail(f"multi_agent_orchestrator.py: missing {label} (needle={needle!r})")


if __name__ == "__main__":
    sys.exit(main())

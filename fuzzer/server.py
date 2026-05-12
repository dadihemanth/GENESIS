"""
GENESIS fuzzer · Tier-3 T9 — coverage-guided fuzzing API.

POST /fuzz
    {
      "binary_path": "/data/security/artifacts/<session>/<name>",
      "seeds": ["BASE64 STRING", ...],           # at least 1
      "argv_template": ["@@"],                   # @@ expands to the input file
      "duration_seconds": 60,                    # hard-capped
      "engine": "afl++"                           # only engine supported today
    }

Returns:
    {
      "ok": true,
      "engine": "afl++",
      "run_id": "...",
      "duration_seconds": <actual>,
      "crashes": [
        { "input_b64": "...", "size": 123, "stderr_excerpt": "..." }
      ],
      "minimized_corpus_count": 14,
      "stdout_tail": "...",
      "stderr_tail": "..."
    }

Hard caps:
  - duration_seconds ≤ 600 (10 minutes)
  - ≤ 20 crash samples returned
  - binary_path must resolve under /data/security/artifacts (read-only mount)
  - argv_template must contain exactly one "@@" (the input-file placeholder)
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import re
import shutil
import signal
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List

from flask import Flask, jsonify, request
from waitress import serve

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("fuzzer")

app = Flask(__name__)

ARTIFACT_ROOT = Path(os.environ.get("ARTIFACT_ROOT", "/data/security/artifacts")).resolve()
WORK_ROOT = Path(os.environ.get("FUZZ_WORK_ROOT", "/tmp/fuzzwork"))
WORK_ROOT.mkdir(parents=True, exist_ok=True)

# T24 — grammar-aware dictionaries shipped in the image. Each subdir has a
# `dict.afl` file consumable by AFL++ via `-x`. Missing grammars → fall back
# to pure random mutation (the v2.5 behaviour).
GRAMMARS_ROOT = Path(os.environ.get("FUZZ_GRAMMARS_ROOT", "/app/grammars")).resolve()

MAX_DURATION = 600
MAX_CRASHES_RETURNED = 20
MAX_INPUT_SIZE = 1024 * 1024  # 1 MB cap on each fuzzer input
# T24 — differential fuzzing
MAX_DIFF_SEEDS = 64
MAX_DIFF_DIVERGENCES = 32
DIFF_PER_RUN_TIMEOUT = 5.0


def _resolve_binary(p: str) -> Path:
    candidate = Path(p).resolve()
    try:
        candidate.relative_to(ARTIFACT_ROOT)
    except ValueError as exc:
        raise PermissionError(
            f"binary_path must live under {ARTIFACT_ROOT}; got {candidate}"
        ) from exc
    if not candidate.is_file():
        raise FileNotFoundError(f"binary not found: {candidate}")
    if not os.access(candidate, os.R_OK):
        raise PermissionError(f"binary not readable: {candidate}")
    return candidate


def _write_seeds(seed_dir: Path, seeds_b64: List[str]) -> int:
    seed_dir.mkdir(parents=True, exist_ok=True)
    written = 0
    for idx, enc in enumerate(seeds_b64[:64]):  # cap seed corpus at 64 entries
        try:
            raw = base64.b64decode(enc, validate=False)
        except Exception:
            continue
        if len(raw) == 0 or len(raw) > MAX_INPUT_SIZE:
            continue
        (seed_dir / f"seed{idx:04d}").write_bytes(raw)
        written += 1
    if written == 0:
        # AFL demands at least one seed; synthesise a minimal one.
        (seed_dir / "seed0000").write_bytes(b"A")
        written = 1
    return written


def _validate_argv(argv: List[str]) -> List[str]:
    if not argv or not isinstance(argv, list):
        return ["@@"]
    placeholder_hits = sum(1 for x in argv if isinstance(x, str) and "@@" in x)
    if placeholder_hits != 1:
        return ["@@"]
    # Shallow-sanitise args — nothing exotic, no shell metacharacters.
    for a in argv:
        if not isinstance(a, str) or re.search(r"[;|&`$<>\n]", a):
            return ["@@"]
    return argv


def _collect_crashes(crash_dir: Path) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if not crash_dir.is_dir():
        return out
    for f in sorted(crash_dir.iterdir())[:MAX_CRASHES_RETURNED]:
        if not f.is_file() or f.name.startswith("README"):
            continue
        try:
            raw = f.read_bytes()
        except Exception:
            continue
        out.append({
            "filename": f.name,
            "size": len(raw),
            "input_b64": base64.b64encode(raw[:MAX_INPUT_SIZE]).decode(),
        })
    return out


def _tail_text(p: Path, n: int = 4096) -> str:
    if not p.is_file():
        return ""
    try:
        data = p.read_bytes()
    except Exception:
        return ""
    return data[-n:].decode(errors="replace")


def _resolve_grammar(name: str) -> Path | None:
    """Return the dict.afl file for a grammar name, or None if missing.

    Grammar names are lowercased and constrained to [a-z0-9_-]. Missing
    grammars are a soft-fail: the fuzzer continues with pure random
    mutation, returning ``grammar_used=false`` so the caller knows.
    """
    if not name:
        return None
    safe = re.sub(r"[^a-z0-9_-]", "", name.lower())
    if not safe:
        return None
    candidate = GRAMMARS_ROOT / safe / "dict.afl"
    try:
        candidate = candidate.resolve()
        candidate.relative_to(GRAMMARS_ROOT)
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def _fuzz_afl(
    binary: Path,
    seed_dir: Path,
    work: Path,
    argv: List[str],
    duration: int,
    dict_path: Path | None = None,
) -> Dict[str, Any]:
    """Run AFL++ for `duration` seconds, then report."""
    out_dir = work / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    cmdline_argv = [binary.as_posix(), *[a for a in argv]]
    cmd = [
        "afl-fuzz",
        "-i", seed_dir.as_posix(),
        "-o", out_dir.as_posix(),
        "-V", str(duration),
        "-m", "none",       # no memory limit — caller sets cgroup
        "-t", "5000",       # 5 s per run
    ]
    if dict_path is not None:
        cmd.extend(["-x", dict_path.as_posix()])
    cmd.extend(["--", *cmdline_argv])
    log.info("afl-fuzz launching: %s", " ".join(cmd))
    proc = subprocess.Popen(
        cmd,
        cwd=work.as_posix(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=os.setsid,
        env={**os.environ, "AFL_NO_UI": "1"},
    )
    try:
        stdout_b, stderr_b = proc.communicate(timeout=duration + 30)
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGTERM)
        time.sleep(0.5)
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout_b, stderr_b = proc.communicate(timeout=5)
        rc = -1

    crash_dir = out_dir / "default" / "crashes"
    queue_dir = out_dir / "default" / "queue"
    return {
        "rc": rc,
        "crashes": _collect_crashes(crash_dir),
        "corpus_count": sum(1 for _ in queue_dir.iterdir()) if queue_dir.is_dir() else 0,
        "stdout": stdout_b.decode(errors="replace")[-4096:],
        "stderr": stderr_b.decode(errors="replace")[-4096:],
    }


# honggfuzz was previously available as a secondary engine but is no
# longer packaged in the distros we target. AFL++ is the only engine
# shipped in this container. If a future base image adds honggfuzz back,
# _fuzz_honggfuzz can be reinstated and the engine allow-list below
# extended — until then, the server rejects engine=honggfuzz with a
# clear error.


@app.get("/health")
def health() -> Any:
    grammars: List[str] = []
    if GRAMMARS_ROOT.is_dir():
        for child in sorted(GRAMMARS_ROOT.iterdir()):
            if child.is_dir() and (child / "dict.afl").is_file():
                grammars.append(child.name)
    return jsonify({
        "ok": True,
        "service": "fuzzer",
        "engines": ["afl++"],
        "grammars": grammars,
        "diff_supported": True,
    })


@app.post("/fuzz")
def fuzz() -> Any:
    body = request.get_json(force=True, silent=True) or {}
    binary_raw = str(body.get("binary_path") or "").strip()
    if not binary_raw:
        return jsonify({"ok": False, "error": "binary_path required"}), 400

    try:
        binary = _resolve_binary(binary_raw)
    except (FileNotFoundError, PermissionError) as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    seeds = body.get("seeds") or []
    if not isinstance(seeds, list):
        return jsonify({"ok": False, "error": "seeds must be an array of base64 strings"}), 400

    argv = _validate_argv(body.get("argv_template") or ["@@"])
    engine = str(body.get("engine") or "afl++").lower()
    if engine != "afl++":
        return jsonify({
            "ok": False,
            "error": (
                f"unsupported engine '{engine}'. Only 'afl++' is shipped in "
                "this container (honggfuzz was removed when the upstream "
                "distro dropped the package)."
            ),
        }), 400

    try:
        duration = int(body.get("duration_seconds") or 60)
    except (TypeError, ValueError):
        duration = 60
    duration = max(10, min(MAX_DURATION, duration))

    run_id = uuid.uuid4().hex[:12]
    work = WORK_ROOT / run_id
    work.mkdir(parents=True, exist_ok=True)
    seed_dir = work / "seeds"
    written = _write_seeds(seed_dir, seeds)

    # T24 — optional grammar-seeded dictionary (AFL++ `-x`).
    grammar_name = str(body.get("grammar") or "").strip()
    dict_path = _resolve_grammar(grammar_name) if grammar_name else None
    grammar_used = dict_path is not None

    log.info(
        "run=%s engine=%s binary=%s duration=%d seeds=%d grammar=%s(used=%s)",
        run_id, engine, binary, duration, written, grammar_name or "-", grammar_used,
    )

    start = time.monotonic()
    try:
        # engine is already validated above — afl++ is the only supported engine.
        result = _fuzz_afl(binary, seed_dir, work, argv, duration, dict_path=dict_path)
    except Exception as exc:
        log.exception("fuzz run failed")
        return jsonify({"ok": False, "error": f"fuzz failed: {exc}", "run_id": run_id}), 500

    elapsed = round(time.monotonic() - start, 1)

    # Clean up immediately — crashes are already returned inline.
    try:
        shutil.rmtree(work, ignore_errors=True)
    except Exception:
        pass

    return jsonify({
        "ok": True,
        "run_id": run_id,
        "engine": engine,
        "binary": str(binary),
        "duration_seconds": elapsed,
        "requested_duration_seconds": duration,
        "seed_count": written,
        "corpus_count": result.get("corpus_count", 0),
        "crashes": result.get("crashes", []),
        "crash_count": len(result.get("crashes", [])),
        "exit_code": result.get("rc"),
        "stdout_tail": result.get("stdout", ""),
        "stderr_tail": result.get("stderr", ""),
        "grammar": grammar_name or None,
        "grammar_used": grammar_used,
    })


# ── T24 — differential fuzzing ────────────────────────────────────────────
def _run_diff_single(binary: Path, argv: List[str], seed_bytes: bytes, input_path: Path) -> Dict[str, Any]:
    """Run ``binary argv...`` where the template's ``@@`` has already been
    substituted with ``input_path``. Returns a compact trace for comparison.
    """
    try:
        input_path.write_bytes(seed_bytes[:MAX_INPUT_SIZE])
    except Exception as exc:
        return {"error": f"write seed failed: {exc}"}

    concrete_argv = [binary.as_posix(), *[(input_path.as_posix() if "@@" in a else a) for a in argv]]
    try:
        proc = subprocess.Popen(
            concrete_argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            out_b, err_b = proc.communicate(timeout=DIFF_PER_RUN_TIMEOUT)
            rc = proc.returncode
            timed_out = False
        except subprocess.TimeoutExpired:
            proc.kill()
            out_b, err_b = proc.communicate(timeout=2)
            rc = -9
            timed_out = True
    except Exception as exc:
        return {"error": f"exec failed: {exc}"}

    # Hash + a prefix for compact comparison + forensics.
    h = hashlib.sha1(out_b).hexdigest()[:16]
    return {
        "exit_code": rc,
        "timed_out": timed_out,
        "stdout_sha1": h,
        "stdout_prefix": out_b[:256].decode("utf-8", errors="replace"),
        "stderr_prefix": err_b[:256].decode("utf-8", errors="replace"),
        "stdout_bytes": len(out_b),
    }


@app.post("/fuzz_diff")
def fuzz_diff() -> Any:
    body = request.get_json(force=True, silent=True) or {}
    binaries_raw = body.get("binaries") or []
    if not isinstance(binaries_raw, list) or len(binaries_raw) != 2:
        return jsonify({
            "ok": False,
            "error": "binaries must be a length-2 array of artifact paths",
        }), 400

    try:
        bin_a = _resolve_binary(str(binaries_raw[0]))
        bin_b = _resolve_binary(str(binaries_raw[1]))
    except (FileNotFoundError, PermissionError) as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    seeds = body.get("seeds") or []
    if not isinstance(seeds, list) or not seeds:
        return jsonify({"ok": False, "error": "seeds must be a non-empty array of base64 strings"}), 400

    argv = _validate_argv(body.get("argv_template") or ["@@"])
    oracle = str(body.get("oracle") or "both").lower()
    if oracle not in ("stdout", "exit_code", "both"):
        return jsonify({"ok": False, "error": "oracle must be 'stdout' | 'exit_code' | 'both'"}), 400

    try:
        duration = int(body.get("duration_seconds") or 60)
    except (TypeError, ValueError):
        duration = 60
    duration = max(1, min(MAX_DURATION, duration))

    run_id = uuid.uuid4().hex[:12]
    work = WORK_ROOT / f"diff-{run_id}"
    work.mkdir(parents=True, exist_ok=True)

    divergences: List[Dict[str, Any]] = []
    seeds_tried = 0
    seeds_skipped = 0
    start = time.monotonic()
    try:
        for idx, enc in enumerate(seeds[:MAX_DIFF_SEEDS]):
            if time.monotonic() - start >= duration:
                break
            try:
                raw = base64.b64decode(enc, validate=False)
            except Exception:
                seeds_skipped += 1
                continue
            if not raw or len(raw) > MAX_INPUT_SIZE:
                seeds_skipped += 1
                continue

            seeds_tried += 1
            input_a = work / f"in-{idx:04d}-a"
            input_b = work / f"in-{idx:04d}-b"
            trace_a = _run_diff_single(bin_a, argv, raw, input_a)
            trace_b = _run_diff_single(bin_b, argv, raw, input_b)
            if "error" in trace_a or "error" in trace_b:
                continue

            diverges = False
            reasons: List[str] = []
            if oracle in ("exit_code", "both"):
                if trace_a["exit_code"] != trace_b["exit_code"]:
                    diverges = True
                    reasons.append(f"exit_code {trace_a['exit_code']} vs {trace_b['exit_code']}")
            if oracle in ("stdout", "both"):
                if trace_a["stdout_sha1"] != trace_b["stdout_sha1"]:
                    diverges = True
                    reasons.append(
                        f"stdout_sha1 {trace_a['stdout_sha1']}({trace_a['stdout_bytes']}B) vs "
                        f"{trace_b['stdout_sha1']}({trace_b['stdout_bytes']}B)"
                    )

            if diverges:
                divergences.append({
                    "seed_index": idx,
                    "seed_sha1": hashlib.sha1(raw).hexdigest()[:16],
                    "seed_b64": base64.b64encode(raw).decode(),
                    "reasons": reasons,
                    "trace_a": trace_a,
                    "trace_b": trace_b,
                })
                if len(divergences) >= MAX_DIFF_DIVERGENCES:
                    break
    finally:
        try:
            shutil.rmtree(work, ignore_errors=True)
        except Exception:
            pass

    elapsed = round(time.monotonic() - start, 1)
    return jsonify({
        "ok": True,
        "run_id": run_id,
        "binary_a": str(bin_a),
        "binary_b": str(bin_b),
        "oracle": oracle,
        "duration_seconds": elapsed,
        "requested_duration_seconds": duration,
        "seeds_tried": seeds_tried,
        "seeds_skipped": seeds_skipped,
        "divergence_count": len(divergences),
        "divergences": divergences,
        "hit_divergence_cap": len(divergences) >= MAX_DIFF_DIVERGENCES,
    })


if __name__ == "__main__":
    log.info("fuzzer listening on 0.0.0.0:3401 · artifact_root=%s", ARTIFACT_ROOT)
    serve(app, host="0.0.0.0", port=3401, threads=2)

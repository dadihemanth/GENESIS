"""GENESIS instrumentation · Tier-5 T25 — dynamic instrumentation API.

Wraps Frida (spawn mode) and DynamoRIO behind a single HTTP endpoint so the
orchestrator can point at a pulled binary artifact, inject a hook script,
and stream the resulting trace back as structured evidence.

Contract (POST /instrument):
    {
      "mode": "frida" | "dynamorio",
      "binary_path": "/data/security/artifacts/<session>/<name>",
      "argv": ["--input", "/tmp/instwork/x"],     # optional
      "stdin_b64": "base64",                       # optional
      "hook_spec": "<frida JavaScript>" ,          # frida mode
      "dr_client": "drcov" | "drstrace" | "drltrace",  # dynamorio mode
      "wall_time_s": 30                            # hard max 180
    }

Response (frida):
    {
      "ok": true,
      "mode": "frida",
      "frida_version": "16.4.10",
      "exit_code": 0,
      "duration_ms": 1234,
      "events": [{"type": "send", "payload": ...}, ...],   # up to 1000
      "events_truncated": false,
      "stdout_tail": "...",
      "stderr_tail": "...",
      "timed_out": false
    }

Response (dynamorio):
    {
      "ok": true,
      "mode": "dynamorio",
      "dr_version": "10.0.0",
      "dr_client": "drcov",
      "exit_code": 0,
      "coverage_summary": {"basic_blocks": 1234, "modules": [...]},
      "client_stdout_tail": "...",
      "target_stdout_tail": "...",
      "target_stderr_tail": "..."
    }

Fails gracefully with {"ok": false, "reason": "...", "available": false} when
a requested tool isn't present in the image (e.g. DynamoRIO download failed
at build time).

Security posture:
  - binary_path MUST resolve under /data/security/artifacts (read-only mount)
  - argv is sanitised against shell metacharacters
  - wall_time is hard-capped at 180s
  - hook script size is capped at 64KB
  - stdout/stderr + trace event count are truncated (1MB / 1000 events)
"""
from __future__ import annotations

import base64
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, request
from waitress import serve

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("instrumentation")

app = Flask(__name__)

ARTIFACT_ROOT = Path(os.environ.get("ARTIFACT_ROOT", "/data/security/artifacts")).resolve()
INSTWORK = Path(os.environ.get("INSTWORK", "/tmp/instwork"))
INSTWORK.mkdir(parents=True, exist_ok=True)

HARD_MAX_WALL_TIME_S = 180
DEFAULT_WALL_TIME_S = 30
MAX_EVENTS = 1000
MAX_HOOK_SCRIPT_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 1 * 1024 * 1024

_DR_CLIENTS = {"drcov", "drstrace", "drltrace"}


def _truncate(s: str, cap: int = MAX_OUTPUT_BYTES) -> tuple[str, bool]:
    if len(s) <= cap:
        return s, False
    return s[:cap] + f"\n[...truncated at {cap} bytes]", True


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


def _sanitise_argv(argv: List[Any]) -> List[str]:
    out: List[str] = []
    if not isinstance(argv, list):
        return out
    for item in argv[:32]:
        s = str(item)
        if re.search(r"[;|&`$<>\n]", s):
            continue
        out.append(s[:512])
    return out


# ── Frida spawn mode ──────────────────────────────────────────────────────
def _run_frida(
    binary: Path,
    argv: List[str],
    stdin_bytes: Optional[bytes],
    hook_script: str,
    wall_time_s: int,
) -> Dict[str, Any]:
    try:
        import frida  # type: ignore
    except ImportError as exc:
        return {"ok": False, "reason": f"frida not installed: {exc}", "available": False}

    if not hook_script.strip():
        hook_script = "// (no hook) — trace stays silent; process runs to completion"

    events: List[Dict[str, Any]] = []
    events_truncated = False

    def on_message(msg: Dict[str, Any], data: Optional[bytes]) -> None:
        nonlocal events_truncated
        if len(events) >= MAX_EVENTS:
            events_truncated = True
            return
        entry = {"type": msg.get("type"), "payload": msg.get("payload")}
        if msg.get("type") == "error":
            entry["description"] = msg.get("description")
            entry["stack"] = msg.get("stack")
        if data is not None:
            # Attach raw bytes as base64 for the agent to decode if needed.
            entry["data_b64"] = base64.b64encode(data[:4096]).decode("ascii")
        events.append(entry)

    device = frida.get_local_device()
    pid: Optional[int] = None
    session = None
    script = None
    stdout_path = INSTWORK / f"frida-stdout-{uuid.uuid4().hex[:8]}.log"
    stderr_path = INSTWORK / f"frida-stderr-{uuid.uuid4().hex[:8]}.log"

    start = time.monotonic()
    try:
        pid = device.spawn([str(binary), *argv], stdio="pipe")
        session = device.attach(pid)
        script = session.create_script(hook_script)
        script.on("message", on_message)
        try:
            script.load()
        except frida.InvalidArgumentError as exc:
            return {"ok": False, "reason": f"hook_spec rejected by frida: {exc}"}
        device.resume(pid)

        # Wait for the process to exit or the wall-clock budget to run out.
        # We don't have a direct poll via frida's Python API; use a best-effort
        # loop with session detach as the exit signal.
        exited = False
        end_by = start + wall_time_s
        # If stdin was supplied, push it in one go via /proc/<pid>/fd/0.
        if stdin_bytes:
            try:
                with open(f"/proc/{pid}/fd/0", "wb") as f:
                    f.write(stdin_bytes)
            except Exception as exc:  # noqa: BLE001
                events.append({"type": "meta", "payload": f"stdin push failed: {exc}"})

        while time.monotonic() < end_by:
            try:
                # If os.kill with signal 0 raises ProcessLookupError the child
                # exited on its own.
                os.kill(pid, 0)
            except ProcessLookupError:
                exited = True
                break
            except PermissionError:
                # Still alive but not ours — very unusual; stop waiting.
                break
            time.sleep(0.1)

        timed_out = not exited
        exit_code: Optional[int] = None
        if not exited:
            try:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.3)
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        duration_ms = int((time.monotonic() - start) * 1000)

        # Try to drain any stdio frida captured. The Python API exposes
        # "output" messages via the session.on('detached', ...) path; we
        # collect them from events we've already accumulated into on_message.
        stdout_tail = ""
        stderr_tail = ""
        for ev in events:
            if ev.get("type") == "send" and isinstance(ev.get("payload"), dict):
                payload = ev["payload"]
                if isinstance(payload.get("stdout"), str):
                    stdout_tail += payload["stdout"]
                if isinstance(payload.get("stderr"), str):
                    stderr_tail += payload["stderr"]

        stdout_tail, out_trunc = _truncate(stdout_tail)
        stderr_tail, err_trunc = _truncate(stderr_tail)

        return {
            "ok": True,
            "mode": "frida",
            "frida_version": getattr(frida, "__version__", "unknown"),
            "exit_code": exit_code,
            "timed_out": timed_out,
            "duration_ms": duration_ms,
            "events": events,
            "events_truncated": events_truncated,
            "stdout_tail": stdout_tail,
            "stderr_tail": stderr_tail,
            "stdout_truncated": out_trunc,
            "stderr_truncated": err_trunc,
        }
    except frida.ExecutableNotFoundError as exc:
        return {"ok": False, "reason": f"spawn failed: {exc}"}
    except frida.NotSupportedError as exc:
        return {"ok": False, "reason": f"frida not supported for this binary: {exc}"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "reason": f"frida error: {type(exc).__name__}: {exc}"}
    finally:
        try:
            if script is not None:
                script.unload()
        except Exception:  # noqa: BLE001
            pass
        try:
            if session is not None:
                session.detach()
        except Exception:  # noqa: BLE001
            pass
        if pid is not None:
            try:
                os.kill(pid, signal.SIGKILL)
            except Exception:  # noqa: BLE001
                pass
        for p in (stdout_path, stderr_path):
            try:
                p.unlink(missing_ok=True)
            except Exception:  # noqa: BLE001
                pass


# ── DynamoRIO mode ────────────────────────────────────────────────────────
def _drrun_available() -> tuple[bool, str | None]:
    drrun = shutil.which("drrun")
    if not drrun:
        return False, None
    try:
        out = subprocess.run(
            ["drrun", "-version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        version = (out.stdout + out.stderr).strip().splitlines()[0] if (out.stdout or out.stderr) else None
    except Exception:  # noqa: BLE001
        version = None
    return True, version


def _run_dynamorio(
    binary: Path,
    argv: List[str],
    stdin_bytes: Optional[bytes],
    dr_client: str,
    wall_time_s: int,
) -> Dict[str, Any]:
    available, version = _drrun_available()
    if not available:
        return {
            "ok": False,
            "reason": "DynamoRIO (drrun) is not installed in this container; "
                      "rebuild the instrumentation image with network access to fetch it, "
                      "or use mode='frida' instead.",
            "available": False,
            "mode": "dynamorio",
        }
    if dr_client not in _DR_CLIENTS:
        return {
            "ok": False,
            "reason": f"unknown dr_client '{dr_client}'. Supported: {sorted(_DR_CLIENTS)}",
        }

    run_id = uuid.uuid4().hex[:10]
    outdir = INSTWORK / f"dr-{run_id}"
    outdir.mkdir(parents=True, exist_ok=True)
    cmd = ["drrun", "-t", dr_client, "-logdir", str(outdir), "--", str(binary), *argv]
    start = time.monotonic()
    proc: Optional[subprocess.Popen[bytes]] = None
    timed_out = False
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(outdir),
        )
        try:
            stdout_b, stderr_b = proc.communicate(input=stdin_bytes, timeout=wall_time_s)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            stdout_b, stderr_b = proc.communicate(timeout=5)
            exit_code = -9
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "reason": f"drrun failed: {type(exc).__name__}: {exc}"}
    finally:
        if proc is not None and proc.poll() is None:
            proc.kill()

    duration_ms = int((time.monotonic() - start) * 1000)

    # Minimal parse of the drcov log to give a coverage summary the agent can
    # reason about. drcov writes to drcov.<exe>.<pid>.0000.proc.log in outdir.
    coverage_summary: Dict[str, Any] = {}
    if dr_client == "drcov":
        try:
            logs = sorted(outdir.glob("drcov.*.log"))
            if logs:
                content = logs[0].read_text(errors="replace")
                bb_match = re.search(r"BB Table:\s*(\d+)\s+bbs", content)
                module_count = len(re.findall(r"^\d+,\s*\d+,\s*0x[0-9a-fA-F]+", content, re.MULTILINE))
                coverage_summary = {
                    "basic_blocks": int(bb_match.group(1)) if bb_match else None,
                    "module_count": module_count,
                    "log_file": str(logs[0].name),
                }
        except Exception as exc:  # noqa: BLE001
            coverage_summary = {"parse_error": str(exc)}

    stdout_tail, out_trunc = _truncate(stdout_b.decode("utf-8", errors="replace"))
    stderr_tail, err_trunc = _truncate(stderr_b.decode("utf-8", errors="replace"))

    # DynamoRIO prints client messages to stderr. We return both tails.
    # Cleanup the log dir so repeat runs don't leak disk.
    try:
        shutil.rmtree(outdir)
    except Exception:  # noqa: BLE001
        pass

    return {
        "ok": True,
        "mode": "dynamorio",
        "dr_version": version,
        "dr_client": dr_client,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "duration_ms": duration_ms,
        "coverage_summary": coverage_summary,
        "target_stdout_tail": stdout_tail,
        "target_stderr_tail": stderr_tail,
        "stdout_truncated": out_trunc,
        "stderr_truncated": err_trunc,
    }


# ── Routes ────────────────────────────────────────────────────────────────
@app.get("/health")
def health() -> Any:
    available_dr, dr_version = _drrun_available()
    try:
        import frida  # type: ignore
        frida_version = getattr(frida, "__version__", "unknown")
        frida_ok = True
    except ImportError:
        frida_version = None
        frida_ok = False
    return jsonify({
        "ok": True,
        "service": "instrumentation",
        "frida": {"available": frida_ok, "version": frida_version},
        "dynamorio": {"available": available_dr, "version": dr_version},
    })


@app.post("/instrument")
def instrument() -> Any:
    try:
        body = request.get_json(force=True) or {}
    except Exception as exc:
        return jsonify({"ok": False, "reason": f"invalid JSON: {exc}"}), 400

    mode = str(body.get("mode", "")).lower()
    if mode not in ("frida", "dynamorio"):
        return jsonify({"ok": False, "reason": "mode must be 'frida' or 'dynamorio'"}), 400

    try:
        binary = _resolve_binary(str(body.get("binary_path", "")))
    except (PermissionError, FileNotFoundError) as exc:
        return jsonify({"ok": False, "reason": str(exc)}), 400

    argv = _sanitise_argv(body.get("argv") or [])
    stdin_bytes: Optional[bytes] = None
    if body.get("stdin_b64"):
        try:
            stdin_bytes = base64.b64decode(str(body["stdin_b64"]), validate=False)[:1024 * 1024]
        except Exception as exc:  # noqa: BLE001
            return jsonify({"ok": False, "reason": f"stdin_b64 decode failed: {exc}"}), 400

    wall_time_s = int(body.get("wall_time_s") or DEFAULT_WALL_TIME_S)
    wall_time_s = max(1, min(wall_time_s, HARD_MAX_WALL_TIME_S))

    if mode == "frida":
        hook_script = str(body.get("hook_spec") or "")
        if len(hook_script.encode("utf-8", errors="ignore")) > MAX_HOOK_SCRIPT_BYTES:
            return jsonify({
                "ok": False,
                "reason": f"hook_spec exceeds {MAX_HOOK_SCRIPT_BYTES} bytes",
            }), 400
        result = _run_frida(binary, argv, stdin_bytes, hook_script, wall_time_s)
    else:
        dr_client = str(body.get("dr_client", "drcov")).lower()
        result = _run_dynamorio(binary, argv, stdin_bytes, dr_client, wall_time_s)

    status = 200 if result.get("ok") or result.get("available") is False else 500
    return jsonify(result), status


def main() -> None:
    port = int(os.environ.get("PORT", "3601"))
    log.info("[instrumentation] listening on 0.0.0.0:%d (artifact_root=%s)", port, ARTIFACT_ROOT)
    serve(app, host="0.0.0.0", port=port, threads=4)


if __name__ == "__main__":
    main()

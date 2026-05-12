"""GENESIS forge_sandbox — HTTP server that executes LLM-authored scripts.

Contract (POST /run):
    {
      "lang": "python" | "node" | "bash",
      "code": "<script body, <= 8 KB>",
      "stdin": "<optional stdin>",
      "wall_time_s": 60,          # hard max 180
      "session_id": "<session UUID for audit log>"
    }

Response:
    {
      "stdout": "...",
      "stderr": "...",
      "exit_code": 0,
      "duration_ms": 1234,
      "timed_out": false
    }

Security posture: the container is already rootless + read-only rootfs at the
Docker level. The server layer additionally enforces:
  - per-request wall-time via subprocess.TimeoutExpired (terminate + kill)
  - max script size (8 KB)
  - cwd pinned to /tmp/work (the only writable mount)
  - no shell=True anywhere; scripts run as argv lists
  - stdout/stderr streamed into 1 MB ring buffers (truncate beyond)

Egress restriction (target IP + OOB only) is NOT enforced by this server —
it's enforced by Docker's network configuration for this container. This
layer trusts that.
"""
from __future__ import annotations

import json
import os
import resource
import signal
import subprocess
import tempfile
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Tuple

PORT = int(os.environ.get("PORT", "3201"))
MAX_CODE_BYTES = 8 * 1024
MAX_OUTPUT_BYTES = 1 * 1024 * 1024  # 1 MB
HARD_MAX_WALL_TIME = 180
DEFAULT_WALL_TIME = 60
WORKDIR = "/tmp/work"


def _truncate(s: str, cap: int = MAX_OUTPUT_BYTES) -> Tuple[str, bool]:
    if len(s) <= cap:
        return s, False
    return s[:cap] + f"\n[...truncated at {cap} bytes]", True


def _set_rlimits() -> None:
    """Preexec: apply CPU / address-space / file-size / nproc limits."""
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (HARD_MAX_WALL_TIME, HARD_MAX_WALL_TIME))
    except Exception:
        pass
    try:
        # 512 MB address space ceiling (container also caps memory at 256 MB)
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    except Exception:
        pass
    try:
        resource.setrlimit(resource.RLIMIT_FSIZE, (50 * 1024 * 1024, 50 * 1024 * 1024))
    except Exception:
        pass
    try:
        resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
    except Exception:
        pass
    # New session so signal.killpg hits all children
    try:
        os.setsid()
    except Exception:
        pass


def _run(lang: str, code: str, stdin: str, wall_time_s: int) -> dict:
    if len(code.encode("utf-8", errors="ignore")) > MAX_CODE_BYTES:
        return {"error": "code exceeds max size", "max_bytes": MAX_CODE_BYTES}

    wall_time_s = max(1, min(wall_time_s, HARD_MAX_WALL_TIME))

    suffix = {"python": ".py", "node": ".js", "bash": ".sh"}.get(lang)
    if suffix is None:
        return {"error": f"unsupported lang '{lang}'. Use python|node|bash."}

    os.makedirs(WORKDIR, exist_ok=True)
    script_path = os.path.join(WORKDIR, f"forge-{uuid.uuid4().hex[:10]}{suffix}")
    try:
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(code)
        if lang == "bash":
            os.chmod(script_path, 0o700)

        if lang == "python":
            argv = ["python", "-I", "-B", script_path]
        elif lang == "node":
            argv = ["node", "--no-deprecation", "--disallow-code-generation-from-strings", script_path]
        else:  # bash
            argv = ["bash", "--noprofile", "--norc", script_path]

        start = time.time()
        timed_out = False
        try:
            proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=WORKDIR,
                preexec_fn=_set_rlimits,
                env={
                    "PATH": "/usr/local/bin:/usr/bin:/bin",
                    "HOME": WORKDIR,
                    "PYTHONUNBUFFERED": "1",
                    "NO_COLOR": "1",
                },
            )
        except FileNotFoundError as exc:
            return {"error": f"interpreter missing: {exc}"}

        try:
            stdout_b, stderr_b = proc.communicate(
                input=stdin.encode("utf-8", errors="ignore") if stdin else None,
                timeout=wall_time_s,
            )
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                time.sleep(0.5)
                os.killpg(proc.pid, signal.SIGKILL)
            except Exception:
                proc.kill()
            stdout_b, stderr_b = proc.communicate(timeout=5)
            exit_code = -9

        duration_ms = int((time.time() - start) * 1000)
        stdout, out_trunc = _truncate(stdout_b.decode("utf-8", errors="replace"))
        stderr, err_trunc = _truncate(stderr_b.decode("utf-8", errors="replace"))
        return {
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "timed_out": timed_out,
            "stdout_truncated": out_trunc,
            "stderr_truncated": err_trunc,
            "lang": lang,
        }
    finally:
        try:
            os.unlink(script_path)
        except Exception:
            pass


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:  # noqa: D401
        # Quiet the default access log — rely on parent service logs
        pass

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._json(200, {"ok": True, "service": "forge_sandbox"})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/run":
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > 32 * 1024:
            self._json(413, {"error": "request too large"})
            return
        try:
            raw = self.rfile.read(length)
            body = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            self._json(400, {"error": f"invalid JSON: {exc}"})
            return

        lang = str(body.get("lang", "python")).lower()
        code = str(body.get("code", ""))
        stdin = str(body.get("stdin", ""))
        wall_time_s = int(body.get("wall_time_s", DEFAULT_WALL_TIME) or DEFAULT_WALL_TIME)
        if not code.strip():
            self._json(400, {"error": "code is empty"})
            return

        result = _run(lang, code, stdin, wall_time_s)
        self._json(200, result)


def main() -> None:
    os.makedirs(WORKDIR, exist_ok=True)
    print(f"[forge_sandbox] listening on 0.0.0.0:{PORT}", flush=True)
    HTTPServer(("0.0.0.0", PORT), _Handler).serve_forever()


if __name__ == "__main__":
    main()

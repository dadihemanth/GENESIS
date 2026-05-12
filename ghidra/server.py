"""Ghidra headless HTTP wrapper.

POST /decompile
    { "artifact_path": "/data/security/artifacts/.../<file>",
      "top_n": 25, "project_name": "optional" }
-> returns the JSON output of DumpPseudoC.java.

Caches results by (sha256 + top_n) on /work so a second call for the same
artifact is cheap.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(os.environ.get("PORT", "3101"))
GHIDRA_HOME = os.environ.get("GHIDRA_HOME", "/opt/ghidra")
SCRIPT_DIR = "/scripts"
WORK_ROOT = "/work"
CACHE_DIR = os.path.join(WORK_ROOT, "cache")
ANALYZE_TIMEOUT_S = int(os.environ.get("GHIDRA_TIMEOUT_S", "600"))


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _run_headless(artifact_path: str, top_n: int) -> dict:
    if not os.path.exists(artifact_path):
        return {"error": "artifact not found", "path": artifact_path}

    digest = _sha256(artifact_path)
    cache_path = os.path.join(CACHE_DIR, f"{digest}-top{top_n}.json")
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                return {"cached": True, **json.load(f)}
        except Exception:
            pass  # fall through to re-analyze

    project_dir = tempfile.mkdtemp(prefix="ghidra-proj-", dir=WORK_ROOT)
    project_name = f"forge_{uuid.uuid4().hex[:10]}"
    output_json = os.path.join(project_dir, "dump.json")

    argv = [
        os.path.join(GHIDRA_HOME, "support", "analyzeHeadless"),
        project_dir,
        project_name,
        "-import", artifact_path,
        "-readOnly",
        "-scriptPath", SCRIPT_DIR,
        "-postScript", "DumpPseudoC.java", output_json, str(top_n),
        "-deleteProject",
    ]

    start = time.time()
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            timeout=ANALYZE_TIMEOUT_S,
            env={"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": WORK_ROOT},
        )
    except subprocess.TimeoutExpired:
        return {"error": "ghidra analyzeHeadless timed out", "timeout_s": ANALYZE_TIMEOUT_S}
    except FileNotFoundError as exc:
        return {"error": f"analyzeHeadless missing: {exc}"}

    duration_ms = int((time.time() - start) * 1000)

    if not os.path.exists(output_json):
        return {
            "error": "DumpPseudoC produced no output",
            "exit_code": proc.returncode,
            "stderr_tail": proc.stderr.decode("utf-8", errors="replace")[-4000:],
            "stdout_tail": proc.stdout.decode("utf-8", errors="replace")[-2000:],
        }

    try:
        with open(output_json, "r", encoding="utf-8") as f:
            parsed = json.load(f)
    except Exception as exc:
        return {"error": f"output JSON parse failed: {exc}"}
    finally:
        try:
            os.unlink(output_json)
        except Exception:
            pass

    parsed["sha256"] = digest
    parsed["analyze_duration_ms"] = duration_ms
    parsed["top_n"] = top_n

    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(parsed, f)
    except Exception:
        pass

    return {"cached": False, **parsed}


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:  # noqa: D401
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
            self._json(200, {"ok": True, "service": "ghidra_headless"})
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/decompile":
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > 8 * 1024:
            self._json(413, {"error": "request too large"})
            return
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception as exc:
            self._json(400, {"error": f"bad JSON: {exc}"})
            return

        artifact_path = str(body.get("artifact_path", "")).strip()
        top_n = int(body.get("top_n", 25) or 25)
        top_n = max(3, min(60, top_n))
        if not artifact_path:
            self._json(400, {"error": "artifact_path is required"})
            return
        # Guard against escapes out of the artifacts tree
        real = os.path.realpath(artifact_path)
        if not real.startswith("/data/security/artifacts/"):
            self._json(403, {"error": "artifact path outside /data/security/artifacts"})
            return

        self._json(200, _run_headless(real, top_n))


def main() -> None:
    os.makedirs(WORK_ROOT, exist_ok=True)
    os.makedirs(CACHE_DIR, exist_ok=True)
    print(f"[ghidra_headless] listening on 0.0.0.0:{PORT}", flush=True)
    HTTPServer(("0.0.0.0", PORT), _Handler).serve_forever()


if __name__ == "__main__":
    main()

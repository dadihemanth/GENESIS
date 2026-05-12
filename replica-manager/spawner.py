"""Spawner — maps a stack_pin to a docker-compose.yml template and scaffolds stub app files."""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import List, Optional

REPLICA_NETWORK = os.getenv("REPLICA_NETWORK", "genesis_replica_net")


def compose_for_stack(stack_pin: str, port: int, observed_routes: List[str]) -> str:
    """Return docker-compose YAML for the given stack pin."""
    pin = stack_pin.lower()

    if "express" in pin or ("node" in pin and "spring" not in pin):
        version = extract_version(stack_pin, "express") or "4.18"
        return f"""version: '3.8'
services:
  app:
    image: node:18-alpine
    command: sh -c "npm install express@{version} && node /app/server.js"
    ports: ["{port}:3000"]
    volumes: ["/tmp/replica_{port}:/app"]
    networks: [{REPLICA_NETWORK}]
networks:
  {REPLICA_NETWORK}:
    external: true
"""
    if "django" in pin:
        return f"""version: '3.8'
services:
  app:
    image: python:3.11-alpine
    command: sh -c "pip install django && python /app/manage.py runserver 0.0.0.0:8000"
    ports: ["{port}:8000"]
    volumes: ["/tmp/replica_{port}:/app"]
    networks: [{REPLICA_NETWORK}]
networks:
  {REPLICA_NETWORK}:
    external: true
"""
    if "flask" in pin or "python" in pin:
        return f"""version: '3.8'
services:
  app:
    image: python:3.11-alpine
    command: sh -c "pip install flask && python /app/app.py"
    ports: ["{port}:5000"]
    volumes: ["/tmp/replica_{port}:/app"]
    networks: [{REPLICA_NETWORK}]
networks:
  {REPLICA_NETWORK}:
    external: true
"""
    if "spring" in pin or "java" in pin or "tomcat" in pin:
        return f"""version: '3.8'
services:
  app:
    image: tomcat:10-jdk17-openjdk-slim
    ports: ["{port}:8080"]
    networks: [{REPLICA_NETWORK}]
networks:
  {REPLICA_NETWORK}:
    external: true
"""
    if "php" in pin or "apache" in pin:
        return f"""version: '3.8'
services:
  app:
    image: php:8.2-apache
    ports: ["{port}:80"]
    volumes: ["/tmp/replica_{port}:/var/www/html"]
    networks: [{REPLICA_NETWORK}]
networks:
  {REPLICA_NETWORK}:
    external: true
"""
    if "rails" in pin or "ruby" in pin:
        return f"""version: '3.8'
services:
  app:
    image: ruby:3.2-alpine
    command: sh -c "gem install rails && rails server -b 0.0.0.0 -p 3000"
    ports: ["{port}:3000"]
    volumes: ["/tmp/replica_{port}:/app"]
    networks: [{REPLICA_NETWORK}]
networks:
  {REPLICA_NETWORK}:
    external: true
"""
    # Generic nginx fallback
    return f"""version: '3.8'
services:
  app:
    image: nginx:alpine
    ports: ["{port}:80"]
    networks: [{REPLICA_NETWORK}]
networks:
  {REPLICA_NETWORK}:
    external: true
"""


def extract_version(stack_pin: str, component: str) -> Optional[str]:
    """Extract a semver string for a named component from the stack pin."""
    pattern = rf"{re.escape(component)}\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)"
    m = re.search(pattern, stack_pin, re.IGNORECASE)
    return m.group(1) if m else None


def scaffold_app(stack_pin: str, port: int, observed_routes: List[str]) -> None:
    """Write a minimal stub application for the replica container."""
    work_dir = Path(f"/tmp/replica_{port}")
    work_dir.mkdir(parents=True, exist_ok=True)
    pin = stack_pin.lower()

    if "express" in pin or ("node" in pin and "spring" not in pin):
        routes_code = "\n".join(
            f"app.all('{r}', (req, res) => res.json({{stub: true, path: '{r}'}}));"
            for r in observed_routes
        ) or "app.all('*', (req, res) => res.json({stub: true}));"
        (work_dir / "server.js").write_text(
            f"const express = require('express');\nconst app = express();\n{routes_code}\napp.listen(3000);\n"
        )
    elif "django" in pin:
        (work_dir / "manage.py").write_text(
            "import sys\nfrom django.core.management import execute_from_command_line\n"
            "execute_from_command_line(sys.argv)\n"
        )
    elif "flask" in pin or "python" in pin:
        routes_code = "\n".join(
            f"@app.route('{r}', methods=['GET','POST','PUT','DELETE'])\n"
            f"def route_{abs(hash(r))}():\n    return {{\"stub\": True}}"
            for r in observed_routes
        ) or "@app.route('/', methods=['GET'])\ndef index():\n    return {'stub': True}"
        (work_dir / "app.py").write_text(
            f"from flask import Flask, jsonify\napp = Flask(__name__)\n{routes_code}\n"
            "if __name__ == '__main__': app.run(host='0.0.0.0', port=5000)\n"
        )
    elif "php" in pin:
        (work_dir / "index.php").write_text("<?php echo json_encode(['stub' => true]); ?>")


def ensure_replica_network() -> None:
    """Create the replica Docker network if it doesn't already exist."""
    try:
        subprocess.run(
            ["docker", "network", "create", REPLICA_NETWORK],
            capture_output=True, timeout=10,
        )
    except Exception:
        pass

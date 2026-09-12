#!/usr/bin/env python3
"""Static smoke checks for the supported Version 2 Compose profiles."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

COMPOSE_FILES = (
    "docker-compose.yml",
    "monitoring/docker-compose-closed.yml",
    "monitoring/docker-compose-enhanced.yml",
    "monitoring/laptop-optimization.yml",
    "monitoring/docker-compose.yml",
)


def run() -> int:
    failures: list[str] = []

    version = subprocess.run(
        [sys.executable, "cyberrange.py", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    if version.returncode or "2.0.0" not in version.stdout:
        failures.append("canonical Version 2 entry point")

    for path in COMPOSE_FILES:
        if not Path(path).is_file():
            failures.append(f"missing {path}")

    try:
        docker = subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        docker = None

    if docker is None or docker.returncode:
        print("Docker Compose unavailable; static Python tests still apply.")
    else:
        for path in COMPOSE_FILES:
            result = subprocess.run(
                ["docker", "compose", "-f", path, "config", "--quiet"],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode:
                failures.append(f"Compose validation failed for {path}: {result.stderr.strip()}")

    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1

    print("Version 2 Docker profile contract: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())

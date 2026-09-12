#!/usr/bin/env python3
"""Show or launch the supported Version 2 Docker profiles."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

PROFILES = {
    "1": ("Closed four-service range", "monitoring/docker-compose-closed.yml"),
    "2": ("Enhanced range with monitoring and offline IDS validation", "monitoring/docker-compose-enhanced.yml"),
    "3": ("Laptop-friendly monitored range", "monitoring/laptop-optimization.yml"),
}


def main() -> int:
    print("CPS Cyber Range Version 2 Docker Runner")
    print("=" * 42)

    missing = [path for _, path in PROFILES.values() if not Path(path).is_file()]
    if missing:
        for path in missing:
            print(f"Missing required file: {path}", file=sys.stderr)
        return 1

    for key, (label, path) in PROFILES.items():
        print(f"{key}. {label}\n   {path}")

    print("\nCanonical simulator example:")
    print("  python cyberrange.py --compose monitoring/docker-compose-enhanced.yml --scripted-agents --rounds 20")
    print("\nLive packet capture is intentionally excluded. See monitoring/security-controls.md before enabling it.")

    try:
        choice = input("\nStart a profile now (1-3, or Enter to exit)? ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return 0

    if not choice:
        return 0
    if choice not in PROFILES:
        print("Invalid selection.", file=sys.stderr)
        return 2

    _, compose_path = PROFILES[choice]
    command = ["docker", "compose", "-f", compose_path, "up", "-d"]
    print("Running:", " ".join(command))
    try:
        return subprocess.run(command, check=False).returncode
    except FileNotFoundError:
        print("Docker CLI not found. Install Docker with the Compose plugin.", file=sys.stderr)
        return 127


if __name__ == "__main__":
    raise SystemExit(main())

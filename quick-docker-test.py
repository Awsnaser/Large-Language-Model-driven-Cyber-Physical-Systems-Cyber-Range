#!/usr/bin/env python3
"""Quick, Docker-free inventory check for CPS Cyber Range Version 2."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def load_range_module():
    module_path = Path(__file__).with_name("cyberrange.py")
    spec = importlib.util.spec_from_file_location("cyberrange_v2", module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    try:
        module = load_range_module()
        expected = ("gw_dmz_01", "hist_data_01", "hmi_ops_01", "plc_industrial_01")
        inventories = {
            "standard": tuple(module.STANDARD_CONTAINERS),
            "enhanced simulator": tuple(module.ENHANCED_CONTAINERS),
            "laptop simulator": tuple(module.LAPTOP_CONTAINERS),
        }
        failures = [name for name, inventory in inventories.items() if inventory != expected]

        compose_files = (
            "docker-compose.yml",
            "monitoring/docker-compose-closed.yml",
            "monitoring/docker-compose-enhanced.yml",
            "monitoring/laptop-optimization.yml",
        )
        failures.extend(path for path in compose_files if not Path(path).is_file())

        for name, inventory in inventories.items():
            print(f"{name}: {len(inventory)} modeled assets ({', '.join(inventory)})")

        if failures:
            print("Failed checks: " + ", ".join(failures), file=sys.stderr)
            return 1

        print("Version 2 inventory contract: OK")
        print("Run: python cyberrange.py --compose monitoring/docker-compose-enhanced.yml --scripted-agents --rounds 20")
        return 0
    except Exception as exc:
        print(f"Configuration check failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Version 2 Suricata integration smoke check (no live capture is started)."""
from pathlib import Path
import sys
import yaml

ROOT = Path(__file__).resolve().parent
COMPOSE = ROOT / "monitoring/docker-compose-enhanced.yml"
CONFIG = ROOT / "configs/suricata/suricata.yaml"
RULES = ROOT / "configs/suricata/custom-cps.rules"


def test_suricata_integration() -> bool:
    try:
        compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
        config = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
        rules = RULES.read_text(encoding="utf-8")
        services = compose["services"]
        validator = services["suricata-ids"]
        live = services["suricata-live"]
        assert validator["container_name"] == "cps_suricata_ids"
        assert validator["command"] == ["-T", "-c", "/etc/suricata/suricata.yaml"]
        assert live["container_name"] == "cps_suricata_live"
        assert live["profiles"] == ["dangerous-packet-capture"]
        assert live.get("network_mode") != "host"
        assert live.get("privileged") is not True
        assert {"NET_ADMIN", "NET_RAW"}.issubset(set(live["cap_add"]))
        assert config["rule-files"] == ["custom-cps.rules"]
        assert "sid:1000001" in rules
        assert (ROOT / "configs/suricata/logs").is_dir()
    except (AssertionError, KeyError, OSError, TypeError, yaml.YAMLError) as exc:
        print(f"Suricata Version 2 integration check failed: {exc}")
        return False
    print("Suricata Version 2 integration contract: OK")
    print("Live capture remains explicit: --profile dangerous-packet-capture")
    return True


if __name__ == "__main__":
    raise SystemExit(0 if test_suricata_integration() else 1)

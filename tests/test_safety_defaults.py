import importlib.util
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sys

import yaml


ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "python cyberrange_all_in_one.py"


def _load_suricata_monitor():
    path = ROOT / "suricata-monitor.py"
    spec = importlib.util.spec_from_file_location("suricata_monitor", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_default_compose_ports_bind_to_loopback():
    for relative_path in ("docker-compose.yml", "monitoring/docker-compose.yml"):
        config = yaml.safe_load((ROOT / relative_path).read_text(encoding="utf-8"))
        for service in config["services"].values():
            for published_port in service.get("ports", []):
                assert str(published_port).startswith("127.0.0.1:")


def test_recent_suricata_alert_accepts_utc_z_timestamp():
    module = _load_suricata_monitor()
    monitor = module.SuricataMonitor()
    monitor.alerts = [
        {"timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
    ]
    assert monitor.get_recent_alerts(minutes=5) == monitor.alerts


def test_external_modbus_requires_explicit_acknowledgement():
    result = subprocess.run(
        [
            sys.executable,
            str(MAIN),
            "--real-modbus",
            "--modbus-host",
            "192.0.2.10",
            "--no-docker-up",
            "--rounds",
            "1",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 2
    assert "Refusing non-loopback" in result.stderr


def test_standard_compose_is_not_rewritten_by_default():
    compose = ROOT / "docker-compose.yml"
    before = compose.read_bytes()
    result = subprocess.run(
        [sys.executable, str(MAIN), "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0
    assert compose.read_bytes() == before

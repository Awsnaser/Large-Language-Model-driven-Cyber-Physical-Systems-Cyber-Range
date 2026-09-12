import importlib.util
from pathlib import Path
import subprocess
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_canonical_module_and_cli_report_v2():
    spec = importlib.util.spec_from_file_location("cyberrange_v2", ROOT / "cyberrange.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.__version__ == "2.0.0"

    result = subprocess.run(
        [sys.executable, str(ROOT / "cyberrange.py"), "--version"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0
    assert result.stdout.strip().endswith("2.0.0")


def test_historical_entrypoint_remains_compatible():
    result = subprocess.run(
        [sys.executable, str(ROOT / "python cyberrange_all_in_one.py"), "--version"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0
    assert result.stdout.strip().endswith("2.0.0")


def test_all_compose_profiles_use_v2_plc_marker():
    compose_files = [
        ROOT / "docker-compose.yml",
        ROOT / "monitoring/docker-compose-closed.yml",
        ROOT / "monitoring/docker-compose-enhanced.yml",
        ROOT / "monitoring/laptop-optimization.yml",
    ]
    for compose_file in compose_files:
        config = yaml.safe_load(compose_file.read_text(encoding="utf-8"))
        command = config["services"]["plc_industrial_01"]["command"]
        assert "SAFE_v2" in str(command)

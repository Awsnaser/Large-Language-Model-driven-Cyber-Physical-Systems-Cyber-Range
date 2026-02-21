import importlib.util
import json
from pathlib import Path
import sys
import types

import numpy as np


def _inject_optional_stubs():
    if "docker" not in sys.modules:
        docker_stub = types.SimpleNamespace(from_env=lambda: types.SimpleNamespace(containers=None))
        sys.modules["docker"] = docker_stub
    if "ollama" not in sys.modules:
        ollama_stub = types.SimpleNamespace(chat=lambda *args, **kwargs: {"message": {"content": "{}"}})
        sys.modules["ollama"] = ollama_stub
    if "faker" not in sys.modules:
        class _FakeFaker:
            def __init__(self, *args, **kwargs):
                pass

        sys.modules["faker"] = types.SimpleNamespace(Faker=_FakeFaker)


def _load_module():
    _inject_optional_stubs()
    module_path = Path(__file__).resolve().parents[1] / "python cyberrange_all_in_one.py"
    spec = importlib.util.spec_from_file_location("cyberrange_all_in_one", str(module_path))
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


m = _load_module()


def test_dense_damage_risk_boundaries():
    assert m.dense_damage_risk(m.TANK_LEVEL_EMPTY) == 1.0
    assert m.dense_damage_risk(m.TANK_LEVEL_OVERFLOW) == 1.0

    center = m.dense_damage_risk(50.0)
    near_low = m.dense_damage_risk(m.TANK_LEVEL_SAFE_LOW - 1.0)
    near_high = m.dense_damage_risk(m.TANK_LEVEL_SAFE_HIGH + 1.0)

    assert 0.0 <= center <= 1.0
    assert near_low > center
    assert near_high > center


def test_modbus_mappings_roundtrip():
    for cmd, code in m.MODBUS_PUMP_CODE.items():
        assert m.MODBUS_PUMP_CODE_INV[code] == cmd
    for cmd, code in m.MODBUS_VALVE_CODE.items():
        assert m.MODBUS_VALVE_CODE_INV[code] == cmd
    assert m.MODBUS_REG_STATE_BASE == 100
    assert m.MODBUS_REG_CMD_BASE == 201


def test_active_policy_respects_confidence_safety_filter():
    env = m.CPSRange(seed=1, max_rounds=5)
    policy = m.ActiveInterventionPolicy(damage_prob_max=0.25)

    class DummyMOGP:
        ready = True

        def __init__(self):
            # candidate order in policy: AUTO/AUTO, FORCE_OFF/AUTO, AUTO/FORCE_OPEN,
            # AUTO/FORCE_CLOSED, FORCE_ON/AUTO, FORCE_ON/FORCE_CLOSED
            self.i = -1
            self.responses = [
                (0.10, 0.01, 0.20, 0.02, 0.00, 0.10),
                (0.15, 0.01, 0.30, 0.02, 0.20, 0.02),
                (0.40, 0.02, 0.50, 0.02, -0.50, 0.03),
                (0.12, 0.01, 0.10, 0.02, 0.10, 0.02),
                (0.70, 0.09, 0.60, 0.03, 1.20, 0.20),
                (0.90, 0.05, 0.80, 0.03, 1.70, 0.15),
            ]

        def predict(self, _z):
            self.i += 1
            mu_dmg, var_dmg, mu_alarm, var_alarm, mu_delta, var_delta = self.responses[self.i]
            return {
                "delta": (np.array([mu_delta]), np.array([var_delta])),
                "alarm": (np.array([mu_alarm]), np.array([var_alarm])),
                "damage": (np.array([mu_dmg]), np.array([var_dmg])),
            }

        def prob_damage(self, x):
            return float(min(1.0, max(0.0, x)))

        def prob_alarm(self, x):
            return float(1.0 / (1.0 + np.exp(-x)))

    chosen = policy.select(DummyMOGP(), env.tank, env.attacker_zone)
    assert chosen["name"] in {"AUTO/AUTO", "FORCE_OFF/AUTO", "AUTO/FORCE_CLOSED"}
    assert chosen.get("p_damage_ucb", 0.0) <= 0.25


def test_benchmark_suite_outputs_schema(tmp_path):
    out = m.run_benchmark_suite(output_dir=str(tmp_path), seeds=2, rounds=6)
    assert Path(out["rows_path"]).exists()
    assert Path(out["summary_path"]).exists()
    assert Path(out["summary_csv_path"]).exists()
    assert out["effective_seeds"] >= 1
    assert out["effective_rounds"] >= 1


def test_benchmark_config_override(tmp_path):
    config_path = tmp_path / "bench.json"
    config = {
        "global": {"seeds": 1, "rounds": 4},
        "agents": [
            {
                "name": "custom_agent",
                "red_mode": "scripted",
                "blue_mode": "safety",
                "active_probe": False,
                "probe_every": 2,
            }
        ],
    }
    config_path.write_text(json.dumps(config), encoding="utf-8")

    out = m.run_benchmark_suite(output_dir=str(tmp_path / "out"), seeds=3, rounds=9, config_path=str(config_path))
    assert out["effective_seeds"] == 1
    assert out["effective_rounds"] == 4
    assert len(out["summary"]) == 1
    assert out["summary"][0]["agent"] == "custom_agent"


def test_benchmark_config_sanitizes_invalid_values(tmp_path):
    config_path = tmp_path / "bench_invalid.json"
    config = {
        "global": {"seeds": "bad", "rounds": -3},
        "agents": [
            {
                "name": "unsafe_modes",
                "red_mode": "unsupported-red",
                "blue_mode": "unsupported-blue",
                "active_probe": True,
                "probe_every": 0,
            }
        ],
    }
    config_path.write_text(json.dumps(config), encoding="utf-8")

    loaded = m._load_benchmark_config(str(config_path))
    assert loaded["global"]["seeds"] == 1
    assert loaded["global"]["rounds"] == 1
    assert loaded["agents"][0]["red_mode"] == "scripted"
    assert loaded["agents"][0]["blue_mode"] == "monitor"
    assert loaded["agents"][0]["probe_every"] == 1

    out = m.run_benchmark_suite(output_dir=str(tmp_path / "out_invalid"), seeds=2, rounds=4, config_path=str(config_path))
    assert out["effective_seeds"] == 1
    assert out["effective_rounds"] == 1


def test_extract_plot_context_handles_partial_and_invalid_history():
    history = {
        "round": [1, "bad", None, 4],
        "tank_level": [50.0],
        # Intentionally missing most keys to exercise default padding behavior
    }

    ctx = m._extract_plot_context(history)
    assert ctx is not None
    assert len(ctx["round"]) == 4
    assert len(ctx["tank_level"]) == 4
    assert len(ctx["alerts_total"]) == 4
    assert len(ctx["gp_p_damage"]) == 4
    assert np.isfinite(ctx["round"]).all()


def test_plot_run_disables_show_when_output_paths_present():
    calls = {"panel": None, "story": None, "kill": None, "anim": None, "topo": None}

    def _panel(_history, save_path=None, show=True):
        calls["panel"] = bool(show)
        return None

    def _story(_history, save_path=None, show=True, scenario_count=5):
        calls["story"] = bool(show)
        return None

    def _kill(_rows, out_dir=None, prefix="run", show=True):
        calls["kill"] = bool(show)
        return []

    def _anim(_history, _rows, save_path=None, show=False):
        calls["anim"] = bool(show)
        return None

    def _topo(_rows, _assets, save_path=None, show=False, dim="2d"):
        calls["topo"] = bool(show)
        return None

    old_panel = m._plot_publication_grid
    old_story = m._plot_scenario_storyboard
    old_kill = m._plot_kill_chain_and_tools
    old_anim = m._animate_run_timeline
    old_topo = m._animate_topology_infra

    try:
        m._plot_publication_grid = _panel
        m._plot_scenario_storyboard = _story
        m._plot_kill_chain_and_tools = _kill
        m._animate_run_timeline = _anim
        m._animate_topology_infra = _topo

        m.plot_run(
            history={"round": [1], "tank_level": [50.0], "alerts_total": [0], "compromised_count": [0], "alarm_flag": [0.0], "damage_flag": [0.0], "gp_p_alarm": [0.0], "gp_p_damage": [0.0], "policy_choice": [""]},
            save_path="out/run.png",
            dataset_rows=[{"red_action": "RECON", "blue_action": "MONITOR"}],
            killchain_plots=True,
            animate=True,
            animate_save_path="out/timeline.gif",
            topology_assets=[{"asset_id": "a1", "zone": "IT", "kind": "gateway", "ip": "127.0.0.1", "network": "n1"}],
            topology_animate=True,
            topology_dim="2d",
            topology_save_path="out/topo.gif",
        )
    finally:
        m._plot_publication_grid = old_panel
        m._plot_scenario_storyboard = old_story
        m._plot_kill_chain_and_tools = old_kill
        m._animate_run_timeline = old_anim
        m._animate_topology_infra = old_topo

    assert calls["panel"] is False
    assert calls["story"] is False
    assert calls["kill"] is False
    assert calls["anim"] is False
    assert calls["topo"] is False

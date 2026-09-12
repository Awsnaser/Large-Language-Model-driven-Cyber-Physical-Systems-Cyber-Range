"""Static contract tests for the Version 2 container/IDS Compose files."""
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILES = {
    "standard": ROOT / "docker-compose.yml",
    "monitoring": ROOT / "monitoring/docker-compose.yml",
    "closed": ROOT / "monitoring/docker-compose-closed.yml",
    "enhanced": ROOT / "monitoring/docker-compose-enhanced.yml",
    "laptop": ROOT / "monitoring/laptop-optimization.yml",
}
EXPECTED_SERVICES = {
    "standard": {"gw_dmz_01", "hist_data_01", "hmi_ops_01", "plc_industrial_01"},
    "monitoring": {"prometheus", "grafana"},
    "closed": {"gw_dmz_01", "hist_data_01", "hmi_ops_01", "plc_industrial_01"},
    "enhanced": {
        "gw_dmz_01", "hist_data_01", "hmi_ops_01", "plc_industrial_01",
        "prometheus", "grafana", "suricata-ids", "suricata-live",
    },
    "laptop": {
        "gw_dmz_01", "hist_data_01", "hmi_ops_01", "plc_industrial_01",
        "prometheus", "grafana", "suricata-ids",
    },
}
SAFE_SHARED_CONTAINERS = {
    "gw_dmz_01": "gw_dmz_01",
    "hist_data_01": "hist_data_01",
    "hmi_ops_01": "hmi_ops_01",
    "plc_industrial_01": "plc_industrial_01",
    "prometheus": "cps_prometheus",
    "grafana": "cps_grafana",
    "suricata-ids": "cps_suricata_ids",
}
DANGEROUS_CAPABILITIES = {"NET_ADMIN", "NET_RAW"}


def _load(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _default_services(config):
    """Compose services with profiles are not selected by bare `compose up`."""
    return {
        name: service
        for name, service in config["services"].items()
        if not service.get("profiles")
    }


def _bind_sources(compose_path, service, named_volumes):
    for mount in service.get("volumes", []):
        if isinstance(mount, str):
            source = mount.split(":", 1)[0]
            if source.startswith(".") or source.startswith("/"):
                yield Path(source)
        elif isinstance(mount, dict) and mount.get("type") == "bind":
            yield Path(mount["source"])


def test_compose_v2_service_inventories_are_deliberate():
    configs = {name: _load(path) for name, path in COMPOSE_FILES.items()}
    for name, config in configs.items():
        assert set(config["services"]) == EXPECTED_SERVICES[name]
        for service_name, service in config["services"].items():
            assert not service["image"].endswith(":latest"), f"{name}/{service_name} is unpinned"

    # The laptop stack is a resource-constrained safe subset of enhanced.
    assert set(configs["laptop"]["services"]).issubset(set(configs["enhanced"]["services"]))
    for config in configs.values():
        for service_name, container_name in SAFE_SHARED_CONTAINERS.items():
            if service_name in config["services"]:
                assert config["services"][service_name]["container_name"] == container_name


def test_compose_v2_default_services_have_safe_network_and_port_defaults():
    for name, compose_path in COMPOSE_FILES.items():
        config = _load(compose_path)
        for service_name, service in _default_services(config).items():
            assert service.get("network_mode") != "host", f"{name}/{service_name} uses host networking"
            assert service.get("privileged") is not True, f"{name}/{service_name} is privileged"
            assert not (set(service.get("cap_add", [])) & DANGEROUS_CAPABILITIES), (
                f"{name}/{service_name} requests a packet-capture capability"
            )
            for published_port in service.get("ports", []):
                assert str(published_port).startswith("127.0.0.1:"), (
                    f"{name}/{service_name} exposes {published_port!r} beyond loopback"
                )


def test_compose_v2_all_bind_mount_sources_exist():
    for compose_path in COMPOSE_FILES.values():
        config = _load(compose_path)
        named_volumes = set(config.get("volumes", {}))
        for service in config["services"].values():
            for source in _bind_sources(compose_path, service, named_volumes):
                resolved = source if source.is_absolute() else compose_path.parent / source
                assert resolved.exists(), f"{compose_path}: missing bind source {source}"


def test_enhanced_suricata_is_real_and_live_capture_is_explicitly_opt_in():
    enhanced = _load(COMPOSE_FILES["enhanced"])["services"]
    offline = enhanced["suricata-ids"]
    live = enhanced["suricata-live"]

    assert offline["image"] == "jasonish/suricata:7.0.11"
    assert offline["command"] == ["-T", "-c", "/etc/suricata/suricata.yaml"]
    assert "../configs/suricata:/etc/suricata:ro" in offline["volumes"]
    assert live["profiles"] == ["dangerous-packet-capture"]
    assert DANGEROUS_CAPABILITIES.issubset(set(live["cap_add"]))
    assert live.get("network_mode") != "host"
    assert live.get("privileged") is not True

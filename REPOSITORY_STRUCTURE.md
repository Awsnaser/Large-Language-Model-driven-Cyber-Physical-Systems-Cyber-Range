# Repository structure — Version 2.0.0

```text
.
├── cyberrange.py                       # Canonical Version 2 CLI and simulator
├── python cyberrange_all_in_one.py     # Historical compatibility wrapper
├── docker-compose.yml                  # Standard four-service range
├── pyproject.toml                      # Package metadata and console script
├── requirements.txt                    # Core runtime dependencies
├── requirements-neural.txt             # Optional Torch dependency set
├── multi_agent_system.py               # Optional multi-agent subsystem
├── neural_agent_integration.py         # Simulator/neural action adapter
├── advanced_neural_architectures.py    # Neural experiments and components
├── configs/
│   └── suricata/
│       ├── suricata.yaml               # Version 2 Suricata configuration
│       └── custom-cps.rules            # CPS rule set
├── monitoring/
│   ├── docker-compose.yml              # Standalone Prometheus/Grafana stack
│   ├── docker-compose-closed.yml       # Closed, safe four-service range
│   ├── docker-compose-enhanced.yml     # Range, monitoring, Suricata validation,
│   │                                   # plus opt-in dangerous capture profile
│   ├── laptop-optimization.yml         # Resource-limited safe stack
│   ├── prometheus.yml
│   └── grafana/                        # Provisioning and dashboards
├── topology-viewer/                    # React/Vite static topology viewer
├── tests/                              # Python regression and safety tests
└── *.md                                # Project documentation
```

## Entry points

- **Supported CLI:** `python cyberrange.py` or, after package installation, `cps-cyberrange`.
- **Compatibility CLI:** `python "python cyberrange_all_in_one.py"`. It delegates to `cyberrange.py`; new use should not target it.
- **Viewer:** from `topology-viewer`, run `npm install` and `npm run dev`.

## Compose service model

The simulator models four CPS assets: `gw_dmz_01`, `hist_data_01`, `hmi_ops_01`, and `plc_industrial_01`. Compose files may add monitoring or validation services; they are not extra modeled assets.

| File | Default services | Notes |
| --- | --- | --- |
| `docker-compose.yml` | Four CPS services | Standard range. |
| `monitoring/docker-compose-closed.yml` | Four CPS services | Closed safe range selected explicitly with `--compose monitoring/docker-compose-closed.yml`. |
| `monitoring/docker-compose-enhanced.yml` | Four CPS services plus monitoring and IDS validation | Safe enhanced range selected by `--enhanced-docker`. |
| `monitoring/docker-compose.yml` | Prometheus, Grafana | Standalone monitoring stack used by `--monitoring-up`. |
| `monitoring/docker-compose-enhanced.yml` | Four CPS services, Prometheus, Grafana, `suricata-ids` | The normal Suricata service validates configuration only. `suricata-live` is excluded behind `dangerous-packet-capture`. |
| `monitoring/laptop-optimization.yml` | Safe enhanced subset with limits | Includes offline `suricata-ids`; no live capture service. |

Normal services use bridge networking and Compose-published ports bind to loopback. This is a practical default, not a claim of complete isolation.

## Suricata paths and profiles

The current IDS files are `configs/suricata/suricata.yaml` and `configs/suricata/custom-cps.rules`. `suricata-ids` runs Suricata's `-T` validation and exits. Live packet capture is available only through the explicitly named `dangerous-packet-capture` profile in `monitoring/docker-compose-enhanced.yml`; it requests capture capabilities and is for an isolated lab host only.

## Neural subsystem

The neural files implement optional Torch-based components. The Version 2 simulator runner exposes only `deep_feedforward` and `deep` via `--neural-arch`; it does not make transformer, GNN, memory, or neuroevolution architectures runnable choices. `--neuroevolution` is rejected by the runner.

## Documentation map

- [README.md](README.md): overview and common commands.
- [QUICK_START.md](QUICK_START.md): short installation and smoke-test path.
- [SETUP.md](SETUP.md): prerequisites and optional integrations.
- [SURICATA_INTEGRATION.md](SURICATA_INTEGRATION.md): validation and live-capture distinction.
- [VERSION_2.md](VERSION_2.md): release overview, migration, and upgrade checklist.
- [CONTRIBUTING.md](CONTRIBUTING.md): contribution workflow.

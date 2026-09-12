# LLM CPS Cyber Range — Version 2.0.0

A local, symbolic cyber-physical range simulator with a four-asset Docker substrate, red/blue simulation, tank-process modeling, multi-output Gaussian-process risk estimates, optional neural agents, and a browser topology viewer.

> **Safety boundary:** actions are simulated. Docker profiles are safe by default, but they are not a guarantee of complete isolation or a production security control. Review Docker access, host networking, ports, mounts, and any optional hardware integration before use.

## Quick start

Python 3.10+ is required. This smoke run is simulator-only and does not start Docker services:

```bash
python -m venv .venv
source .venv/bin/activate             # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python cyberrange.py --no-docker-up --scripted-agents --rounds 20
```

The canonical Version 2 entry point is `python cyberrange.py`. The historical command remains compatible but is only a wrapper:

```bash
python "python cyberrange_all_in_one.py" --scripted-agents --rounds 20
```

Check the installed release with `python cyberrange.py --version`; it reports `2.0.0`.

## Common runs

```bash
# Start the default four-service Docker range.
python cyberrange.py --scripted-agents --rounds 20

# Use local Ollama-controlled agents instead of scripted agents.
# Ollama must be running and the selected models must be available.
python cyberrange.py --rounds 20 --model-red llama3.2:1b --model-blue llama3.2:1b

# Export a viewer-compatible topology file.
python cyberrange.py --no-docker-up --scripted-agents --rounds 20 \
  --export-topology-json outputs/topology.json

# Optional Torch-based neural subsystem.
python -m pip install -r requirements-neural.txt
python cyberrange.py --no-docker-up --multi-agent \
  --neural-arch deep_feedforward --rounds 20
```

`--scripted-agents` is useful for deterministic, Ollama-free validation. The Version 2 CLI supports `deep_feedforward` and `deep` as neural decision architectures. Transformer, GNN, memory, and neuroevolution choices are not integrated CLI alternatives; `--neuroevolution` is explicitly rejected by the simulator loop.

## Docker and monitoring profiles

| Command | Scope |
| --- | --- |
| `python cyberrange.py --rounds 20` | Default four-service range from `docker-compose.yml`. |
| `python cyberrange.py --enhanced-docker --rounds 20` | Safe enhanced range with four modeled CPS assets, monitoring, and offline IDS validation. |
| `python cyberrange.py --laptop-docker --rounds 20` | Resource-limited safe range with monitoring and offline Suricata validation. |
| `python cyberrange.py --compose monitoring/docker-compose-enhanced.yml --rounds 20` | Safe enhanced stack: core range, monitoring, and offline Suricata validation. |
| `python cyberrange.py --metrics --monitoring-up --rounds 20` | Standard range plus the standalone monitoring Compose stack. |

Docker runs require a running Docker Engine and the Compose v2 command (`docker compose`). Compose-published management ports bind to loopback (`127.0.0.1`). This does not describe or restrict the host-side Python metrics listener; review its exposure before using `--metrics`.

Set a Grafana password before starting a monitoring stack:

```bash
export GRAFANA_ADMIN_PASSWORD='use-a-unique-local-password'
```

The configured Grafana user is `admin`; `admin/admin` is not a supported default.

## Suricata safety model

`suricata-ids` is a safe **configuration-validation** job. It uses the shipped `configs/suricata/suricata.yaml` and `custom-cps.rules`, runs Suricata with `-T`, needs no packet-capture capabilities, and exits after validation. It does not automatically capture traffic.

The only live-capture service is `suricata-live`, excluded from normal startup behind the explicit `dangerous-packet-capture` profile:

```bash
# Isolated lab host only.
docker compose -f monitoring/docker-compose-enhanced.yml \
  --profile dangerous-packet-capture up -d
```

It captures on its Compose bridge interface and requests `NET_ADMIN`/`NET_RAW`; it does not use host networking. See [SURICATA_INTEGRATION.md](SURICATA_INTEGRATION.md) and [VERSION_2.md](VERSION_2.md) before enabling it.

## Topology viewer

```bash
cd topology-viewer
npm install
npm run dev
```

Open the Vite URL and use **Load JSON** to select a file produced by `--export-topology-json`. Build checks are `npm run typecheck`, `npm test`, and `npm run build`.

## Optional integrations and validation

- `--pcap PATH` exports simulated traffic and requires `scapy`; it does not turn on live capture.
- `--real-modbus` requires `pymodbus` and can read/write the target. Non-loopback endpoints are refused unless `--allow-external-modbus` explicitly acknowledges the risk. Use only a reviewed lab or simulator endpoint.
- Before a Compose run, use `docker compose -f <file> config -q` and verify Docker with `docker info`.
- A successful Suricata `-T` job validates configuration syntax; it is not evidence of live detection.

See [QUICK_START.md](QUICK_START.md) for a short workflow, [SETUP.md](SETUP.md) for prerequisites, and [VERSION_2.md](VERSION_2.md) for migration and the full upgrade checklist.

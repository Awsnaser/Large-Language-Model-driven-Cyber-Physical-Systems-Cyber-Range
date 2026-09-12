# Version 2.0.0

Version 2 is the supported release of the CPS range. The canonical command is:

```bash
python cyberrange.py --scripted-agents --rounds 20
```

The historical filename remains a compatibility wrapper:

```bash
python "python cyberrange_all_in_one.py" --scripted-agents --rounds 20
```

Both report version `2.0.0` with `--version`. New scripts and documentation should use `python cyberrange.py` (or the installed `cps-cyberrange` command).

## Install and run

Requires Python 3.10+; Docker is needed only when starting Compose services.

```bash
python -m venv .venv
source .venv/bin/activate             # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# Simulator-only run: does not start Compose services.
python cyberrange.py --no-docker-up --scripted-agents --rounds 20

# Default four-service range: starts docker-compose.yml.
python cyberrange.py --scripted-agents --rounds 20
```

`--scripted-agents` avoids the local LLM dependency. Without it, the standard simulation uses the configured Ollama models (default: `llama3.2:1b`), so Ollama must be running and the models must be available.

To install the optional Torch-based neural subsystem:

```bash
python -m pip install -r requirements-neural.txt
python cyberrange.py --no-docker-up --multi-agent --neural-arch deep_feedforward --rounds 20
```

## Safe-profile model

Compose profiles are safe by default, not a claim of complete or production-grade isolation. Published Compose management ports are bound to `127.0.0.1`; still review local Docker permissions, firewall policy, mounted data, and any host-side metrics listener before use.

| Use case | Command | What it does |
| --- | --- | --- |
| Standard range | `python cyberrange.py --rounds 20` | Starts the four modeled CPS services in `docker-compose.yml`. |
| Enhanced monitored range | `python cyberrange.py --enhanced-docker --rounds 20` | Uses `monitoring/docker-compose-enhanced.yml`: four modeled CPS assets, Prometheus, Grafana, and offline IDS validation. |
| Laptop safe stack | `python cyberrange.py --laptop-docker --rounds 20` | Starts the resource-limited range, Prometheus, Grafana, and offline Suricata validation. |
| Full safe enhanced stack | `python cyberrange.py --compose monitoring/docker-compose-enhanced.yml --rounds 20` | Starts core range services plus monitoring and offline Suricata validation. |
| Monitoring with the standard range | `python cyberrange.py --metrics --monitoring-up --rounds 20` | Starts `monitoring/docker-compose.yml` and exposes simulator metrics. |

`--no-docker-up` stops the runner from starting Compose. It may still try to inspect Docker for container metadata; if Docker is unavailable, the simulator falls back to placeholder IPs.

### Suricata: validation versus live capture

The normal `suricata-ids` service is an **offline configuration-validation service**. It runs:

```text
suricata -T -c /etc/suricata/suricata.yaml
```

against the read-only files in `configs/suricata/`, needs no packet-capture capabilities, and exits after validation. It does **not** inspect traffic or produce a live alert stream. Run the safe enhanced stack with:

```bash
docker compose -f monitoring/docker-compose-enhanced.yml up -d
docker compose -f monitoring/docker-compose-enhanced.yml ps suricata-ids
```

Live capture is deliberately separate and never starts automatically. Only on an isolated lab host, explicitly enable the `dangerous-packet-capture` profile:

```bash
docker compose -f monitoring/docker-compose-enhanced.yml \
  --profile dangerous-packet-capture up -d
```

That profile adds `suricata-live`, which captures on its Compose bridge interface and requests `NET_ADMIN` and `NET_RAW`. It is neither host-network capture nor a substitute for a controlled lab review. The laptop profile has no live-capture service.

## Neural behavior

`--multi-agent` enables the optional Torch subsystem. The Version 2 runner accepts only these integrated decision-network values:

```text
--neural-arch deep_feedforward
--neural-arch deep
```

Other architecture classes in the repository are not runner-selectable. In particular, `--neuroevolution` is rejected by the Version 2 simulator loop; it is not an alternative runtime architecture. Install the neural requirements before using `--multi-agent`; otherwise the runner disables the unavailable optional subsystem with a warning.

## Topology viewer

Export a simulation, then load its JSON from the browser UI:

```bash
python cyberrange.py --no-docker-up --scripted-agents --rounds 20 \
  --export-topology-json outputs/topology.json

cd topology-viewer
npm install
npm run dev
```

Open the local Vite URL and choose **Load JSON**. For a production bundle, use `npm run typecheck`, `npm test`, and `npm run build`.

## Migration notes

- Replace `python "python cyberrange_all_in_one.py" ...` with `python cyberrange.py ...`. The old command remains supported as a wrapper.
- Replace legacy `docker-compose` examples with the Compose v2 form `docker compose`.
- Do not use old container inventories, honeypot lists, container names, host-network capture instructions, or old Suricata paths. Version 2 tracks four modeled CPS assets; the enhanced/laptop files add only the services shown in their Compose definitions.
- Treat `monitoring/docker-compose-closed.yml` as a closed four-service range, not as the full monitoring stack. Use `monitoring/docker-compose-enhanced.yml` when the safe monitoring and validation services are wanted.
- Configure Grafana with `GRAFANA_ADMIN_PASSWORD`; the configured user is `admin`, but there is no supported `admin/admin` default.
- PCAP export (`--pcap PATH`) writes simulated traffic and requires the optional `scapy` package. It does not enable a live capture service.

## Runtime validation and upgrade checklist

Before relying on a run, validate the environment rather than assuming a profile succeeded:

1. Check the interpreter and installation: `python --version` (3.10+) and `python cyberrange.py --version`.
2. For Compose runs, confirm a running Docker Engine and Compose v2: `docker compose version` and `docker info`.
3. Validate rendered Compose before startup: `docker compose -f <file> config -q`.
4. For the safe enhanced/laptop IDS service, confirm the `suricata-ids` job exits successfully after its `-T` configuration check. A successful validation is not proof of live detection.
5. Use `--scripted-agents` for an Ollama-free smoke run; otherwise verify Ollama and the selected models first.
6. Install `requirements-neural.txt` before `--multi-agent`; install `pymodbus` before `--real-modbus`; install `scapy` before `--pcap`.
7. `--real-modbus` writes to the configured endpoint. It accepts loopback by default and refuses non-loopback targets unless `--allow-external-modbus` is supplied. Use only a lab/simulator device after review.
8. Set `GRAFANA_ADMIN_PASSWORD` before starting Grafana, and review exposure of the Python `--metrics` endpoint separately from Compose-published ports.
9. Enable `dangerous-packet-capture` only after an isolated-lab and capability review; it is intentionally opt-in.

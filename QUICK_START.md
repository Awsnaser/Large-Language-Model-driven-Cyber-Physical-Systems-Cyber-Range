# Quick Start — Version 2.0.0

Use the canonical entry point: `python cyberrange.py`.

## 1. Install

```bash
python --version                     # Python 3.10+
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python cyberrange.py --version       # 2.0.0
```

## 2. Run a safe simulator-only smoke test

```bash
python cyberrange.py --no-docker-up --scripted-agents --rounds 10
```

This does not start Docker services and does not need Ollama. `--no-docker-up` may still attempt Docker metadata lookup; if Docker is unavailable, the simulator uses placeholder IPs.

## 3. Start the default Docker range

Install Docker Engine and Compose v2, then verify them:

```bash
docker compose version
docker info
python cyberrange.py --scripted-agents --rounds 20
```

The default range starts the four services in `docker-compose.yml`. Stop it with:

```bash
docker compose down -v
```

## 4. Choose a safe profile

```bash
# Enhanced safe range with monitoring and offline IDS validation.
python cyberrange.py --enhanced-docker --scripted-agents --rounds 20

# Closed four-service profile, selected explicitly.
python cyberrange.py --compose monitoring/docker-compose-closed.yml --scripted-agents --rounds 20

# Resource-limited range plus monitoring and offline Suricata validation.
python cyberrange.py --laptop-docker --scripted-agents --rounds 20

# Safe enhanced stack with monitoring and offline Suricata validation.
python cyberrange.py --compose monitoring/docker-compose-enhanced.yml \
  --scripted-agents --rounds 20
```

All normal profiles avoid host networking, privileged containers, and packet-capture capabilities. Published Compose management ports bind to `127.0.0.1`; do not interpret that as a guarantee of complete host isolation.

## 5. Use Suricata safely

The normal `suricata-ids` service only runs `suricata -T` against `configs/suricata/suricata.yaml` and then exits. It validates configuration; it does not capture traffic automatically.

```bash
docker compose -f monitoring/docker-compose-enhanced.yml up -d
docker compose -f monitoring/docker-compose-enhanced.yml ps suricata-ids
```

Live capture is separately opt-in and is intended only for an isolated lab host:

```bash
docker compose -f monitoring/docker-compose-enhanced.yml \
  --profile dangerous-packet-capture up -d
```

This adds `suricata-live`, which requests `NET_ADMIN` and `NET_RAW` on its Compose bridge interface. It is not host-network capture.

## Optional features

### Local LLM agents

Omit `--scripted-agents` only after a local Ollama service and the selected models are available:

```bash
python cyberrange.py --rounds 20 --model-red llama3.2:1b --model-blue llama3.2:1b
```

### Neural subsystem

```bash
python -m pip install -r requirements-neural.txt
python cyberrange.py --no-docker-up --multi-agent \
  --neural-arch deep_feedforward --rounds 20
```

Only `deep_feedforward` and `deep` are supported runner choices. `--neuroevolution` is not wired into the Version 2 loop.

### Monitoring and Grafana

```bash
export GRAFANA_ADMIN_PASSWORD='use-a-unique-local-password'
python cyberrange.py --metrics --monitoring-up --scripted-agents --rounds 20
```

Grafana uses the configured `admin` user and the password above; there is no `admin/admin` default. Review the host-side metrics listener independently of the loopback-only Compose port mappings.

### Topology viewer

```bash
python cyberrange.py --no-docker-up --scripted-agents --rounds 20 \
  --export-topology-json outputs/topology.json
cd topology-viewer
npm install
npm run dev
```

Open the Vite URL and select the export with **Load JSON**.

## If something fails

1. Confirm Python 3.10+ and reinstall `requirements.txt`.
2. For Docker runs, check `docker info` and `docker compose -f <file> config -q`.
3. Use `--scripted-agents` to rule out Ollama/model availability.
4. Install optional packages before their features: Torch for `--multi-agent`, `pymodbus` for `--real-modbus`, and `scapy` for `--pcap`.
5. Treat a failed or nonzero `suricata-ids` job as a configuration-validation failure; an exited-successfully job is not a live-capture service.

For migration, runtime validation requirements, and the historical wrapper, see [VERSION_2.md](VERSION_2.md).

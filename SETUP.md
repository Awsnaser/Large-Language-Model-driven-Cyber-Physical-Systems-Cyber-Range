# Setup — Version 2.0.0

## Requirements

- Python 3.10+
- `pip`
- Docker Engine plus Compose v2 (`docker compose`) only for Docker/monitoring profiles
- A local Ollama service and model only for non-scripted LLM runs

Install the core runtime:

```bash
python -m venv .venv
source .venv/bin/activate             # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python cyberrange.py --version
```

The Version 2 command is `python cyberrange.py`. The legacy command `python "python cyberrange_all_in_one.py"` remains a wrapper for compatibility.

## First run

Start with an Ollama-free simulator-only run:

```bash
python cyberrange.py --no-docker-up --scripted-agents --rounds 10
```

`--no-docker-up` prevents Compose startup. The simulator may still try Docker metadata lookup; unavailable Docker falls back to placeholder IPs.

For the default Docker range:

```bash
docker compose version
docker info
python cyberrange.py --scripted-agents --rounds 20
```

## Compose choices

Validate a Compose file before starting it:

```bash
docker compose -f docker-compose.yml config -q
```

| Choice | Run command | Description |
| --- | --- | --- |
| Standard | `python cyberrange.py --rounds 20` | Four modeled CPS services from `docker-compose.yml`. |
| Enhanced monitored range | `python cyberrange.py --enhanced-docker --rounds 20` | Uses `monitoring/docker-compose-enhanced.yml` with four modeled CPS assets, monitoring, and offline IDS validation. |
| Laptop | `python cyberrange.py --laptop-docker --rounds 20` | Resource-limited safe range plus monitoring and Suricata configuration validation. |
| Safe enhanced | `python cyberrange.py --compose monitoring/docker-compose-enhanced.yml --rounds 20` | Range, monitoring, and Suricata configuration validation. |

Normal Compose services do not use host networking, privileged mode, or packet-capture capabilities. Their published management ports bind to `127.0.0.1`; that does not establish complete host isolation.

## Optional components

### LLM-controlled agents

The default (non-scripted) run calls Ollama. Ensure the service is running and the selected models are installed before omitting `--scripted-agents`:

```bash
python cyberrange.py --rounds 20 --model-red llama3.2:1b --model-blue llama3.2:1b
```

### Neural agents

```bash
python -m pip install -r requirements-neural.txt
python cyberrange.py --no-docker-up --multi-agent \
  --neural-arch deep_feedforward --rounds 20
```

The Version 2 runner supports `deep_feedforward` and `deep`. It does not expose transformer, GNN, or memory choices as integrated runner architectures, and rejects `--neuroevolution`.

### Monitoring

```bash
export GRAFANA_ADMIN_PASSWORD='use-a-unique-local-password'
python cyberrange.py --metrics --monitoring-up --scripted-agents --rounds 20
```

Grafana is configured with the `admin` user and the supplied password. Do not use or document an `admin/admin` default. Review the host-side Python metrics listener separately from Compose port mappings.

### Modbus and PCAP options

- Install `pymodbus` before `--real-modbus`. This mode reads from and writes to the selected endpoint; a non-loopback target also requires `--allow-external-modbus` and should be a reviewed lab/simulator device.
- Install `scapy` before `--pcap PATH`. This exports simulated traffic and does not start live capture.

See [SURICATA_INTEGRATION.md](SURICATA_INTEGRATION.md) for the IDS profiles and [VERSION_2.md](VERSION_2.md) for the upgrade checklist.

# 🏭 Advanced Cyber-Physical Range Simulator with Multi-Agent Neural Networks

A comprehensive CPS cyber range simulation featuring Docker-based infrastructure, multi-agent LLM systems, neural network decision making, Suricata IDS, and advanced security monitoring.

> 🛡️ **Safety**: This project is simulation-only. No real exploit code is executed. All activities are contained within isolated Docker environments.

## 🚀 Key Features

### 🐳 **Advanced Docker Infrastructure**
- **26 Enhanced Containers**: Full CPS environment with honeypots
- **16 Laptop Containers**: Optimized for resource-constrained systems
- **Network Segmentation**: IT/OT/DMZ zones with proper isolation
- **Honeypot Systems**: PLC, OPC UA, Web, DB, SSH, FTP decoys
- **Security Monitoring**: Suricata IDS, SIEM, packet capture

### 🧠 **Multi-Agent Neural Networks**
- **Advanced Architectures**: Transformers, GNNs, Memory Networks
- **Agent Types**: Attackers, Defenders, Analysts, Coordinators
- **Real-time Learning**: Experience replay and adaptation
- **Neuroevolution**: Genetic algorithm optimization
- **Agent Coordination**: Communication and teamwork

### 🔍 **Blue Team Defense**
- **Suricata IDS**: Real-time intrusion detection
- **CPS-Specific Rules**: Industrial protocol security
- **Live Monitoring Dashboard**: Alert analysis and reporting
- **Threat Intelligence**: Attacker profiling and pattern recognition

### 📊 **Simulation Capabilities**
- **LLM-vs-LLM Gameplay**: Red vs Blue agent competition
- **Gaussian Process Modeling**: Multi-output causal inference
- **Active Intervention**: Safe policy optimization
- **Benchmark Mode**: Performance evaluation and testing
- Tank process physics with alarms + damage boundaries
- Multi-output GP (`delta`, `alarm`, `damage-risk`) with dense risk target
- Active safe probing policy (uncertainty + confidence-aware safety filter)
- Prometheus metrics + Grafana dashboard provisioning
- Benchmark suite with baseline agents and CI-style summary stats
- Separate figure exports + publication-style storyboard plots
- Interactive terminal UX (startup status + live round dashboard, optional ANSI colors)

## Quick start

```bash
pip install docker matplotlib ollama faker numpy scikit-learn prometheus-client
python "python cyberrange_all_in_one.py" --rounds 60
```

### Interactive terminal UX

```bash
python "python cyberrange_all_in_one.py" --interactive-startup --live-round-ui --color-ui
```

- Disable live startup line: `--no-interactive-startup`
- Disable live round line: `--no-live-round-ui`
- Disable color: `--no-color-ui`

## Plot modes

```bash
python "python cyberrange_all_in_one.py" --separate-plots --save-plot outputs/run.png --scenario-count 5
```

With animations + topology + kill-chain diagnostics saved as separate files:

```bash
python "python cyberrange_all_in_one.py" \
  --rounds 80 \
  --separate-plots \
  --save-plot outputs/paper_run.png \
  --scenario-count 5 \
  --killchain-plots \
  --animate --animate-save outputs/paper_run_timeline.gif \
  --topology-animate --topology-dim 3d --topology-save outputs/paper_run_topology_3d.gif
```

Outputs include:

- `*_publication_grid.png`
- `*_scenario_storyboard.png`
- `*_safety_vs_intervention.png`
- `*_residual_diagnostics.png`
- `*_killchain_red.png`
- `*_killchain_blue.png`
- `*_tool_usage.png`
- optional timeline/topology GIFs when `--animate-save` / `--topology-save` are set

Notes:

- When any output path is provided (`--save-plot`, `--animate-save`, `--topology-save`), plots are rendered non-interactively to avoid blocking terminal runs.
- `--scenario-count` controls storyboard segmentation rows (typically 3–6 for publication layouts).

## Monitoring stack (Grafana + Prometheus)

```bash
python "python cyberrange_all_in_one.py" --metrics --metrics-port 8000 --monitoring-up
```

- Grafana: `http://localhost:3000`
- Prometheus: `http://localhost:9090`

## Benchmark suite

Default baselines:

- random red + monitor blue
- scripted red + monitor blue
- scripted red + scripted blue
- scripted red + safety blue
- scripted red + scripted blue + active probe

Run:

```bash
python "python cyberrange_all_in_one.py" --benchmark --benchmark-seeds 10 --benchmark-out benchmark_out
```

Config-driven run (matrix override):

```bash
python "python cyberrange_all_in_one.py" --benchmark --benchmark-config benchmark/benchmark_config.sample.json
```

Config schema (`benchmark/benchmark_config.sample.json`):

- `global.seeds` (positive int)
- `global.rounds` (positive int)
- `agents[]` entries:
  - `name` (string)
  - `red_mode` in `{scripted, random}`
  - `blue_mode` in `{monitor, scripted, random, safety}`
  - `active_probe` (bool)
  - `probe_every` (positive int)

Invalid values are sanitized at load time (e.g., unsupported modes fall back to safe defaults).

Artifacts:

- `benchmark_runs.csv`
- `benchmark_summary.csv`
- `benchmark_summary.json`

## Large-scale infrastructure (300+ IPs, 8 subnets)

Generate and visualize a realistic CPS infrastructure with 300+ hosts across 8 subnets spanning IT, DMZ, OT, SCADA, and Cloud zones.

**Static infrastructure map:**

```bash
python "python cyberrange_all_in_one.py" --large-infra --large-infra-save outputs/infra_map.png
```

**Animated 2D topology during simulation:**

```bash
python "python cyberrange_all_in_one.py" --no-docker-up --rounds 60 \
  --large-infra-animate --large-infra-animate-save outputs/large_topo.gif \
  --large-infra-save outputs/infra_map.png
```

**Subnets (8 total):**

| Subnet | Zone | CIDR | Example hosts |
|---|---|---|---|
| **Corporate LAN** | IT | 10.1.0.0/24 | 60 workstations, 12 printers, 20 VoIP phones |
| **IT Server Farm** | IT | 10.1.1.0/24 | 25 servers, 3 domain controllers, 5 databases |
| **DMZ Public** | DMZ | 172.16.0.0/24 | 15 web servers, 4 gateways, 3 DNS, 2 mail |
| **DMZ Services** | DMZ | 172.16.1.0/24 | 6 historians, 3 jumpboxes, 4 proxies |
| **OT Control Net** | OT | 192.168.10.0/24 | 8 HMIs, 5 eng workstations, 20 PLCs, 15 RTUs |
| **OT Field Bus** | OT | 192.168.11.0/24 | 40 sensors, 25 actuators, 10 IEDs |
| **SCADA Network** | OT | 192.168.20.0/24 | 4 SCADA servers, 3 historians, 2 alarm servers |
| **Cloud/Mgmt** | IT | 10.200.0.0/24 | 2 cloud gateways, 2 SIEMs, 3 NMS, 2 VPN concentrators |

**Animation features:**

- Subnet bounding boxes with CIDR labels
- Inter-subnet routing links
- Per-asset markers sized by criticality (HIGH/MEDIUM/LOW)
- Animated attacker movement with red attack arrows
- Blue defender arrows
- Compromise propagation (red highlighting)
- IP labels on high-criticality assets
- Live status bar (round, actions, tank level, compromised count)

## Scripted agents (improved simulation results)

The default LLM agents often produce poor results (P_safe=1.0 flat, GP never learns, red gets stuck). Use `--scripted-agents` to replace them with well-designed kill-chain RED + reactive BLUE agents:

```bash
python "python cyberrange_all_in_one.py" --no-docker-up --rounds 100 --scripted-agents --active-probe
```

**What `--scripted-agents` fixes:**

- **Kill-chain RED agent**: deterministic IT→DMZ→OT→PLC IMPACT progression with COVER evasion
- **Reactive BLUE agent**: MONITOR → PATCH → ISOLATE → RESTORE based on threat level
- **Passive compromise effects**: compromised OT assets cause sensor drift, pump perturbation, physical degradation even without explicit IMPACT
- **GP probing**: early non-trivial interventional probes (N_int > 0) for real GP learning
- **HMI/PLC services exposed**: red agent can actually reach OT assets from DMZ

**Expected result improvements:**

| Metric | Before (LLM agents) | After (scripted) |
|---|---|---|
| P_safe | Flat 1.0 | Drops to 0.3–0.6 under attack |
| GP P(alarm) | Stuck at 0.50 | Rises to 0.7–0.9 |
| GP P(damage) | Stuck at 0.00 | Rises to 0.3–0.6 |
| Compromised count | Saturates at 2 | Oscillates 1–4 with restore cycles |
| N_int (interventional) | 0 forever | 15–30 probes |
| Tank level | Flat ~50% | Wild oscillations 20–85% |

## React topology viewer

Interactive browser-based topology animation viewer with playback controls, status panels, and tank gauge.

**Quick start:**

```bash
cd topology-viewer
npm install
npm start
```

Then open `http://localhost:3000` in your browser. The viewer loads with demo data automatically.

**Export simulation data for the viewer:**

```bash
python "python cyberrange_all_in_one.py" --no-docker-up --rounds 100 --scripted-agents \
  --export-topology-json outputs/topology_data.json
```

Then load `outputs/topology_data.json` via the "Load JSON" button in the viewer.

**Features:**

- Canvas-based 2D topology with subnet bounding boxes and CIDR labels
- Animated attacker movement with red attack arrows
- Blue defender arrows
- Compromise propagation (red glow on compromised assets)
- IP labels on high-criticality assets
- Playback controls (play/pause/stop/seek/FPS)
- Real-time status panels (round info, red/blue actions, GP predictions)
- Tank level gauge with safe-band markers
- Compromised asset tracker

## Scenario comparison (attack variants + GP ablation)

Generate a publication-quality 2×3 overlay figure comparing 4 attack scenarios and 3 GP ablation variants, averaged over multiple seeds:

```bash
python "python cyberrange_all_in_one.py" --scenario-compare --compare-seeds 5 --rounds 100 --compare-save outputs/comparison.png
```

**Row 1 — Attack scenario comparison** (all with GP + active probe):

- **Baseline (scripted)** — standard scripted red vs scripted blue
- **Aggressive attack** — fast exploitation, immediate IMPACT on PLC once compromised
- **Stealthy attack** — passive RECON/COVER until round 30, then slow methodical progression
- **No GP defense** — scripted red vs monitor-only blue, GP disabled entirely

**Row 2 — GP ablation study** (all with scripted red vs scripted blue):

- **GP + active probe (ours)** — full method with info-gain-based safe probing
- **GP + random probe** — GP enabled but probes are randomly selected (no info-gain)
- **GP passive (no probe)** — GP learns from observational data only, no interventional probes

Each panel shows mean ± std shading across seeds. Panels cover: empirical safety P(safe), alert accumulation, GP damage-risk prediction, intervention load, and compromised asset count.

## Real Modbus/PLC bridge mode

```bash
pip install pymodbus
python "python cyberrange_all_in_one.py" --real-modbus --modbus-host 127.0.0.1 --modbus-port 1502 --modbus-unit 1
```

Read external commands from holding registers:

- `201`: pump command (`0=AUTO, 1=FORCE_ON, 2=FORCE_OFF`)
- `202`: valve command (`0=AUTO, 1=FORCE_OPEN, 2=FORCE_CLOSED`)

Write simulator state to holding registers:

- `100`: tank level ×10 (uint16)
- `101`: current pump command code
- `102`: current valve command code
- `103`: sensor status (`0/1`)
- `104`: safety interlock (`0/1`)
- `105`: alarm flag (`0/1`)
- `106`: damage flag (`0/1`)

The bridge supports both pymodbus calling conventions (`slave=` and `unit=`) for compatibility across versions.

Reference register profile:

- `modbus/register_profile.sample.json`

## Testing

Regression tests (dense risk, active policy safety, benchmark schema, Modbus mappings):

```bash
pytest -q
```

Test file:

- `tests/test_cyberrange_regressions.py`
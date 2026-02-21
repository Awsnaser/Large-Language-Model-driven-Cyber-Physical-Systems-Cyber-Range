# 📁 Repository Structure

This document provides a comprehensive overview of the Advanced Cyber-Physical Range Simulator repository structure.

## 🏗️ Overview

The repository is organized into several key directories, each serving specific purposes in the CPS simulation ecosystem.

```
advanced-cyber-range-simulator/
├── 📄 Main Simulation Files
├── 🧠 Neural Network Components
├── 🐳 Docker Configuration
├── 🔍 Security & Monitoring
├── 📊 Visualization & UI
├── ⚙️ Configuration Files
├── 🧪 Testing & Benchmarking
├── 📚 Documentation
└── 🔧 Development Tools
```

## 📄 Main Simulation Files

### `python cyberrange_all_in_one.py`
**Main simulation script and entry point**
- **Purpose**: Primary simulation orchestrator
- **Size**: ~15,000 lines
- **Key Features**:
  - Multi-agent coordination
  - Docker container management
  - Neural network integration
  - Simulation loop control
  - Command-line interface
  - Metrics collection
  - Result export

### Core Classes and Functions
- `CPSRange`: Main simulation environment
- `LLMControlAgent`: LLM-based agent controller
- `GaussianProcessModel`: Multi-output GP for causal inference
- `DockerRunner`: Container orchestration
- `MetricsCollector`: Performance tracking

## 🧠 Neural Network Components

### `multi_agent_system.py`
**Multi-agent architecture and coordination**
- **Purpose**: Core multi-agent system implementation
- **Size**: ~10,000 lines
- **Key Components**:
  - `DeepDecisionNetwork`: Neural decision making
  - `AttentionModule`: Multi-head attention mechanisms
  - `MemoryNetwork`: Experience storage and retrieval
  - `NeuralLLMAgent`: Neural-enhanced LLM agent
  - `MultiAgentCoordinator`: Agent orchestration

### `neural_agent_integration.py`
**Neural network integration layer**
- **Purpose**: Bridge between neural networks and CPS simulation
- **Size**: ~8,000 lines
- **Key Components**:
  - `NeuralEnhancedSimulation`: Main integration class
  - `NeuralArchitectureFactory`: Architecture selection
  - `IntegrationUtils`: Helper functions
  - `PerformanceTracker`: Metrics collection

### `advanced_neural_architectures.py`
**Advanced neural network models**
- **Purpose**: Sophisticated neural architectures
- **Size**: ~12,000 lines
- **Key Architectures**:
  - `MultiAgentTransformer`: Coordination and reasoning
  - `GraphNeuralNetwork`: Topology analysis
  - `MemoryAugmentedAgent`: Long-term learning
  - `HierarchicalRLAgent`: Multi-level decision making
  - `EnsembleAgent`: Robust decision making
  - `NeuroevolutionAgent`: Evolutionary optimization

## 🐳 Docker Configuration

### `docker-compose.yml`
**Standard container setup (4 containers)**
- **Purpose**: Basic CPS infrastructure
- **Containers**:
  - `gw_dmz_01`: DMZ gateway
  - `hist_data_01`: Historian server
  - `hmi_ops_01`: HMI operations
  - `plc_industrial_01`: Industrial PLC

### `monitoring/docker-compose-closed.yml`
**Enhanced setup with full security stack (26 containers)**
- **Purpose**: Complete CPS environment with honeypots
- **Container Categories**:
  - **Core CPS** (4): Basic infrastructure
  - **Industrial Systems** (4): PLC, OPC UA, HMI, Historian
  - **IT Infrastructure** (5): Web, DB, DC, DNS, DHCP
  - **Honeypots** (6): PLC, OPC UA, Web, DB, SSH, FTP
  - **Security** (6): Router, Traffic Gen, IDS, SIEM, Suricata, Packet Capture

### `monitoring/laptop-optimization.yml`
**Lightweight setup for resource-constrained systems (16 containers)**
- **Purpose**: Optimized for laptop deployment
- **Features**:
  - Reduced resource requirements
  - Faster startup time
  - Essential functionality maintained

## 🔍 Security & Monitoring

### `suricata-monitor.py`
**Suricata IDS monitoring dashboard**
- **Purpose**: Real-time intrusion detection and alerting
- **Features**:
  - Live alert display
  - Attacker profiling
  - Threat intelligence
  - Automated reporting
  - JSON export

### `configs/suricata/`
**Suricata configuration directory**
```
configs/suricata/
├── suricata.yaml          # Main Suricata configuration
└── custom-cps.rules       # CPS-specific security rules
```

#### `suricata.yaml`
**Main Suricata configuration**
- **Network Configuration**: Interface settings, port groups
- **Logging**: EVE JSON, alerts, statistics
- **Performance**: Memory management, threading
- **Protocol Detection**: Modbus, OPC UA, DNP3, EtherNet/IP

#### `custom-cps.rules`
**CPS-specific security rules (20+ rules)**
- **Critical Alerts**: Modbus anomalies, data exfiltration
- **High Priority**: Unauthorized access, web attacks
- **Medium Priority**: Honeypot activity, lateral movement
- **Low Priority**: Reconnaissance, policy violations

## 📊 Visualization & UI

### `topology-viewer/`
**React-based topology visualization**
```
topology-viewer/
├── src/
│   ├── components/        # React components
│   ├── utils/            # Helper functions
│   └── App.js            # Main application
├── public/               # Static assets
├── package.json          # Node.js dependencies
└── README.md             # Viewer documentation
```

#### Key Features
- **Interactive Canvas**: 2D/3D topology visualization
- **Real-time Updates**: Live simulation status
- **Playback Controls**: Timeline navigation
- **Asset Details**: IP, services, status information
- **Attack Visualization**: Red/blue agent movements

## ⚙️ Configuration Files

### Main Configuration
- **`python cyberrange_all_in_one.py`**: Command-line arguments and settings
- **`configs/`**: Various configuration files
- **Environment variables**: Runtime configuration

### Docker Configuration
- **Network Settings**: IT/OT/DMZ segmentation
- **Volume Mounts**: Data persistence
- **Resource Limits**: CPU and memory constraints
- **Environment Variables**: Container configuration

### Neural Network Configuration
- **Architecture Selection**: Model type and parameters
- **Training Settings**: Learning rates, batch sizes
- **Agent Configuration**: Counts and behaviors
- **Performance Tuning**: Optimization parameters

## 🧪 Testing & Benchmarking

### `tests/`
**Test suite directory**
```
tests/
├── test_neural_system.py      # Neural network tests
├── test_suricata.py           # Suricata integration tests
├── test_docker_integration.py # Docker container tests
└── test_simulation_logic.py   # Simulation logic tests
```

### `benchmark/`
**Benchmark configuration and results**
```
benchmark/
├── benchmark_config.sample.json    # Benchmark configuration
├── benchmark_runs.csv              # Run results
├── benchmark_summary.csv           # Summary statistics
└── benchmark_summary.json          # Detailed results
```

### Test Scripts
- **`test-neural-system.py`**: Neural network verification
- **`test-suricata.py`**: Suricata integration testing
- **`test-enhanced-docker.py`**: Docker container verification

## 📚 Documentation

### Main Documentation
- **`README.md`**: Comprehensive project overview
- **`SETUP.md`**: Installation and configuration guide
- **`CONTRIBUTING.md`**: Development contribution guidelines
- **`CHANGELOG.md`**: Version history and changes
- **`LICENSE`**: MIT license with educational use notice

### Specialized Documentation
- **`SURICATA_INTEGRATION.md`**: Suricata IDS documentation
- **`NEURAL_SYSTEM_USAGE.md`**: Neural network usage guide
- **`REPOSITORY_STRUCTURE.md`**: This file

### API Documentation
- **Inline Documentation**: Function and class docstrings
- **Type Hints**: Parameter and return type annotations
- **Code Examples**: Usage examples in docstrings

## 🔧 Development Tools

### Installation Scripts
- **`install-neural-system.sh`**: Complete setup automation
- **`requirements.txt`**: Basic Python dependencies
- **`requirements-neural.txt`**: Neural network dependencies

### Utility Scripts
- **`run-enhanced-docker.py`**: Docker setup runner
- **`quick-docker-test.py`**: Quick verification script
- **`suricata-monitor.py`**: Security monitoring dashboard

### Configuration Files
- **`.gitignore`**: Git ignore patterns
- **`.dockerignore`**: Docker ignore patterns
- **`package.json`**: Node.js dependencies (topology viewer)

## 📦 File Sizes and Complexity

| File/Directory | Size (lines) | Purpose | Complexity |
|----------------|--------------|---------|------------|
| `python cyberrange_all_in_one.py` | ~15,000 | Main simulation | High |
| `advanced_neural_architectures.py` | ~12,000 | Neural models | High |
| `multi_agent_system.py` | ~10,000 | Multi-agent system | High |
| `neural_agent_integration.py` | ~8,000 | Integration layer | Medium |
| `suricata-monitor.py` | ~5,000 | Security monitoring | Medium |
| `topology-viewer/` | ~3,000 | Visualization | Medium |
| `configs/suricata/` | ~2,000 | Security config | Low |
| `tests/` | ~4,000 | Test suite | Medium |

## 🔗 Dependencies and Relationships

### Core Dependencies
```
python cyberrange_all_in_one.py
├── multi_agent_system.py (neural agents)
├── neural_agent_integration.py (integration)
├── advanced_neural_architectures.py (models)
├── suricata-monitor.py (security)
└── monitoring/docker-compose-closed.yml (infrastructure)
```

### Docker Dependencies
```
docker-compose-closed.yml
├── configs/suricata/suricata.yaml (IDS config)
├── configs/suricata/custom-cps.rules (security rules)
└── Various container images (Docker Hub)
```

### Neural Network Dependencies
```
advanced_neural_architectures.py
├── torch (core ML framework)
├── transformers (attention models)
├── torch-geometric (GNNs)
└── ray (distributed training)
```

## 🚀 Deployment Architecture

### Development Environment
```
Local Machine
├── Python 3.8+ (simulation)
├── Docker Desktop (containers)
├── Node.js (topology viewer)
└── Git (version control)
```

### Production Deployment
```
Production Server
├── Docker Swarm/Kubernetes (orchestration)
├── Prometheus + Grafana (monitoring)
├── Nginx (reverse proxy)
└── SSL/TLS (security)
```

## 📊 Usage Patterns

### Research Use
- **Academic Research**: Security studies and analysis
- **Industry Testing**: Security validation and training
- **Education**: Cybersecurity training and simulation

### Development Use
- **Feature Development**: New capabilities and enhancements
- **Testing**: Validation and verification
- **Documentation**: Guides and tutorials

### Operational Use
- **Security Training**: Red/blue team exercises
- **Compliance**: Security validation and reporting
- **Monitoring**: Continuous security assessment

---

This repository structure is designed to be:
- **Modular**: Clear separation of concerns
- **Scalable**: Easy to add new features
- **Maintainable**: Well-documented and tested
- **Accessible**: Multiple entry points and interfaces
- **Extensible**: Plugin architecture for customizations

For detailed information about any specific component, refer to the individual documentation files or inline code comments.

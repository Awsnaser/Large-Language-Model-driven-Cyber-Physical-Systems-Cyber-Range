# 🚀 Setup Guide

## Prerequisites

### System Requirements
- **Docker Desktop** (latest version)
- **Python 3.8+** 
- **8GB+ RAM** for enhanced setup
- **4GB+ RAM** for laptop setup
- **10GB+ Disk Space**

### Required Python Packages
```bash
pip install docker matplotlib numpy scipy scikit-learn faker prometheus-client
```

### Optional Neural Network Packages
```bash
pip install torch torchvision transformers ray[rllib] pettingzoo
```

## Quick Installation

### 1. Clone Repository
```bash
git clone <your-repo-url>
cd advanced-cyber-range-simulator
```

### 2. Install Dependencies
```bash
# Basic dependencies
pip install -r requirements.txt

# Neural network dependencies (optional)
pip install -r requirements-neural.txt

# Run installation script
chmod +x install-neural-system.sh
./install-neural-system.sh
```

### 3. Docker Setup
```bash
# Start Docker Desktop
docker --version
docker-compose --version
```

## Configuration Options

### Environment Variables
```bash
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
export CUDA_VISIBLE_DEVICES=0  # For GPU acceleration
```

### Docker Compose Files
- **Standard**: `docker-compose.yml` (4 containers)
- **Enhanced**: `monitoring/docker-compose-closed.yml` (26 containers)
- **Laptop**: `monitoring/laptop-optimization.yml` (16 containers)

## Running the Simulation

### Basic Simulation
```bash
python "python cyberrange_all_in_one.py" --scripted-agents --rounds 20
```

### Enhanced Infrastructure
```bash
python "python cyberrange_all_in_one.py" --enhanced-docker --scripted-agents --rounds 20
```

### Neural Multi-Agent System
```bash
python "python cyberrange_all_in_one.py" \
  --enhanced-docker \
  --multi-agent \
  --num-attackers 4 \
  --num-defenders 4 \
  --num-analysts 2 \
  --neural-arch transformer \
  --agent-coordination \
  --scripted-agents \
  --rounds 50
```

### Suricata Monitoring
```bash
# Start monitoring dashboard
python suricata-monitor.py

# Check Suricata status
docker ps --filter name=suricata
```

## Troubleshooting

### Common Issues

#### Docker Container Conflicts
```bash
# Clean up existing containers
docker-compose -f monitoring/docker-compose-closed.yml down --remove-orphans
docker system prune -f
```

#### Missing Dependencies
```bash
# Install missing packages
pip install docker matplotlib numpy scipy scikit-learn faker

# For neural networks
pip install torch torchvision
```

#### Permission Issues
```bash
# Docker permissions (Linux/Mac)
sudo usermod -aG docker $USER

# Restart Docker service
sudo systemctl restart docker
```

#### Port Conflicts
```bash
# Check port usage
netstat -tulpn | grep :3000
netstat -tulpn | grep :9090

# Kill conflicting processes
sudo kill -9 <PID>
```

### Performance Optimization

#### For Enhanced Setup (26 containers)
- **RAM**: 8GB+ recommended
- **CPU**: 4+ cores recommended
- **Disk**: 10GB+ free space

#### For Laptop Setup (16 containers)
- **RAM**: 4GB+ recommended  
- **CPU**: 2+ cores recommended
- **Disk**: 5GB+ free space

#### GPU Acceleration (Neural Networks)
```bash
# Check CUDA availability
python -c "import torch; print(f'CUDA available: {torch.cuda.is_available()}')"

# Install CUDA PyTorch (if available)
pip install torch torchvision --index-url https://download.pytorch.org/whl/cu118
```

## Verification

### Test Basic Setup
```bash
python test-enhanced-docker.py
```

### Test Neural Integration
```bash
python test-neural-system.py
```

### Test Suricata Integration
```bash
python test-suricata.py
```

## Configuration Files

### Main Configuration
- **`python cyberrange_all_in_one.py`**: Main simulation script
- **`configs/suricata/suricata.yaml`**: Suricata IDS configuration
- **`configs/suricata/custom-cps.rules`**: CPS-specific security rules

### Docker Configuration
- **`docker-compose.yml`**: Standard container setup
- **`monitoring/docker-compose-closed.yml`**: Enhanced setup with honeypots
- **`monitoring/laptop-optimization.yml`**: Lightweight laptop setup

### Neural Network Configuration
- **`multi_agent_system.py`**: Multi-agent architecture
- **`neural_agent_integration.py`**: Neural integration layer
- **`advanced_neural_architectures.py`**: Advanced neural models

## Monitoring and Logs

### Container Logs
```bash
# View all container logs
docker-compose logs

# View specific container logs
docker logs cps-suricata-ids
docker logs cps-plc-01
```

### System Monitoring
- **Grafana**: http://localhost:3000
- **Prometheus**: http://localhost:9090
- **Suricata Dashboard**: Run `python suricata-monitor.py`

### Export Data
```bash
# Export simulation data
python "python cyberrange_all_in_one.py" --export-dataset outputs/data

# Export PCAP files
python "python cyberrange_all_in_one.py" --pcap outputs/capture.pcap
```

## Support

### Documentation
- **`README.md`**: Complete project overview
- **`SURICATA_INTEGRATION.md`**: Suricata IDS documentation
- **`NEURAL_SYSTEM_USAGE.md`**: Neural network usage guide

### Issues and Help
1. Check Docker Desktop is running
2. Verify all dependencies are installed
3. Check system resources (RAM/CPU)
4. Review container logs for errors
5. Run verification tests

### Community
- **Issues**: Report bugs via GitHub Issues
- **Discussions**: Use GitHub Discussions for questions
- **Contributions**: Pull requests welcome

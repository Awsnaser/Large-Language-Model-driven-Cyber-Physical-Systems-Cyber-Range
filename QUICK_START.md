# 🚀 Quick Start Guide

Get the Advanced Cyber-Physical Range Simulator running in minutes!

## ⚡ 5-Minute Quick Start

### 1. Prerequisites
```bash
# Check Python version (3.8+ required)
python --version

# Check Docker installation
docker --version
docker-compose --version
```

### 2. Install Dependencies
```bash
# Basic dependencies
pip install docker matplotlib numpy scipy scikit-learn faker prometheus-client

# Clone and navigate to project
git clone <your-repo-url>
cd advanced-cyber-range-simulator
```

### 3. Run Basic Simulation
```bash
# Quick test with standard setup
python "python cyberrange_all_in_one.py" --scripted-agents --rounds 5
```

### 4. Run Enhanced Setup
```bash
# Full CPS environment with all containers
python "python cyberrange_all_in_one.py" --enhanced-docker --scripted-agents --rounds 10
```

### 5. Start Security Monitoring
```bash
# In a new terminal, start Suricata monitoring
python suricata-monitor.py
```

## 🎯 Success Indicators

You should see:
- ✅ Container startup messages
- ✅ Round-by-round simulation progress
- ✅ Red vs Blue agent actions
- ✅ Physical process updates (tank level, alarms)
- ✅ Final summary with statistics

## 🐳 Docker Setup Options

### Option 1: Standard (4 containers)
```bash
python "python cyberrange_all_in_one.py" --scripted-agents --rounds 20
```
**Best for**: Quick testing, development, learning

### Option 2: Enhanced (26 containers)
```bash
python "python cyberrange_all_in_one.py" --enhanced-docker --scripted-agents --rounds 20
```
**Best for**: Full research, security testing, realistic simulation

### Option 3: Laptop (16 containers)
```bash
python "python cyberrange_all_in_one.py" --laptop-docker --scripted-agents --rounds 20
```
**Best for**: Resource-constrained systems, laptops

## 🧠 Neural Multi-Agent System

### Basic Neural Setup
```bash
python "python cyberrange_all_in_one.py" \
  --enhanced-docker \
  --multi-agent \
  --scripted-agents \
  --rounds 20
```

### Advanced Neural Configuration
```bash
python "python cyberrange_all_in_one.py" \
  --enhanced-docker \
  --multi-agent \
  --num-attackers 4 \
  --num-defenders 4 \
  --num-analysts 2 \
  --neural-arch transformer \
  --agent-coordination \
  --neural-training \
  --scripted-agents \
  --rounds 50
```

## 🔍 Security Monitoring

### Start Suricata Dashboard
```bash
python suricata-monitor.py
```

### Check Container Status
```bash
# List running containers
docker ps --filter name=cps-

# View Suricata logs
docker logs cps-suricata-ids

# Check network traffic
docker exec cps-suricata-ids tail -f /var/log/suricata/eve.json
```

## 📊 Monitoring Stack

### Start Grafana + Prometheus
```bash
python "python cyberrange_all_in_one.py" --metrics --monitoring-up
```

### Access Dashboards
- **Grafana**: http://localhost:3000 (admin/admin)
- **Prometheus**: http://localhost:9090
- **Suricata Monitor**: Run `python suricata-monitor.py`

## 🎮 Interactive Features

### Interactive Terminal UI
```bash
python "python cyberrange_all_in_one.py" \
  --interactive-startup \
  --live-round-ui \
  --color-ui \
  --scripted-agents \
  --rounds 20
```

### Visualization Options
```bash
# Generate plots and animations
python "python cyberrange_all_in_one.py" \
  --separate-plots \
  --save-plot outputs/simulation.png \
  --scripted-agents \
  --rounds 50
```

### React Topology Viewer
```bash
cd topology-viewer
npm install
npm start
# Then open http://localhost:3000
```

## 🧪 Testing and Verification

### Quick System Test
```bash
python test-enhanced-docker.py
```

### Neural Network Test
```bash
python test-neural-system.py
```

### Suricata Integration Test
```bash
python test-suricata.py
```

## 🔧 Common Issues & Solutions

### Docker Issues
```bash
# Clean up containers
docker-compose -f monitoring/docker-compose-closed.yml down --remove-orphans
docker system prune -f

# Restart Docker Desktop
# (Restart Docker Desktop application)
```

### Python Dependencies
```bash
# Install missing packages
pip install docker matplotlib numpy scipy scikit-learn faker

# For neural networks
pip install torch torchvision transformers
```

### Port Conflicts
```bash
# Check port usage
netstat -tulpn | grep :3000
netstat -tulpn | grep :9090

# Kill conflicting processes
sudo kill -9 <PID>
```

### Permission Issues (Linux/Mac)
```bash
# Add user to docker group
sudo usermod -aG docker $USER
# Then log out and log back in
```

## 📈 Performance Tips

### For Enhanced Setup (26 containers)
- **RAM**: 8GB+ recommended
- **CPU**: 4+ cores recommended
- **Disk**: 10GB+ free space

### For Laptop Setup (16 containers)
- **RAM**: 4GB+ recommended
- **CPU**: 2+ cores recommended
- **Disk**: 5GB+ free space

### GPU Acceleration (Neural Networks)
```bash
# Check CUDA availability
python -c "import torch; print(f'CUDA: {torch.cuda.is_available()}')"

# Install CUDA PyTorch (if available)
pip install torch torchvision --index-url https://download.pytorch.org/whl/cu118
```

## 🎯 Example Workflows

### Research Workflow
```bash
# 1. Start enhanced environment
python "python cyberrange_all_in_one.py" --enhanced-docker --scripted-agents --rounds 50

# 2. Start monitoring
python suricata-monitor.py

# 3. Analyze results
python "python cyberrange_all_in_one.py" --export-dataset research_data
```

### Development Workflow
```bash
# 1. Quick test
python "python cyberrange_all_in_one.py" --scripted-agents --rounds 5

# 2. Run tests
python test-neural-system.py

# 3. Start visualization
cd topology-viewer && npm start
```

### Training Workflow
```bash
# 1. Neural multi-agent training
python "python cyberrange_all_in_one.py" \
  --enhanced-docker \
  --multi-agent \
  --neural-training \
  --save-neural-models models/trained_agents.pt \
  --rounds 100

# 2. Evaluate performance
python "python cyberrange_all_in_one.py" \
  --enhanced-docker \
  --multi-agent \
  --scripted-agents \
  --rounds 50
```

## 📚 Next Steps

### Learn More
- **README.md**: Complete project overview
- **SETUP.md**: Detailed installation guide
- **CONTRIBUTING.md**: Development guidelines
- **SURICATA_INTEGRATION.md**: Security monitoring

### Advanced Features
- **Benchmark Mode**: Performance evaluation
- **Large Infrastructure**: 300+ IP simulation
- **Custom Agents**: Develop your own agents
- **Integration**: Connect to external systems

### Community
- **GitHub Issues**: Report bugs and request features
- **GitHub Discussions**: Ask questions and share ideas
- **Contributing**: Submit pull requests and improvements

## 🎉 You're Ready!

You now have:
- ✅ Working CPS simulation environment
- ✅ Docker containers with network isolation
- ✅ Neural multi-agent system (optional)
- ✅ Suricata security monitoring
- ✅ Real-time visualization and monitoring
- ✅ Comprehensive testing and verification

## 🆘 Need Help?

1. **Check the logs**: Look for error messages in terminal output
2. **Verify prerequisites**: Ensure Docker and Python are properly installed
3. **Check resources**: Verify sufficient RAM and disk space
4. **Run tests**: Use the test scripts to verify installation
5. **Consult documentation**: Read detailed guides and API docs
6. **Ask the community**: Use GitHub Discussions for help

---

**Happy simulating! 🎯**

For more detailed information, see the complete documentation in the repository.

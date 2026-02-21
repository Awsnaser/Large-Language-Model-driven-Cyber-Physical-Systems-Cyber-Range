# 🔒 CPS Simulation Security Controls

## Network Isolation
- **Closed Environment**: All services run in isolated Docker networks
- **No External Access**: Only localhost access to monitoring ports
- **Network Segmentation**: IT, DMZ, and OT zones are properly separated
- **Firewall Rules**: Block external connections to critical services

## Honeypot Security
- **6 Honeypot Types**: Web, PLC, OPC UA, SSH, FTP, Database
- **Vulnerable by Design**: Intentionally weak for attack simulation
- **Activity Logging**: All honeypot interactions are captured
- **Safe Isolation**: Honeypots cannot access production systems

## Data Protection
- **Local Storage Only**: No data leaves the laptop
- **Encrypted Volumes**: Sensitive data stored in encrypted Docker volumes
- **Log Rotation**: Automatic cleanup of old logs and captures
- **Privacy Compliant**: No personal or production data involved

## Resource Management
- **Memory Limits**: Each container has memory constraints
- **CPU Limits**: Prevents system overload
- **Graceful Shutdown**: Clean container termination
- **Health Checks**: Automatic service monitoring

## Access Control
- **Localhost Only**: Critical services only accessible from localhost
- **Authentication**: Default credentials for research (changeable)
- **No Remote Access**: SSH and management ports blocked externally
- **Container Isolation**: Each service runs in isolated containers

## Monitoring Security
- **Internal Monitoring**: Grafana/Prometheus only accessible locally
- **Audit Logs**: All activities logged for analysis
- **Packet Capture**: Network traffic captured for research
- **IDS Integration**: Intrusion detection for honeypot activities

## Laptop Safety Features
- **Resource Optimization**: Lightweight configurations for laptop use
- **Battery Friendly**: Minimal CPU usage when idle
- **Thermal Management**: Prevents overheating
- **Storage Management**: Automatic cleanup of large files

## 🚀 Quick Start Commands

### Start Lightweight Version (Recommended for Laptop)
```bash
# Start optimized environment
docker-compose -f monitoring/laptop-optimization.yml up -d

# Check resource usage
docker stats

# Stop environment
docker-compose -f monitoring/laptop-optimization.yml down
```

### Start Full Version (If Resources Available)
```bash
# Start full environment
docker-compose -f monitoring/docker-compose-closed.yml up -d

# Monitor resources
docker-compose -f monitoring/docker-compose-closed.yml top

# Stop environment
docker-compose -f monitoring/docker-compose-closed.yml down
```

## 📊 Resource Requirements

### Lightweight Version (Laptop)
- **Memory**: ~2GB RAM
- **CPU**: 2 cores
- **Storage**: ~5GB
- **Network**: Local only

### Full Version (High-Performance)
- **Memory**: ~8GB RAM
- **CPU**: 4+ cores
- **Storage**: ~20GB
- **Network**: Local only

## 🔍 Verification Commands

### Check Network Isolation
```bash
# Verify only localhost access
curl -I http://localhost:3000  # Should work
curl -I http://$(hostname):3000  # Should fail

# Check network segmentation
docker network ls
docker network inspect monitoring_it_network
```

### Check Honeypot Activity
```bash
# View honeypot logs
docker logs cps-honeypot-web-lite
docker logs cps-honeypot-plc-lite

# Check packet captures
ls -la pcaps/
tcpdump -r pcaps/capture_*.pcap -nn
```

### Monitor Resource Usage
```bash
# Real-time resource monitoring
docker stats --no-stream

# System resource check
htop
df -h
```

## 🛡️ Security Best Practices

1. **Never expose ports externally** - keep everything localhost-only
2. **Change default passwords** - update Grafana/admin credentials
3. **Monitor resource usage** - ensure laptop doesn't overheat
4. **Regular cleanup** - remove old logs and captures
5. **Update containers** - keep Docker images updated
6. **Network monitoring** - watch for unexpected traffic patterns

## 🚨 Emergency Shutdown

```bash
# Immediate stop all containers
docker-compose -f monitoring/laptop-optimization.yml down
docker-compose -f monitoring/docker-compose-closed.yml down

# Clean up all resources
docker system prune -f
docker volume prune -f

# Kill any remaining processes
sudo pkill -f docker
```

## 📝 Research Notes

- This environment is **100% isolated** and safe for laptop use
- All network traffic is **contained within Docker networks**
- Honeypots are **designed to be attacked** safely
- No **real production systems** are at risk
- Perfect for **academic research** and **security training**
- **Comprehensive logging** for analysis and learning

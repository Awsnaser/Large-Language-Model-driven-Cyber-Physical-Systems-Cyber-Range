# Suricata Blue Team Defender Integration

## Overview
Added **Suricata IDS** as an advanced **Blue Team Defender** to the CPS simulation environment, providing real-time intrusion detection and network security monitoring.

## Components Added

### 1. Docker Integration
- **Enhanced Setup**: `cps-suricata-ids` container in `docker-compose-closed.yml`
- **Laptop Setup**: `cps-suricata-lite` container in `laptop-optimization.yml`
- **Host Network Mode**: Full network visibility across all interfaces
- **Privileged Access**: Required for packet inspection

### 2. Configuration Files
- **`configs/suricata/suricata.yaml`**: Main Suricata configuration
  - CPS-specific port groups (Modbus, OPC UA, SSH honeypots)
  - App-layer protocol detection
  - EVE JSON logging for structured alerts
  - Performance tuning for container environment

- **`configs/suricata/custom-cps.rules`**: CPS-specific security rules
  - Suspicious Modbus traffic detection
  - OPC UA unauthorized connection alerts
  - SSH brute force attack detection
  - Web application attack patterns
  - Honeypot access monitoring
  - Data exfiltration detection
  - Lateral movement indicators

### 3. Python Integration
- **Enhanced Containers**: 24 containers (including Suricata)
- **Laptop Containers**: 16 containers (including Suricata)
- **IP Assignment**: `172.16.0.29` (enhanced), `172.16.0.34` (laptop)
- **Port Configuration**: HTTP 8089, SSH 2234/2241

### 4. Monitoring Dashboard
- **`suricata-monitor.py`**: Real-time monitoring application
  - Live alert display with severity indicators
  - Top attacker identification
  - Targeted asset summary
  - CPS-specific alert filtering
  - Automated report generation
  - JSON-based security reports

## Security Rules Included

### Critical Alerts
- **Modbus Anomalies**: Function code anomalies, programming changes
- **Data Exfiltration**: Large transfers from OT network
- **Ransomware Activity**: Pattern-based detection

### High Priority Alerts
- **Unauthorized Access**: OPC UA connections, SSH brute force
- **Web Attacks**: SQL injection, suspicious user agents
- **Network Discovery**: ICMP scanning, DNS tunneling

### Medium Priority Alerts
- **Honeypot Activity**: Access attempts, credential stuffing
- **Protocol Anomalies**: SCADA protocol issues
- **Lateral Movement**: SSH connections between assets

### Low Priority Alerts
- **Reconnaissance**: Port scanning, service discovery
- **Policy Violations**: TLS certificate issues

## Usage Commands

### Start Enhanced CPS with Suricata
```bash
python "python cyberrange_all_in_one.py" --enhanced-docker --scripted-agents --rounds 20
```

### Start Laptop-Optimized with Suricata
```bash
python "python cyberrange_all_in_one.py" --laptop-docker --scripted-agents --rounds 20
```

### Start Suricata Monitoring Dashboard
```bash
python suricata-monitor.py
```

### Check Suricata Status
```bash
docker ps --filter name=suricata
docker logs cps-suricata-ids
```

### View Real-time Alerts
```bash
docker exec cps-suricata-ids tail -f /var/log/suricata/eve.json
```

## Integration Features

### Network Visibility
- **Host Network Mode**: Monitors all network interfaces
- **Protocol Detection**: Modbus, OPC UA, DNP3, EtherNet/IP
- **Honeypot Monitoring**: All honeypot traffic analysis
- **Cross-Network Detection**: IT/OT network boundary monitoring

### Alert Correlation
- **EVE JSON Format**: Structured alert data
- **Timestamp Correlation**: Event timeline analysis
- **Source/Destination Tracking**: Attack path mapping
- **Severity Classification**: Priority-based alerting

### Performance Optimization
- **Resource Limits**: 512MB memory, 0.5 CPU (laptop)
- **Threshold Rules**: Rate limiting for alert storms
- **Log Rotation**: Automatic log management
- **Efficient Rulesets**: Optimized for CPS environment

## Blue Team Defender Capabilities

### Real-time Detection
- **Immediate Alerting**: Sub-second detection
- **Pattern Matching**: Advanced signature detection
- **Behavioral Analysis**: Anomaly detection rules
- **Protocol Analysis**: Deep packet inspection

### Threat Intelligence
- **Attacker Profiling**: IP-based tracking
- **Attack Pattern Recognition**: TTP identification
- **Asset Targeting**: Critical asset protection
- **Trend Analysis**: Attack trend monitoring

### Incident Response
- **Alert Prioritization**: Severity-based response
- **Automated Reporting**: JSON-based reports
- **Integration Ready**: SIEM integration capability
- **Forensic Data**: PCAP correlation

## Container Specifications

### Enhanced Suricata Container
- **Image**: `jasonish/suricata:latest`
- **Resources**: Unlimited (production)
- **Features**: Full rule set, automatic updates
- **Storage**: Dedicated log volume

### Laptop Suricata Container
- **Image**: `jasonish/suricata:latest`
- **Resources**: 512MB memory, 0.5 CPU
- **Features**: Optimized rule set, basic logging
- **Storage**: Shared log volume

## Monitoring Dashboard Features

### Real-time Display
- **Alert Stream**: Live alert feed
- **Severity Indicators**: Visual priority markers
- **Statistics**: Alert count by severity
- **Recent History**: Last 10 alerts

### Analysis Tools
- **Top Attackers**: Most active source IPs
- **Target Summary**: Most targeted assets
- **CPS Alerts**: Industrial system specific alerts
- **Trend Analysis**: Time-based patterns

### Reporting
- **JSON Reports**: Structured data export
- **Statistics Summary**: Comprehensive metrics
- **Alert History**: Complete alert log
- **Performance Data**: System performance metrics

## Benefits for CPS Security

### Enhanced Visibility
- **Network-wide Monitoring**: Complete traffic visibility
- **Protocol Awareness**: Industrial protocol understanding
- **Honeypot Integration**: Decoy system monitoring
- **Cross-segment Analysis**: IT/OT boundary protection

### Proactive Defense
- **Early Detection**: Attack identification before impact
- **Pattern Recognition**: Known attack pattern detection
- **Anomaly Detection**: Unusual behavior identification
- **Threat Intelligence**: Attacker behavior analysis

### Compliance Support
- **Audit Trail**: Complete security event logging
- **Incident Documentation**: Detailed alert records
- **Performance Metrics**: System effectiveness data
- **Reporting Capability**: Automated report generation

## Troubleshooting

### Common Issues
1. **Container Not Starting**: Check Docker permissions
2. **No Alerts Generated**: Verify network traffic
3. **High Resource Usage**: Adjust resource limits
4. **Missing Logs**: Check volume mounts

### Debug Commands
```bash
# Check container status
docker ps --filter name=suricata

# View logs
docker logs cps-suricata-ids

# Check configuration
docker exec cps-suricata-ids suricata -T

# Test rule syntax
docker exec cps-suricata-ids suricatasc -c /etc/suricata/suricata.yaml
```

## Future Enhancements

### Planned Features
- **Machine Learning Integration**: Anomaly detection models
- **Threat Feeds**: External intelligence integration
- **Automated Response**: Active defense capabilities
- **Advanced Analytics**: Behavioral analysis tools

### Integration Opportunities
- **Neural Agent Coordination**: AI-driven response
- **Multi-agent Learning**: Shared threat intelligence
- **Automated Mitigation**: Dynamic defense adaptation
- **Predictive Analytics**: Attack prediction models

## Summary

The Suricata Blue Team Defender integration provides:
- **24/7 Network Monitoring**: Continuous security surveillance
- **CPS-Specific Protection**: Industrial protocol security
- **Real-time Alerting**: Immediate threat notification
- **Comprehensive Reporting**: Detailed security analytics
- **Scalable Architecture**: Adaptable to different environments

This creates a **complete blue team defense capability** for the CPS simulation environment, enabling realistic cybersecurity training and research scenarios.

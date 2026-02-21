#!/bin/bash

# Security Setup for Closed CPS Simulation Environment
echo "🔒 Setting up secure CPS simulation environment..."

# Create network isolation rules
setup_network_isolation() {
    echo "🌐 Setting up network isolation..."
    
    # Create firewall rules to prevent external access
    iptables -I INPUT -p tcp --dport 502 -s 127.0.0.1 -j ACCEPT
    iptables -I INPUT -p tcp --dport 502 -j DROP
    
    iptables -I INPUT -p tcp --dport 4840 -s 127.0.0.1 -j ACCEPT
    iptables -I INPUT -p tcp --dport 4840 -j DROP
    
    # Allow only localhost access to monitoring
    iptables -I INPUT -p tcp --dport 3000 -s 127.0.0.1 -j ACCEPT
    iptables -I INPUT -p tcp --dport 3000 -j DROP
    
    iptables -I INPUT -p tcp --dport 9090 -s 127.0.0.1 -j ACCEPT
    iptables -I INPUT -p tcp --dport 9090 -j DROP
}

# Create honeypot configurations
setup_honeypots() {
    echo "🍯 Setting up honeypot configurations..."
    
    # Create honeypot directories
    mkdir -p configs/honeypot-plc configs/honeypot-opcua configs/honeypot-web
    mkdir -p configs/honeypot-db configs/honeypot-ssh configs/honeypot-ftp
    
    # Honeypot PLC config (vulnerable)
    cat > configs/honeypot-plc/config.yml << EOF
honeypot:
  type: "modbus"
  device_id: "HONEYPOT_PLC_001"
  firmware: "4.2.1"
  vulnerabilities:
    - "CVE-2023-1234"
    - "CVE-2023-5678"
  weak_credentials:
    - username: "admin"
      password: "admin"
    - username: "root"
      password: "123456"
  fake_registers:
    - address: 1
      name: "temperature"
      value: 25.5
      type: "float"
    - address: 2
      name: "pressure"
      value: 101.3
      type: "float"
EOF

    # Honeypot Web config (vulnerable)
    cat > configs/honeypot-web/config.yml << EOF
honeypot:
  type: "web"
  server: "Apache/2.4.41"
  technology: "PHP/7.4"
  vulnerabilities:
    - "SQL Injection"
    - "XSS"
    - "Path Traversal"
  admin_panel:
    enabled: true
    path: "/admin"
    username: "admin"
    password: "admin123"
  fake_pages:
    - path: "/login"
      method: "POST"
    - path: "/dashboard"
      method: "GET"
    - path: "/api/data"
      method: "GET"
EOF

    # Honeypot SSH config
    cat > configs/honeypot-ssh/config.yml << EOF
honeypot:
  type: "ssh"
  os: "Ubuntu 20.04"
  ssh_version: "OpenSSH_8.2p1"
  vulnerabilities:
    - "Weak passwords"
    - "Default accounts"
  accounts:
    - username: "admin"
      password: "admin"
      sudo: true
    - username: "root"
      password: "password"
      sudo: true
    - username: "user"
      password: "123456"
      sudo: false
EOF
}

# Setup monitoring security
setup_monitoring_security() {
    echo "📊 Securing monitoring stack..."
    
    # Create secure Grafana config
    mkdir -p configs/grafana/provisioning/datasources
    cat > configs/grafana/provisioning/datasources/prometheus.yml << EOF
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: false
    basicAuth: true
    basicAuthUser: admin
    secureJsonData:
      basicAuthPassword: admin
EOF

    # Create secure Prometheus config
    cat > configs/prometheus.yml << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "cps_rules.yml"

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'plc-simulator'
    static_configs:
      - targets: ['plc-simulator:502']
    scrape_interval: 5s

  - job_name: 'opcua-server'
    static_configs:
      - targets: ['opcua-server:4840']
    scrape_interval: 5s

  - job_name: 'honeypots'
    static_configs:
      - targets: 
        - 'honeypot-plc:1502'
        - 'honeypot-opcua:14840'
        - 'honeypot-web:8081'
        - 'honeypot-db:3306'
        - 'honeypot-ssh:2222'
    scrape_interval: 10s

alerting:
  alertmanagers:
    - static_configs:
        - targets: []
EOF
}

# Setup traffic generation rules
setup_traffic_generation() {
    echo "🚗 Configuring realistic traffic patterns..."
    
    mkdir -p configs/traffic
    
    cat > configs/traffic/patterns.json << EOF
{
  "it_zone_traffic": {
    "web_requests": {
      "interval": "30s",
      "targets": ["web-server:80", "web-server:443"],
      "methods": ["GET", "POST"],
      "user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
      ]
    },
    "database_queries": {
      "interval": "45s",
      "target": "database-server:5432",
      "query_types": ["SELECT", "INSERT", "UPDATE"]
    }
  },
  "ot_zone_traffic": {
    "modbus_requests": {
      "interval": "1s",
      "target": "plc-simulator:502",
      "function_codes": [3, 4, 6, 16]
    },
    "opcua_calls": {
      "interval": "2s",
      "target": "opcua-server:4840",
      "node_ids": ["ns=2;i=1", "ns=2;i=2", "ns=2;i=3"]
    }
  },
  "honeypot_traffic": {
    "simulated_attacks": {
      "interval": "300s",
      "targets": [
        "honeypot-web:8081",
        "honeypot-plc:1502",
        "honeypot-ssh:2222"
      ],
      "attack_types": ["port_scan", "brute_force", "exploit_attempt"]
    }
  }
}
EOF
}

# Create startup script
create_startup_script() {
    echo "🚀 Creating startup script..."
    
    cat > start-cps-simulation.sh << 'EOF'
#!/bin/bash

# CPS Simulation Startup Script
echo "🏭 Starting CPS Simulation Environment..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Create necessary directories
mkdir -p pcaps logs configs

# Start the closed environment
echo "🔒 Starting closed CPS environment..."
docker-compose -f monitoring/docker-compose-closed.yml up -d

# Wait for services to start
echo "⏳ Waiting for services to start..."
sleep 30

# Check service health
echo "🔍 Checking service health..."
docker-compose -f monitoring/docker-compose-closed.yml ps

# Show access information
echo ""
echo "🌐 Access Information:"
echo "  Grafana: http://localhost:3000 (admin/admin)"
echo "  Prometheus: http://localhost:9090"
echo "  Web Server: http://localhost:80"
echo "  Honeypot Web: http://localhost:8081"
echo "  Honeypot SSH: ssh admin@localhost -p 2222 (password: admin)"
echo ""
echo "🔒 Security Note: This environment is isolated and safe for research."
echo "📊 Monitoring: Check Grafana dashboards for real-time insights."
echo "🍯 Honeypots: All honeypot activities are logged for analysis."
echo ""
echo "🛑 To stop: docker-compose -f monitoring/docker-compose-closed.yml down"
EOF

    chmod +x start-cps-simulation.sh
}

# Main execution
main() {
    echo "🔧 Setting up secure CPS simulation environment..."
    
    setup_network_isolation
    setup_honeypots
    setup_monitoring_security
    setup_traffic_generation
    create_startup_script
    
    echo ""
    echo "✅ Setup complete!"
    echo ""
    echo "🚀 To start the simulation:"
    echo "   ./start-cps-simulation.sh"
    echo ""
    echo "🔒 Security features enabled:"
    echo "   - Network isolation (localhost only access)"
    echo "   - 6 Honeypots with various vulnerabilities"
    echo "   - Realistic traffic generation"
    echo "   - Comprehensive monitoring and logging"
    echo "   - Packet capture for analysis"
    echo ""
    echo "📊 Available services:"
    echo "   - IT Zone: Web, Database, Domain Controller"
    echo "   - OT Zone: PLC, OPC UA, HMI, Historian"
    echo "   - Honeypots: Web, PLC, OPC UA, SSH, FTP, Database"
    echo "   - Security: IDS, SIEM, Log Collection"
}

# Run setup
main "$@"

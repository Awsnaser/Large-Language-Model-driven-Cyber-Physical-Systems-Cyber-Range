#!/usr/bin/env python3
"""
Suricata Blue Team Defender Monitoring Dashboard
Real-time intrusion detection and alerting for CPS environment
"""

import json
import time
import subprocess
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any
import threading

class SuricataMonitor:
    """Suricata monitoring and alerting system"""
    
    def __init__(self, log_path: str = "./configs/suricata/logs"):
        self.log_path = log_path
        self.eve_log_path = os.path.join(log_path, "eve.json")
        self.alerts = []
        self.stats = {
            "total_alerts": 0,
            "critical_alerts": 0,
            "high_alerts": 0,
            "medium_alerts": 0,
            "low_alerts": 0
        }
        self.running = False
        self.monitor_thread = None
        
    def start_monitoring(self):
        """Start real-time monitoring"""
        print("🛡️  Starting Suricata Blue Team Defender Monitoring")
        print("=" * 60)
        
        if not os.path.exists(self.eve_log_path):
            print(f"⚠️  Eve log not found at {self.eve_log_path}")
            print("   Make sure Suricata is running and generating logs")
            return False
            
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        return True
        
    def _monitor_loop(self):
        """Main monitoring loop"""
        print("📡 Monitoring Suricata alerts in real-time...")
        print("   Press Ctrl+C to stop monitoring")
        
        try:
            with open(self.eve_log_path, 'r') as f:
                # Go to end of file
                f.seek(0, 2)
                
                while self.running:
                    line = f.readline()
                    if line:
                        try:
                            alert = json.loads(line.strip())
                            if alert.get("event_type") == "alert":
                                self._process_alert(alert)
                        except json.JSONDecodeError:
                            continue
                    else:
                        time.sleep(0.1)
                        
        except FileNotFoundError:
            print(f"❌ Cannot find eve log: {self.eve_log_path}")
        except KeyboardInterrupt:
            print("\n🛑 Monitoring stopped by user")
        except Exception as e:
            print(f"❌ Monitoring error: {e}")
            
    def _process_alert(self, alert: Dict[str, Any]):
        """Process individual alert"""
        timestamp = alert.get("timestamp", "")
        src_ip = alert.get("src_ip", "unknown")
        dst_ip = alert.get("dest_ip", "unknown")
        signature = alert.get("alert", {}).get("signature", "Unknown alert")
        severity = alert.get("alert", {}).get("severity", "low")
        category = alert.get("alert", {}).get("category", "unknown")
        
        # Update statistics
        self.stats["total_alerts"] += 1
        if severity == "critical":
            self.stats["critical_alerts"] += 1
        elif severity == "high":
            self.stats["high_alerts"] += 1
        elif severity == "medium":
            self.stats["medium_alerts"] += 1
        else:
            self.stats["low_alerts"] += 1
            
        # Store alert
        alert_data = {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "signature": signature,
            "severity": severity,
            "category": category
        }
        
        self.alerts.append(alert_data)
        
        # Display alert
        self._display_alert(alert_data)
        
    def _display_alert(self, alert: Dict[str, Any]):
        """Display alert with appropriate formatting"""
        severity_icons = {
            "critical": "🚨",
            "high": "⚠️",
            "medium": "🔶",
            "low": "ℹ️"
        }
        
        icon = severity_icons.get(alert["severity"], "ℹ️")
        
        print(f"{icon} [{alert['timestamp'].split('T')[1][:8]}] "
              f"{alert['signature']} "
              f"({alert['severity'].upper()}) "
              f"{alert['src_ip']} → {alert['dst_ip']}")
              
    def get_recent_alerts(self, minutes: int = 5) -> List[Dict[str, Any]]:
        """Get alerts from last N minutes"""
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        recent = []
        
        for alert in self.alerts:
            try:
                alert_time = datetime.fromisoformat(alert["timestamp"].replace('Z', '+00:00'))
                if alert_time >= cutoff_time:
                    recent.append(alert)
            except:
                continue
                
        return recent
        
    def get_top_attackers(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top attacking IPs"""
        attacker_counts = {}
        
        for alert in self.alerts:
            src_ip = alert["src_ip"]
            if src_ip not in attacker_counts:
                attacker_counts[src_ip] = {
                    "ip": src_ip,
                    "count": 0,
                    "signatures": set()
                }
            attacker_counts[src_ip]["count"] += 1
            attacker_counts[src_ip]["signatures"].add(alert["signature"])
            
        # Sort by count
        sorted_attackers = sorted(
            attacker_counts.values(),
            key=lambda x: x["count"],
            reverse=True
        )
        
        # Convert sets to lists for JSON serialization
        for attacker in sorted_attackers:
            attacker["signatures"] = list(attacker["signatures"])
            
        return sorted_attackers[:limit]
        
    def get_target_summary(self) -> Dict[str, Any]:
        """Get summary of targeted assets"""
        targets = {}
        
        for alert in self.alerts:
            dst_ip = alert["dst_ip"]
            if dst_ip not in targets:
                targets[dst_ip] = {
                    "ip": dst_ip,
                    "alert_count": 0,
                    "categories": set()
                }
            targets[dst_ip]["alert_count"] += 1
            targets[dst_ip]["categories"].add(alert["category"])
            
        # Convert sets to lists
        for target in targets.values():
            target["categories"] = list(target["categories"])
            
        return targets
        
    def stop_monitoring(self):
        """Stop monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1)
            
    def generate_report(self, output_file: str = "suricata_report.json"):
        """Generate comprehensive security report"""
        report = {
            "generated_at": datetime.now().isoformat(),
            "monitoring_period": {
                "start": self.alerts[0]["timestamp"] if self.alerts else None,
                "end": self.alerts[-1]["timestamp"] if self.alerts else None
            },
            "statistics": self.stats,
            "top_attackers": self.get_top_attackers(),
            "targeted_assets": self.get_target_summary(),
            "recent_alerts": self.get_recent_alerts(10),
            "total_alerts": len(self.alerts)
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
            
        print(f"📊 Security report saved to {output_file}")
        return report

def display_dashboard(monitor: SuricataMonitor):
    """Display real-time dashboard"""
    while monitor.running:
        os.system('cls' if os.name == 'nt' else 'clear')
        
        print("🛡️  SURICATA BLUE TEAM DEFENDER DASHBOARD")
        print("=" * 60)
        print(f"📊 Total Alerts: {monitor.stats['total_alerts']}")
        print(f"🚨 Critical: {monitor.stats['critical_alerts']} | "
              f"⚠️  High: {monitor.stats['high_alerts']} | "
              f"🔶 Medium: {monitor.stats['medium_alerts']} | "
              f"ℹ️  Low: {monitor.stats['low_alerts']}")
        print()
        
        # Recent alerts
        recent = monitor.get_recent_alerts(5)
        if recent:
            print("📡 RECENT ALERTS:")
            for alert in recent[-5:]:
                print(f"   • {alert['signature']} ({alert['severity']}) "
                      f"{alert['src_ip']} → {alert['dst_ip']}")
        print()
        
        # Top attackers
        top_attackers = monitor.get_top_attackers(3)
        if top_attackers:
            print("🎯 TOP ATTACKERS:")
            for attacker in top_attackers:
                print(f"   • {attacker['ip']} - {attacker['count']} alerts")
        print()
        
        # CPS-specific alerts
        cps_alerts = [a for a in monitor.alerts if "CPS" in a["signature"]]
        if cps_alerts:
            print("🏭 CPS SECURITY ALERTS:")
            for alert in cps_alerts[-3:]:
                print(f"   • {alert['signature']} ({alert['severity']})")
        print()
        
        print("🔄 Updating... (Ctrl+C to stop)")
        time.sleep(5)

def check_suricata_status():
    """Check if Suricata is running"""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=cps-suricata-ids", "--format", "{{.Status}}"],
            capture_output=True, text=True, timeout=10
        )
        
        if result.returncode == 0 and result.stdout.strip():
            status = result.stdout.strip()
            if "Up" in status:
                print("✅ Suricata IDS is running")
                return True
            else:
                print(f"⚠️  Suricata status: {status}")
                return False
        else:
            print("❌ Suricata container not found")
            return False
            
    except Exception as e:
        print(f"❌ Error checking Suricata status: {e}")
        return False

def main():
    """Main monitoring application"""
    print("🛡️  Suricata Blue Team Defender for CPS")
    print("=" * 50)
    
    # Check if Suricata is running
    if not check_suricata_status():
        print("\n🚀 Starting Suricata container...")
        try:
            subprocess.run([
                "docker-compose", "-f", "monitoring/docker-compose-closed.yml", 
                "up", "-d", "suricata-ids"
            ], check=True)
            print("✅ Suricata container started")
            time.sleep(5)  # Give it time to initialize
        except Exception as e:
            print(f"❌ Failed to start Suricata: {e}")
            return
    
    # Start monitoring
    monitor = SuricataMonitor()
    
    if monitor.start_monitoring():
        # Start dashboard in separate thread
        dashboard_thread = threading.Thread(
            target=display_dashboard, 
            args=(monitor,)
        )
        dashboard_thread.daemon = True
        dashboard_thread.start()
        
        try:
            # Keep main thread alive
            while monitor.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Shutting down...")
            monitor.stop_monitoring()
            
            # Generate final report
            if monitor.alerts:
                monitor.generate_report()
                print(f"📊 Final report: {len(monitor.alerts)} alerts processed")
            else:
                print("ℹ️  No alerts processed")
                
    else:
        print("❌ Failed to start monitoring")

if __name__ == "__main__":
    main()

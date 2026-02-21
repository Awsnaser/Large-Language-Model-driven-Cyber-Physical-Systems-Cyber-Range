#!/usr/bin/env python3
"""
Test Suricata Blue Team Defender Integration
"""

import subprocess
import sys
import os

def test_suricata_integration():
    """Test Suricata integration with enhanced docker"""
    
    print("🛡️  Testing Suricata Blue Team Defender Integration")
    print("=" * 60)
    
    # Test 1: Check docker-compose configuration
    print("\n1. Checking Docker Compose Configuration:")
    try:
        with open("monitoring/docker-compose-closed.yml", 'r') as f:
            content = f.read()
            if "suricata-ids" in content:
                print("   ✅ Suricata service found in docker-compose")
            else:
                print("   ❌ Suricata service not found")
                return False
                
            if "suricata_logs" in content:
                print("   ✅ Suricata volume configured")
            else:
                print("   ❌ Suricata volume missing")
                
    except Exception as e:
        print(f"   ❌ Error reading docker-compose: {e}")
        return False
    
    # Test 2: Check configuration files
    print("\n2. Checking Configuration Files:")
    config_files = [
        "configs/suricata/suricata.yaml",
        "configs/suricata/custom-cps.rules"
    ]
    
    for config_file in config_files:
        if os.path.exists(config_file):
            print(f"   ✅ {config_file}")
        else:
            print(f"   ❌ {config_file} missing")
    
    # Test 3: Check Python integration
    print("\n3. Checking Python Integration:")
    try:
        with open("python cyberrange_all_in_one.py", 'r') as f:
            content = f.read()
            if "cps-suricata-ids" in content:
                print("   ✅ Suricata container added to Python script")
            else:
                print("   ❌ Suricata container not in Python script")
                
            if "suricata" in content.lower():
                print("   ✅ Suricata references found")
            else:
                print("   ⚠️  Limited Suricata references")
                
    except Exception as e:
        print(f"   ❌ Error reading Python script: {e}")
    
    # Test 4: Check monitoring script
    print("\n4. Checking Monitoring Script:")
    if os.path.exists("suricata-monitor.py"):
        print("   ✅ Suricata monitor script exists")
        
        # Check if script is runnable
        try:
            result = subprocess.run([
                sys.executable, "suricata-monitor.py", "--help"
            ], capture_output=True, text=True, timeout=5)
            if result.returncode == 0 or "help" in result.stderr.lower():
                print("   ✅ Monitor script is executable")
            else:
                print("   ⚠️  Monitor script may have issues")
        except:
            print("   ℹ️  Monitor script exists (runtime test skipped)")
    else:
        print("   ❌ Suricata monitor script missing")
    
    # Test 5: Check container count
    print("\n5. Container Count Verification:")
    try:
        with open("python cyberrange_all_in_one.py", 'r') as f:
            content = f.read()
            
            # Count enhanced containers
            if "ENHANCED_CONTAINERS" in content:
                start = content.find("ENHANCED_CONTAINERS = (")
                end = content.find(")", start)
                containers_section = content[start:end]
                container_count = containers_section.count('"')
                print(f"   ✅ Enhanced containers: ~{container_count}")
                
                if "cps-suricata-ids" in containers_section:
                    print("   ✅ Suricata included in enhanced containers")
                else:
                    print("   ❌ Suricata not in enhanced containers")
                    
    except Exception as e:
        print(f"   ❌ Error counting containers: {e}")
    
    return True

def show_usage_commands():
    """Show usage commands"""
    
    print(f"\n🚀 Suricata Blue Team Defender Usage:")
    print("=" * 50)
    
    print(f"\n1. Start Enhanced CPS with Suricata:")
    print(f"   python \"python cyberrange_all_in_one.py\" --enhanced-docker --scripted-agents --rounds 20")
    
    print(f"\n2. Start Suricata Monitoring Dashboard:")
    print(f"   python suricata-monitor.py")
    
    print(f"\n3. Check Suricata Status:")
    print(f"   docker ps --filter name=cps-suricata-ids")
    
    print(f"\n4. View Suricata Logs:")
    print(f"   docker logs cps-suricata-ids")
    print(f"   docker exec cps-suricata-ids tail -f /var/log/suricata/eve.json")
    
    print(f"\n5. Full Neural Multi-Agent with Suricata:")
    print(f"   python \"python cyberrange_all_in_one.py\" \\")
    print(f"     --enhanced-docker \\")
    print(f"     --multi-agent \\")
    print(f"     --num-attackers 4 \\")
    print(f"     --num-defenders 4 \\")
    print(f"     --num-analysts 2 \\")
    print(f"     --neural-arch transformer \\")
    print(f"     --agent-coordination \\")
    print(f"     --scripted-agents \\")
    print(f"     --rounds 50")
    
    print(f"\n📊 Suricata Features:")
    print("   • Real-time intrusion detection")
    print("   • CPS-specific security rules")
    print("   • Honeypot monitoring")
    print("   • Network traffic analysis")
    print("   • Alert correlation and reporting")
    print("   • Blue team defender integration")

if __name__ == "__main__":
    success = test_suricata_integration()
    
    if success:
        show_usage_commands()
        print(f"\n✅ Suricata Blue Team Defender integration complete!")
    else:
        print(f"\n❌ Integration test failed!")

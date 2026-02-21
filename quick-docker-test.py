#!/usr/bin/env python3
"""
Quick test for enhanced docker configuration
"""

import sys
import os

def test_container_configurations():
    """Test container configurations without Docker"""
    
    print("Testing Enhanced Docker Container Configurations")
    print("=" * 50)
    
    # Import the main module to test configurations
    sys.path.append('.')
    
    try:
        # Import container names
        from python_cyberrange_all_in_one import (
            STANDARD_CONTAINERS, ENHANCED_CONTAINERS, LAPTOP_CONTAINERS,
            PLACEHOLDER_IPS, ASSET_PORTS
        )
        
        print(f"✅ Standard containers: {len(STANDARD_CONTAINERS)}")
        for container in STANDARD_CONTAINERS:
            print(f"   - {container}")
        
        print(f"\n✅ Enhanced containers: {len(ENHANCED_CONTAINERS)}")
        for container in ENHANCED_CONTAINERS:
            ip = PLACEHOLDER_IPS.get(container, "N/A")
            ports = ASSET_PORTS.get(container, {})
            print(f"   - {container} ({ip}) - {list(ports.keys())}")
        
        print(f"\n✅ Laptop containers: {len(LAPTOP_CONTAINERS)}")
        for container in LAPTOP_CONTAINERS:
            ip = PLACEHOLDER_IPS.get(container, "N/A")
            ports = ASSET_PORTS.get(container, {})
            print(f"   - {container} ({ip}) - {list(ports.keys())}")
        
        # Test docker-compose files exist
        print(f"\n📁 Checking Docker Compose Files:")
        
        files_to_check = [
            "docker-compose.yml",
            "monitoring/docker-compose-closed.yml", 
            "monitoring/laptop-optimization.yml"
        ]
        
        for file_path in files_to_check:
            if os.path.exists(file_path):
                print(f"   ✅ {file_path}")
            else:
                print(f"   ❌ {file_path}")
        
        print(f"\n🎯 Configuration Summary:")
        print(f"   - Standard setup: {len(STANDARD_CONTAINERS)} containers")
        print(f"   - Enhanced setup: {len(ENHANCED_CONTAINERS)} containers")
        print(f"   - Laptop setup: {len(LAPTOP_CONTAINERS)} containers")
        print(f"   - Total IPs configured: {len(PLACEHOLDER_IPS)}")
        print(f"   - Total port configurations: {len(ASSET_PORTS)}")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False

def show_usage_commands():
    """Show usage commands"""
    
    print(f"\n🚀 Usage Commands:")
    print(f"=" * 30)
    
    print(f"\n1. Standard Docker Setup:")
    print(f"   python \"python cyberrange_all_in_one.py\" --scripted-agents --rounds 20")
    
    print(f"\n2. Enhanced Docker Setup (with honeypots):")
    print(f"   python \"python cyberrange_all_in_one.py\" --enhanced-docker --scripted-agents --rounds 20")
    
    print(f"\n3. Laptop-Optimized Setup:")
    print(f"   python \"python cyberrange_all_in_one.py\" --laptop-docker --scripted-agents --rounds 20")
    
    print(f"\n4. Neural Multi-Agent Setup:")
    print(f"   python \"python cyberrange_all_in_one.py\" --enhanced-docker --multi-agent --scripted-agents --rounds 20")
    
    print(f"\n5. Full Neural Setup:")
    print(f"   python \"python cyberrange_all_in_one.py\" --enhanced-docker --multi-agent --neural-arch transformer --agent-coordination --scripted-agents --rounds 50")

if __name__ == "__main__":
    success = test_container_configurations()
    
    if success:
        show_usage_commands()
        print(f"\n✅ All configurations ready!")
    else:
        print(f"\n❌ Configuration test failed!")

#!/usr/bin/env python3
"""
Test script for enhanced docker containers
"""

import subprocess
import sys
import os

def test_docker_compose():
    """Test different docker-compose configurations"""
    
    print("🐳 Testing Enhanced Docker Containers")
    print("=" * 50)
    
    # Test 1: Standard containers
    print("\n1. Testing Standard Containers:")
    try:
        result = subprocess.run([
            sys.executable, "python cyberrange_all_in_one.py",
            "--no-docker-up", "--no-write-compose"
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✅ Standard configuration works")
        else:
            print(f"❌ Standard configuration failed: {result.stderr}")
    except Exception as e:
        print(f"❌ Standard test error: {e}")
    
    # Test 2: Enhanced containers
    print("\n2. Testing Enhanced Containers:")
    try:
        result = subprocess.run([
            sys.executable, "python cyberrange_all_in_one.py",
            "--enhanced-docker", "--no-docker-up", "--no-write-compose"
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✅ Enhanced configuration works")
            if "Total containers: 23" in result.stdout:
                print("✅ Enhanced container count correct")
            else:
                print("⚠️  Container count might be wrong")
        else:
            print(f"❌ Enhanced configuration failed: {result.stderr}")
    except Exception as e:
        print(f"❌ Enhanced test error: {e}")
    
    # Test 3: Laptop containers
    print("\n3. Testing Laptop Containers:")
    try:
        result = subprocess.run([
            sys.executable, "python cyberrange_all_in_one.py",
            "--laptop-docker", "--no-docker-up", "--no-write-compose"
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✅ Laptop configuration works")
            if "Total containers: 15" in result.stdout:
                print("✅ Laptop container count correct")
            else:
                print("⚠️  Container count might be wrong")
        else:
            print(f"❌ Laptop configuration failed: {result.stderr}")
    except Exception as e:
        print(f"❌ Laptop test error: {e}")
    
    # Test 4: Check docker-compose files exist
    print("\n4. Checking Docker Compose Files:")
    
    files_to_check = [
        "docker-compose.yml",
        "monitoring/docker-compose-closed.yml",
        "monitoring/laptop-optimization.yml"
    ]
    
    for file_path in files_to_check:
        if os.path.exists(file_path):
            print(f"✅ {file_path} exists")
        else:
            print(f"❌ {file_path} missing")
    
    # Test 5: Check if Docker is available
    print("\n5. Checking Docker Availability:")
    try:
        result = subprocess.run(["docker", "--version"], capture_output=True, text=True)
        print(f"✅ Docker available: {result.stdout.strip()}")
        
        # Check docker-compose
        result = subprocess.run(["docker-compose", "--version"], capture_output=True, text=True)
        print(f"✅ Docker Compose available: {result.stdout.strip()}")
        
    except Exception as e:
        print(f"❌ Docker not available: {e}")
    
    print("\n🎯 Quick Test Commands:")
    print("Run enhanced containers:")
    print("  python python\\ cyberrange_all_in_one.py --enhanced-docker --scripted-agents --rounds 10")
    print("\nRun laptop containers:")
    print("  python python\\ cyberrange_all_in_one.py --laptop-docker --scripted-agents --rounds 10")
    print("\nRun standard containers:")
    print("  python python\\ cyberrange_all_in_one.py --scripted-agents --rounds 10")

if __name__ == "__main__":
    test_docker_compose()

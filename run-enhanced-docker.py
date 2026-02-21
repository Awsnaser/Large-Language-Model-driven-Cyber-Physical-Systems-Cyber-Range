#!/usr/bin/env python3
"""
Run Enhanced Docker Simulation with All Containers
"""

import subprocess
import sys
import os

def main():
    print("Enhanced Docker CPS Simulation Runner")
    print("=" * 40)
    
    # Check if docker-compose files exist
    required_files = [
        "monitoring/docker-compose-closed.yml",
        "monitoring/laptop-optimization.yml"
    ]
    
    print("Checking required files...")
    for file_path in required_files:
        if os.path.exists(file_path):
            print(f"  ✓ {file_path}")
        else:
            print(f"  ✗ {file_path} - MISSING!")
            return False
    
    print("\nAvailable Docker Options:")
    print("1. Standard (4 containers)")
    print("2. Enhanced with Honeypots (23 containers)")
    print("3. Laptop-Optimized (15 containers)")
    
    print("\nRecommended Commands:")
    print("\n1. Enhanced Setup with Honeypots:")
    print("   python \"python cyberrange_all_in_one.py\" --enhanced-docker --scripted-agents --rounds 20")
    
    print("\n2. Laptop-Optimized Setup:")
    print("   python \"python cyberrange_all_in_one.py\" --laptop-docker --scripted-agents --rounds 20")
    
    print("\n3. Neural Multi-Agent Enhanced Setup:")
    print("   python \"python cyberrange_all_in_one.py\" --enhanced-docker --multi-agent --scripted-agents --rounds 20")
    
    print("\n4. Full Neural Setup with All Features:")
    print("   python \"python cyberrange_all_in_one.py\" \\")
    print("     --enhanced-docker \\")
    print("     --multi-agent \\")
    print("     --num-attackers 4 \\")
    print("     --num-defenders 4 \\")
    print("     --num-analysts 2 \\")
    print("     --neural-arch transformer \\")
    print("     --agent-coordination \\")
    print("     --neural-training \\")
    print("     --scripted-agents \\")
    print("     --rounds 50")
    
    # Ask user if they want to run a test
    try:
        choice = input("\nRun enhanced docker test? (y/n): ").lower().strip()
        if choice == 'y':
            print("\nStarting Enhanced Docker Test...")
            cmd = [
                sys.executable, 
                "python cyberrange_all_in_one.py",
                "--enhanced-docker",
                "--scripted-agents", 
                "--rounds", "5"
            ]
            
            print(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd)
            
            if result.returncode == 0:
                print("\n✅ Enhanced docker test completed successfully!")
            else:
                print(f"\n❌ Test failed with exit code: {result.returncode}")
                
    except KeyboardInterrupt:
        print("\nTest cancelled by user")
    except Exception as e:
        print(f"\nError running test: {e}")
    
    return True

if __name__ == "__main__":
    main()

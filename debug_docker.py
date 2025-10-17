#!/usr/bin/env python3
"""
Debug script to test AutoAR commands in Docker environment
"""

import os
import subprocess
import sys

def test_environment():
    """Test environment variables and file existence."""
    print("=== Environment Variables ===")
    print(f"DISCORD_BOT_TOKEN: {'SET' if os.getenv('DISCORD_BOT_TOKEN') else 'NOT SET'}")
    print(f"AUTOAR_SCRIPT_PATH: {os.getenv('AUTOAR_SCRIPT_PATH', 'NOT SET')}")
    print(f"AUTOAR_CONFIG_FILE: {os.getenv('AUTOAR_CONFIG_FILE', 'NOT SET')}")
    print(f"DB_TYPE: {os.getenv('DB_TYPE', 'NOT SET')}")
    print(f"DB_HOST: {os.getenv('DB_HOST', 'NOT SET')}")
    print(f"DISCORD_WEBHOOK: {'SET' if os.getenv('DISCORD_WEBHOOK') else 'NOT SET'}")
    
    print("\n=== File Existence ===")
    script_path = os.getenv('AUTOAR_SCRIPT_PATH', '/app/main.sh')
    config_file = os.getenv('AUTOAR_CONFIG_FILE', '/app/autoar.yaml')
    print(f"Script exists: {os.path.exists(script_path)}")
    print(f"Config exists: {os.path.exists(config_file)}")
    print(f"Script executable: {os.access(script_path, os.X_OK)}")
    
    print("\n=== Testing Commands ===")
    
    # Test help command
    try:
        result = subprocess.run([script_path, "help"], 
                              capture_output=True, text=True, timeout=10)
        print(f"Help command: exit_code={result.returncode}")
        if result.stderr:
            print(f"Help stderr: {result.stderr[:200]}")
    except Exception as e:
        print(f"Help command error: {e}")
    
    # Test check-tools command
    try:
        result = subprocess.run([script_path, "check-tools", "run"], 
                              capture_output=True, text=True, timeout=30)
        print(f"Check-tools command: exit_code={result.returncode}")
        if result.stderr:
            print(f"Check-tools stderr: {result.stderr[:200]}")
    except Exception as e:
        print(f"Check-tools command error: {e}")
    
    # Test db command
    try:
        result = subprocess.run([script_path, "db", "domains", "list"], 
                              capture_output=True, text=True, timeout=10)
        print(f"DB domains command: exit_code={result.returncode}")
        if result.stderr:
            print(f"DB domains stderr: {result.stderr[:200]}")
        if result.stdout:
            print(f"DB domains stdout: {result.stdout[:200]}")
    except Exception as e:
        print(f"DB domains command error: {e}")

if __name__ == "__main__":
    test_environment()

#!/usr/bin/env python3
"""
AutoAR Launcher
Launches the AutoAR tool in different modes: Discord bot, API server, or both.
"""

import os
import sys
import signal
import subprocess
import multiprocessing
from typing import List, Optional

# Configuration
MODE = os.getenv("AUTOAR_MODE", "discord").lower()  # discord, api, or both
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))


def print_banner():
    """Print AutoAR banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                   AutoAR Launcher                          ║
    ║        Automated Application Reconnaissance Tool           ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)


def run_discord_bot():
    """Run the Discord bot."""
    print("[Launcher] Starting Discord Bot mode...")
    try:
        import discord_bot

        # The discord_bot.py will run when imported or we can call its main
        subprocess.run([sys.executable, "/app/discord_bot.py"], check=True)
    except Exception as e:
        print(f"[Launcher] Error starting Discord bot: {e}")
        sys.exit(1)


def run_api_server():
    """Run the API server."""
    print(f"[Launcher] Starting API Server mode on {API_HOST}:{API_PORT}...")
    try:
        import api_server

        api_server.main()
    except Exception as e:
        print(f"[Launcher] Error starting API server: {e}")
        sys.exit(1)


def run_both():
    """Run both Discord bot and API server in separate processes."""
    print("[Launcher] Starting BOTH Discord Bot and API Server...")

    processes = []

    # Start API server in a separate process
    api_process = multiprocessing.Process(target=run_api_server, name="API-Server")
    api_process.start()
    processes.append(api_process)

    print(f"[Launcher] API Server started with PID: {api_process.pid}")

    # Start Discord bot in a separate process
    discord_process = multiprocessing.Process(
        target=run_discord_bot, name="Discord-Bot"
    )
    discord_process.start()
    processes.append(discord_process)

    print(f"[Launcher] Discord Bot started with PID: {discord_process.pid}")

    # Signal handler for graceful shutdown
    def signal_handler(signum, frame):
        print(f"\n[Launcher] Received signal {signum}, shutting down...")
        for proc in processes:
            if proc.is_alive():
                print(f"[Launcher] Terminating {proc.name} (PID: {proc.pid})...")
                proc.terminate()

        # Wait for processes to terminate
        for proc in processes:
            proc.join(timeout=5)
            if proc.is_alive():
                print(f"[Launcher] Force killing {proc.name}...")
                proc.kill()

        sys.exit(0)

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Wait for all processes
    try:
        for proc in processes:
            proc.join()
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)


def validate_environment():
    """Validate required environment variables based on mode."""
    errors = []

    if MODE in ["discord", "both"]:
        if not os.getenv("DISCORD_BOT_TOKEN"):
            errors.append("DISCORD_BOT_TOKEN is required for Discord bot mode")

    if MODE in ["api", "both"]:
        # API mode has no strict requirements, but we can check optional ones
        pass

    if errors:
        print("[Launcher] Configuration errors:")
        for error in errors:
            print(f"  - {error}")
        sys.exit(1)


def print_mode_info():
    """Print information about the current mode."""
    print(f"\n[Launcher] Mode: {MODE.upper()}")

    if MODE in ["discord", "both"]:
        print("[Launcher] Discord Bot: ENABLED")
        token_set = "✓" if os.getenv("DISCORD_BOT_TOKEN") else "✗"
        print(f"[Launcher]   - Token configured: {token_set}")

    if MODE in ["api", "both"]:
        print("[Launcher] API Server: ENABLED")
        print(f"[Launcher]   - Host: {API_HOST}")
        print(f"[Launcher]   - Port: {API_PORT}")
        print(f"[Launcher]   - Docs: http://{API_HOST}:{API_PORT}/docs")

    print()


def main():
    """Main launcher entry point."""
    print_banner()

    # Validate environment
    validate_environment()

    # Print mode information
    print_mode_info()

    # Launch based on mode
    if MODE == "discord":
        run_discord_bot()
    elif MODE == "api":
        run_api_server()
    elif MODE == "both":
        run_both()
    else:
        print(f"[Launcher] Error: Invalid mode '{MODE}'")
        print("[Launcher] Valid modes: discord, api, both")
        print("[Launcher] Set AUTOAR_MODE environment variable to choose mode")
        sys.exit(1)


if __name__ == "__main__":
    main()

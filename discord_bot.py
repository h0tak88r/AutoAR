#!/usr/bin/env python3
"""
AutoAR Discord Bot
A Discord bot interface for the AutoAR security scanning tool.
"""

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse

import discord
from discord import app_commands
from discord.ext import commands
import yaml

# Bot configuration
BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
AUTOAR_SCRIPT_PATH = os.getenv("AUTOAR_SCRIPT_PATH", "/app/main.sh")
CONFIG_FILE = os.getenv("AUTOAR_CONFIG_FILE", "/app/autoar.yaml")
RESULTS_DIR = os.getenv("AUTOAR_RESULTS_DIR", "/app/new-results")

# Bot permissions
intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True
intents.guild_messages = True

# Create bot instance
bot = commands.Bot(command_prefix="!", intents=intents)

# Global variables
active_scans = {}  # Track active scans
scan_results = {}  # Store scan results


class AutoARBot(commands.Cog):
    """Main AutoAR Discord Bot cog with all commands."""

    def __init__(self, bot):
        self.bot = bot
        self.config = self.load_config()

    def load_config(self) -> Dict[str, Any]:
        """Load AutoAR configuration from YAML file with environment variable fallback."""
        config = {}

        # Try to load from YAML file if it exists
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    config = yaml.safe_load(f) or {}
            except Exception as e:
                print(f"Warning: Could not load config file: {e}")

        # Override with environment variables if they exist
        env_mappings = {
            "DISCORD_WEBHOOK": os.getenv("DISCORD_WEBHOOK"),
            "DB_NAME": os.getenv("DB_NAME"),
            "SAVE_TO_DB": os.getenv("SAVE_TO_DB"),
            "VERBOSE": os.getenv("VERBOSE"),
            "GITHUB_TOKEN": os.getenv("GITHUB_TOKEN"),
            "SECURITYTRAILS_API_KEY": os.getenv("SECURITYTRAILS_API_KEY"),
            "SHODAN_API_KEY": os.getenv("SHODAN_API_KEY"),
            "VIRUSTOTAL_API_KEY": os.getenv("VIRUSTOTAL_API_KEY"),
        }

        for key, value in env_mappings.items():
            if value is not None:
                config[key] = value

        return config

    def get_discord_webhook(self) -> Optional[str]:
        """Get Discord webhook URL from config or environment."""
        return self.config.get("DISCORD_WEBHOOK") or os.getenv("DISCORD_WEBHOOK")

    async def run_autoar_command(
        self, command: list, scan_id: str, timeout: int = 30
    ) -> Dict[str, Any]:
        """Run AutoAR command and return results."""
        try:
            # Set environment variables
            env = os.environ.copy()
            env["AUTOAR_CONFIG"] = CONFIG_FILE

            # Run the command with timeout
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                cwd=os.path.dirname(AUTOAR_SCRIPT_PATH),
            )

            # Add timeout to prevent hanging
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                print(f"[WARN] Command timed out after {timeout} seconds")
                process.kill()
                await process.wait()
                return {
                    "returncode": -1,
                    "stdout": "",
                    "stderr": f"Command timed out after {timeout} seconds",
                    "scan_id": scan_id,
                    "timestamp": datetime.now().isoformat(),
                }

            return {
                "returncode": process.returncode,
                "stdout": stdout.decode("utf-8"),
                "stderr": stderr.decode("utf-8"),
                "scan_id": scan_id,
                "timestamp": datetime.now().isoformat(),
            }

        except Exception as e:
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": str(e),
                "scan_id": scan_id,
                "timestamp": datetime.now().isoformat(),
            }

    def create_scan_embed(
        self, scan_type: str, target: str, status: str, results: Optional[Dict] = None
    ) -> discord.Embed:
        """Create a Discord embed for scan results."""
        embed = discord.Embed(
            title=f"🔍 AutoAR {scan_type.title()} Scan",
            description=f"**Target:** `{target}`",
            color=discord.Color.blue()
            if status == "running"
            else discord.Color.green()
            if status == "completed"
            else discord.Color.red(),
        )

        embed.add_field(name="Status", value=status.upper(), inline=True)
        embed.add_field(
            name="Timestamp",
            value=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            inline=True,
        )

        if results:
            if results["returncode"] == 0:
                embed.color = discord.Color.green()
                embed.add_field(
                    name="Result", value="✅ Scan completed successfully", inline=False
                )
            else:
                embed.color = discord.Color.red()
                embed.add_field(
                    name="Error",
                    value=f"❌ Scan failed (Exit code: {results['returncode']})",
                    inline=False,
                )
                if results["stderr"]:
                    embed.add_field(
                        name="Error Details",
                        value=f"```{results['stderr'][:1000]}```",
                        inline=False,
                    )

        return embed

    @app_commands.command(name="scan_domain", description="Perform a full domain scan")
    @app_commands.describe(
        domain="The domain to scan",
        verbose="Enable verbose output",
        keep_results="Keep scan results after completion",
    )
    async def scan_domain(
        self,
        interaction: discord.Interaction,
        domain: str,
        verbose: bool = False,
        keep_results: bool = False,
    ):
        """Perform a full domain scan."""
        scan_id = f"domain_{int(time.time())}"

        # Create command
        command = [AUTOAR_SCRIPT_PATH, "domain", "run", "-d", domain]
        if verbose:
            command.append("-v")
        if keep_results:
            command.append("--keep-results")

        # Store active scan
        active_scans[scan_id] = {
            "type": "domain",
            "target": domain,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }

        # Send initial response
        embed = self.create_scan_embed("Domain", domain, "running")
        await interaction.response.send_message(embed=embed)

        # Run scan in background
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="scan_subdomain", description="Scan a single subdomain")
    @app_commands.describe(
        subdomain="The subdomain to scan", verbose="Enable verbose output"
    )
    async def scan_subdomain(
        self, interaction: discord.Interaction, subdomain: str, verbose: bool = False
    ):
        """Scan a single subdomain."""
        scan_id = f"subdomain_{int(time.time())}"

        command = [AUTOAR_SCRIPT_PATH, "subdomains", "get", "-d", subdomain]
        if verbose:
            command.append("-v")

        active_scans[scan_id] = {
            "type": "subdomain",
            "target": subdomain,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }

        embed = self.create_scan_embed("Subdomain", subdomain, "running")
        await interaction.response.send_message(embed=embed)

        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="lite_scan", description="Perform a lite domain scan")
    @app_commands.describe(
        domain="The domain to scan",
        verbose="Enable verbose output",
        skip_js="Skip JavaScript scanning step",
        phase_timeout="Default per-phase timeout in seconds (0 = no limit, default 3600)",
        timeout_livehosts="Override timeout for livehosts phase (seconds, optional)",
        timeout_reflection="Override timeout for reflection phase (seconds, optional)",
        timeout_js="Override timeout for JS phase (seconds, optional)",
        timeout_nuclei="Override timeout for nuclei phase (seconds, optional)",
    )
    async def lite_scan(
        self,
        interaction: discord.Interaction,
        domain: str,
        verbose: bool = False,
        skip_js: bool = False,
        phase_timeout: int = 3600,
        timeout_livehosts: Optional[int] = None,
        timeout_reflection: Optional[int] = None,
        timeout_js: Optional[int] = None,
        timeout_nuclei: Optional[int] = None,
    ):
        """Perform a lite domain scan."""
        scan_id = f"lite_{int(time.time())}"

        command = [AUTOAR_SCRIPT_PATH, "lite", "run", "-d", domain]
        if verbose:
            command.append("-v")
        if skip_js:
            command.append("--skip-js")

        # Per-phase timeout configuration
        if phase_timeout and phase_timeout > 0:
            command.extend(["--phase-timeout", str(phase_timeout)])
        if timeout_livehosts is not None and timeout_livehosts >= 0:
            command.extend(["--timeout-livehosts", str(timeout_livehosts)])
        if timeout_reflection is not None and timeout_reflection >= 0:
            command.extend(["--timeout-reflection", str(timeout_reflection)])
        if timeout_js is not None and timeout_js >= 0:
            command.extend(["--timeout-js", str(timeout_js)])
        if timeout_nuclei is not None and timeout_nuclei >= 0:
            command.extend(["--timeout-nuclei", str(timeout_nuclei)])

        active_scans[scan_id] = {
            "type": "lite",
            "target": domain,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }

        embed_desc = f"**Target:** `{domain}`\n**Default per-phase timeout:** {phase_timeout or 0}s"
        if skip_js:
            embed_desc += "\n**JS Phase:** skipped"
        embed = discord.Embed(
            title="🔍 AutoAR Lite Scan",
            description=embed_desc,
            color=discord.Color.blue(),
        )
        await interaction.response.send_message(embed=embed)

        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="fast_look", description="Perform a fast domain lookup")
    @app_commands.describe(domain="The domain to scan", verbose="Enable verbose output")
    async def fast_look(
        self, interaction: discord.Interaction, domain: str, verbose: bool = False
    ):
        """Perform a fast domain lookup."""
        scan_id = f"fast_{int(time.time())}"

        command = [AUTOAR_SCRIPT_PATH, "fastlook", "run", "-d", domain]
        if verbose:
            command.append("-v")

        active_scans[scan_id] = {
            "type": "fast",
            "target": domain,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }

        embed = self.create_scan_embed("Fast Look", domain, "running")
        await interaction.response.send_message(embed=embed)

        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(
        name="js_scan", description="Scan for JavaScript files and endpoints"
    )
    @app_commands.describe(
        domain="The domain to scan",
        subdomain="Specific subdomain to scan (optional)",
        verbose="Enable verbose output",
    )
    async def js_scan(
        self,
        interaction: discord.Interaction,
        domain: str,
        subdomain: Optional[str] = None,
        verbose: bool = False,
    ):
        """Scan for JavaScript files and endpoints."""
        scan_id = f"js_{int(time.time())}"

        command = [AUTOAR_SCRIPT_PATH, "js", "scan", "-d", domain]
        if subdomain:
            command.extend(["-s", subdomain])
        if verbose:
            command.append("-v")

        target = f"{subdomain}.{domain}" if subdomain else domain
        active_scans[scan_id] = {
            "type": "js",
            "target": target,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }

        embed = self.create_scan_embed("JavaScript Scan", target, "running")
        await interaction.response.send_message(embed=embed)

        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(
        name="jwt_scan",
        description="🔐 Test JWT security using ticarpi/jwt_tool",
    )
    @app_commands.describe(
        url="Target URL to test (e.g. https://www.ticarpi.com/)",
        cookie="Cookie string with JWT (format: name=value, e.g. auth=JWT_TOKEN)",
        header="Header string with JWT (format: name: value, e.g. Authorization: Bearer JWT_TOKEN)",
        canary="Expected text in a successful response (jwt_tool -cv)",
        post_data="Optional POST body to send with the request",
        mode="jwt_tool attack mode (default: pb)",
    )
    async def jwt_scan_cmd(
        self,
        interaction: discord.Interaction,
        url: str,
        cookie: Optional[str] = None,
        header: Optional[str] = None,
        canary: Optional[str] = None,
        post_data: Optional[str] = None,
        mode: str = "pb",
    ):
        """Run jwt_tool against a target URL with cookie or header."""
        if not cookie and not header:
            await interaction.response.send_message(
                "❌ You must provide either `cookie` or `header` parameter.",
                ephemeral=True,
            )
            return

        if cookie and header:
            await interaction.response.send_message(
                "❌ You cannot provide both `cookie` and `header`. Choose one.",
                ephemeral=True,
            )
            return

        scan_id = f"jwt_{int(time.time())}"

        command = [AUTOAR_SCRIPT_PATH, "jwt", "scan", "-t", url]
        if cookie:
            command.extend(["--cookie", cookie])
            via = "cookie"
        else:
            command.extend(["--header", header])
            via = "header"

        if canary:
            command.extend(["--canary", canary])
        if post_data:
            command.extend(["--post-data", post_data])
        if mode:
            command.extend(["-M", mode])

        active_scans[scan_id] = {
            "type": "jwt",
            "target": url,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }

        embed = discord.Embed(
            title="🔐 JWT Security Test",
            description=f"**Target:** `{url}`\n**Mode:** `{mode}`\n**Via:** `{via}`",
            color=discord.Color.blue(),
        )
        await interaction.response.send_message(embed=embed)

        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(
        name="jwt_query",
        description="🔍 Query JWT tool log by request ID",
    )
    @app_commands.describe(
        query_id="JWT tool request ID (e.g. jwttool_4e7d0ae3c2bb25dfa4d765d9bb3f8317)",
    )
    async def jwt_query_cmd(
        self,
        interaction: discord.Interaction,
        query_id: str,
    ):
        """Query JWT tool log entry by ID."""
        command = [AUTOAR_SCRIPT_PATH, "jwt", "query", query_id]

        embed = discord.Embed(
            title="🔍 JWT Log Query",
            description=f"**Query ID:** `{query_id}`",
            color=discord.Color.blue(),
        )
        await interaction.response.send_message(embed=embed)

        # Run query synchronously since it's quick
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                output = result.stdout
                # Strip ANSI escape codes (colors, formatting, etc.)
                import re
                ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
                output = ansi_escape.sub('', output)
                
                # Always send as file to avoid Discord message limits and formatting issues
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as f:
                    f.write(output)
                    temp_path = f.name
                
                embed = discord.Embed(
                    title="✅ JWT Log Query Result",
                    description=f"**Query ID:** `{query_id}`\n\nSee attached file for query results.",
                    color=discord.Color.green(),
                )
                file = discord.File(temp_path, filename=f"jwt_query_{query_id}.txt")
                await interaction.edit_original_response(embed=embed, attachments=[file])
                # Clean up temp file after sending
                import os
                try:
                    os.unlink(temp_path)
                except:
                    pass
            else:
                # Try to get error message from stderr or stdout
                error_msg = result.stderr.strip() if result.stderr else ""
                if not error_msg and result.stdout:
                    # Sometimes errors go to stdout
                    error_msg = result.stdout.strip()[:500]  # Limit length
                if not error_msg:
                    error_msg = f"Command exited with code {result.returncode}"
                
                embed = discord.Embed(
                    title="❌ JWT Log Query Failed",
                    description=f"**Query ID:** `{query_id}`\n\nError: {error_msg}",
                    color=discord.Color.red(),
                )
                await interaction.edit_original_response(embed=embed)
        except subprocess.TimeoutExpired:
            embed = discord.Embed(
                title="⏱️ JWT Log Query Timeout",
                description=f"Query for `{query_id}` took too long.",
                color=discord.Color.orange(),
            )
            await interaction.edit_original_response(embed=embed)
        except Exception as e:
            embed = discord.Embed(
                title="❌ JWT Log Query Error",
                description=f"Error querying log: {str(e)}",
                color=discord.Color.red(),
            )
            await interaction.edit_original_response(embed=embed)

    @app_commands.command(name="s3_scan", description="Scan for S3 buckets")
    @app_commands.describe(
        bucket="S3 bucket name to scan",
        region="AWS region (optional)",
        verbose="Enable verbose output",
    )
    async def s3_scan(
        self,
        interaction: discord.Interaction,
        bucket: str,
        region: Optional[str] = None,
        verbose: bool = False,
    ):
        """Scan for S3 buckets."""
        scan_id = f"s3_{int(time.time())}"

        command = [AUTOAR_SCRIPT_PATH, "s3", "scan", "-b", bucket]
        if region:
            command.extend(["-r", region])
        if verbose:
            command.append("-v")

        active_scans[scan_id] = {
            "type": "s3",
            "target": bucket,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }

        embed = self.create_scan_embed("S3 Scan", bucket, "running")
        await interaction.response.send_message(embed=embed)

        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(
        name="github_scan", description="Scan GitHub repository for secrets"
    )
    @app_commands.describe(
        repo="GitHub repository (owner/repo)", verbose="Enable verbose output"
    )
    async def github_scan(
        self, interaction: discord.Interaction, repo: str, verbose: bool = False
    ):
        """Scan GitHub repository for secrets."""
        scan_id = f"github_{int(time.time())}"

        command = [AUTOAR_SCRIPT_PATH, "github", "scan", "-r", repo]
        if verbose:
            command.append("-v")

        active_scans[scan_id] = {
            "type": "github",
            "target": repo,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }

        embed = self.create_scan_embed("GitHub Scan", repo, "running")
        await interaction.response.send_message(embed=embed)

        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(
        name="github_org_scan", description="Scan GitHub organization for secrets"
    )
    @app_commands.describe(
        org="GitHub organization name",
        max_repos="Maximum number of repositories to scan",
        verbose="Enable verbose output",
    )
    async def github_org_scan(
        self,
        interaction: discord.Interaction,
        org: str,
        max_repos: int = 50,
        verbose: bool = False,
    ):
        """Scan GitHub organization for secrets."""
        scan_id = f"github_org_{int(time.time())}"

        command = [AUTOAR_SCRIPT_PATH, "github", "org", "-o", org, "-m", str(max_repos)]
        if verbose:
            command.append("-v")

        active_scans[scan_id] = {
            "type": "github_org",
            "target": org,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }

        embed = self.create_scan_embed("GitHub Org Scan", org, "running")
        await interaction.response.send_message(embed=embed)

        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(
        name="github_experimental_scan",
        description="Scan GitHub repository using TruffleHog experimental mode with object discovery",
    )
    @app_commands.describe(
        repo="GitHub repository (owner/repo)", verbose="Enable verbose output"
    )
    async def github_experimental_scan(
        self, interaction: discord.Interaction, repo: str, verbose: bool = False
    ):
        """Scan GitHub repository using TruffleHog experimental mode."""
        scan_id = f"github_experimental_{int(time.time())}"

        command = [AUTOAR_SCRIPT_PATH, "github", "experimental", "-r", repo]
        if verbose:
            command.append("-v")

        active_scans[scan_id] = {
            "type": "github_experimental",
            "target": repo,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }

        embed = self.create_scan_embed("GitHub Experimental Scan", repo, "running")
        await interaction.response.send_message(embed=embed)

        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(
        name="wp_depconf", description="WordPress dependency confusion scan"
    )
    @app_commands.describe(
        domain="The domain to scan",
        list_file="Path to plugin list file (optional)",
        verbose="Enable verbose output",
    )
    async def wp_depconf(
        self,
        interaction: discord.Interaction,
        domain: str,
        list_file: Optional[str] = None,
        verbose: bool = False,
    ):
        """WordPress dependency confusion scan."""
        scan_id = f"wp_depconf_{int(time.time())}"

        command = [AUTOAR_SCRIPT_PATH, "wpDepConf", "scan", "-d", domain]
        if list_file:
            command.extend(["-l", list_file])
        if verbose:
            command.append("-v")

        active_scans[scan_id] = {
            "type": "wp_depconf",
            "target": domain,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }

        embed = self.create_scan_embed("WordPress DepConf", domain, "running")
        await interaction.response.send_message(embed=embed)

        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(
        name="github_wordlist",
        description="Generate GitHub target-based wordlist from organization",
    )
    @app_commands.describe(
        org="GitHub organization name",
        token="GitHub token (optional, can use GITHUB_TOKEN env var)",
    )
    async def github_wordlist(
        self, interaction: discord.Interaction, org: str, token: Optional[str] = None
    ):
        """Generate GitHub target-based wordlist from organization."""
        scan_id = f"github_wordlist_{int(time.time())}"

        command = [AUTOAR_SCRIPT_PATH, "github-wordlist", org]
        if token:
            command.extend(["-t", token])

        active_scans[scan_id] = {
            "type": "github_wordlist",
            "target": org,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }

        embed = self.create_scan_embed("GitHub Wordlist", org, "running")
        await interaction.response.send_message(embed=embed)

        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(
        name="backup_scan", description="Discover backup files using Fuzzuli"
    )
    @app_commands.describe(
        domain="Target domain to scan for backup files",
        threads="Number of threads (default: 100)",
        delay="Delay between requests in ms (default: 100)",
        full="Run full backup scan on all subdomains (default: False)",
    )
    async def backup_scan(
        self,
        interaction: discord.Interaction,
        domain: str,
        threads: int = 100,
        delay: int = 100,
        full: bool = False,
    ):
        """Discover backup files using Fuzzuli."""
        scan_id = f"backup_{int(time.time())}"

        command = [
            AUTOAR_SCRIPT_PATH,
            "backup",
            "scan",
            "-d",
            domain,
            "-t",
            str(threads),
            "--delay",
            str(delay),
        ]
        if full:
            command.append("--full")

        scan_type = "backup_full" if full else "backup"
        active_scans[scan_id] = {
            "type": scan_type,
            "target": domain,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }

        embed = self.create_scan_embed(scan_type, domain, "running")
        await interaction.response.send_message(embed=embed)

        # Run scan in background
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(
        name="githubdepconf",
        description="🔍 GitHub organization dependency confusion scan",
    )
    @app_commands.describe(
        org="GitHub organization name to scan",
        workers="Number of workers (default: 10, max: 50)",
        verbose="Enable verbose output",
    )
    async def githubdepconf(
        self,
        interaction: discord.Interaction,
        org: str,
        workers: int = 10,
        verbose: bool = False,
    ):
        """GitHub organization dependency confusion scan."""
        # Validate workers parameter
        if workers < 1 or workers > 50:
            await interaction.response.send_message(
                "❌ **Workers must be between 1 and 50**", ephemeral=True
            )
            return

        scan_id = f"githubdepconf_{int(time.time())}"

        command = [
            AUTOAR_SCRIPT_PATH,
            "depconfusion",
            "github",
            "org",
            org,
            "-w",
            str(workers),
        ]
        if verbose:
            command.append("-v")

        active_scans[scan_id] = {
            "type": "githubdepconf",
            "target": org,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }

        embed = discord.Embed(
            title="🔍 GitHub Organization Scan",
            description=f"**Organization:** {org}\n**Workers:** {workers}",
            color=0x00FF00,
        )
        embed.add_field(name="Scan ID", value=scan_id, inline=True)

        await interaction.response.send_message(embed=embed)

        # Run scan in background
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(
        name="live_depconfusion_scan",
        description="Scan live hosts for dependency confusion vulnerabilities",
    )
    @app_commands.describe(
        domain="Target domain to scan",
        threads="Number of threads (default: 10)",
        delay="Delay between requests in ms (default: 100)",
    )
    async def live_depconfusion_scan(
        self,
        interaction: discord.Interaction,
        domain: str,
        threads: int = 10,
        delay: int = 100,
    ):
        """Scan live hosts for dependency confusion vulnerabilities."""
        scan_id = f"live_depconfusion_{int(time.time())}"

        command = [
            AUTOAR_SCRIPT_PATH,
            "depconfusion",
            "web",
            f"https://{domain}",
            "-w",
            str(threads),
        ]

        active_scans[scan_id] = {
            "type": "live_depconfusion",
            "target": domain,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }

        embed = self.create_scan_embed("Live Dependency Confusion", domain, "running")
        await interaction.response.send_message(embed=embed)

        # Run scan in background
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(
        name="webdepconf", description="🔍 Web dependency confusion scan"
    )
    @app_commands.describe(
        target="Target URL or domain to scan",
        workers="Number of workers (default: 10, max: 50)",
        verbose="Enable verbose output",
        full="Collect subdomains and live hosts first",
    )
    async def webdepconf(
        self,
        interaction: discord.Interaction,
        target: str,
        workers: int = 10,
        verbose: bool = False,
        full: bool = False,
    ):
        """Web dependency confusion scan."""
        # Validate workers parameter
        if workers < 1 or workers > 50:
            await interaction.response.send_message(
                "❌ **Workers must be between 1 and 50**", ephemeral=True
            )
            return

        scan_id = f"webdepconf_{int(time.time())}"

        if full:
            # Use web-full command for subdomain collection
            command = [
                AUTOAR_SCRIPT_PATH,
                "depconfusion",
                "web-full",
                target,
                "-w",
                str(workers),
            ]
        else:
            # Use regular web command for single target
            command = [
                AUTOAR_SCRIPT_PATH,
                "depconfusion",
                "web",
                target,
                "--deep",
                "-w",
                str(workers),
            ]

        if verbose:
            command.append("-v")

        active_scans[scan_id] = {
            "type": "webdepconf",
            "target": target,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }

        embed = discord.Embed(
            title="🔍 Web Dependency Confusion Scan",
            description=f"**Target:** {target}\n**Workers:** {workers}\n**Mode:** {'Full (subdomains + live hosts)' if full else 'Single target (deep scan)'}",
            color=0x00FF00,
        )
        embed.add_field(name="Scan ID", value=scan_id, inline=True)

        await interaction.response.send_message(embed=embed)

        # Run scan in background
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(
        name="misconfig",
        description="🔍 Scan for security misconfigurations in third-party services",
    )
    @app_commands.describe(
        target="Company/organization name or domain to scan",
        service="Service ID to scan (default: all services)",
        delay="Delay between requests in milliseconds (default: 1000)",
        skip_checks="Skip misconfiguration checks (enumeration only)",
        verbose="Enable verbose output (sets verbose=2)",
        as_domain="Treat target as domain instead of company name",
    )
    async def misconfig(
        self,
        interaction: discord.Interaction,
        target: str,
        service: str = "*",
        delay: int = 1000,
        skip_checks: bool = False,
        verbose: bool = False,
        as_domain: bool = False,
    ):
        """Scan for security misconfigurations in third-party services."""
        # Validate parameters
        if delay < 100 or delay > 10000:
            await interaction.response.send_message(
                "❌ **Delay must be between 100 and 10000 milliseconds**",
                ephemeral=True,
            )
            return

        scan_id = f"misconfig_{int(time.time())}"

        # Build command with flags
        command = [AUTOAR_SCRIPT_PATH, "misconfig", "scan", target, service]

        # Add flags
        if verbose:
            command.append("-v")
        if delay != 1000:
            command.extend(["-d", str(delay)])
        if skip_checks:
            command.append("--skip-checks")
        if as_domain:
            command.append("--as-domain")

        active_scans[scan_id] = {
            "type": "misconfig",
            "target": target,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }

        embed = discord.Embed(
            title="🔍 Misconfiguration Scan",
            description=f"**Target:** {target}\n**Service:** {service}\n**Delay:** {delay}ms\n**Skip Checks:** {skip_checks}\n**Verbose:** {verbose}\n**As Domain:** {as_domain}",
            color=0x00FF00,
        )
        embed.add_field(name="Scan ID", value=scan_id, inline=True)

        await interaction.response.send_message(embed=embed)

        # Run scan in background
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(
        name="check_tools", description="Check if all required tools are installed"
    )
    async def check_tools(self, interaction: discord.Interaction):
        """Check if all required tools are installed."""
        try:
            command = [AUTOAR_SCRIPT_PATH, "check-tools", "run"]

            embed = discord.Embed(
                title="🔧 Tool Check",
                description="Checking required tools...",
                color=discord.Color.blue(),
            )
            await interaction.response.send_message(embed=embed)

            results = await self.run_autoar_command(command, "tool_check", timeout=60)

            if results["returncode"] == 0:
                embed.color = discord.Color.green()
                embed.title = "✅ Tool Check Complete"
                embed.description = (
                    "All required tools are installed and working properly."
                )
            else:
                embed.color = discord.Color.red()
                embed.title = "❌ Tool Check Failed"
                embed.description = "Some tools are missing or not working properly."
                if results["stderr"]:
                    embed.add_field(
                        name="Details",
                        value=f"```{results['stderr'][:1000]}```",
                        inline=False,
                    )
                if results["stdout"]:
                    embed.add_field(
                        name="Output",
                        value=f"```{results['stdout'][:1000]}```",
                        inline=False,
                    )

            await interaction.edit_original_response(embed=embed)
        except Exception as e:
            print(f"[ERROR] check_tools command failed: {e}")
            await interaction.response.send_message(
                f"❌ Error: {str(e)}", ephemeral=True
            )

    @app_commands.command(
        name="scan_status", description="Check status of active scans"
    )
    async def scan_status(self, interaction: discord.Interaction):
        """Check status of active scans."""
        if not active_scans:
            embed = discord.Embed(
                title="📊 Scan Status",
                description="No active scans",
                color=discord.Color.blue(),
            )
        else:
            embed = discord.Embed(title="📊 Active Scans", color=discord.Color.blue())

            for scan_id, scan_info in active_scans.items():
                duration = datetime.now() - scan_info["start_time"]
                status_emoji = "🟢" if scan_info["status"] == "running" else "🔴"

                embed.add_field(
                    name=f"{status_emoji} {scan_info['type'].title()} - {scan_info['target']}",
                    value=f"Status: {scan_info['status']}\nDuration: {duration}",
                    inline=False,
                )

        await interaction.response.send_message(embed=embed)

    @app_commands.command(name="subdomains", description="Enumerate subdomains")
    @app_commands.describe(
        domain="The domain to enumerate",
        threads="Number of threads for subfinder (default: 100)",
    )
    async def subdomains_cmd(
        self, interaction: discord.Interaction, domain: str, threads: int = 100
    ):
        scan_id = f"subdomains_{int(time.time())}"
        command = [
            AUTOAR_SCRIPT_PATH,
            "subdomains",
            "get",
            "-d",
            domain,
            "-t",
            str(threads),
        ]
        active_scans[scan_id] = {
            "type": "subdomains",
            "target": domain,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }
        embed = self.create_scan_embed("Subdomains", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(
        name="cnames", description="Collect CNAME records for domain subdomains"
    )
    @app_commands.describe(domain="The domain")
    async def cnames_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"cnames_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "cnames", "get", "-d", domain]
        active_scans[scan_id] = {
            "type": "cnames",
            "target": domain,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }
        embed = self.create_scan_embed("CNAMEs", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(
        name="livehosts", description="Filter live hosts from subdomains"
    )
    @app_commands.describe(
        domain="The domain", threads="Number of threads for httpx (default: 100)"
    )
    async def livehosts_cmd(
        self, interaction: discord.Interaction, domain: str, threads: int = 100
    ):
        scan_id = f"live_{int(time.time())}"
        command = [
            AUTOAR_SCRIPT_PATH,
            "livehosts",
            "get",
            "-d",
            domain,
            "-t",
            str(threads),
        ]
        active_scans[scan_id] = {
            "type": "live",
            "target": domain,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }
        embed = self.create_scan_embed("Live Hosts", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="urls", description="Collect URLs and JS URLs")
    @app_commands.describe(
        domain="The domain",
        threads="Number of threads for urlfinder and jsfinder (default: 100)",
    )
    async def urls_cmd(
        self, interaction: discord.Interaction, domain: str, threads: int = 100
    ):
        scan_id = f"urls_{int(time.time())}"
        command = [
            AUTOAR_SCRIPT_PATH,
            "urls",
            "collect",
            "-d",
            domain,
            "-t",
            str(threads),
        ]
        active_scans[scan_id] = {
            "type": "urls",
            "target": domain,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }
        embed = self.create_scan_embed("URLs", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="reflection", description="Run reflection scan (kxss)")
    @app_commands.describe(domain="The domain")
    async def reflection_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"reflection_{int(time.time())}"
        command = [
            AUTOAR_SCRIPT_PATH,
            "js",
            "scan",
            "-d",
            domain,
        ]  # js scan already extracts JS and runs regex; reflection separate:
        # We call reflection module explicitly
        command = [AUTOAR_SCRIPT_PATH, "reflection", "scan", "-d", domain]
        active_scans[scan_id] = {
            "type": "reflection",
            "target": domain,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }
        embed = self.create_scan_embed("Reflection", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(
        name="nuclei", description="Run nuclei templates on domain/URL"
    )
    @app_commands.describe(
        domain="The domain to scan (use either domain or url)",
        url="Single URL to scan (use either domain or url)",
        mode="Scan mode: full, cves, panels, default-logins, or vulnerabilities (default: full)",
        threads="Number of threads for nuclei (default: 100)",
    )
    @app_commands.choices(
        mode=[
            app_commands.Choice(name="Full (All Templates)", value="full"),
            app_commands.Choice(name="CVEs Only", value="cves"),
            app_commands.Choice(name="Panels Discovery", value="panels"),
            app_commands.Choice(name="Default Logins Only", value="default-logins"),
            app_commands.Choice(name="Generic Vulnerabilities", value="vulnerabilities"),
        ]
    )
    async def nuclei_cmd(
        self,
        interaction: discord.Interaction,
        domain: Optional[str] = None,
        url: Optional[str] = None,
        mode: str = "full",
        enum: bool = False,
        threads: int = 100,
    ):
        # Validation
        if not domain and not url:
            await interaction.response.send_message(
                "❌ Either domain or url must be provided", ephemeral=True
            )
            return

        if domain and url:
            await interaction.response.send_message(
                "❌ Cannot use both domain and url together", ephemeral=True
            )
            return

        scan_id = f"nuclei_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "nuclei", "run"]

        # Add target (domain or url)
        if domain:
            command.extend(["-d", domain])
            target = domain
        else:
            command.extend(["-u", url])
            target = url

        # Add mode
        command.extend(["-m", mode])

        # Add enum flag if requested (only valid with domain)
        if enum and domain:
            command.append("-e")

        # Add threads
        command.extend(["-t", str(threads)])

        # Determine scan description
        mode_desc = {
            "full": "Full (All Templates)",
            "cves": "CVEs Only",
            "panels": "Panels Discovery",
        }.get(mode, mode)

        enum_text = " with enum" if enum and domain else ""

        active_scans[scan_id] = {
            "type": f"nuclei-{mode}",
            "target": target,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }

        embed = self.create_scan_embed(
            f"Nuclei {mode_desc}{enum_text}", target, "running"
        )
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(
        name="react2shell",
        description="Test single URL for React Server Components RCE (CVE-2025-55182) using next88 smart scan"
    )
    @app_commands.describe(
        url="Target URL to test (e.g., https://example.com)",
        verbose="Enable verbose output",
    )
    async def react2shell_cmd(
        self,
        interaction: discord.Interaction,
        url: str,
        verbose: bool = False,
    ):
        """Test for React Server Components RCE vulnerability using next88 smart scan."""
        scan_id = f"react2shell_{int(time.time())}"

        # Normalize URL
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        active_scans[scan_id] = {
            "type": "react2shell",
            "target": url,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
            "verbose": verbose,
        }

        embed = discord.Embed(
            title="🔍 React2Shell RCE Test",
            description=f"**Target:** `{url}`\n**Method:** next88 Smart Scan (sequential: normal -> WAF bypass -> Vercel WAF -> paths)",
            color=discord.Color.blue(),
        )
        await interaction.response.send_message(embed=embed)

        # Run next88 smart scan
        asyncio.create_task(
            self._run_react2shell_single(scan_id, url, verbose)
        )

    async def _run_react2shell_single(
        self, scan_id: str, target: str, verbose: bool
    ):
        """Run React2Shell test on single URL using next88 smart scan."""
        try:
            webhook_url = self.get_discord_webhook()
            
            # Find next88 binary
            next88_bin = None
            for bin_name in ["next88", "react2shell"]:
                result = await asyncio.create_subprocess_exec(
                    "which", bin_name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await result.wait()
                if result.returncode == 0:
                    next88_bin = bin_name
                    break
            
            if not next88_bin:
                error_msg = "next88 binary not found. Please install: go install github.com/h0tak88r/next88@latest"
                if scan_id in active_scans:
                    active_scans[scan_id]["status"] = "failed"
                    active_scans[scan_id]["error"] = error_msg
                    interaction = active_scans[scan_id]["interaction"]
                    embed = discord.Embed(
                        title="❌ React2Shell Test Failed",
                        description=f"**Target:** `{target}`\n**Error:** {error_msg}",
                        color=discord.Color.red(),
                    )
                    try:
                        await interaction.edit_original_response(embed=embed)
                    except:
                        pass
                return
            
            # Create temp file for JSON output
            results_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json').name
            
            try:
                # Build next88 command - use JSON output for proper parsing
                command = [
                    next88_bin,
                    "-u", target,
                    "-k",  # Insecure (skip SSL verification)
                    "-o", results_file,
                    "-all-results",  # Get all results in JSON
                ]
                
                # Note: Smart scan flag may not be available in all next88 versions
                # We'll rely on JSON output parsing instead
                
                if webhook_url:
                    command.extend(["--discord-webhook", webhook_url])
                
                # Run next88
                process = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=120
                )
                
                stdout_str = stdout.decode("utf-8", errors="ignore") if stdout else ""
                stderr_str = stderr.decode("utf-8", errors="ignore") if stderr else ""
                
                # Parse JSON results to check if vulnerable and extract details
                is_vulnerable = False
                vulnerability_details = None
                poc_data = None
                
                if os.path.exists(results_file) and os.path.getsize(results_file) > 0:
                    try:
                        with open(results_file, 'r') as f:
                            data = json.load(f)
                            for result in data.get('results', []):
                                if result.get('vulnerable') is True:
                                    is_vulnerable = True
                                    # Extract vulnerability details - try multiple possible field names
                                    vulnerability_details = {
                                        'method': result.get('method', result.get('test_method', 'Unknown')),
                                        'phase': result.get('phase', result.get('waf_bypass', result.get('bypass_type', 'normal'))),
                                        'path': result.get('path', result.get('url', '')),
                                        'status_code': result.get('status_code', result.get('status', '')),
                                    }
                                    # Extract PoC (request/response) - try multiple possible field names
                                    poc_data = {
                                        'request': result.get('request', result.get('request_body', result.get('payload', result.get('request_data', '')))),
                                        'response': result.get('response', result.get('response_body', result.get('response_data', ''))),
                                        'headers': result.get('headers', result.get('request_headers', {})),
                                    }
                                    break
                    except Exception as e:
                        print(f"[WARN] Failed to parse JSON results: {e}")
                        # Fallback to stdout check
                        is_vulnerable = "[VULNERABLE]" in stdout_str or "vulnerable" in stdout_str.lower()
                else:
                    # Fallback to stdout/stderr check
                    is_vulnerable = "[VULNERABLE]" in stdout_str or "vulnerable" in stdout_str.lower() or process.returncode != 0
                
                # Update scan status
                if scan_id in active_scans:
                    active_scans[scan_id]["status"] = "completed"
                active_scans[scan_id]["results"] = {
                    "returncode": process.returncode,
                    "stdout": stdout_str,
                    "stderr": stderr_str,
                }
                
                # Create result embed
                color = discord.Color.red() if is_vulnerable else discord.Color.green()
                embed = discord.Embed(
                    title="🔍 React2Shell RCE Test Results",
                    description=f"**Target:** `{target}`",
                    color=color,
                )
                
                status_text = "🔴 **Vulnerable**" if is_vulnerable else "✅ **Not Vulnerable**"
                embed.add_field(name="Status", value=status_text, inline=False)
                
                # Add detection phase/method details if available
                if is_vulnerable and vulnerability_details:
                    phase = vulnerability_details.get('phase', 'Unknown')
                    method = vulnerability_details.get('method', 'Unknown')
                    
                    # Map phase to readable format
                    phase_map = {
                        'normal': 'Normal RCE Test',
                        'waf_bypass': 'WAF Bypass',
                        'vercel_waf': 'Vercel WAF Bypass',
                        'paths': 'Common Paths',
                    }
                    phase_display = phase_map.get(phase.lower(), phase.title())
                    
                    detection_info = f"**Detection Phase:** {phase_display}"
                    if method and method != 'Unknown':
                        detection_info += f"\n**Method:** {method}"
                    if vulnerability_details.get('path'):
                        detection_info += f"\n**Path:** `{vulnerability_details['path']}`"
                    if vulnerability_details.get('status_code'):
                        detection_info += f"\n**Status Code:** `{vulnerability_details['status_code']}`"
                    
                    embed.add_field(name="Detection Details", value=detection_info, inline=False)
                else:
                    embed.add_field(
                        name="Method",
                        value="next88 Smart Scan (sequential: normal → WAF bypass → Vercel WAF → paths)",
                        inline=False,
                    )
                
                # Add PoC (Proof of Concept) if available
                poc_file_path = None
                if is_vulnerable and poc_data:
                    # Create PoC JSON file
                    poc_json = {
                        'target': target,
                        'vulnerability_details': vulnerability_details,
                        'request': poc_data.get('request', ''),
                        'response': poc_data.get('response', ''),
                        'headers': poc_data.get('headers', {}),
                    }
                    
                    try:
                        safe_filename = target.replace('https://', '').replace('http://', '').replace('/', '_').replace(':', '_')
                        poc_file_path = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json', prefix=f'poc_{safe_filename}_')
                        json.dump(poc_json, poc_file_path, indent=2)
                        poc_file_path.close()
                        poc_file_path = poc_file_path.name
                    except Exception as e:
                        print(f"[WARN] Failed to create PoC file: {e}")
                        poc_file_path = None
                    
                    # Add PoC summary to embed
                    poc_summary = ""
                    if poc_data.get('request'):
                        request_preview = str(poc_data['request'])[:500]
                        poc_summary += f"**Request:**\n```\n{request_preview}{'...' if len(str(poc_data['request'])) > 500 else ''}\n```\n"
                    if poc_data.get('response'):
                        response_preview = str(poc_data['response'])[:500]
                        poc_summary += f"**Response:**\n```\n{response_preview}{'...' if len(str(poc_data['response'])) > 500 else ''}\n```\n"
                    
                    if poc_summary:
                        embed.add_field(name="Proof of Concept", value=poc_summary, inline=False)
                
                # Update Discord message
                interaction = active_scans[scan_id]["interaction"]
                try:
                    if poc_file_path and os.path.exists(poc_file_path):
                        poc_file = discord.File(poc_file_path, filename=f"poc_{target.replace('https://', '').replace('http://', '').replace('/', '_')[:50]}.json")
                        await interaction.edit_original_response(embed=embed, attachments=[poc_file])
                        # Clean up PoC file after sending
                        try:
                            os.unlink(poc_file_path)
                        except:
                            pass
                    else:
                        await interaction.edit_original_response(embed=embed)
                except Exception as e:
                    print(f"[WARN] Failed to send message: {e}")
                    try:
                        await interaction.edit_original_response(embed=embed)
                    except:
                        pass
                
                # Add verbose output if requested
                if verbose and (stdout_str or stderr_str):
                    log_text = ""
                    if stdout_str:
                        log_text += f"**Output:**\n```\n{stdout_str[:1000]}{'...' if len(stdout_str) > 1000 else ''}\n```\n"
                    if stderr_str:
                        log_text += f"**Errors:**\n```\n{stderr_str[:500]}{'...' if len(stderr_str) > 500 else ''}\n```"
                    if log_text:
                        # Create a followup message for verbose output to avoid embed size limits
                        try:
                            await interaction.followup.send(f"**Verbose Output:**\n{log_text}", ephemeral=True)
                        except:
                            pass
            finally:
                # Clean up temp file
                if os.path.exists(results_file):
                    try:
                        os.unlink(results_file)
                    except:
                        pass
                    
        except asyncio.TimeoutError:
            error_msg = "Scan timed out after 120 seconds"
            if scan_id in active_scans:
                active_scans[scan_id]["status"] = "failed"
                active_scans[scan_id]["error"] = error_msg
                interaction = active_scans[scan_id]["interaction"]
                embed = discord.Embed(
                    title="⏱️ React2Shell Test Timeout",
                    description=f"**Target:** `{target}`\n**Error:** {error_msg}",
                    color=discord.Color.orange(),
                )
                try:
                    await interaction.edit_original_response(embed=embed)
                except:
                    pass
        except Exception as e:
            print(f"Error in React2Shell test {scan_id}: {e}")
            if scan_id in active_scans:
                active_scans[scan_id]["status"] = "failed"
                active_scans[scan_id]["error"] = str(e)
                interaction = active_scans[scan_id]["interaction"]
                embed = discord.Embed(
                    title="❌ React2Shell Test Failed",
                    description=f"**Target:** `{target}`\n**Error:** {str(e)}",
                    color=discord.Color.red(),
                )
                try:
                    await interaction.edit_original_response(embed=embed)
                except:
                    pass

    @app_commands.command(name="tech", description="Detect technologies on live hosts")
    @app_commands.describe(
        domain="The domain", threads="Number of threads for httpx (default: 100)"
    )
    async def tech_cmd(
        self, interaction: discord.Interaction, domain: str, threads: int = 100
    ):
        scan_id = f"tech_{int(time.time())}"
        command = [
            AUTOAR_SCRIPT_PATH,
            "tech",
            "detect",
            "-d",
            domain,
            "-t",
            str(threads),
        ]
        active_scans[scan_id] = {
            "type": "tech",
            "target": domain,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }
        embed = self.create_scan_embed("Tech Detect", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(
        name="react2shell_scan",
        description="Scan domain hosts for React Server Components RCE (CVE-2025-55182) using WAF bypass methods"
    )
    @app_commands.describe(
        domain="The domain to scan",
        threads="Number of threads for livehosts detection (default: 100)",
        enable_source_exposure="Enable source code exposure check via ACTION_ID extraction from JS files (default: False, can be slow)",
        dos_test="Enable DoS test by sending multiple requests (default: False)"
    )
    async def react2shell_scan_cmd(
        self, interaction: discord.Interaction, domain: str, threads: int = 100, enable_source_exposure: bool = False, dos_test: bool = False
    ):
        scan_id = f"react2shell_scan_{int(time.time())}"
        active_scans[scan_id] = {
            "type": "react2shell_scan",
            "target": domain,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
            "enable_source_exposure": enable_source_exposure,
            "dos_test": dos_test,
            "threads": threads,
        }
        
        # Create embed with source exposure status
        embed_title = "React2Shell Host Scan"
        embed_desc = f"**Domain:** `{domain}`\n**Threads:** {threads}"
        if enable_source_exposure:
            embed_desc += "\n**Source Exposure Check:** Enabled (may take longer)"
        else:
            embed_desc += "\n**Source Exposure Check:** Disabled (faster scan)"
        if dos_test:
            embed_desc += "\n**DoS Test:** Enabled"
        else:
            embed_desc += "\n**DoS Test:** Disabled"
        embed_desc += "\n**Scan Method:** Smart Scan (next88 - sequential testing)"
        
        embed = discord.Embed(
            title=embed_title,
            description=embed_desc,
            color=discord.Color.blue(),
        )
        embed.add_field(name="Status", value="🟡 Running", inline=False)
        
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_react2shell_scan(scan_id, domain, threads, enable_source_exposure, dos_test))

    @app_commands.command(
        name="ports", description="Run port scan (naabu) on live hosts"
    )
    @app_commands.describe(
        domain="The domain", threads="Number of threads for naabu (default: 100)"
    )
    async def ports_cmd(
        self, interaction: discord.Interaction, domain: str, threads: int = 100
    ):
        scan_id = f"ports_{int(time.time())}"
        command = [
            AUTOAR_SCRIPT_PATH,
            "ports",
            "scan",
            "-d",
            domain,
            "-t",
            str(threads),
        ]
        active_scans[scan_id] = {
            "type": "ports",
            "target": domain,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }
        embed = self.create_scan_embed("Ports", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="gf_scan", description="Run GF pattern scans")
    @app_commands.describe(domain="The domain")
    async def gf_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"gf_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "gf", "scan", "-d", domain]
        active_scans[scan_id] = {
            "type": "gf",
            "target": domain,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }
        embed = self.create_scan_embed("GF Scan", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="sqlmap", description="Run SQLMap on GF SQLi results")
    @app_commands.describe(
        domain="The domain", threads="Number of threads for sqlmap (default: 100)"
    )
    async def sqlmap_cmd(
        self, interaction: discord.Interaction, domain: str, threads: int = 100
    ):
        scan_id = f"sqlmap_{int(time.time())}"
        command = [
            AUTOAR_SCRIPT_PATH,
            "sqlmap",
            "run",
            "-d",
            domain,
            "-t",
            str(threads),
        ]
        active_scans[scan_id] = {
            "type": "sqlmap",
            "target": domain,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }
        embed = self.create_scan_embed("SQLMap", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="dalfox", description="Run Dalfox XSS scan")
    @app_commands.describe(
        domain="The domain", threads="Number of threads for dalfox (default: 100)"
    )
    async def dalfox_cmd(
        self, interaction: discord.Interaction, domain: str, threads: int = 100
    ):
        scan_id = f"dalfox_{int(time.time())}"
        command = [
            AUTOAR_SCRIPT_PATH,
            "dalfox",
            "run",
            "-d",
            domain,
            "-t",
            str(threads),
        ]
        active_scans[scan_id] = {
            "type": "dalfox",
            "target": domain,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }
        embed = self.create_scan_embed("Dalfox", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(
        name="dns_takeover", description="Run comprehensive DNS takeover scan"
    )
    @app_commands.describe(domain="The domain")
    async def dns_takeover_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"dnstko_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "dns", "takeover", "-d", domain]
        active_scans[scan_id] = {
            "type": "dns_takeover",
            "target": domain,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }
        embed = self.create_scan_embed("DNS Takeover", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="dns_cname", description="Run CNAME takeover scan")
    @app_commands.describe(domain="The domain")
    async def dns_cname_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"dnscname_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "dns", "cname", "-d", domain]
        active_scans[scan_id] = {
            "type": "dns_cname",
            "target": domain,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }
        embed = self.create_scan_embed("DNS CNAME", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="dns_ns", description="Run NS takeover scan")
    @app_commands.describe(domain="The domain")
    async def dns_ns_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"dnsns_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "dns", "ns", "-d", domain]
        active_scans[scan_id] = {
            "type": "dns_ns",
            "target": domain,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }
        embed = self.create_scan_embed("DNS NS", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(
        name="dns_azure_aws", description="Run Azure & AWS takeover scan"
    )
    @app_commands.describe(domain="The domain")
    async def dns_azure_aws_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"dnscloud_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "dns", "azure-aws", "-d", domain]
        active_scans[scan_id] = {
            "type": "dns_azure_aws",
            "target": domain,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }
        embed = self.create_scan_embed("DNS Azure/AWS", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(
        name="keyhack_list", description="📋 List all API key validation templates"
    )
    async def keyhack_list_cmd(self, interaction: discord.Interaction):
        """List all available API key validation templates."""
        await interaction.response.defer()
        
        scan_id = f"keyhack_list_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "keyhack", "list"]
        
        active_scans[scan_id] = {
            "type": "keyhack_list",
            "target": "all",
            "started_at": datetime.now().isoformat(),
            "status": "running",
        }
        
        result = await self.run_autoar_command(command, scan_id, timeout=10)
        
        if result["returncode"] == 0:
            output = result["stdout"]
            active_scans[scan_id]["status"] = "completed"
            active_scans[scan_id]["output"] = output
            
            embed = discord.Embed(
                title="📋 KeyHack Templates List",
                description="All available API key validation templates",
                color=discord.Color.blue(),
            )
            
            # Format output for Discord (limit to 2000 chars)
            if len(output) > 1900:
                output = output[:1900] + "\n... (truncated - use search for specific templates)"
            
            embed.add_field(name="Templates", value=f"```\n{output}\n```", inline=False)
            await interaction.followup.send(embed=embed)
        else:
            error_msg = result["stderr"] or "Failed to list templates"
            active_scans[scan_id]["status"] = "failed"
            active_scans[scan_id]["error"] = error_msg
            
            embed = discord.Embed(
                title="❌ KeyHack List Failed",
                color=discord.Color.red(),
            )
            embed.add_field(name="Error", value=f"```\n{error_msg}\n```", inline=False)
            await interaction.followup.send(embed=embed)

    @app_commands.command(
        name="keyhack_search", description="🔍 Search for API key validation templates"
    )
    @app_commands.describe(
        query="Search query (provider name or partial match)"
    )
    async def keyhack_search_cmd(
        self, interaction: discord.Interaction, query: str
    ):
        """Search for API key validation templates."""
        await interaction.response.defer()
        
        scan_id = f"keyhack_search_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "keyhack", "search", query]
        
        active_scans[scan_id] = {
            "type": "keyhack_search",
            "target": query,
            "started_at": datetime.now().isoformat(),
            "status": "running",
        }
        
        result = await self.run_autoar_command(command, scan_id, timeout=10)
        
        if result["returncode"] == 0:
            output = result["stdout"]
            active_scans[scan_id]["status"] = "completed"
            active_scans[scan_id]["output"] = output
            
            embed = discord.Embed(
                title="🔍 KeyHack Search Results",
                description=f"**Query:** `{query}`",
                color=discord.Color.blue(),
            )
            
            # Format output for Discord (limit to 2000 chars)
            if len(output) > 1900:
                output = output[:1900] + "\n... (truncated)"
            
            embed.add_field(name="Results", value=f"```\n{output}\n```", inline=False)
            await interaction.followup.send(embed=embed)
        else:
            error_msg = result["stderr"] or "Search failed"
            active_scans[scan_id]["status"] = "failed"
            active_scans[scan_id]["error"] = error_msg
            
            embed = discord.Embed(
                title="❌ KeyHack Search Failed",
                description=f"**Query:** `{query}`",
                color=discord.Color.red(),
            )
            embed.add_field(name="Error", value=f"```\n{error_msg}\n```", inline=False)
            await interaction.followup.send(embed=embed)

    @app_commands.command(
        name="keyhack_add", description="➕ Add a new API key validation template"
    )
    @app_commands.describe(
        keyname="Template name (e.g., Slack, Bing Maps)",
        command="Validation command (curl or shell command with $API_KEY placeholder)",
        description="Description of the template",
        notes="Optional notes or additional information"
    )
    async def keyhack_add_cmd(
        self,
        interaction: discord.Interaction,
        keyname: str,
        command: str,
        description: str,
        notes: str = "",
    ):
        """Add a new API key validation template to the database."""
        await interaction.response.defer()

        scan_id = f"keyhack_add_{int(time.time())}"
        cmd = [AUTOAR_SCRIPT_PATH, "keyhack", "add", keyname, command, description]
        if notes:
            cmd.append(notes)

        active_scans[scan_id] = {
            "type": "keyhack_add",
            "target": keyname,
            "started_at": datetime.now().isoformat(),
            "status": "running",
        }

        result = await self.run_autoar_command(cmd, scan_id, timeout=10)

        if result["returncode"] == 0:
            output = result["stdout"]
            active_scans[scan_id]["status"] = "completed"
            active_scans[scan_id]["output"] = output

            embed = discord.Embed(
                title="✅ Template Added Successfully",
                description=f"**Template:** `{keyname}`",
                color=discord.Color.green(),
            )
            embed.add_field(name="Description", value=description, inline=False)
            if notes:
                embed.add_field(name="Notes", value=notes, inline=False)
            embed.add_field(
                name="Command", value=f"```bash\n{command[:500]}\n```", inline=False
            )

            await interaction.followup.send(embed=embed)
        else:
            error_msg = result["stderr"] or result["stdout"] or "Failed to add template"
            active_scans[scan_id]["status"] = "failed"
            active_scans[scan_id]["error"] = error_msg

            embed = discord.Embed(
                title="❌ Failed to Add Template",
                description=f"**Template:** `{keyname}`",
                color=discord.Color.red(),
            )
            embed.add_field(name="Error", value=f"```\n{error_msg[:1000]}\n```", inline=False)
            await interaction.followup.send(embed=embed)

    @app_commands.command(
        name="keyhack_validate", description="🔐 Generate API key validation command"
    )
    @app_commands.describe(
        provider="Provider name (e.g., Stripe, AWS, GitHub)",
        api_key="API key to validate"
    )
    async def keyhack_validate_cmd(
        self, interaction: discord.Interaction, provider: str, api_key: str
    ):
        """Generate validation command for an API key."""
        await interaction.response.defer()
        
        scan_id = f"keyhack_validate_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "keyhack", "validate", provider, api_key]
        
        active_scans[scan_id] = {
            "type": "keyhack_validate",
            "target": provider,
            "started_at": datetime.now().isoformat(),
            "status": "running",
        }
        
        result = await self.run_autoar_command(command, scan_id, timeout=10)
        
        if result["returncode"] == 0:
            output = result["stdout"]
            active_scans[scan_id]["status"] = "completed"
            active_scans[scan_id]["output"] = output
            
            embed = discord.Embed(
                title="🔐 API Key Validation Command",
                description=f"**Provider:** `{provider}`",
                color=discord.Color.green(),
            )
            
            # Extract command from output (look for the curl command)
            import re
            command_match = re.search(r'curl[^\n]+', output)
            if command_match:
                command_line = command_match.group(0)
                embed.add_field(
                    name="Validation Command",
                    value=f"```bash\n{command_line}\n```",
                    inline=False,
                )
            else:
                # Format full output for Discord (limit to 2000 chars)
                if len(output) > 1900:
                    output = output[:1900] + "\n... (truncated)"
                embed.add_field(name="Output", value=f"```\n{output}\n```", inline=False)
            
            await interaction.followup.send(embed=embed)
        else:
            error_msg = result["stderr"] or "Validation failed"
            active_scans[scan_id]["status"] = "failed"
            active_scans[scan_id]["error"] = error_msg
            
            embed = discord.Embed(
                title="❌ API Key Validation Failed",
                description=f"**Provider:** `{provider}`",
                color=discord.Color.red(),
            )
            embed.add_field(name="Error", value=f"```\n{error_msg}\n```", inline=False)
            await interaction.followup.send(embed=embed)

    @app_commands.command(
        name="dns_dnsreaper", description="Run DNSReaper takeover scan"
    )
    @app_commands.describe(domain="The domain")
    async def dns_dnsreaper_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"dnsreaper_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "dns", "dnsreaper", "-d", domain]
        active_scans[scan_id] = {
            "type": "dns_dnsreaper",
            "target": domain,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }
        embed = self.create_scan_embed("DNSReaper", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="domain_run", description="Run full domain workflow")
    @app_commands.describe(domain="The domain")
    async def domain_run_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"domainrun_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "domain", "run", "-d", domain]
        active_scans[scan_id] = {
            "type": "domain",
            "target": domain,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }
        embed = self.create_scan_embed("Domain Workflow", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(
        name="db_domains",
        description="List distinct domains stored in PostgreSQL database",
    )
    async def db_domains_cmd(self, interaction: discord.Interaction):
        scan_id = f"dbdomains_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "db", "domains", "list"]
        active_scans[scan_id] = {
            "type": "db_domains",
            "target": "db",
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }
        db_name = os.getenv("DB_NAME", "autoar")
        embed = self.create_scan_embed(
            "DB Domains", f"{db_name} (PostgreSQL)", "running"
        )
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(
        name="db_subdomains",
        description="List subdomains for a domain from PostgreSQL database",
    )
    @app_commands.describe(domain="The domain to list subdomains for")
    async def db_subdomains_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"dbsubs_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "db", "subdomains", "list", "-d", domain]
        active_scans[scan_id] = {
            "type": "db_subdomains",
            "target": domain,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }
        embed = self.create_scan_embed("DB Subdomains", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(
        name="db_delete_domain",
        description="Delete domain and all related data from database",
    )
    @app_commands.describe(
        domain="The domain to delete", force="Skip confirmation prompt"
    )
    async def db_delete_domain_cmd(
        self, interaction: discord.Interaction, domain: str, force: bool = False
    ):
        """Delete domain and all related data from database."""
        scan_id = f"dbdel_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "db", "domains", "delete", "-d", domain]
        if force:
            command.append("-f")

        active_scans[scan_id] = {
            "type": "db_delete_domain",
            "target": domain,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }

        embed = self.create_scan_embed("DB Delete Domain", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="s3_enum", description="Enumerate potential S3 buckets")
    @app_commands.describe(root="Root domain name, e.g., vulnweb")
    async def s3_enum_cmd(self, interaction: discord.Interaction, root: str):
        scan_id = f"s3enum_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "s3", "enum", "-b", root]
        active_scans[scan_id] = {
            "type": "s3_enum",
            "target": root,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }
        embed = self.create_scan_embed("S3 Enum", root, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="cleanup", description="Cleanup results for a domain")
    @app_commands.describe(
        domain="The domain to cleanup", keep="Keep results (do nothing)"
    )
    async def cleanup_cmd(
        self, interaction: discord.Interaction, domain: str, keep: bool = False
    ):
        scan_id = f"cleanup_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "cleanup", "run", "--domain", domain]
        if keep:
            command.append("--keep")
        active_scans[scan_id] = {
            "type": "cleanup",
            "target": domain,
            "status": "running",
            "start_time": datetime.now(),
            "interaction": interaction,
        }
        embed = self.create_scan_embed("Cleanup", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(
        name="help_autoar", description="Show AutoAR help information"
    )
    async def help_autoar(self, interaction: discord.Interaction):
        """Show AutoAR help information."""
        # Send immediate response
        embed = discord.Embed(
            title="📖 AutoAR Help",
            description="Loading AutoAR help information...",
            color=discord.Color.blue(),
        )
        await interaction.response.send_message(embed=embed)

        # Run command in background
        command = [AUTOAR_SCRIPT_PATH, "help"]
        results = await self.run_autoar_command(command, "help", timeout=10)

        # Update with actual help content
        embed.description = "AutoAR Security Scanning Tool - Available Commands"
        if results["returncode"] == 0 and results["stdout"]:
            help_text = results["stdout"][:1900]
            if len(results["stdout"]) > 1900:
                help_text += "\n... (truncated)"
            embed.add_field(name="Commands", value=f"```{help_text}```", inline=False)
        else:
            # Fallback to manual command list
            embed.add_field(
                name="Core Commands",
                value="• `/lite_scan` - Quick scan\n• `/fast_look` - Fast lookup\n• `/scan_domain` - Full scan\n• `/js_scan` - JavaScript scan\n• `/gf_scan` - GF pattern scans\n• `/sqlmap` - SQLMap scan\n• `/dalfox` - Dalfox XSS scan",
                inline=False,
            )
            embed.add_field(
                name="Database Commands",
                value="• `/db_domains` - List domains\n• `/db_subdomains` - List subdomains\n• `/db_domains_delete` - Delete domain\n• `/db_stats` - Statistics\n• `/db_cleanup` - Cleanup old data\n• `/db_subdomains_all` - All subdomains\n• `/db_js_list` - JS files",
                inline=False,
            )
            embed.add_field(
                name="Other Commands",
                value="• `/nuclei` - Nuclei scan (modes: full, cves, panels, default-logins, vulnerabilities)\n  (subdomain/livehost enumeration is automatic for domain scans)\n• `/ports` - Port scan\n• `/tech` - Tech detection\n• `/s3_scan` - S3 bucket scan\n• `/github_scan` - GitHub secrets scan",
                inline=False,
            )

        await interaction.edit_original_response(embed=embed)


    async def _run_react2shell_scan(
        self, scan_id: str, domain: str, threads: int, enable_source_exposure: bool, dos_test: bool
    ):
        """Run React2Shell scan directly using next88 tool."""
        try:
            # Get Discord webhook for next88
            discord_webhook = self.get_discord_webhook()
            
            # Step 1: Get live hosts
            live_hosts_file = await self._get_live_hosts(domain, threads)
            if not live_hosts_file:
                await self._update_scan_embed(scan_id, "❌ No live hosts found", discord.Color.red())
                return
            
            # Normalize hosts (add https:// if missing)
            normalized_hosts = await self._normalize_hosts(live_hosts_file)
            if not normalized_hosts:
                await self._update_scan_embed(scan_id, "❌ Failed to normalize hosts", discord.Color.red())
                return
            
            # Step 2: Run smart scan (normal -> WAF bypass -> Vercel WAF -> paths sequentially)
            smart_scan_results = await self._run_next88_scan(normalized_hosts, ["-smart-scan"], discord_webhook)
            
            # Step 3: DoS test (if enabled)
            dos_results = []
            if dos_test:
                dos_results = await self._run_next88_scan(normalized_hosts, ["-dos-test", "-dos-requests", "100"], discord_webhook)
            
            # Step 4: Source code exposure check (optional)
            source_exposure_results = []
            if enable_source_exposure:
                source_exposure_results = await self._run_source_exposure_check(domain, normalized_hosts, discord_webhook)
            
            # Collect all vulnerable hosts (from smart scan + optional tests)
            all_vulnerable = set()
            all_vulnerable.update(smart_scan_results)
            all_vulnerable.update(dos_results)
            all_vulnerable.update(source_exposure_results)
            
            # Format and send results
            await self._send_react2shell_results(
                scan_id, domain, len(normalized_hosts), 
                len(smart_scan_results), len(dos_results), len(source_exposure_results), 
                list(all_vulnerable)
            )
            
        except Exception as e:
            error_msg = f"❌ Error during scan: {str(e)}"
            print(f"[ERROR] {error_msg}")
            await self._update_scan_embed(scan_id, error_msg, discord.Color.red())
    
    async def _get_live_hosts(self, domain: str, threads: int) -> Optional[str]:
        """Get live hosts using livehosts module."""
        try:
            livehosts_script = Path("/app/modules/livehosts.sh")
            if not livehosts_script.exists():
                return None
            
            # Run livehosts module
            command = [str(livehosts_script), "get", "-d", domain, "-t", str(threads), "--silent"]
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.wait()
            
            # Check for live hosts file
            results_dir = Path(RESULTS_DIR) / domain
            live_hosts_file = results_dir / "subs" / "live-subs.txt"
            
            if live_hosts_file.exists() and live_hosts_file.stat().st_size > 0:
                return str(live_hosts_file)
            
            # Try all-subs.txt as fallback
            all_subs_file = results_dir / "subs" / "all-subs.txt"
            if all_subs_file.exists() and all_subs_file.stat().st_size > 0:
                return str(all_subs_file)
            
            return None
        except Exception as e:
            print(f"[ERROR] Failed to get live hosts: {e}")
            return None
    
    async def _normalize_hosts(self, hosts_file: str) -> Optional[list]:
        """Normalize hosts (add https:// if missing)."""
        try:
            normalized = []
            with open(hosts_file, 'r') as f:
                for line in f:
                    host = line.strip()
                    if not host:
                        continue
                    if not host.startswith(('http://', 'https://')):
                        host = f"https://{host}"
                    normalized.append(host)
            return normalized if normalized else None
        except Exception as e:
            print(f"[ERROR] Failed to normalize hosts: {e}")
            return None
    
    async def _run_next88_scan(self, hosts: list, extra_flags: list, discord_webhook: Optional[str]) -> list:
        """Run next88 scan with given flags."""
        try:
            # Find next88 binary
            next88_bin = None
            for bin_name in ["next88", "react2shell"]:
                result = await asyncio.create_subprocess_exec(
                    "which", bin_name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await result.wait()
                if result.returncode == 0:
                    next88_bin = bin_name
                    break
            
            if not next88_bin:
                # Fallback to Python script
                python_script = Path("/app/python/react2shell.py")
                if not python_script.exists():
                    return []
                next88_bin = "python3"
                extra_flags = [str(python_script)] + extra_flags
            
            # Write hosts to temp file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                for host in hosts:
                    f.write(f"{host}\n")
                temp_file = f.name
            
            # Write results to temp JSON file
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
                results_file = f.name
            
            try:
                command = [next88_bin]
                if next88_bin == "python3":
                    # Python script flags
                    command.extend([
                        "-l", temp_file,
                        "-k", "-q", "-o", results_file, "-all-results"
                    ])
                    # Convert Go flags to Python flags
                    python_flags = []
                    i = 0
                    while i < len(extra_flags):
                        flag = extra_flags[i]
                        if flag == "-waf-bypass":
                            python_flags.append("--waf-bypass")
                        elif flag == "-vercel-waf-bypass":
                            python_flags.append("--vercel-waf-bypass")
                        elif flag == "-check-source-exposure":
                            python_flags.append("--check-source-exposure")
                        elif flag == "-dos-test":
                            python_flags.append("--dos-test")
                        elif flag == "-dos-requests" and i + 1 < len(extra_flags):
                            python_flags.extend(["--dos-requests", extra_flags[i + 1]])
                            i += 1
                        elif flag == "-smart-scan":
                            python_flags.append("--smart-scan")
                        elif flag == "-path-file" and i + 1 < len(extra_flags):
                            python_flags.extend(["--path-file", extra_flags[i + 1]])
                            i += 1
                        i += 1
                    command.extend(python_flags)
                else:
                    # Go binary flags
                    command.extend([
                        "-l", temp_file,
                        "-k", "-q", "-o", results_file, "-all-results"
                    ])
                    # Handle flags - smart-scan may not be available, so we'll try it but handle errors
                    i = 0
                    while i < len(extra_flags):
                        flag = extra_flags[i]
                        if flag == "-dos-test":
                            command.append("-dos-test")
                        elif flag == "-dos-requests" and i + 1 < len(extra_flags):
                            command.extend(["-dos-requests", extra_flags[i + 1]])
                            i += 1
                        elif flag == "-smart-scan":
                            # Try to add smart-scan flag - if next88 doesn't support it, it will error
                            # But we'll catch that and continue without it
                            command.append("-smart-scan")
                        else:
                            command.append(flag)
                        i += 1
                
                # Add Discord webhook if available
                if discord_webhook:
                    if next88_bin == "python3":
                        command.extend(["--discord-webhook", discord_webhook])
                    else:
                        command.extend(["--discord-webhook", discord_webhook])
                
                process = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await process.communicate()
                await process.wait()
                
                # Check for errors (like unknown flag)
                stderr_str = stderr.decode("utf-8", errors="ignore") if stderr else ""
                stdout_str = stdout.decode("utf-8", errors="ignore") if stdout else ""
                
                # Log command for debugging
                print(f"[DEBUG] next88 command: {' '.join(command)}")
                print(f"[DEBUG] next88 return code: {process.returncode}")
                
                if stderr_str and ("not defined" in stderr_str.lower() or "unknown flag" in stderr_str.lower()):
                    print(f"[WARN] next88 error: {stderr_str}")
                    # If smart-scan flag failed, retry without it
                    if "-smart-scan" in extra_flags:
                        print("[INFO] Retrying without -smart-scan flag...")
                        # Remove smart-scan and retry with normal scan
                        retry_flags = [f for f in extra_flags if f != "-smart-scan"]
                        return await self._run_next88_scan(hosts, retry_flags, discord_webhook)
                
                # Also check if process failed
                if process.returncode != 0 and not stderr_str:
                    print(f"[WARN] next88 exited with code {process.returncode} but no stderr")
                    if stdout_str:
                        print(f"[DEBUG] stdout: {stdout_str[:500]}")
                
                # Parse JSON results
                vulnerable_hosts = set()
                if os.path.exists(results_file) and os.path.getsize(results_file) > 0:
                    try:
                        with open(results_file, 'r') as f:
                            data = json.load(f)
                            
                        # Debug: Print structure to understand format
                        print(f"[DEBUG] next88 JSON structure - top level keys: {list(data.keys())}")
                        if 'results' in data:
                            print(f"[DEBUG] Number of results: {len(data.get('results', []))}")
                            if len(data.get('results', [])) > 0:
                                print(f"[DEBUG] First result keys: {list(data['results'][0].keys())}")
                                print(f"[DEBUG] First result sample: {json.dumps(data['results'][0], indent=2)[:500]}")
                        
                        # Handle different JSON structures
                        results_list = data.get('results', [])
                        if not results_list and isinstance(data, list):
                            # Sometimes the JSON is just an array
                            results_list = data
                        
                        for result in results_list:
                            # Check multiple possible field names for vulnerability
                            is_vulnerable = (
                                result.get('vulnerable') is True or
                                result.get('vulnerable') == 'true' or
                                result.get('vulnerable') == 'True' or
                                result.get('is_vulnerable') is True or
                                result.get('found') is True or
                                result.get('detected') is True or
                                'vulnerable' in str(result).lower() and 'false' not in str(result).lower()
                            )
                            
                            if is_vulnerable:
                                host = result.get('host', result.get('url', result.get('target', result.get('hostname', ''))))
                                if host:
                                    # Clean up host string
                                    host = host.strip()
                                    parsed = urlparse(host)
                                    if parsed.netloc:
                                        vulnerable_hosts.add(parsed.netloc.split(':')[0])
                                    else:
                                        # Remove protocol and path
                                        clean_host = host.replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
                                        if clean_host:
                                            vulnerable_hosts.add(clean_host)
                                print(f"[DEBUG] Found vulnerable host: {host}")
                        
                        print(f"[DEBUG] Total vulnerable hosts found: {len(vulnerable_hosts)}")
                    except Exception as e:
                        print(f"[ERROR] Failed to parse next88 JSON results: {e}")
                        import traceback
                        traceback.print_exc()
                        # Try to read raw file for debugging
                        if os.path.exists(results_file):
                            try:
                                with open(results_file, 'r') as f:
                                    content = f.read()
                                    print(f"[DEBUG] JSON file content (first 1000 chars): {content[:1000]}")
                            except:
                                pass
                else:
                    print(f"[WARN] Results file missing or empty: {results_file}")
                    if stderr_str:
                        print(f"[WARN] next88 stderr: {stderr_str[:500]}")
                    if stdout:
                        stdout_str = stdout.decode("utf-8", errors="ignore") if stdout else ""
                        if stdout_str:
                            print(f"[DEBUG] next88 stdout (first 500 chars): {stdout_str[:500]}")
                
                return list(vulnerable_hosts)
            finally:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
                if os.path.exists(results_file):
                    os.unlink(results_file)
        except Exception as e:
            print(f"[ERROR] next88 scan failed: {e}")
            return []
    
    async def _run_source_exposure_check(
        self, domain: str, hosts: list, discord_webhook: Optional[str]
    ) -> list:
        """Run source code exposure check via ACTION_ID extraction."""
        try:
            # This is a simplified version - the full implementation would:
            # 1. Collect JS URLs using ensure_urls
            # 2. Download JS files and extract ACTION_IDs
            # 3. Test ACTION_IDs with next88 --check-source-exposure
            
            # For now, just run next88 with --check-source-exposure flag
            return await self._run_next88_scan(
                hosts, ["-check-source-exposure"], discord_webhook
            )
        except Exception as e:
            print(f"[ERROR] Source exposure check failed: {e}")
            return []
    
    async def _send_react2shell_results(
        self, scan_id: str, domain: str, total_hosts: int,
        smart_scan_count: int, dos_count: int, source_exposure_count: int,
        all_vulnerable: list
    ):
        """Format and send React2Shell scan results."""
        try:
            interaction = active_scans[scan_id]["interaction"]
            
            embed = discord.Embed(
                title="🔍 React2Shell RCE Test Results",
                description=f"**Target:** `{domain}`",
                color=discord.Color.red() if all_vulnerable else discord.Color.green(),
            )
            
            if all_vulnerable:
                embed.add_field(
                    name="Status", value="🔴 **Vulnerable**", inline=False
                )
                embed.add_field(
                    name="Vulnerable Hosts Found",
                    value=f"**{len(all_vulnerable)}** unique host(s)",
                    inline=False,
                )
                
                # Add vulnerable hosts list
                hosts_text = ""
                for i, host in enumerate(all_vulnerable[:15], 1):
                    hosts_text += f"`{host}`\n"
                if len(all_vulnerable) > 15:
                    hosts_text += f"\n... and {len(all_vulnerable) - 15} more"
                embed.add_field(
                    name="Vulnerable Hosts", value=hosts_text, inline=False
                )
                
                # Add breakdown (smart scan + optional tests)
                breakdown = []
                if smart_scan_count > 0:
                    breakdown.append(f"Smart Scan: {smart_scan_count}")
                if dos_count > 0:
                    breakdown.append(f"DoS Test: {dos_count}")
                if source_exposure_count > 0:
                    breakdown.append(f"Source Exposure: {source_exposure_count}")
                if breakdown:
                    embed.add_field(
                        name="Breakdown", value=" • ".join(breakdown), inline=False
                    )
            else:
                embed.add_field(
                    name="Status", value="✅ **Not Vulnerable**", inline=False
                )
                stats_text = f"**Live hosts:** `{total_hosts}`\n"
                stats_text += f"**Smart Scan findings:** `{smart_scan_count}`\n"
                if dos_count > 0:
                    stats_text += f"**DoS Test findings:** `{dos_count}`\n"
                if source_exposure_count > 0:
                    stats_text += f"**Source Exposure findings:** `{source_exposure_count}`\n"
                embed.add_field(name="Statistics", value=stats_text, inline=False)
            
            await interaction.edit_original_response(embed=embed)
            active_scans[scan_id]["status"] = "completed"
        except Exception as e:
            print(f"[ERROR] Failed to send results: {e}")
    
    async def _update_scan_embed(self, scan_id: str, message: str, color: discord.Color):
        """Update scan embed with message."""
        try:
            if scan_id in active_scans:
                interaction = active_scans[scan_id]["interaction"]
                embed = discord.Embed(
                    title="React2Shell Host Scan",
                    description=message,
                    color=color,
                )
                await interaction.edit_original_response(embed=embed)
        except Exception as e:
            print(f"[ERROR] Failed to update embed: {e}")

    async def _run_scan_background(self, scan_id: str, command: list):
        """Run scan in background and update Discord."""
        try:
            # Determine timeout based on scan type
            timeout = 5 * 60 * 60  # 5 hours default for all scans

            # Run the scan
            results = await self.run_autoar_command(command, scan_id, timeout)

            # Update scan status
            if scan_id in active_scans:
                active_scans[scan_id]["status"] = "completed"
                active_scans[scan_id]["results"] = results

                # Update Discord message
                interaction = active_scans[scan_id]["interaction"]
                scan_type = active_scans[scan_id]["type"]
                
                # react2shell_scan and react2shell use their own result formatting
                # No special formatting needed here for these scan types
                if scan_type not in ["react2shell_scan", "react2shell"]:
                    embed = self.create_scan_embed(
                        scan_type,
                        active_scans[scan_id]["target"],
                        "completed",
                        results,
                    )

                    # Add logs to embed if available (only for non-react2shell_scan)
                    if results["stdout"] or results["stderr"]:
                        log_text = ""
                        if results["stdout"]:
                            log_text += f"**Output:**\n```\n{results['stdout'][:1000]}{'...' if len(results['stdout']) > 1000 else ''}\n```\n"
                        if results["stderr"]:
                            log_text += f"**Errors:**\n```\n{results['stderr'][:1000]}{'...' if len(results['stderr']) > 1000 else ''}\n```"

                        if log_text:
                            embed.add_field(
                                name="Execution Logs", value=log_text, inline=False
                            )

                try:
                    await interaction.edit_original_response(embed=embed)
                except:
                    pass  # Ignore if message was deleted

                # Store results
                scan_results[scan_id] = results

                # Send files if scan was successful and results exist
                # Note: Files are now sent progressively via webhooks during scan execution
                # Only send files if no webhook is available (fallback)
                if results["returncode"] == 0 and not os.getenv("DISCORD_WEBHOOK"):
                    await self._send_scan_files(scan_id, interaction)

        except Exception as e:
            print(f"Error in background scan {scan_id}: {e}")
            if scan_id in active_scans:
                active_scans[scan_id]["status"] = "failed"
                active_scans[scan_id]["error"] = str(e)

    async def _send_scan_files(self, scan_id: str, interaction: discord.Interaction):
        """Send scan result files to Discord using the bot."""
        try:
            scan_info = active_scans.get(scan_id, {})
            target = scan_info.get("target", "unknown")
            scan_type = scan_info.get("type", "unknown")

            # Look for result files in the results directory
            results_path = Path(RESULTS_DIR)
            if not results_path.exists():
                print(f"Results directory not found: {results_path}")
                return

            # Find the most recent scan directory for this target
            target_dirs = [
                d for d in results_path.iterdir() if d.is_dir() and target in d.name
            ]
            if not target_dirs:
                print(f"No target directories found for {target}")
                print(
                    f"Available directories: {[d.name for d in results_path.iterdir() if d.is_dir()]}"
                )
                return

            latest_dir = max(target_dirs, key=os.path.getctime)

            # Send relevant files based on scan type
            files_to_send = []

            if scan_type in ["domain", "subdomain", "lite", "fast"]:
                # Look for common result files in subdirectories
                for pattern in [
                    "all-subs.txt",
                    "live-subs.txt",
                    "all-urls.txt",
                    "js-urls.txt",
                ]:
                    # Check in subs/ and urls/ subdirectories
                    for subdir in ["subs", "urls"]:
                        file_path = latest_dir / subdir / pattern
                        print(
                            f"Checking file: {file_path} (exists: {file_path.exists()}, size: {file_path.stat().st_size if file_path.exists() else 0})"
                        )
                        if file_path.exists() and file_path.stat().st_size > 0:
                            files_to_send.append(
                                (
                                    file_path,
                                    f"{scan_type.title()} scan results: {pattern}",
                                )
                            )

                # Also look for CNAME records
                cname_file = latest_dir / "subs" / "cname-records.txt"
                print(
                    f"Checking CNAME file: {cname_file} (exists: {cname_file.exists()}, size: {cname_file.stat().st_size if cname_file.exists() else 0})"
                )
                if cname_file.exists() and cname_file.stat().st_size > 0:
                    files_to_send.append(
                        (
                            cname_file,
                            f"{scan_type.title()} scan results: cname-records.txt",
                        )
                    )

            elif scan_type == "js":
                js_files = list(latest_dir.glob("**/js-urls.txt"))
                if js_files:
                    files_to_send.append((js_files[0], "JavaScript scan results"))

            elif scan_type == "s3":
                s3_files = list(latest_dir.glob("**/s3-*.txt"))
                if s3_files:
                    files_to_send.append((s3_files[0], "S3 scan results"))

            elif scan_type in ["github", "github_org"]:
                # Look for GitHub scan result files (JSON and HTML)
                # Use set to avoid duplicates
                found_files = set()

                # Find all relevant files
                all_json_files = list(latest_dir.glob("**/*_secrets.json")) + list(
                    latest_dir.glob("**/org_secrets.json")
                )
                all_html_files = list(latest_dir.glob("**/*_secrets.html")) + list(
                    latest_dir.glob("**/org_secrets.html")
                )

                # Add JSON files (avoid duplicates)
                for json_file in all_json_files:
                    if (
                        json_file.exists()
                        and json_file.stat().st_size > 0
                        and str(json_file) not in found_files
                    ):
                        files_to_send.append(
                            (json_file, f"GitHub secrets (JSON): {json_file.name}")
                        )
                        found_files.add(str(json_file))

                # Add HTML files (avoid duplicates)
                for html_file in all_html_files:
                    if (
                        html_file.exists()
                        and html_file.stat().st_size > 0
                        and str(html_file) not in found_files
                    ):
                        files_to_send.append(
                            (html_file, f"GitHub secrets (HTML): {html_file.name}")
                        )
                        found_files.add(str(html_file))

            elif scan_type in [
                "dns_takeover",
                "dns_cname",
                "dns_ns",
                "dns_azure_aws",
                "dns_dnsreaper",
            ]:
                # Look for DNS takeover result files
                dns_dir = latest_dir / "vulnerabilities" / "dns-takeover"
                if dns_dir.exists():
                    # Look for all takeover-related files
                    takeover_files = [
                        "nuclei-takeover-public.txt",
                        "nuclei-takeover-custom.txt",
                        "azure-takeover.txt",
                        "aws-takeover.txt",
                        "azure-aws-takeover.txt",
                        "ns-takeover-raw.txt",
                        "ns-takeover-vuln.txt",
                        "ns-servers.txt",
                        "ns-servers-vuln.txt",
                        "dns-takeover-summary.txt",
                        "dnsreaper-results.txt",
                        "filtered-ns-takeover-vuln.txt",
                    ]

                    for filename in takeover_files:
                        file_path = dns_dir / filename
                        if file_path.exists() and file_path.stat().st_size > 0:
                            files_to_send.append(
                                (file_path, f"DNS Takeover: {filename}")
                            )

            elif scan_type in [
                "db_domains",
                "db_subdomains",
                "db_domains_delete",
                "db_stats",
                "db_cleanup",
                "db_subdomains_all",
                "db_js_list",
            ]:
                # For database commands, look for any .txt files
                txt_files = list(latest_dir.glob("**/*.txt"))
                if txt_files:
                    for txt_file in txt_files[:3]:  # Limit to 3 files
                        files_to_send.append(
                            (txt_file, f"Database export: {txt_file.name}")
                        )

            # Send files using Discord bot (25MB limit per file)
            if files_to_send:
                print(f"Found {len(files_to_send)} files to send")

                # Send files in batches (Discord allows up to 10 files per message)
                for i in range(0, len(files_to_send), 10):
                    batch = files_to_send[i : i + 10]

                    # Create embed for file batch
                    embed = discord.Embed(
                        title="📄 Scan Results",
                        description=f"Found {len(batch)} result file(s) for {scan_type} scan of `{target}`",
                        color=discord.Color.green(),
                    )

                    # Prepare files for sending
                    discord_files = []
                    file_descriptions = []

                    for file_path, description in batch:
                        if file_path.stat().st_size < 25 * 1024 * 1024:  # 25MB limit
                            try:
                                discord_files.append(
                                    discord.File(
                                        str(file_path), filename=file_path.name
                                    )
                                )
                                file_descriptions.append(
                                    f"• {file_path.name} ({file_path.stat().st_size} bytes)"
                                )
                            except Exception as e:
                                print(f"Error preparing file {file_path}: {e}")
                        else:
                            print(
                                f"File too large to send: {file_path} ({file_path.stat().st_size} bytes)"
                            )

                    if discord_files:
                        # Add file list to embed
                        embed.add_field(
                            name="Files",
                            value="\n".join(file_descriptions[:10]),
                            inline=False,
                        )

                        try:
                            await interaction.followup.send(
                                embed=embed, files=discord_files
                            )
                            print(f"Successfully sent {len(discord_files)} files")
                        except Exception as e:
                            print(f"Error sending files: {e}")
                    else:
                        print("No valid files to send")
            else:
                print(f"No result files found for {scan_type} scan of {target}")

        except Exception as e:
            print(f"Error sending scan files: {e}")

    # --- Simplified Monitor Updates workflow ---
    @app_commands.command(
        name="monitor_updates_add", description="Monitor Updates: add a URL target"
    )
    @app_commands.describe(
        url="URL to monitor",
        strategy="hash|size|headers|regex (default: hash)",
        pattern="Regex pattern if strategy=regex",
    )
    async def monitor_updates_add(
        self,
        interaction: discord.Interaction,
        url: str,
        strategy: str = "hash",
        pattern: str = "",
    ):
        scan_id = f"mon_updates_add_{int(time.time())}"
        cmd = [
            AUTOAR_SCRIPT_PATH,
            "monitor",
            "updates",
            "add",
            "-u",
            url,
            "--strategy",
            strategy,
        ]
        if pattern:
            cmd.extend(["--pattern", pattern])
        await interaction.response.send_message(
            embed=self.create_scan_embed("Monitor Updates: Add", url, "running")
        )
        res = await self.run_autoar_command(cmd, scan_id, timeout=30)
        color = (
            discord.Color.green()
            if res.get("returncode", 1) == 0
            else discord.Color.red()
        )
        pattern_section = f"\n**Pattern:** {pattern}" if pattern else ""
        embed = discord.Embed(
            title="✅ Target Added",
            description=f"**URL:** `{url}`\n**Strategy:** {strategy}{pattern_section}",
            color=color,
        )
        if res.get("stdout"):
            embed.add_field(
                name="Output", value=f"```{res['stdout'][:500]}```", inline=False
            )
        if res.get("stderr") and res.get("returncode", 0) != 0:
            embed.add_field(
                name="Error", value=f"```{res['stderr'][:500]}```", inline=False
            )
        await interaction.followup.send(embed=embed)

    @app_commands.command(
        name="monitor_updates_remove",
        description="Monitor Updates: remove a URL target",
    )
    @app_commands.describe(url="URL to remove")
    async def monitor_updates_remove(self, interaction: discord.Interaction, url: str):
        scan_id = f"mon_updates_remove_{int(time.time())}"
        cmd = [AUTOAR_SCRIPT_PATH, "monitor", "updates", "remove", "-u", url]
        await interaction.response.send_message(
            embed=self.create_scan_embed("Monitor Updates: Remove", url, "running")
        )
        res = await self.run_autoar_command(cmd, scan_id, timeout=30)
        color = (
            discord.Color.green()
            if res.get("returncode", 1) == 0
            else discord.Color.red()
        )
        embed = discord.Embed(
            title="🗑️ Target Removed", description=f"`{url}`", color=color
        )
        if res.get("stdout"):
            embed.add_field(
                name="Output", value=f"```{res['stdout'][:500]}```", inline=False
            )
        if res.get("stderr") and res.get("returncode", 0) != 0:
            embed.add_field(
                name="Error", value=f"```{res['stderr'][:500]}```", inline=False
            )
        await interaction.followup.send(embed=embed)

    @app_commands.command(
        name="monitor_updates_start",
        description="Monitor Updates: start monitoring target(s)",
    )
    @app_commands.describe(
        url="Specific URL to monitor (leave empty for all targets)",
        interval="Interval in seconds between checks (default: 86400 = 1 day)",
    )
    async def monitor_updates_start(
        self, interaction: discord.Interaction, url: str = None, interval: int = 86400
    ):
        scan_id = f"mon_updates_start_{int(time.time())}"

        if url:
            # Start single target
            cmd = [
                AUTOAR_SCRIPT_PATH,
                "monitor",
                "updates",
                "start",
                "-u",
                url,
                "--interval",
                str(interval),
                "--daemon",
            ]
            target_desc = url
        else:
            # Start all targets
            cmd = [
                AUTOAR_SCRIPT_PATH,
                "monitor",
                "updates",
                "start",
                "--all",
                "--interval",
                str(interval),
                "--daemon",
            ]
            target_desc = "all targets"

        await interaction.response.send_message(
            embed=self.create_scan_embed(
                "Monitor Updates: Start", target_desc, "running"
            )
        )
        res = await self.run_autoar_command(cmd, scan_id, timeout=30)
        color = (
            discord.Color.green()
            if res.get("returncode", 1) == 0
            else discord.Color.red()
        )

        mode_text = f"Single target: `{url}`" if url else "All targets"
        embed = discord.Embed(
            title="📡 Updates Monitor Started",
            description=f"**Mode:** {mode_text}\n**Interval:** {interval}s ({interval // 3600}h)",
            color=color,
        )
        if res.get("stdout"):
            embed.add_field(
                name="Output", value=f"```{res['stdout'][:1000]}```", inline=False
            )
        if res.get("stderr") and res.get("returncode", 0) != 0:
            embed.add_field(
                name="Error", value=f"```{res['stderr'][:1000]}```", inline=False
            )
        await interaction.followup.send(embed=embed)

    @app_commands.command(
        name="monitor_updates_stop",
        description="Monitor Updates: stop monitoring target(s)",
    )
    @app_commands.describe(
        url="Specific URL to stop monitoring (leave empty for all targets)"
    )
    async def monitor_updates_stop(
        self, interaction: discord.Interaction, url: str = None
    ):
        scan_id = f"mon_updates_stop_{int(time.time())}"

        if url:
            # Stop single target
            cmd = [AUTOAR_SCRIPT_PATH, "monitor", "updates", "stop", "-u", url]
            target_desc = url
        else:
            # Stop all targets
            cmd = [AUTOAR_SCRIPT_PATH, "monitor", "updates", "stop", "--all"]
            target_desc = "all targets"

        await interaction.response.send_message(
            embed=self.create_scan_embed(
                "Monitor Updates: Stop", target_desc, "running"
            )
        )
        res = await self.run_autoar_command(cmd, scan_id, timeout=30)
        color = (
            discord.Color.green()
            if res.get("returncode", 1) == 0
            else discord.Color.red()
        )

        mode_text = f"Single target: `{url}`" if url else "All targets"
        embed = discord.Embed(
            title="🛑 Updates Monitor Stopped",
            description=f"**Mode:** {mode_text}",
            color=color,
        )
        if res.get("stdout"):
            embed.add_field(
                name="Output", value=f"```{res['stdout'][:1000]}```", inline=False
            )
        if res.get("stderr") and res.get("returncode", 0) != 0:
            embed.add_field(
                name="Error", value=f"```{res['stderr'][:1000]}```", inline=False
            )
        await interaction.followup.send(embed=embed)

    @app_commands.command(
        name="monitor_updates_list",
        description="Monitor Updates: list DB targets and running monitors",
    )
    async def monitor_updates_list(self, interaction: discord.Interaction):
        scan_id = f"mon_updates_list_{int(time.time())}"
        # We call two commands to include DB and running monitors
        # First, DB targets
        db_cmd = [AUTOAR_SCRIPT_PATH, "db", "domains", "list"]  # fallback view
        # Prefer calling updates monitor list which now prints DB targets with statuses
        cmd = [AUTOAR_SCRIPT_PATH, "monitor", "updates", "list"]
        await interaction.response.send_message(
            embed=self.create_scan_embed("Monitor Updates: List", "monitors", "running")
        )
        res = await self.run_autoar_command(cmd, scan_id, timeout=30)
        color = (
            discord.Color.green()
            if res.get("returncode", 1) == 0
            else discord.Color.red()
        )
        desc = res.get("stdout", "").strip() or "No targets configured"
        await interaction.followup.send(
            embed=discord.Embed(
                title="📡 Updates Monitors",
                description=f"```\n{desc[:1900]}\n```",
                color=color,
            )
        )

    # --- End simplified Monitor Updates workflow ---


@bot.event
async def on_ready():
    """Bot ready event."""
    print(f"{bot.user} has connected to Discord!")

    # Sync slash commands
    try:
        synced = await bot.tree.sync()
        print(f"Synced {len(synced)} command(s)")
    except Exception as e:
        print(f"Failed to sync commands: {e}")


@bot.event
async def on_guild_join(guild):
    """Bot joined a new guild."""
    print(f"Joined guild: {guild.name} (id: {guild.id})")


async def main():
    """Main function."""
    if not BOT_TOKEN:
        print("Error: DISCORD_BOT_TOKEN environment variable not set")
        sys.exit(1)

    if not os.path.exists(AUTOAR_SCRIPT_PATH):
        print(f"Error: AutoAR script not found at {AUTOAR_SCRIPT_PATH}")
        sys.exit(1)

    if not os.path.exists(CONFIG_FILE):
        print(f"Warning: Config file not found at {CONFIG_FILE}")

    # Add the cog to the bot
    await bot.add_cog(AutoARBot(bot))

    # Run the bot
    try:
        await bot.start(BOT_TOKEN)
    except Exception as e:
        print(f"Error running bot: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())

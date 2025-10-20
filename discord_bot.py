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
from typing import Optional, Dict, Any

import discord
from discord import app_commands
from discord.ext import commands
import yaml

# Bot configuration
BOT_TOKEN = os.getenv('DISCORD_BOT_TOKEN')
AUTOAR_SCRIPT_PATH = os.getenv('AUTOAR_SCRIPT_PATH', '/app/main.sh')
CONFIG_FILE = os.getenv('AUTOAR_CONFIG_FILE', '/app/autoar.yaml')
RESULTS_DIR = os.getenv('AUTOAR_RESULTS_DIR', '/app/new-results')

# Bot permissions
intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True
intents.guild_messages = True

# Create bot instance
bot = commands.Bot(command_prefix='!', intents=intents)

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
                with open(CONFIG_FILE, 'r') as f:
                    config = yaml.safe_load(f) or {}
            except Exception as e:
                print(f"Warning: Could not load config file: {e}")
        
        # Override with environment variables if they exist
        env_mappings = {
            'DISCORD_WEBHOOK': os.getenv('DISCORD_WEBHOOK'),
            'DB_NAME': os.getenv('DB_NAME'),
            'SAVE_TO_DB': os.getenv('SAVE_TO_DB'),
            'VERBOSE': os.getenv('VERBOSE'),
            'GITHUB_TOKEN': os.getenv('GITHUB_TOKEN'),
            'SECURITYTRAILS_API_KEY': os.getenv('SECURITYTRAILS_API_KEY'),
            'SHODAN_API_KEY': os.getenv('SHODAN_API_KEY'),
            'VIRUSTOTAL_API_KEY': os.getenv('VIRUSTOTAL_API_KEY'),
        }
        
        for key, value in env_mappings.items():
            if value is not None:
                config[key] = value
        
        return config
    
    def get_discord_webhook(self) -> Optional[str]:
        """Get Discord webhook URL from config or environment."""
        return self.config.get('DISCORD_WEBHOOK') or os.getenv('DISCORD_WEBHOOK')
    
    async def run_autoar_command(self, command: list, scan_id: str, timeout: int = 30) -> Dict[str, Any]:
        """Run AutoAR command and return results."""
        try:
            print(f"[DEBUG] Running command: {' '.join(command)}")
            
            # Set environment variables
            env = os.environ.copy()
            env['AUTOAR_CONFIG'] = CONFIG_FILE
            
            # Run the command with timeout
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                cwd=os.path.dirname(AUTOAR_SCRIPT_PATH)
            )
            
            # Add timeout to prevent hanging
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                print(f"[WARN] Command timed out after {timeout} seconds")
                process.kill()
                await process.wait()
                return {
                    'returncode': -1,
                    'stdout': '',
                    'stderr': f'Command timed out after {timeout} seconds',
                    'scan_id': scan_id,
                    'timestamp': datetime.now().isoformat()
                }
            
            print(f"[DEBUG] Command exit code: {process.returncode}")
            if stdout:
                print(f"[DEBUG] Command stdout: {stdout.decode('utf-8')[:200]}")
            if stderr:
                print(f"[DEBUG] Command stderr: {stderr.decode('utf-8')[:200]}")
            
            return {
                'returncode': process.returncode,
                'stdout': stdout.decode('utf-8'),
                'stderr': stderr.decode('utf-8'),
                'scan_id': scan_id,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            print(f"[DEBUG] Command error: {e}")
            return {
                'returncode': -1,
                'stdout': '',
                'stderr': str(e),
                'scan_id': scan_id,
                'timestamp': datetime.now().isoformat()
            }
    
    def create_scan_embed(self, scan_type: str, target: str, status: str, 
                         results: Optional[Dict] = None) -> discord.Embed:
        """Create a Discord embed for scan results."""
        embed = discord.Embed(
            title=f"🔍 AutoAR {scan_type.title()} Scan",
            description=f"**Target:** `{target}`",
            color=discord.Color.blue() if status == "running" else 
                  discord.Color.green() if status == "completed" else 
                  discord.Color.red()
        )
        
        embed.add_field(name="Status", value=status.upper(), inline=True)
        embed.add_field(name="Timestamp", value=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), inline=True)
        
        if results:
            if results['returncode'] == 0:
                embed.color = discord.Color.green()
                embed.add_field(name="Result", value="✅ Scan completed successfully", inline=False)
            else:
                embed.color = discord.Color.red()
                embed.add_field(name="Error", value=f"❌ Scan failed (Exit code: {results['returncode']})", inline=False)
                if results['stderr']:
                    embed.add_field(name="Error Details", value=f"```{results['stderr'][:1000]}```", inline=False)
        
        return embed
    
    @app_commands.command(name="scan_domain", description="Perform a full domain scan")
    @app_commands.describe(
        domain="The domain to scan",
        verbose="Enable verbose output",
        keep_results="Keep scan results after completion"
    )
    async def scan_domain(self, interaction: discord.Interaction, domain: str, 
                         verbose: bool = False, keep_results: bool = False):
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
            'type': 'domain',
            'target': domain,
            'status': 'running',
            'start_time': datetime.now(),
            'interaction': interaction
        }
        
        # Send initial response
        embed = self.create_scan_embed("Domain", domain, "running")
        await interaction.response.send_message(embed=embed)
        
        # Run scan in background
        asyncio.create_task(self._run_scan_background(scan_id, command))
    
    @app_commands.command(name="scan_subdomain", description="Scan a single subdomain")
    @app_commands.describe(
        subdomain="The subdomain to scan",
        verbose="Enable verbose output"
    )
    async def scan_subdomain(self, interaction: discord.Interaction, subdomain: str, 
                            verbose: bool = False):
        """Scan a single subdomain."""
        scan_id = f"subdomain_{int(time.time())}"
        
        command = [AUTOAR_SCRIPT_PATH, "subdomains", "get", "-d", subdomain]
        if verbose:
            command.append("-v")
        
        active_scans[scan_id] = {
            'type': 'subdomain',
            'target': subdomain,
            'status': 'running',
            'start_time': datetime.now(),
            'interaction': interaction
        }
        
        embed = self.create_scan_embed("Subdomain", subdomain, "running")
        await interaction.response.send_message(embed=embed)
        
        asyncio.create_task(self._run_scan_background(scan_id, command))
    
    @app_commands.command(name="lite_scan", description="Perform a lite domain scan")
    @app_commands.describe(
        domain="The domain to scan",
        verbose="Enable verbose output"
    )
    async def lite_scan(self, interaction: discord.Interaction, domain: str, 
                       verbose: bool = False):
        """Perform a lite domain scan."""
        scan_id = f"lite_{int(time.time())}"
        
        command = [AUTOAR_SCRIPT_PATH, "lite", "run", "-d", domain]
        if verbose:
            command.append("-v")
        
        active_scans[scan_id] = {
            'type': 'lite',
            'target': domain,
            'status': 'running',
            'start_time': datetime.now(),
            'interaction': interaction
        }
        
        embed = self.create_scan_embed("Lite Scan", domain, "running")
        await interaction.response.send_message(embed=embed)
        
        asyncio.create_task(self._run_scan_background(scan_id, command))
    
    @app_commands.command(name="fast_look", description="Perform a fast domain lookup")
    @app_commands.describe(
        domain="The domain to scan",
        verbose="Enable verbose output"
    )
    async def fast_look(self, interaction: discord.Interaction, domain: str, 
                       verbose: bool = False):
        """Perform a fast domain lookup."""
        scan_id = f"fast_{int(time.time())}"
        
        command = [AUTOAR_SCRIPT_PATH, "fastlook", "run", "-d", domain]
        if verbose:
            command.append("-v")
        
        active_scans[scan_id] = {
            'type': 'fast',
            'target': domain,
            'status': 'running',
            'start_time': datetime.now(),
            'interaction': interaction
        }
        
        embed = self.create_scan_embed("Fast Look", domain, "running")
        await interaction.response.send_message(embed=embed)
        
        asyncio.create_task(self._run_scan_background(scan_id, command))
    
    @app_commands.command(name="js_scan", description="Scan for JavaScript files and endpoints")
    @app_commands.describe(
        domain="The domain to scan",
        subdomain="Specific subdomain to scan (optional)",
        verbose="Enable verbose output"
    )
    async def js_scan(self, interaction: discord.Interaction, domain: str, 
                     subdomain: Optional[str] = None, verbose: bool = False):
        """Scan for JavaScript files and endpoints."""
        scan_id = f"js_{int(time.time())}"
        
        command = [AUTOAR_SCRIPT_PATH, "js", "scan", "-d", domain]
        if subdomain:
            command.extend(["-s", subdomain])
        if verbose:
            command.append("-v")
        
        target = f"{subdomain}.{domain}" if subdomain else domain
        active_scans[scan_id] = {
            'type': 'js',
            'target': target,
            'status': 'running',
            'start_time': datetime.now(),
            'interaction': interaction
        }
        
        embed = self.create_scan_embed("JavaScript Scan", target, "running")
        await interaction.response.send_message(embed=embed)
        
        asyncio.create_task(self._run_scan_background(scan_id, command))
    
    @app_commands.command(name="s3_scan", description="Scan for S3 buckets")
    @app_commands.describe(
        bucket="S3 bucket name to scan",
        region="AWS region (optional)",
        verbose="Enable verbose output"
    )
    async def s3_scan(self, interaction: discord.Interaction, bucket: str, 
                     region: Optional[str] = None, verbose: bool = False):
        """Scan for S3 buckets."""
        scan_id = f"s3_{int(time.time())}"
        
        command = [AUTOAR_SCRIPT_PATH, "s3", "scan", "-b", bucket]
        if region:
            command.extend(["-r", region])
        if verbose:
            command.append("-v")
        
        active_scans[scan_id] = {
            'type': 's3',
            'target': bucket,
            'status': 'running',
            'start_time': datetime.now(),
            'interaction': interaction
        }
        
        embed = self.create_scan_embed("S3 Scan", bucket, "running")
        await interaction.response.send_message(embed=embed)
        
        asyncio.create_task(self._run_scan_background(scan_id, command))
    
    @app_commands.command(name="github_scan", description="Scan GitHub repository for secrets")
    @app_commands.describe(
        repo="GitHub repository (owner/repo)",
        verbose="Enable verbose output"
    )
    async def github_scan(self, interaction: discord.Interaction, repo: str, 
                         verbose: bool = False):
        """Scan GitHub repository for secrets."""
        scan_id = f"github_{int(time.time())}"
        
        command = [AUTOAR_SCRIPT_PATH, "github", "scan", "-r", repo]
        if verbose:
            command.append("-v")
        
        active_scans[scan_id] = {
            'type': 'github',
            'target': repo,
            'status': 'running',
            'start_time': datetime.now(),
            'interaction': interaction
        }
        
        embed = self.create_scan_embed("GitHub Scan", repo, "running")
        await interaction.response.send_message(embed=embed)
        
        asyncio.create_task(self._run_scan_background(scan_id, command))
    
    @app_commands.command(name="github_org_scan", description="Scan GitHub organization for secrets")
    @app_commands.describe(
        org="GitHub organization name",
        max_repos="Maximum number of repositories to scan",
        verbose="Enable verbose output"
    )
    async def github_org_scan(self, interaction: discord.Interaction, org: str, 
                             max_repos: int = 50, verbose: bool = False):
        """Scan GitHub organization for secrets."""
        scan_id = f"github_org_{int(time.time())}"
        
        command = [AUTOAR_SCRIPT_PATH, "github", "org", "-o", org, "-m", str(max_repos)]
        if verbose:
            command.append("-v")
        
        active_scans[scan_id] = {
            'type': 'github_org',
            'target': org,
            'status': 'running',
            'start_time': datetime.now(),
            'interaction': interaction
        }
        
        embed = self.create_scan_embed("GitHub Org Scan", org, "running")
        await interaction.response.send_message(embed=embed)
        
        asyncio.create_task(self._run_scan_background(scan_id, command))
    
    @app_commands.command(name="wp_depconf", description="WordPress dependency confusion scan")
    @app_commands.describe(
        domain="The domain to scan",
        list_file="Path to plugin list file (optional)",
        verbose="Enable verbose output"
    )
    async def wp_depconf(self, interaction: discord.Interaction, domain: str, 
                        list_file: Optional[str] = None, verbose: bool = False):
        """WordPress dependency confusion scan."""
        scan_id = f"wp_depconf_{int(time.time())}"
        
        command = [AUTOAR_SCRIPT_PATH, "wpDepConf", "scan", "-d", domain]
        if list_file:
            command.extend(["-l", list_file])
        if verbose:
            command.append("-v")
        
        active_scans[scan_id] = {
            'type': 'wp_depconf',
            'target': domain,
            'status': 'running',
            'start_time': datetime.now(),
            'interaction': interaction
        }
        
        embed = self.create_scan_embed("WordPress DepConf", domain, "running")
        await interaction.response.send_message(embed=embed)
        
        asyncio.create_task(self._run_scan_background(scan_id, command))
    
    @app_commands.command(name="github_wordlist", description="Generate GitHub target-based wordlist from organization")
    @app_commands.describe(
        org="GitHub organization name",
        token="GitHub token (optional, can use GITHUB_TOKEN env var)"
    )
    async def github_wordlist(self, interaction: discord.Interaction, org: str, 
                             token: Optional[str] = None):
        """Generate GitHub target-based wordlist from organization."""
        scan_id = f"github_wordlist_{int(time.time())}"
        
        command = [AUTOAR_SCRIPT_PATH, "github-wordlist", org]
        if token:
            command.extend(["-t", token])
        
        active_scans[scan_id] = {
            'type': 'github_wordlist',
            'target': org,
            'status': 'running',
            'start_time': datetime.now(),
            'interaction': interaction
        }
        
        embed = self.create_scan_embed("GitHub Wordlist", org, "running")
        await interaction.response.send_message(embed=embed)
        
        asyncio.create_task(self._run_scan_background(scan_id, command))
    
    @app_commands.command(name="check_tools", description="Check if all required tools are installed")
    async def check_tools(self, interaction: discord.Interaction):
        """Check if all required tools are installed."""
        try:
            command = [AUTOAR_SCRIPT_PATH, "check-tools", "run"]
            
            embed = discord.Embed(
                title="🔧 Tool Check",
                description="Checking required tools...",
                color=discord.Color.blue()
            )
            await interaction.response.send_message(embed=embed)
            
            results = await self.run_autoar_command(command, "tool_check", timeout=60)
            
            if results['returncode'] == 0:
                embed.color = discord.Color.green()
                embed.title = "✅ Tool Check Complete"
                embed.description = "All required tools are installed and working properly."
            else:
                embed.color = discord.Color.red()
                embed.title = "❌ Tool Check Failed"
                embed.description = "Some tools are missing or not working properly."
                if results['stderr']:
                    embed.add_field(name="Details", value=f"```{results['stderr'][:1000]}```", inline=False)
                if results['stdout']:
                    embed.add_field(name="Output", value=f"```{results['stdout'][:1000]}```", inline=False)
            
            await interaction.edit_original_response(embed=embed)
        except Exception as e:
            print(f"[ERROR] check_tools command failed: {e}")
            await interaction.response.send_message(f"❌ Error: {str(e)}", ephemeral=True)
    
    @app_commands.command(name="scan_status", description="Check status of active scans")
    async def scan_status(self, interaction: discord.Interaction):
        """Check status of active scans."""
        if not active_scans:
            embed = discord.Embed(
                title="📊 Scan Status",
                description="No active scans",
                color=discord.Color.blue()
            )
        else:
            embed = discord.Embed(
                title="📊 Active Scans",
                color=discord.Color.blue()
            )
            
            for scan_id, scan_info in active_scans.items():
                duration = datetime.now() - scan_info['start_time']
                status_emoji = "🟢" if scan_info['status'] == 'running' else "🔴"
                
                embed.add_field(
                    name=f"{status_emoji} {scan_info['type'].title()} - {scan_info['target']}",
                    value=f"Status: {scan_info['status']}\nDuration: {duration}",
                    inline=False
                )
        
        await interaction.response.send_message(embed=embed)

    @app_commands.command(name="subdomains", description="Enumerate subdomains")
    @app_commands.describe(domain="The domain to enumerate")
    async def subdomains_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"subdomains_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "subdomains", "get", "-d", domain]
        active_scans[scan_id] = { 'type': 'subdomains', 'target': domain, 'status': 'running', 'start_time': datetime.now(), 'interaction': interaction }
        embed = self.create_scan_embed("Subdomains", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="cnames", description="Collect CNAME records for domain subdomains")
    @app_commands.describe(domain="The domain")
    async def cnames_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"cnames_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "cnames", "get", "-d", domain]
        active_scans[scan_id] = { 'type': 'cnames', 'target': domain, 'status': 'running', 'start_time': datetime.now(), 'interaction': interaction }
        embed = self.create_scan_embed("CNAMEs", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="livehosts", description="Filter live hosts from subdomains")
    @app_commands.describe(domain="The domain")
    async def livehosts_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"live_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "livehosts", "get", "-d", domain]
        active_scans[scan_id] = { 'type': 'live', 'target': domain, 'status': 'running', 'start_time': datetime.now(), 'interaction': interaction }
        embed = self.create_scan_embed("Live Hosts", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="urls", description="Collect URLs and JS URLs")
    @app_commands.describe(domain="The domain")
    async def urls_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"urls_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "urls", "collect", "-d", domain]
        active_scans[scan_id] = { 'type': 'urls', 'target': domain, 'status': 'running', 'start_time': datetime.now(), 'interaction': interaction }
        embed = self.create_scan_embed("URLs", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="reflection", description="Run reflection scan (kxss)")
    @app_commands.describe(domain="The domain")
    async def reflection_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"reflection_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "js", "scan", "-d", domain]  # js scan already extracts JS and runs regex; reflection separate:
        # We call reflection module explicitly
        command = [AUTOAR_SCRIPT_PATH, "reflection", "scan", "-d", domain]
        active_scans[scan_id] = { 'type': 'reflection', 'target': domain, 'status': 'running', 'start_time': datetime.now(), 'interaction': interaction }
        embed = self.create_scan_embed("Reflection", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="nuclei", description="Run nuclei templates on live subdomains")
    @app_commands.describe(domain="The domain")
    async def nuclei_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"nuclei_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "nuclei", "run", "-d", domain]
        active_scans[scan_id] = { 'type': 'nuclei', 'target': domain, 'status': 'running', 'start_time': datetime.now(), 'interaction': interaction }
        embed = self.create_scan_embed("Nuclei", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="tech", description="Detect technologies on live hosts")
    @app_commands.describe(domain="The domain")
    async def tech_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"tech_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "tech", "detect", "-d", domain]
        active_scans[scan_id] = { 'type': 'tech', 'target': domain, 'status': 'running', 'start_time': datetime.now(), 'interaction': interaction }
        embed = self.create_scan_embed("Tech Detect", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="ports", description="Run port scan (naabu) on live hosts")
    @app_commands.describe(domain="The domain")
    async def ports_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"ports_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "ports", "scan", "-d", domain]
        active_scans[scan_id] = { 'type': 'ports', 'target': domain, 'status': 'running', 'start_time': datetime.now(), 'interaction': interaction }
        embed = self.create_scan_embed("Ports", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="gf_scan", description="Run GF pattern scans")
    @app_commands.describe(domain="The domain")
    async def gf_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"gf_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "gf", "scan", "-d", domain]
        active_scans[scan_id] = { 'type': 'gf', 'target': domain, 'status': 'running', 'start_time': datetime.now(), 'interaction': interaction }
        embed = self.create_scan_embed("GF Scan", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="sqlmap", description="Run SQLMap on GF SQLi results")
    @app_commands.describe(domain="The domain")
    async def sqlmap_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"sqlmap_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "sqlmap", "run", "-d", domain]
        active_scans[scan_id] = { 'type': 'sqlmap', 'target': domain, 'status': 'running', 'start_time': datetime.now(), 'interaction': interaction }
        embed = self.create_scan_embed("SQLMap", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="dalfox", description="Run Dalfox XSS scan")
    @app_commands.describe(domain="The domain")
    async def dalfox_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"dalfox_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "dalfox", "run", "-d", domain]
        active_scans[scan_id] = { 'type': 'dalfox', 'target': domain, 'status': 'running', 'start_time': datetime.now(), 'interaction': interaction }
        embed = self.create_scan_embed("Dalfox", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="dns_takeover", description="Run comprehensive DNS takeover scan")
    @app_commands.describe(domain="The domain")
    async def dns_takeover_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"dnstko_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "dns", "takeover", "-d", domain]
        active_scans[scan_id] = { 'type': 'dns_takeover', 'target': domain, 'status': 'running', 'start_time': datetime.now(), 'interaction': interaction }
        embed = self.create_scan_embed("DNS Takeover", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="dns_cname", description="Run CNAME takeover scan")
    @app_commands.describe(domain="The domain")
    async def dns_cname_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"dnscname_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "dns", "cname", "-d", domain]
        active_scans[scan_id] = { 'type': 'dns_cname', 'target': domain, 'status': 'running', 'start_time': datetime.now(), 'interaction': interaction }
        embed = self.create_scan_embed("DNS CNAME", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="dns_ns", description="Run NS takeover scan")
    @app_commands.describe(domain="The domain")
    async def dns_ns_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"dnsns_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "dns", "ns", "-d", domain]
        active_scans[scan_id] = { 'type': 'dns_ns', 'target': domain, 'status': 'running', 'start_time': datetime.now(), 'interaction': interaction }
        embed = self.create_scan_embed("DNS NS", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="dns_azure_aws", description="Run Azure & AWS takeover scan")
    @app_commands.describe(domain="The domain")
    async def dns_azure_aws_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"dnscloud_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "dns", "azure-aws", "-d", domain]
        active_scans[scan_id] = { 'type': 'dns_azure_aws', 'target': domain, 'status': 'running', 'start_time': datetime.now(), 'interaction': interaction }
        embed = self.create_scan_embed("DNS Azure/AWS", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="dns_dnsreaper", description="Run DNSReaper takeover scan")
    @app_commands.describe(domain="The domain")
    async def dns_dnsreaper_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"dnsreaper_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "dns", "dnsreaper", "-d", domain]
        active_scans[scan_id] = { 'type': 'dns_dnsreaper', 'target': domain, 'status': 'running', 'start_time': datetime.now(), 'interaction': interaction }
        embed = self.create_scan_embed("DNSReaper", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="domain_run", description="Run full domain workflow")
    @app_commands.describe(domain="The domain")
    async def domain_run_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"domainrun_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "domain", "run", "-d", domain]
        active_scans[scan_id] = { 'type': 'domain', 'target': domain, 'status': 'running', 'start_time': datetime.now(), 'interaction': interaction }
        embed = self.create_scan_embed("Domain Workflow", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="db_domains", description="List distinct domains stored in PostgreSQL database")
    async def db_domains_cmd(self, interaction: discord.Interaction):
        scan_id = f"dbdomains_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "db", "domains", "list"]
        active_scans[scan_id] = { 'type': 'db_domains', 'target': 'db', 'status': 'running', 'start_time': datetime.now(), 'interaction': interaction }
        db_name = os.getenv('DB_NAME', 'autoar')
        embed = self.create_scan_embed("DB Domains", f"{db_name} (PostgreSQL)", "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="db_subdomains", description="List subdomains for a domain from PostgreSQL database")
    @app_commands.describe(domain="The domain to list subdomains for")
    async def db_subdomains_cmd(self, interaction: discord.Interaction, domain: str):
        scan_id = f"dbsubs_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "db", "subdomains", "list", "-d", domain]
        active_scans[scan_id] = { 'type': 'db_subdomains', 'target': domain, 'status': 'running', 'start_time': datetime.now(), 'interaction': interaction }
        embed = self.create_scan_embed("DB Subdomains", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="db_delete_domain", description="Delete domain and all related data from database")
    @app_commands.describe(
        domain="The domain to delete",
        force="Skip confirmation prompt"
    )
    async def db_delete_domain_cmd(self, interaction: discord.Interaction, domain: str, force: bool = False):
        """Delete domain and all related data from database."""
        scan_id = f"dbdel_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "db", "domains", "delete", "-d", domain]
        if force:
            command.append("-f")
        
        active_scans[scan_id] = { 
            'type': 'db_delete_domain', 
            'target': domain, 
            'status': 'running', 
            'start_time': datetime.now(), 
            'interaction': interaction 
        }
        
        embed = self.create_scan_embed("DB Delete Domain", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="s3_enum", description="Enumerate potential S3 buckets")
    @app_commands.describe(root="Root domain name, e.g., vulnweb")
    async def s3_enum_cmd(self, interaction: discord.Interaction, root: str):
        scan_id = f"s3enum_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "s3", "enum", "-b", root]
        active_scans[scan_id] = { 'type': 's3_enum', 'target': root, 'status': 'running', 'start_time': datetime.now(), 'interaction': interaction }
        embed = self.create_scan_embed("S3 Enum", root, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))

    @app_commands.command(name="cleanup", description="Cleanup results for a domain")
    @app_commands.describe(domain="The domain to cleanup", keep="Keep results (do nothing)")
    async def cleanup_cmd(self, interaction: discord.Interaction, domain: str, keep: bool=False):
        scan_id = f"cleanup_{int(time.time())}"
        command = [AUTOAR_SCRIPT_PATH, "cleanup", "run", "--domain", domain]
        if keep:
            command.append("--keep")
        active_scans[scan_id] = { 'type': 'cleanup', 'target': domain, 'status': 'running', 'start_time': datetime.now(), 'interaction': interaction }
        embed = self.create_scan_embed("Cleanup", domain, "running")
        await interaction.response.send_message(embed=embed)
        asyncio.create_task(self._run_scan_background(scan_id, command))
    
    @app_commands.command(name="help_autoar", description="Show AutoAR help information")
    async def help_autoar(self, interaction: discord.Interaction):
        """Show AutoAR help information."""
        # Send immediate response
        embed = discord.Embed(
            title="📖 AutoAR Help",
            description="Loading AutoAR help information...",
            color=discord.Color.blue()
        )
        await interaction.response.send_message(embed=embed)
        
        # Run command in background
        command = [AUTOAR_SCRIPT_PATH, "help"]
        results = await self.run_autoar_command(command, "help", timeout=10)
        
        # Update with actual help content
        embed.description = "AutoAR Security Scanning Tool - Available Commands"
        if results['returncode'] == 0 and results['stdout']:
            help_text = results['stdout'][:1900]
            if len(results['stdout']) > 1900:
                help_text += "\n... (truncated)"
            embed.add_field(name="Commands", value=f"```{help_text}```", inline=False)
        else:
            # Fallback to manual command list
            embed.add_field(name="Core Commands", value="• `/lite_scan` - Quick scan\n• `/fast_look` - Fast lookup\n• `/scan_domain` - Full scan\n• `/js_scan` - JavaScript scan\n• `/gf_scan` - GF pattern scans\n• `/sqlmap` - SQLMap scan\n• `/dalfox` - Dalfox XSS scan", inline=False)
            embed.add_field(name="Database Commands", value="• `/db_domains` - List domains\n• `/db_subdomains` - List subdomains\n• `/db_domains_delete` - Delete domain\n• `/db_stats` - Statistics\n• `/db_cleanup` - Cleanup old data\n• `/db_subdomains_all` - All subdomains\n• `/db_js_list` - JS files", inline=False)
            embed.add_field(name="Other Commands", value="• `/nuclei` - Nuclei scan\n• `/ports` - Port scan\n• `/tech` - Tech detection\n• `/s3_scan` - S3 bucket scan\n• `/github_scan` - GitHub secrets scan", inline=False)
        
        await interaction.edit_original_response(embed=embed)
    
    async def _run_scan_background(self, scan_id: str, command: list):
        """Run scan in background and update Discord."""
        try:
            # Determine timeout based on scan type
            timeout = 300  # 5 minutes default for long-running scans
            if any(cmd in command for cmd in ['wpDepConf', 'wp_depconf']):
                timeout = 600  # 10 minutes for WordPress Plugin Confusion scans
            elif any(cmd in command for cmd in ['github-wordlist']):
                timeout = 900  # 15 minutes for GitHub wordlist generation
            
            # Run the scan
            results = await self.run_autoar_command(command, scan_id, timeout)
            
            # Update scan status
            if scan_id in active_scans:
                active_scans[scan_id]['status'] = 'completed'
                active_scans[scan_id]['results'] = results
                
                # Update Discord message
                interaction = active_scans[scan_id]['interaction']
                embed = self.create_scan_embed(
                    active_scans[scan_id]['type'],
                    active_scans[scan_id]['target'],
                    'completed',
                    results
                )
                
                # Add logs to embed if available
                if results['stdout'] or results['stderr']:
                    log_text = ""
                    if results['stdout']:
                        log_text += f"**Output:**\n```\n{results['stdout'][:1000]}{'...' if len(results['stdout']) > 1000 else ''}\n```\n"
                    if results['stderr']:
                        log_text += f"**Errors:**\n```\n{results['stderr'][:1000]}{'...' if len(results['stderr']) > 1000 else ''}\n```"
                    
                    if log_text:
                        embed.add_field(name="Execution Logs", value=log_text, inline=False)
                
                try:
                    await interaction.edit_original_response(embed=embed)
                except:
                    pass  # Ignore if message was deleted
                
                # Store results
                scan_results[scan_id] = results
                
                # Send files if scan was successful and results exist
                # Note: Files are now sent progressively via webhooks during scan execution
                # Only send files if no webhook is available (fallback)
                if results['returncode'] == 0 and not os.getenv('DISCORD_WEBHOOK'):
                    await self._send_scan_files(scan_id, interaction)
            
        except Exception as e:
            print(f"Error in background scan {scan_id}: {e}")
            if scan_id in active_scans:
                active_scans[scan_id]['status'] = 'failed'
                active_scans[scan_id]['error'] = str(e)
    
    async def _send_scan_files(self, scan_id: str, interaction: discord.Interaction):
        """Send scan result files to Discord using the bot."""
        try:
            scan_info = active_scans.get(scan_id, {})
            target = scan_info.get('target', 'unknown')
            scan_type = scan_info.get('type', 'unknown')
            
            # Look for result files in the results directory
            results_path = Path(RESULTS_DIR)
            if not results_path.exists():
                print(f"Results directory not found: {results_path}")
                return
            
            # Find the most recent scan directory for this target
            target_dirs = [d for d in results_path.iterdir() if d.is_dir() and target in d.name]
            if not target_dirs:
                print(f"No target directories found for {target}")
                print(f"Available directories: {[d.name for d in results_path.iterdir() if d.is_dir()]}")
                return
            
            latest_dir = max(target_dirs, key=os.path.getctime)
            print(f"Looking for files in: {latest_dir}")
            print(f"Directory contents: {[f.name for f in latest_dir.iterdir()]}")
            
            # Send relevant files based on scan type
            files_to_send = []
            
            if scan_type in ['domain', 'subdomain', 'lite', 'fast']:
                # Look for common result files in subdirectories
                for pattern in ['all-subs.txt', 'live-subs.txt', 'all-urls.txt', 'js-urls.txt']:
                    # Check in subs/ and urls/ subdirectories
                    for subdir in ['subs', 'urls']:
                        file_path = latest_dir / subdir / pattern
                        print(f"Checking file: {file_path} (exists: {file_path.exists()}, size: {file_path.stat().st_size if file_path.exists() else 0})")
                        if file_path.exists() and file_path.stat().st_size > 0:
                            files_to_send.append((file_path, f"{scan_type.title()} scan results: {pattern}"))
                
                # Also look for CNAME records
                cname_file = latest_dir / 'subs' / 'cname-records.txt'
                print(f"Checking CNAME file: {cname_file} (exists: {cname_file.exists()}, size: {cname_file.stat().st_size if cname_file.exists() else 0})")
                if cname_file.exists() and cname_file.stat().st_size > 0:
                    files_to_send.append((cname_file, f"{scan_type.title()} scan results: cname-records.txt"))
            
            elif scan_type == 'js':
                js_files = list(latest_dir.glob('**/js-urls.txt'))
                if js_files:
                    files_to_send.append((js_files[0], "JavaScript scan results"))
            
            elif scan_type == 's3':
                s3_files = list(latest_dir.glob('**/s3-*.txt'))
                if s3_files:
                    files_to_send.append((s3_files[0], "S3 scan results"))
            
            elif scan_type in ['github', 'github_org']:
                # Look for GitHub scan result files (JSON and HTML)
                # Use set to avoid duplicates
                found_files = set()
                
                # Find all relevant files
                all_json_files = list(latest_dir.glob('**/*_secrets.json')) + list(latest_dir.glob('**/org_secrets.json'))
                all_html_files = list(latest_dir.glob('**/*_secrets.html')) + list(latest_dir.glob('**/org_secrets.html'))
                
                # Add JSON files (avoid duplicates)
                for json_file in all_json_files:
                    if json_file.exists() and json_file.stat().st_size > 0 and str(json_file) not in found_files:
                        files_to_send.append((json_file, f"GitHub secrets (JSON): {json_file.name}"))
                        found_files.add(str(json_file))
                
                # Add HTML files (avoid duplicates)
                for html_file in all_html_files:
                    if html_file.exists() and html_file.stat().st_size > 0 and str(html_file) not in found_files:
                        files_to_send.append((html_file, f"GitHub secrets (HTML): {html_file.name}"))
                        found_files.add(str(html_file))
            
            elif scan_type in ['dns_takeover', 'dns_cname', 'dns_ns', 'dns_azure_aws', 'dns_dnsreaper']:
                # Look for DNS takeover result files
                dns_dir = latest_dir / 'vulnerabilities' / 'dns-takeover'
                if dns_dir.exists():
                    # Look for all takeover-related files
                    takeover_files = [
                        'nuclei-takeover-public.txt',
                        'nuclei-takeover-custom.txt',
                        'azure-takeover.txt',
                        'aws-takeover.txt',
                        'azure-aws-takeover.txt',
                        'ns-takeover-raw.txt',
                        'ns-takeover-vuln.txt',
                        'ns-servers.txt',
                        'ns-servers-vuln.txt',
                        'dns-takeover-summary.txt',
                        'dnsreaper-results.txt',
                        'filtered-ns-takeover-vuln.txt'
                    ]
                    
                    for filename in takeover_files:
                        file_path = dns_dir / filename
                        if file_path.exists() and file_path.stat().st_size > 0:
                            files_to_send.append((file_path, f"DNS Takeover: {filename}"))
            
            elif scan_type in ['db_domains', 'db_subdomains', 'db_domains_delete', 'db_stats', 'db_cleanup', 'db_subdomains_all', 'db_js_list']:
                # For database commands, look for any .txt files
                txt_files = list(latest_dir.glob('**/*.txt'))
                if txt_files:
                    for txt_file in txt_files[:3]:  # Limit to 3 files
                        files_to_send.append((txt_file, f"Database export: {txt_file.name}"))
            
            # Send files using Discord bot (25MB limit per file)
            if files_to_send:
                print(f"Found {len(files_to_send)} files to send")
                
                # Send files in batches (Discord allows up to 10 files per message)
                for i in range(0, len(files_to_send), 10):
                    batch = files_to_send[i:i+10]
                    
                    # Create embed for file batch
                    embed = discord.Embed(
                        title="📄 Scan Results",
                        description=f"Found {len(batch)} result file(s) for {scan_type} scan of `{target}`",
                        color=discord.Color.green()
                    )
                    
                    # Prepare files for sending
                    discord_files = []
                    file_descriptions = []
                    
                    for file_path, description in batch:
                        if file_path.stat().st_size < 25 * 1024 * 1024:  # 25MB limit
                            try:
                                discord_files.append(discord.File(str(file_path), filename=file_path.name))
                                file_descriptions.append(f"• {file_path.name} ({file_path.stat().st_size} bytes)")
                            except Exception as e:
                                print(f"Error preparing file {file_path}: {e}")
                        else:
                            print(f"File too large to send: {file_path} ({file_path.stat().st_size} bytes)")
                    
                    if discord_files:
                        # Add file list to embed
                        embed.add_field(
                            name="Files", 
                            value="\n".join(file_descriptions[:10]), 
                            inline=False
                        )
                        
                        try:
                            await interaction.followup.send(
                                embed=embed,
                                files=discord_files
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

@bot.event
async def on_ready():
    """Bot ready event."""
    print(f'{bot.user} has connected to Discord!')
    
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

#!/usr/bin/env python3
"""
AutoAR API Server
A REST API interface for the AutoAR security scanning tool.
"""

import asyncio
import json
import os
import subprocess
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, Body
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field
import yaml
import uvicorn

# Configuration
AUTOAR_SCRIPT_PATH = os.getenv("AUTOAR_SCRIPT_PATH", "/app/main.sh")
CONFIG_FILE = os.getenv("AUTOAR_CONFIG_FILE", "/app/autoar.yaml")
RESULTS_DIR = os.getenv("AUTOAR_RESULTS_DIR", "/app/new-results")
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))

# Create FastAPI app
app = FastAPI(
    title="AutoAR Security Scanner API",
    description="REST API for AutoAR - Automated Application Reconnaissance",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Global variables
active_scans = {}  # Track active scans
scan_results = {}  # Store scan results


# Request/Response Models
class ScanRequest(BaseModel):
    domain: Optional[str] = Field(None, description="Target domain")
    subdomain: Optional[str] = Field(
        None, description="Specific subdomain (for JS scan)"
    )
    url: Optional[str] = Field(
        None, description="Target URL (for nuclei scan or monitoring)"
    )
    bucket: Optional[str] = Field(None, description="S3 bucket name")
    region: Optional[str] = Field(None, description="AWS region")
    repo: Optional[str] = Field(None, description="GitHub repo (owner/repo)")
    file_path: Optional[str] = Field(None, description="File path for list-based scans")
    strategy: Optional[str] = Field(None, description="Monitoring strategy")
    pattern: Optional[str] = Field(None, description="Regex pattern for monitoring")
    interval: Optional[int] = Field(None, description="Monitoring interval in seconds")
    all: Optional[bool] = Field(False, description="Apply to all monitored targets")
    daemon: Optional[bool] = Field(False, description="Run as daemon")
    mode: Optional[str] = Field(
        "full", description="Nuclei scan mode: full, cves, panels, or default-logins"
    )


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str
    command: Optional[str] = None


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    output: Optional[str] = None
    error: Optional[str] = None


class ScanListResponse(BaseModel):
    active_scans: List[Dict[str, Any]]
    completed_scans: List[Dict[str, Any]]


# Helper Functions
def load_config() -> Dict[str, Any]:
    """Load AutoAR configuration from YAML file."""
    config = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                config = yaml.safe_load(f) or {}
        except Exception as e:
            print(f"Warning: Could not load config file: {e}")
    return config


async def run_autoar_command(
    command: list, scan_id: str, timeout: int = 3600
) -> Dict[str, Any]:
    """Run AutoAR command and return results."""
    try:
        env = os.environ.copy()
        env["AUTOAR_CONFIG"] = CONFIG_FILE

        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            cwd=os.path.dirname(AUTOAR_SCRIPT_PATH),
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )

            return {
                "success": process.returncode == 0,
                "stdout": stdout.decode("utf-8", errors="ignore"),
                "stderr": stderr.decode("utf-8", errors="ignore"),
                "returncode": process.returncode,
            }
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Command timed out after {timeout} seconds",
                "returncode": -1,
            }

    except Exception as e:
        return {"success": False, "stdout": "", "stderr": str(e), "returncode": -1}


async def execute_scan(scan_id: str, command: list, scan_type: str):
    """Execute scan in background and store results."""
    active_scans[scan_id] = {
        "scan_id": scan_id,
        "status": "running",
        "scan_type": scan_type,
        "started_at": datetime.utcnow().isoformat(),
        "command": " ".join(command),
    }

    result = await run_autoar_command(command, scan_id)

    active_scans[scan_id]["status"] = "completed" if result["success"] else "failed"
    active_scans[scan_id]["completed_at"] = datetime.utcnow().isoformat()
    active_scans[scan_id]["output"] = result["stdout"]
    active_scans[scan_id]["error"] = result["stderr"]

    # Move to results
    scan_results[scan_id] = active_scans[scan_id].copy()
    del active_scans[scan_id]


# API Endpoints


@app.get("/")
async def root():
    """API root endpoint."""
    return {
        "message": "AutoAR API Server",
        "version": "1.0.0",
        "docs": "/docs",
        "status": "operational",
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


# Subdomain Enumeration
@app.post("/scan/subdomains", response_model=ScanResponse)
async def scan_subdomains(background_tasks: BackgroundTasks, request: ScanRequest):
    """Enumerate subdomains for a domain."""
    if not request.domain:
        raise HTTPException(status_code=400, detail="Domain is required")

    scan_id = str(uuid.uuid4())
    command = [AUTOAR_SCRIPT_PATH, "subdomains", "get", "-d", request.domain]

    background_tasks.add_task(execute_scan, scan_id, command, "subdomains")

    return ScanResponse(
        scan_id=scan_id,
        status="started",
        message=f"Subdomain enumeration started for {request.domain}",
        command=" ".join(command),
    )


# Live Hosts Discovery
@app.post("/scan/livehosts", response_model=ScanResponse)
async def scan_livehosts(background_tasks: BackgroundTasks, request: ScanRequest):
    """Discover live hosts for a domain."""
    if not request.domain:
        raise HTTPException(status_code=400, detail="Domain is required")

    scan_id = str(uuid.uuid4())
    command = [AUTOAR_SCRIPT_PATH, "livehosts", "get", "-d", request.domain]

    background_tasks.add_task(execute_scan, scan_id, command, "livehosts")

    return ScanResponse(
        scan_id=scan_id,
        status="started",
        message=f"Live hosts discovery started for {request.domain}",
        command=" ".join(command),
    )


# CNAME Records
@app.post("/scan/cnames", response_model=ScanResponse)
async def scan_cnames(background_tasks: BackgroundTasks, request: ScanRequest):
    """Get CNAME records for a domain."""
    if not request.domain:
        raise HTTPException(status_code=400, detail="Domain is required")

    scan_id = str(uuid.uuid4())
    command = [AUTOAR_SCRIPT_PATH, "cnames", "get", "-d", request.domain]

    background_tasks.add_task(execute_scan, scan_id, command, "cnames")

    return ScanResponse(
        scan_id=scan_id,
        status="started",
        message=f"CNAME enumeration started for {request.domain}",
        command=" ".join(command),
    )


# URL Collection
@app.post("/scan/urls", response_model=ScanResponse)
async def scan_urls(background_tasks: BackgroundTasks, request: ScanRequest):
    """Collect URLs for a domain."""
    if not request.domain:
        raise HTTPException(status_code=400, detail="Domain is required")

    scan_id = str(uuid.uuid4())
    command = [AUTOAR_SCRIPT_PATH, "urls", "collect", "-d", request.domain]

    background_tasks.add_task(execute_scan, scan_id, command, "urls")

    return ScanResponse(
        scan_id=scan_id,
        status="started",
        message=f"URL collection started for {request.domain}",
        command=" ".join(command),
    )


# JavaScript Scan
@app.post("/scan/js", response_model=ScanResponse)
async def scan_js(background_tasks: BackgroundTasks, request: ScanRequest):
    """Scan JavaScript files for a domain."""
    if not request.domain:
        raise HTTPException(status_code=400, detail="Domain is required")

    scan_id = str(uuid.uuid4())
    command = [AUTOAR_SCRIPT_PATH, "js", "scan", "-d", request.domain]

    if request.subdomain:
        command.extend(["-s", request.subdomain])

    background_tasks.add_task(execute_scan, scan_id, command, "js")

    return ScanResponse(
        scan_id=scan_id,
        status="started",
        message=f"JavaScript scan started for {request.domain}",
        command=" ".join(command),
    )


# Reflection Scan
@app.post("/scan/reflection", response_model=ScanResponse)
async def scan_reflection(background_tasks: BackgroundTasks, request: ScanRequest):
    """Scan for reflection vulnerabilities."""
    if not request.domain:
        raise HTTPException(status_code=400, detail="Domain is required")

    scan_id = str(uuid.uuid4())
    command = [AUTOAR_SCRIPT_PATH, "reflection", "scan", "-d", request.domain]

    background_tasks.add_task(execute_scan, scan_id, command, "reflection")

    return ScanResponse(
        scan_id=scan_id,
        status="started",
        message=f"Reflection scan started for {request.domain}",
        command=" ".join(command),
    )


# Nuclei Scan
@app.post("/scan/nuclei", response_model=ScanResponse)
async def scan_nuclei(background_tasks: BackgroundTasks, request: ScanRequest):
    """Run Nuclei vulnerability scanner with customizable modes."""
    if not request.domain and not request.url:
        raise HTTPException(status_code=400, detail="Either domain or url is required")

    if request.domain and request.url:
        raise HTTPException(
            status_code=400, detail="Cannot use both domain and url together"
        )

    scan_id = str(uuid.uuid4())
    command = [AUTOAR_SCRIPT_PATH, "nuclei", "run"]

    # Add target (domain or url)
    if request.domain:
        command.extend(["-d", request.domain])
        target = request.domain
    else:
        command.extend(["-u", request.url])
        target = request.url

    # Add mode (full, cves, panels, or default-logins)
    mode = request.mode or "full"
    if mode not in ["full", "cves", "panels", "default-logins"]:
        raise HTTPException(
            status_code=400, detail="Mode must be full, cves, panels, or default-logins"
        )
    command.extend(["-m", mode])
    # Subdomain/livehost enumeration is automatic for domain scans

    background_tasks.add_task(execute_scan, scan_id, command, f"nuclei-{mode}")

    return ScanResponse(
        scan_id=scan_id,
        status="started",
        message=f"Nuclei {mode} scan started for {target}",
        command=" ".join(command),
    )


# Technology Detection
@app.post("/scan/tech", response_model=ScanResponse)
async def scan_tech(background_tasks: BackgroundTasks, request: ScanRequest):
    """Detect technologies used by the domain."""
    if not request.domain:
        raise HTTPException(status_code=400, detail="Domain is required")

    scan_id = str(uuid.uuid4())
    command = [AUTOAR_SCRIPT_PATH, "tech", "detect", "-d", request.domain]

    background_tasks.add_task(execute_scan, scan_id, command, "tech")

    return ScanResponse(
        scan_id=scan_id,
        status="started",
        message=f"Technology detection started for {request.domain}",
        command=" ".join(command),
    )


# Port Scan
@app.post("/scan/ports", response_model=ScanResponse)
async def scan_ports(background_tasks: BackgroundTasks, request: ScanRequest):
    """Scan ports for a domain."""
    if not request.domain:
        raise HTTPException(status_code=400, detail="Domain is required")

    scan_id = str(uuid.uuid4())
    command = [AUTOAR_SCRIPT_PATH, "ports", "scan", "-d", request.domain]

    background_tasks.add_task(execute_scan, scan_id, command, "ports")

    return ScanResponse(
        scan_id=scan_id,
        status="started",
        message=f"Port scan started for {request.domain}",
        command=" ".join(command),
    )


# GF Scan
@app.post("/scan/gf", response_model=ScanResponse)
async def scan_gf(background_tasks: BackgroundTasks, request: ScanRequest):
    """Run GF pattern matching."""
    if not request.domain:
        raise HTTPException(status_code=400, detail="Domain is required")

    scan_id = str(uuid.uuid4())
    command = [AUTOAR_SCRIPT_PATH, "gf", "scan", "-d", request.domain]

    background_tasks.add_task(execute_scan, scan_id, command, "gf")

    return ScanResponse(
        scan_id=scan_id,
        status="started",
        message=f"GF pattern scan started for {request.domain}",
        command=" ".join(command),
    )


# DNS Takeover
@app.post("/scan/dns-takeover", response_model=ScanResponse)
async def scan_dns_takeover(background_tasks: BackgroundTasks, request: ScanRequest):
    """Scan for DNS takeover vulnerabilities."""
    if not request.domain:
        raise HTTPException(status_code=400, detail="Domain is required")

    scan_id = str(uuid.uuid4())
    command = [AUTOAR_SCRIPT_PATH, "dns", "takeover", "-d", request.domain]

    background_tasks.add_task(execute_scan, scan_id, command, "dns-takeover")

    return ScanResponse(
        scan_id=scan_id,
        status="started",
        message=f"DNS takeover scan started for {request.domain}",
        command=" ".join(command),
    )


# S3 Bucket Scan
@app.post("/scan/s3", response_model=ScanResponse)
async def scan_s3(background_tasks: BackgroundTasks, request: ScanRequest):
    """Scan S3 bucket for misconfigurations."""
    if not request.bucket:
        raise HTTPException(status_code=400, detail="Bucket name is required")

    scan_id = str(uuid.uuid4())
    command = [AUTOAR_SCRIPT_PATH, "s3", "scan", "-b", request.bucket]

    if request.region:
        command.extend(["-r", request.region])

    background_tasks.add_task(execute_scan, scan_id, command, "s3")

    return ScanResponse(
        scan_id=scan_id,
        status="started",
        message=f"S3 bucket scan started for {request.bucket}",
        command=" ".join(command),
    )


# GitHub Scan
@app.post("/scan/github", response_model=ScanResponse)
async def scan_github(background_tasks: BackgroundTasks, request: ScanRequest):
    """Scan GitHub repository for secrets."""
    if not request.repo:
        raise HTTPException(
            status_code=400, detail="Repository (owner/repo) is required"
        )

    scan_id = str(uuid.uuid4())
    command = [AUTOAR_SCRIPT_PATH, "github", "scan", "-r", request.repo]

    background_tasks.add_task(execute_scan, scan_id, command, "github")

    return ScanResponse(
        scan_id=scan_id,
        status="started",
        message=f"GitHub scan started for {request.repo}",
        command=" ".join(command),
    )


# Scan Status
@app.get("/scan/{scan_id}/status", response_model=ScanStatusResponse)
async def get_scan_status(scan_id: str):
    """Get status of a specific scan."""
    # Check active scans
    if scan_id in active_scans:
        scan = active_scans[scan_id]
        return ScanStatusResponse(
            scan_id=scan_id,
            status=scan["status"],
            started_at=scan.get("started_at"),
            completed_at=scan.get("completed_at"),
            output=None,  # Don't return output for running scans
            error=None,
        )

    # Check completed scans
    if scan_id in scan_results:
        scan = scan_results[scan_id]
        return ScanStatusResponse(
            scan_id=scan_id,
            status=scan["status"],
            started_at=scan.get("started_at"),
            completed_at=scan.get("completed_at"),
            output=scan.get("output"),
            error=scan.get("error"),
        )

    raise HTTPException(status_code=404, detail="Scan not found")


# List All Scans
@app.get("/scans", response_model=ScanListResponse)
async def list_scans():
    """List all active and completed scans."""
    return ScanListResponse(
        active_scans=[
            {
                "scan_id": scan_id,
                "status": scan["status"],
                "scan_type": scan["scan_type"],
                "started_at": scan["started_at"],
            }
            for scan_id, scan in active_scans.items()
        ],
        completed_scans=[
            {
                "scan_id": scan_id,
                "status": scan["status"],
                "scan_type": scan["scan_type"],
                "started_at": scan["started_at"],
                "completed_at": scan.get("completed_at"),
            }
            for scan_id, scan in list(scan_results.items())[-20:]  # Last 20 results
        ],
    )


# Get Scan Results
@app.get("/scan/{scan_id}/results")
async def get_scan_results(scan_id: str):
    """Get detailed results of a completed scan."""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan results not found")

    return scan_results[scan_id]


# Download Scan Output File
@app.get("/scan/{scan_id}/download")
async def download_scan_results(scan_id: str):
    """Download scan results as a file."""
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan results not found")

    scan = scan_results[scan_id]

    # Create temporary file with results
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        f.write(f"Scan ID: {scan_id}\n")
        f.write(f"Scan Type: {scan['scan_type']}\n")
        f.write(f"Status: {scan['status']}\n")
        f.write(f"Started: {scan['started_at']}\n")
        f.write(f"Completed: {scan.get('completed_at', 'N/A')}\n")
        f.write(f"\n{'=' * 80}\n")
        f.write(f"OUTPUT:\n")
        f.write(f"{'=' * 80}\n\n")
        f.write(scan.get("output", "No output"))

        if scan.get("error"):
            f.write(f"\n\n{'=' * 80}\n")
            f.write(f"ERRORS:\n")
            f.write(f"{'=' * 80}\n\n")
            f.write(scan["error"])

        temp_path = f.name

    return FileResponse(
        temp_path, media_type="text/plain", filename=f"autoar_scan_{scan_id}.txt"
    )


# Main entry point
def main():
    """Start the API server."""
    print(f"Starting AutoAR API Server on {API_HOST}:{API_PORT}")
    print(f"Documentation available at http://{API_HOST}:{API_PORT}/docs")

    uvicorn.run(app, host=API_HOST, port=API_PORT, log_level="info")


if __name__ == "__main__":
    main()

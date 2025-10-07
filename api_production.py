#!/usr/bin/env python3
"""
AutoAR API Server - Production Configuration
A FastAPI-based REST API for the AutoAR reconnaissance tool
"""

import asyncio
import json
import os
import subprocess
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import yaml

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

# Initialize FastAPI app
app = FastAPI(
    title="AutoAR API",
    description="REST API for AutoAR reconnaissance tool",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware for production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables
AUTOAR_SCRIPT = "/home/sallam/AutoAR/autoAr.sh"
RESULTS_DIR = "/home/sallam/AutoAR/new-results"
CONFIG_FILE = "/home/sallam/AutoAR/autoar.yaml"
JOBS_DB = {}  # In-memory job storage (use Redis in production)

# Capacity settings
MAX_CONCURRENT_SCANS = int(os.environ.get("AUTOAR_MAX_CONCURRENT", "5"))

# Pydantic models
class ScanRequest(BaseModel):
    target: str = Field(..., description="Target domain, subdomain, or S3 bucket name to scan")
    scan_type: str = Field(..., description="Type of scan: fastLook, liteScan, domain, subdomain, jsScan, jsMonitor, s3Scan, github_single_repo, github_org_scan")
    verbose: bool = Field(False, description="Enable verbose output")
    discord_webhook: Optional[str] = Field(None, description="Discord webhook URL for notifications")
    securitytrails_key: Optional[str] = Field(None, description="SecurityTrails API key")
    region: Optional[str] = Field(None, description="AWS region for S3 scans")
    no_sign_request: bool = Field(False, description="Use no-sign-request for S3 scans")

class ScanResponse(BaseModel):
    job_id: str
    status: str
    message: str
    target: str
    scan_type: str
    created_at: str

class JobStatus(BaseModel):
    job_id: str
    status: str
    target: str
    scan_type: str
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    progress: Optional[str] = None
    results_path: Optional[str] = None
    error: Optional[str] = None

class ScanResults(BaseModel):
    job_id: str
    target: str
    scan_type: str
    status: str
    results: Dict[str, Any]
    files: List[str]
    summary: Dict[str, Any]

# Utility functions
def load_config():
    """Load AutoAR configuration"""
    try:
        with open(CONFIG_FILE, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        return {}

def save_config(config):
    """Save AutoAR configuration"""
    try:
        with open(CONFIG_FILE, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        return True
    except Exception as e:
        return False

def get_scan_results(job_id: str) -> Dict[str, Any]:
    """Get scan results for a job"""
    if job_id not in JOBS_DB:
        return {}
    
    job = JOBS_DB[job_id]
    target = job['target']
    scan_type = job['scan_type']
    
    # Set results path based on scan type
    if scan_type == 's3Scan':
        results_path = Path(RESULTS_DIR) / f"s3_{target}"
    else:
        results_path = Path(RESULTS_DIR) / target
    
    if not results_path.exists():
        return {}
    
    results = {
        "subdomains": [],
        "urls": [],
        "vulnerabilities": {},
        "ports": [],
        "technologies": [],
        "cname_records": [],
        "js_files": []
    }
    
    # Read subdomains
    subs_file = results_path / "subs" / "all-subs.txt"
    if subs_file.exists():
        with open(subs_file, 'r') as f:
            results["subdomains"] = [line.strip() for line in f if line.strip()]
    
    # Read live subdomains
    live_subs_file = results_path / "subs" / "live-subs.txt"
    if live_subs_file.exists():
        with open(live_subs_file, 'r') as f:
            results["live_subdomains"] = [line.strip() for line in f if line.strip()]
    
    # Read URLs
    urls_file = results_path / "urls" / "all-urls.txt"
    if urls_file.exists():
        with open(urls_file, 'r') as f:
            results["urls"] = [line.strip() for line in f if line.strip()]
    
    # Read JS URLs
    js_urls_file = results_path / "urls" / "js-urls.txt"
    if js_urls_file.exists():
        with open(js_urls_file, 'r') as f:
            results["js_files"] = [line.strip() for line in f if line.strip()]
    
    # Read technologies
    tech_file = results_path / "subs" / "tech-detect.txt"
    if tech_file.exists():
        with open(tech_file, 'r') as f:
            results["technologies"] = [line.strip() for line in f if line.strip()]
    
    # Read CNAME records
    cname_file = results_path / "subs" / "cname-records.txt"
    if cname_file.exists():
        with open(cname_file, 'r') as f:
            results["cname_records"] = [line.strip() for line in f if line.strip()]
    
    # Read ports
    ports_file = results_path / "ports" / "ports.txt"
    if ports_file.exists():
        with open(ports_file, 'r') as f:
            results["ports"] = [line.strip() for line in f if line.strip()]
    
    # Read vulnerabilities
    vuln_dir = results_path / "vulnerabilities"
    if vuln_dir.exists():
        for vuln_type in ["xss", "sqli", "ssrf", "ssti", "lfi", "rce", "idor", "js"]:
            vuln_files = list(vuln_dir.glob(f"{vuln_type}/*.txt"))
            if vuln_files:
                results["vulnerabilities"][vuln_type] = []
                for vuln_file in vuln_files:
                    with open(vuln_file, 'r') as f:
                        results["vulnerabilities"][vuln_type].extend([line.strip() for line in f if line.strip()])
    
    return results

def get_available_files(job_id: str) -> List[str]:
    """Get list of available result files for a job"""
    if job_id not in JOBS_DB:
        return []
    
    job = JOBS_DB[job_id]
    target = job['target']
    scan_type = job['scan_type']
    
    # Set results path based on scan type
    if scan_type == 's3Scan':
        results_path = Path(RESULTS_DIR) / f"s3_{target}"
    else:
        results_path = Path(RESULTS_DIR) / target
    
    if not results_path.exists():
        return []
    
    files = []
    for file_path in results_path.rglob("*.txt"):
        if file_path.is_file():
            files.append(str(file_path.relative_to(results_path)))
    
    return files

async def run_scan_async(job_id: str, target: str, scan_type: str, verbose: bool = False, 
                        discord_webhook: str = None, securitytrails_key: str = None, 
                        region: str = None, no_sign_request: bool = False):
    """Run AutoAR scan asynchronously"""
    try:
        # Update job status
        JOBS_DB[job_id]['status'] = 'running'
        JOBS_DB[job_id]['started_at'] = datetime.now().isoformat()
        JOBS_DB[job_id]['progress'] = 'Starting scan...'
        
        # Build command
        cmd = [AUTOAR_SCRIPT, scan_type]
        
        if scan_type in ['fastLook', 'liteScan', 'domain', 'jsScan', 'jsMonitor']:
            cmd.extend(['-d', target])
        elif scan_type == 'subdomain':
            cmd.extend(['-s', target])
        elif scan_type == 's3Scan':
            cmd.extend(['-b', target])
            if region:
                cmd.extend(['-r', region])
            if no_sign_request:
                cmd.append('-n')
        elif scan_type == 'github_single_repo':
            # Use the integrated GitHub scan function in autoAr.sh
            cmd = ['bash', '/home/sallam/AutoAR/autoAr.sh', 'github', '-r', target]
        elif scan_type == 'github_org_scan':
            # Use the integrated GitHub organization scan function in autoAr.sh
            cmd = ['bash', '/home/sallam/AutoAR/autoAr.sh', 'github-org', '-o', target]
        
        if verbose:
            cmd.append('-v')
        
        if discord_webhook:
            cmd.extend(['-dw', discord_webhook])
        
        if securitytrails_key:
            cmd.extend(['-sk', securitytrails_key])
        
        # Run the scan
        JOBS_DB[job_id]['progress'] = f'Running {scan_type} scan on {target}...'
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd="/home/sallam/AutoAR"
        )
        
        stdout, stderr = await process.communicate()
        
        # Update job status
        if process.returncode == 0:
            JOBS_DB[job_id]['status'] = 'completed'
            JOBS_DB[job_id]['completed_at'] = datetime.now().isoformat()
            JOBS_DB[job_id]['progress'] = 'Scan completed successfully'
            
            # Set results path based on scan type
            if scan_type == 's3Scan':
                JOBS_DB[job_id]['results_path'] = str(Path(RESULTS_DIR) / f"s3_{target}")
            else:
                JOBS_DB[job_id]['results_path'] = str(Path(RESULTS_DIR) / target)
        else:
            JOBS_DB[job_id]['status'] = 'failed'
            JOBS_DB[job_id]['completed_at'] = datetime.now().isoformat()
            JOBS_DB[job_id]['error'] = stderr.decode() if stderr else 'Unknown error'
            JOBS_DB[job_id]['progress'] = 'Scan failed'
    
    except Exception as e:
        JOBS_DB[job_id]['status'] = 'failed'
        JOBS_DB[job_id]['completed_at'] = datetime.now().isoformat()
        JOBS_DB[job_id]['error'] = str(e)
        JOBS_DB[job_id]['progress'] = f'Scan failed: {str(e)}'

# API Endpoints
@app.get("/")
async def root(request: Request):
    """Root endpoint with API information"""
    return {
        "name": "AutoAR API",
        "version": "2.0.0",
        "description": "REST API for AutoAR reconnaissance tool",
        "server_ip": request.client.host,
        "public_url": f"http://{request.url.hostname}:{request.url.port}",
        "docs": f"http://{request.url.hostname}:{request.url.port}/docs",
        "endpoints": {
            "scan": "/scan",
            "status": "/status/{job_id}",
            "results": "/results/{job_id}",
            "download": "/download/{job_id}/{file_path:path}",
            "jobs": "/jobs",
            "config": "/config"
        },
        "available_scan_types": [
            "fastLook", "liteScan", "domain", "subdomain", 
            "jsScan", "jsMonitor", "s3Scan", "github_single_repo", "github_org_scan"
        ]
    }

@app.post("/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new scan"""
    # Generate job ID
    job_id = str(uuid.uuid4())
    
    # Create job record
    JOBS_DB[job_id] = {
        'job_id': job_id,
        'status': 'queued',
        'target': request.target,
        'scan_type': request.scan_type,
        'created_at': datetime.now().isoformat(),
        'started_at': None,
        'completed_at': None,
        'progress': 'Queued for execution',
        'results_path': None,
        'error': None
    }
    
    # Start background task
    background_tasks.add_task(
        run_scan_async,
        job_id,
        request.target,
        request.scan_type,
        request.verbose,
        request.discord_webhook,
        request.securitytrails_key,
        request.region,
        request.no_sign_request
    )
    
    return ScanResponse(
        job_id=job_id,
        status='queued',
        message=f'Scan job created for {request.target}',
        target=request.target,
        scan_type=request.scan_type,
        created_at=JOBS_DB[job_id]['created_at']
    )

@app.get("/status/{job_id}", response_model=JobStatus)
async def get_job_status(job_id: str):
    """Get status of a scan job"""
    if job_id not in JOBS_DB:
        raise HTTPException(status_code=404, detail="Job not found")
    
    job = JOBS_DB[job_id]
    return JobStatus(**job)

@app.get("/results/{job_id}", response_model=ScanResults)
async def get_scan_results(job_id: str):
    """Get scan results for a completed job"""
    if job_id not in JOBS_DB:
        raise HTTPException(status_code=404, detail="Job not found")
    
    job = JOBS_DB[job_id]
    
    if job['status'] != 'completed':
        raise HTTPException(status_code=400, detail="Job not completed yet")
    
    # Get results
    results = get_scan_results(job_id)
    files = get_available_files(job_id)
    
    # Create summary
    summary = {
        "total_subdomains": len(results.get("subdomains", [])),
        "live_subdomains": len(results.get("live_subdomains", [])),
        "total_urls": len(results.get("urls", [])),
        "js_files": len(results.get("js_files", [])),
        "technologies": len(results.get("technologies", [])),
        "cname_records": len(results.get("cname_records", [])),
        "ports": len(results.get("ports", [])),
        "vulnerabilities": {k: len(v) for k, v in results.get("vulnerabilities", {}).items()}
    }
    
    return ScanResults(
        job_id=job_id,
        target=job['target'],
        scan_type=job['scan_type'],
        status=job['status'],
        results=results,
        files=files,
        summary=summary
    )

@app.get("/download/{job_id}/{file_path:path}")
async def download_file(job_id: str, file_path: str):
    """Download a specific result file"""
    if job_id not in JOBS_DB:
        raise HTTPException(status_code=404, detail="Job not found")
    
    job = JOBS_DB[job_id]
    target = job['target']
    full_path = Path(RESULTS_DIR) / target / file_path
    
    if not full_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(
        path=str(full_path),
        filename=Path(file_path).name,
        media_type='text/plain'
    )

@app.get("/jobs")
async def list_jobs(limit: int = Query(10, ge=1, le=100)):
    """List recent jobs"""
    jobs = list(JOBS_DB.values())
    jobs.sort(key=lambda x: x['created_at'], reverse=True)
    return jobs[:limit]

@app.delete("/jobs/{job_id}")
async def delete_job(job_id: str):
    """Delete a job and its results"""
    if job_id not in JOBS_DB:
        raise HTTPException(status_code=404, detail="Job not found")
    
    job = JOBS_DB[job_id]
    target = job['target']
    scan_type = job['scan_type']
    
    # Set results path based on scan type
    if scan_type == 's3Scan':
        results_path = Path(RESULTS_DIR) / f"s3_{target}"
    else:
        results_path = Path(RESULTS_DIR) / target
    
    # Delete results directory
    if results_path.exists():
        import shutil
        shutil.rmtree(results_path)
    
    # Remove job from database
    del JOBS_DB[job_id]
    
    return {"message": f"Job {job_id} and its results deleted successfully"}

@app.get("/config")
async def get_config():
    """Get current configuration"""
    config = load_config()
    return config

@app.put("/config")
async def update_config(config: Dict[str, Any]):
    """Update configuration"""
    if save_config(config):
        return {"message": "Configuration updated successfully"}
    else:
        raise HTTPException(status_code=500, detail="Failed to update configuration")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "active_jobs": len([j for j in JOBS_DB.values() if j['status'] == 'running']),
        "server_ip": "194.163.160.166"
    }

@app.get("/capacity")
async def capacity():
    """Report scheduler capacity for starting new scans"""
    running = [j for j in JOBS_DB.values() if j.get('status') == 'running']
    queued = [j for j in JOBS_DB.values() if j.get('status') == 'queued']
    running_jobs = len(running)
    can_start_new = running_jobs < MAX_CONCURRENT_SCANS
    return {
        "can_start_new": can_start_new,
        "running_jobs": running_jobs,
        "queued_jobs": len(queued),
        "max_concurrent": MAX_CONCURRENT_SCANS,
        "active_job_ids": [j['job_id'] for j in running],
        "timestamp": datetime.now().isoformat()
    }

if __name__ == "__main__":
    # Ensure results directory exists
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    # Start the server
    uvicorn.run(
        "api_production:app",
        host="0.0.0.0",
        port=8000,
        reload=False,  # Disable reload in production
        log_level="info"
    )

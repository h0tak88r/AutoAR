from flask import Flask, jsonify, request, Response
from flask_cors import CORS
import subprocess
import json
import os
import logging
import signal
from typing import Tuple, Dict, Any, Optional

app = Flask(__name__)
CORS(app, resources={
    r"/api/*": {
        "origins": ["http://localhost:3000"],
        "methods": ["GET", "POST", "OPTIONS", "DELETE"],
        "allow_headers": ["Content-Type"]
    }
})

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Store active scan processes
active_scans = {}

def get_script_path() -> str:
    """Get the absolute path to autoAr.sh"""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    script_path = os.path.join(parent_dir, '..', 'autoAr.sh')
    if not os.path.exists(script_path):
        raise FileNotFoundError(f"Script not found at {script_path}")
    return script_path

def get_project_root() -> str:
    """Get the project root directory where autoAr.sh is located"""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    return os.path.dirname(parent_dir)

def run_command(cmd: list) -> Tuple[bool, str, Optional[str]]:
    """Run a command and return its output"""
    try:
        logger.info(f"Running command from directory: {get_project_root()}")
        logger.info(f"Running command: {' '.join(cmd)}")
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            cwd=get_project_root()
        )
        
        # Store the process with the domain as the key
        domain = cmd[cmd.index('-d') + 1] if '-d' in cmd else 'unknown'
        active_scans[domain] = process
        
        output, error = process.communicate()
        success = process.returncode == 0
        
        # Remove process from active scans when complete
        if domain in active_scans:
            del active_scans[domain]
            
        return success, output, error
    except Exception as e:
        logger.error(f"Error running command: {str(e)}")
        return False, "", str(e)

@app.route('/api/scan', methods=['POST', 'OPTIONS'])
def run_scan() -> Response:
    """Handle scan requests"""
    if request.method == 'OPTIONS':
        return jsonify({"status": "ok"})

    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400

        domain = data.get('domain')
        if not domain:
            return jsonify({"success": False, "error": "Domain is required"}), 400

        options = data.get('options', {})
        
        # Build command
        script_path = get_script_path()
        cmd = [script_path, '-d', domain]
        
        # Add webhook if provided
        if options.get('webhook'):
            cmd.extend(['-w', options['webhook']])
        
        if options.get('skip_ports'): cmd.append('--skip-ports')
        if options.get('skip_fuzz'): cmd.append('--skip-fuzz')
        if options.get('skip_sqli'): cmd.append('--skip-sqli')
        if options.get('skip_paramx'): cmd.append('--skip-paramx')
        if options.get('verbose'): cmd.append('-v')
        
        # Run scan
        success, output, error = run_command(cmd)
        
        response = {
            "success": success,
            "output": output,
            "error": error if error else None
        }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error in run_scan: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500

@app.route('/api/scan/<domain>', methods=['DELETE'])
def stop_scan(domain: str) -> Response:
    """Stop a running scan for a specific domain"""
    if domain in active_scans:
        try:
            process = active_scans[domain]
            # Only terminate this specific process
            process.terminate()
            try:
                # Wait for up to 5 seconds for the process to end
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # If it doesn't end gracefully, force kill it
                process.kill()
            
            del active_scans[domain]
            return jsonify({"success": True, "message": f"Scan stopped for domain: {domain}"})
        except Exception as e:
            logger.error(f"Error stopping scan: {str(e)}")
            return jsonify({"success": False, "error": str(e)}), 500
    else:
        return jsonify({"success": False, "error": "No active scan found for this domain"}), 404

@app.route('/api/results/<domain>', methods=['GET'])
def get_results(domain):
    try:
        results_dir = os.path.join(os.path.dirname(get_script_path()), 'results', domain)
        if not os.path.exists(results_dir):
            return jsonify({'error': 'No results found for this domain'}), 404
            
        # Read results from the directory
        results = {
            'subdomains': [],
            'vulnerabilities': [],
            'ports': []
        }
        
        # Add logic to read results from files
        return jsonify(results)
        
    except Exception as e:
        logger.error(f"Error in get_results: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check() -> Response:
    """Health check endpoint"""
    return jsonify({"status": "healthy"})

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')

#!/usr/bin/env python3
"""
AutoAR API Usage Examples
Demonstrates various ways to interact with the AutoAR REST API
"""

import requests
import time
import json
from typing import Dict, Optional, List


class AutoARClient:
    """Simple client for AutoAR API"""

    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url.rstrip("/")

    def health_check(self) -> Dict:
        """Check API health"""
        response = requests.get(f"{self.base_url}/health")
        response.raise_for_status()
        return response.json()

    def start_scan(self, scan_type: str, **kwargs) -> Dict:
        """Start a new scan"""
        response = requests.post(f"{self.base_url}/scan/{scan_type}", json=kwargs)
        response.raise_for_status()
        return response.json()

    def get_scan_status(self, scan_id: str) -> Dict:
        """Get scan status"""
        response = requests.get(f"{self.base_url}/scan/{scan_id}/status")
        response.raise_for_status()
        return response.json()

    def get_scan_results(self, scan_id: str) -> Dict:
        """Get scan results"""
        response = requests.get(f"{self.base_url}/scan/{scan_id}/results")
        response.raise_for_status()
        return response.json()

    def list_scans(self) -> Dict:
        """List all scans"""
        response = requests.get(f"{self.base_url}/scans")
        response.raise_for_status()
        return response.json()

    def download_results(self, scan_id: str, output_file: str):
        """Download scan results to file"""
        response = requests.get(f"{self.base_url}/scan/{scan_id}/download")
        response.raise_for_status()
        with open(output_file, "wb") as f:
            f.write(response.content)

    def wait_for_completion(
        self, scan_id: str, interval: int = 5, max_wait: int = 600
    ) -> str:
        """Wait for scan to complete"""
        start_time = time.time()
        while time.time() - start_time < max_wait:
            status_data = self.get_scan_status(scan_id)
            status = status_data["status"]

            if status in ["completed", "failed"]:
                return status

            print(
                f"  Status: {status} (elapsed: {int(time.time() - start_time)}s)",
                end="\r",
            )
            time.sleep(interval)

        raise TimeoutError(f"Scan {scan_id} did not complete within {max_wait}s")


# Example 1: Simple Subdomain Scan
def example_subdomain_scan():
    """Example: Run a subdomain enumeration scan"""
    print("\n" + "=" * 60)
    print("Example 1: Subdomain Enumeration")
    print("=" * 60)

    client = AutoARClient()

    # Check API health
    health = client.health_check()
    print(f"✓ API Status: {health['status']}")

    # Start subdomain scan
    print("\n[+] Starting subdomain scan for example.com...")
    scan = client.start_scan("subdomains", domain="example.com")
    scan_id = scan["scan_id"]
    print(f"[+] Scan ID: {scan_id}")

    # Wait for completion
    print("[+] Waiting for scan to complete...")
    status = client.wait_for_completion(scan_id, max_wait=300)
    print(f"\n[+] Scan {status}")

    # Get results
    if status == "completed":
        results = client.get_scan_results(scan_id)
        print(f"\n[+] Scan completed at: {results['completed_at']}")
        print(f"[+] Output preview:")
        print(results["output"][:500])


# Example 2: Multiple Scans in Parallel
def example_parallel_scans():
    """Example: Run multiple scans in parallel"""
    print("\n" + "=" * 60)
    print("Example 2: Parallel Scanning")
    print("=" * 60)

    client = AutoARClient()
    domains = ["example.com", "test.com", "demo.com"]

    # Start multiple scans
    scan_ids = []
    for domain in domains:
        print(f"[+] Starting scan for {domain}...")
        scan = client.start_scan("subdomains", domain=domain)
        scan_ids.append((domain, scan["scan_id"]))
        print(f"    Scan ID: {scan['scan_id']}")

    # Monitor all scans
    print("\n[+] Monitoring all scans...")
    results = {}
    for domain, scan_id in scan_ids:
        try:
            status = client.wait_for_completion(scan_id, max_wait=300)
            results[domain] = status
            print(f"\n  {domain}: {status}")
        except TimeoutError:
            results[domain] = "timeout"
            print(f"\n  {domain}: timeout")

    # Summary
    print("\n[+] Summary:")
    for domain, status in results.items():
        print(f"    {domain}: {status}")


# Example 3: Full Reconnaissance Workflow
def example_full_recon_workflow():
    """Example: Complete reconnaissance workflow"""
    print("\n" + "=" * 60)
    print("Example 3: Full Reconnaissance Workflow")
    print("=" * 60)

    client = AutoARClient()
    target = "example.com"
    scan_results = {}

    # Step 1: Subdomain Enumeration
    print(f"\n[1/5] Enumerating subdomains for {target}...")
    scan = client.start_scan("subdomains", domain=target)
    status = client.wait_for_completion(scan["scan_id"])
    scan_results["subdomains"] = scan["scan_id"]
    print(f"      Status: {status}")

    # Step 2: Live Hosts Discovery
    print(f"\n[2/5] Discovering live hosts...")
    scan = client.start_scan("livehosts", domain=target)
    status = client.wait_for_completion(scan["scan_id"])
    scan_results["livehosts"] = scan["scan_id"]
    print(f"      Status: {status}")

    # Step 3: URL Collection
    print(f"\n[3/5] Collecting URLs...")
    scan = client.start_scan("urls", domain=target)
    status = client.wait_for_completion(scan["scan_id"])
    scan_results["urls"] = scan["scan_id"]
    print(f"      Status: {status}")

    # Step 4: Technology Detection
    print(f"\n[4/5] Detecting technologies...")
    scan = client.start_scan("tech", domain=target)
    status = client.wait_for_completion(scan["scan_id"])
    scan_results["tech"] = scan["scan_id"]
    print(f"      Status: {status}")

    # Step 5: Vulnerability Scanning (Nuclei)
    print(f"\n[5/5] Running vulnerability scan...")
    scan = client.start_scan("nuclei", domain=target)
    status = client.wait_for_completion(scan["scan_id"], max_wait=600)
    scan_results["nuclei"] = scan["scan_id"]
    print(f"      Status: {status}")

    # Download all results
    print("\n[+] Downloading results...")
    for scan_type, scan_id in scan_results.items():
        filename = f"{target}_{scan_type}_{scan_id[:8]}.txt"
        client.download_results(scan_id, filename)
        print(f"    Saved: {filename}")

    print("\n[+] Workflow complete!")


# Example 4: JavaScript Analysis
def example_js_analysis():
    """Example: JavaScript file analysis"""
    print("\n" + "=" * 60)
    print("Example 4: JavaScript Analysis")
    print("=" * 60)

    client = AutoARClient()

    # Scan with optional subdomain
    print("[+] Analyzing JavaScript files...")
    scan = client.start_scan("js", domain="example.com", subdomain="api.example.com")

    print(f"[+] Scan ID: {scan['scan_id']}")
    status = client.wait_for_completion(scan["scan_id"])
    print(f"\n[+] Scan {status}")

    if status == "completed":
        results = client.get_scan_results(scan["scan_id"])
        print("\n[+] Results preview:")
        print(results["output"][:500])


# Example 5: S3 Bucket Security Check
def example_s3_scan():
    """Example: S3 bucket security scan"""
    print("\n" + "=" * 60)
    print("Example 5: S3 Bucket Security Scan")
    print("=" * 60)

    client = AutoARClient()

    # Scan S3 bucket
    print("[+] Scanning S3 bucket...")
    scan = client.start_scan("s3", bucket="example-bucket", region="us-east-1")

    print(f"[+] Scan ID: {scan['scan_id']}")
    status = client.wait_for_completion(scan["scan_id"])
    print(f"\n[+] Scan {status}")

    if status == "completed":
        results = client.get_scan_results(scan["scan_id"])
        print("\n[+] Findings:")
        print(results["output"])


# Example 6: GitHub Repository Scan
def example_github_scan():
    """Example: GitHub repository secrets scan"""
    print("\n" + "=" * 60)
    print("Example 6: GitHub Repository Scan")
    print("=" * 60)

    client = AutoARClient()

    # Scan GitHub repository
    print("[+] Scanning GitHub repository...")
    scan = client.start_scan("github", repo="owner/repository")

    print(f"[+] Scan ID: {scan['scan_id']}")
    status = client.wait_for_completion(scan["scan_id"], max_wait=900)
    print(f"\n[+] Scan {status}")

    if status == "completed":
        results = client.get_scan_results(scan["scan_id"])
        print("\n[+] Secrets found:")
        print(results["output"])


# Example 7: DNS Takeover Detection
def example_dns_takeover():
    """Example: DNS takeover vulnerability check"""
    print("\n" + "=" * 60)
    print("Example 7: DNS Takeover Detection")
    print("=" * 60)

    client = AutoARClient()

    print("[+] Checking for DNS takeover vulnerabilities...")
    scan = client.start_scan("dns-takeover", domain="example.com")

    print(f"[+] Scan ID: {scan['scan_id']}")
    status = client.wait_for_completion(scan["scan_id"])
    print(f"\n[+] Scan {status}")

    if status == "completed":
        results = client.get_scan_results(scan["scan_id"])
        print("\n[+] Vulnerabilities:")
        print(results["output"])


# Example 8: List and Monitor Active Scans
def example_monitor_scans():
    """Example: Monitor all active scans"""
    print("\n" + "=" * 60)
    print("Example 8: Monitor Active Scans")
    print("=" * 60)

    client = AutoARClient()

    # Start a few scans
    print("[+] Starting multiple scans...")
    scan_ids = []
    for domain in ["example.com", "test.com"]:
        scan = client.start_scan("subdomains", domain=domain)
        scan_ids.append(scan["scan_id"])

    # Monitor scans
    print("\n[+] Monitoring scans...")
    completed = []
    while len(completed) < len(scan_ids):
        scans_list = client.list_scans()
        active = scans_list["active_scans"]

        print(f"\n  Active scans: {len(active)}")
        for scan in active:
            print(
                f"    - {scan['scan_id'][:8]}... ({scan['scan_type']}) - {scan['status']}"
            )

        # Check which completed
        for scan_id in scan_ids:
            if scan_id not in completed:
                status_data = client.get_scan_status(scan_id)
                if status_data["status"] in ["completed", "failed"]:
                    completed.append(scan_id)
                    print(f"\n  ✓ Scan {scan_id[:8]}... {status_data['status']}")

        if len(completed) < len(scan_ids):
            time.sleep(5)

    print("\n[+] All scans completed!")


# Example 9: Error Handling
def example_error_handling():
    """Example: Proper error handling"""
    print("\n" + "=" * 60)
    print("Example 9: Error Handling")
    print("=" * 60)

    client = AutoARClient()

    try:
        # Invalid scan type
        print("[+] Testing invalid scan type...")
        scan = client.start_scan("invalid_type", domain="example.com")
    except requests.exceptions.HTTPError as e:
        print(f"[!] Expected error: {e}")

    try:
        # Missing required parameter
        print("\n[+] Testing missing parameter...")
        scan = client.start_scan("subdomains")  # Missing domain
    except requests.exceptions.HTTPError as e:
        print(f"[!] Expected error: {e}")

    try:
        # Invalid scan ID
        print("\n[+] Testing invalid scan ID...")
        results = client.get_scan_status("invalid-scan-id")
    except requests.exceptions.HTTPError as e:
        print(f"[!] Expected error: {e}")

    print("\n[+] Error handling working correctly!")


# Example 10: Batch Processing with Results Export
def example_batch_export():
    """Example: Batch process multiple targets and export results"""
    print("\n" + "=" * 60)
    print("Example 10: Batch Processing with Export")
    print("=" * 60)

    client = AutoARClient()
    targets = ["example.com", "test.com", "demo.com"]
    all_results = {}

    for target in targets:
        print(f"\n[+] Processing {target}...")

        # Run scan
        scan = client.start_scan("subdomains", domain=target)
        scan_id = scan["scan_id"]

        # Wait and collect results
        try:
            status = client.wait_for_completion(scan_id, max_wait=300)
            if status == "completed":
                results = client.get_scan_results(scan_id)
                all_results[target] = {
                    "status": status,
                    "scan_id": scan_id,
                    "started_at": results["started_at"],
                    "completed_at": results["completed_at"],
                    "output": results["output"],
                }
                print(f"    ✓ Completed")
            else:
                all_results[target] = {"status": status, "scan_id": scan_id}
                print(f"    ✗ Failed")
        except TimeoutError:
            all_results[target] = {"status": "timeout", "scan_id": scan_id}
            print(f"    ⏱ Timeout")

    # Export all results to JSON
    output_file = "batch_results.json"
    with open(output_file, "w") as f:
        json.dump(all_results, f, indent=2)

    print(f"\n[+] Results exported to {output_file}")


def main():
    """Main function - run examples"""
    print("\n" + "=" * 60)
    print("AutoAR API Examples")
    print("=" * 60)
    print("\nAvailable examples:")
    print("  1. Simple Subdomain Scan")
    print("  2. Parallel Scanning")
    print("  3. Full Reconnaissance Workflow")
    print("  4. JavaScript Analysis")
    print("  5. S3 Bucket Security Check")
    print("  6. GitHub Repository Scan")
    print("  7. DNS Takeover Detection")
    print("  8. Monitor Active Scans")
    print("  9. Error Handling")
    print(" 10. Batch Processing with Export")

    print("\nTo run an example, call its function:")
    print("  python api_example.py")
    print("\nOr import and use:")
    print("  from api_example import example_subdomain_scan")
    print("  example_subdomain_scan()")

    # Uncomment to run a specific example
    # example_subdomain_scan()
    # example_parallel_scans()
    # example_full_recon_workflow()
    # example_js_analysis()
    # example_s3_scan()
    # example_github_scan()
    # example_dns_takeover()
    # example_monitor_scans()
    # example_error_handling()
    # example_batch_export()


if __name__ == "__main__":
    main()


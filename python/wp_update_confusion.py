#!/usr/bin/env python3

import os
import re
import sys
import json
import argparse
import requests
import subprocess
from datetime import datetime


def banner():
    banner = "\n"
    banner += " +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+\n"
    banner += " |W|o|r|d|P|r|e|s|s| |U|p|d|a|t|e| |C|o|n|f|u|s|i|o|n|\n"
    banner += " +-+-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+-+\n"

    return banner


def load_env():
    """Load environment variables from .env file"""
    env_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
    if os.path.exists(env_file):
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    os.environ[key] = value


def send_to_discord(file_path, description):
    """Send file to Discord using the shell discord_file function"""
    try:
        # Get the project root directory
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        discord_script = os.path.join(project_root, 'lib', 'discord.sh')
        
        if not os.path.exists(discord_script):
            print(f"❌ Discord script not found: {discord_script}")
            return
        
        # Use the shell discord_file function
        result = subprocess.run([
            'bash', '-c', 
            f'source "{discord_script}" && discord_file "{file_path}" "{description}"'
        ], capture_output=True, text=True, cwd=project_root)
        
        if result.returncode == 0:
            print(f"✅ Sent to Discord: {description}")
        else:
            print(f"❌ Failed to send to Discord: {result.stderr}")
    except Exception as e:
        print(f"❌ Error sending to Discord: {e}")
        # Try alternative method using curl
        try:
            webhook_url = os.environ.get('DISCORD_WEBHOOK_URL')
            if webhook_url and os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Send as text message if file is small
                if len(content) < 2000:
                    payload = {
                        "content": f"**{description}**\n```\n{content}\n```"
                    }
                    subprocess.run(['curl', '-X', 'POST', webhook_url, '-H', 'Content-Type: application/json', '-d', json.dumps(payload)], check=True)
                    print(f"✅ Sent to Discord via curl: {description}")
        except Exception as curl_e:
            print(f"❌ Failed to send via curl: {curl_e}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="",
        epilog="Have a nice day :)",
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("-u", dest="url", help="URL of WordPress site")
    target.add_argument("-l", dest="list", help="List of WordPress sites")
    check = parser.add_mutually_exclusive_group(required=True)
    check.add_argument(
        "-t", "--theme", dest="theme", action="store_true", help="Check themes"
    )
    check.add_argument(
        "-p", "--plugins", dest="plugins", action="store_true", help="Check plugins"
    )
    parser.add_argument("-o", dest="output", help="Name of output file")
    parser.add_argument(
        "-s", "--silent", dest="silent", action="store_true", help="Silent output"
    )
    parser.add_argument(
        "--discord", dest="discord", action="store_true", help="Send results to Discord"
    )

    return parser.parse_args()


def detect_theme(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0",
    }

    try:
        res = requests.get(
            url,
            headers=headers,
        )
    except:
        return 0

    html = res.text

    match = re.search("wp-content/themes/(.*?)/", html)

    try:
        theme = match.group(1)
    except:
        theme = False

    return theme


def detect_plugins(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0",
    }

    try:
        res = requests.get(url, headers=headers, timeout=5)
    except:
        return 0

    html = res.text

    match = re.findall("wp-content/plugins/(.*?)/", html)
    plugins = list(set(match))

    return plugins


def check_wordpress_org_theme(theme):
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0",
    }

    res = requests.get(
        f"https://wordpress.org/themes/{theme}",
        headers=headers,
    )

    if res.status_code == 404:
        is_vulnerable = True
    else:
        is_vulnerable = False

    return is_vulnerable


def check_wordpress_org_plugin(plugin):
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0",
    }

    res = requests.get(
        f"https://plugins.svn.wordpress.org/{plugin}/",
        headers=headers,
    )

    if res.status_code == 404:
        is_vulnerable = True
    else:
        is_vulnerable = False

    return is_vulnerable


def check_paid_plugins(plugin):
    f = open("paid_plugins.json")

    paid_plugins = json.load(f)

    f.close()

    if plugin in paid_plugins:
        return 1
    else:
        return 0




def is_allowed_slug(plugin):
    # https://meta.trac.wordpress.org/ticket/5868
    # https://meta.trac.wordpress.org/browser/sites/trunk/wordpress.org/public_html/wp-content/plugins/plugin-directory/shortcodes/class-upload-handler.php

    # has_reserved_slug()
    reserved_slug = [
        "about",
        "admin",
        "browse",
        "category",
        "developers",
        "developer",
        "featured",
        "filter",
        "new",
        "page",
        "plugins",
        "popular",
        "post",
        "search",
        "tag",
        "updated",
        "upload",
        "wp-admin",
        "jquery",
        "wordpress",
        "akismet-anti-spam",
        "site-kit-by-google",
        "yoast-seo",
        "woo",
        "wp-media-folder",
        "wp-file-download",
        "wp-table-manager",
    ]

    # has_trademarked_slug()
    trademarked_slug = [
        "adobe-",
        "adsense-",
        "advanced-custom-fields-",
        "adwords-",
        "akismet-",
        "all-in-one-wp-migration",
        "amazon-",
        "android-",
        "apple-",
        "applenews-",
        "aws-",
        "bbpress-",
        "bing-",
        "bootstrap-",
        "buddypress-",
        "contact-form-7-",
        "cpanel-",
        "disqus-",
        "divi-",
        "dropbox-",
        "easy-digital-downloads-",
        "elementor-",
        "envato-",
        "fbook",
        "facebook",
        "fb-",
        "fb-messenger",
        "fedex-",
        "feedburner",
        "ganalytics-",
        "gberg",
        "github-",
        "givewp-",
        "google-",
        "googlebot-",
        "googles-",
        "gravity-form-",
        "gravity-forms-",
        "gutenberg",
        "guten-",
        "hubspot-",
        "ig-",
        "insta-",
        "instagram",
        "internet-explorer-",
        "jetpack-",
        "macintosh-",
        "mailchimp-",
        "microsoft-",
        "ninja-forms-",
        "oculus",
        "onlyfans-",
        "only-fans-",
        "paddle-",
        "paypal-",
        "pinterest-",
        "stripe-",
        "tiktok-",
        "trustpilot",
        "twitter-",
        "tweet",
        "ups-",
        "usps-",
        "vvhatsapp",
        "vvcommerce",
        "vva-",
        "vvoo",
        "wa-",
        "wh4tsapps",
        "whatsapp",
        "whats-app",
        "watson",
        "windows-",
        "wocommerce",
        "woocom-",
        "woocommerce",
        "woocomerce",
        "woo-commerce",
        "woo-",
        "wo-",
        "wordpress",
        "wordpess",
        "wpress",
        "wp-",
        "wp-mail-smtp-",
        "yahoo-",
        "yoast",
        "youtube-",
    ]

    # Check allowed characters
    if not re.match("^[a-z0-9-]*$", plugin):
        return 0

    # Prevent short plugin names (they're generally SEO grabs).
    if len(plugin) < 5:
        return 0

    # Check if forbidden slug
    if plugin in reserved_slug:
        return 0

    # Check if trademarked slug
    for trademark in trademarked_slug:
        # Trademarks ending in "-" indicate slug cannot begin with that term.
        if trademark.endswith("-"):
            if plugin.startswith(trademark):
                return 0
        # Otherwise, the term cannot appear anywhere in slug.
        # check for 'for-TRADEMARK' exceptions.
        elif trademark in plugin and not plugin.endswith(f"for-{trademark}"):
            return 0

    return 1


def main(args):

    urls = []

    if args.silent:
        sys.stdout = open(os.devnull, "a")
        sys.stderr = open(os.devnull, "a")

    # Load environment variables if Discord is enabled
    if args.discord:
        load_env()

    if args.list:
        with open(args.list) as file:
            while (url := file.readline().rstrip()) :
                urls.append(url)
    else:
        urls.append(args.url)

    # Process all URLs and collect results
    all_vulnerable = []
    processed_count = 0
    vulnerable_count = 0
    
    print(f"[i] Processing {len(urls)} targets\n")

    for url in urls:
        vulnerable = []
        print("-------------------------\n")
        print(f"[i] Target: {url}\n")

        if args.theme:
            print("[i] Searching theme\n")

            theme = detect_theme(url)
            if theme:
                print(f"[i] Found WP theme: {theme}\n")

                is_vulnerable = check_wordpress_org_theme(theme)
                if is_vulnerable:
                    print("\t[!] Vulnerable to WP Theme Confusion attack\n")
                    print(f"\t[!] {url}/wp-content/themes/{theme}")
                    print(f"\t[!] https://wordpress.org/themes/{theme}\n")
                    vulnerable.append(f"{url}/wp-content/themes/{theme}")
                else:
                    print(f"\t[i] Not vulnerable\n")

        if args.plugins:
            print(f"[i] Searching plugins\n")
            plugins = detect_plugins(url)

            for plugin in plugins or []:
                print(f"[i] Found WP plugin: {plugin}")

                is_allowed = is_allowed_slug(plugin)
                if not (is_allowed):
                    print(f"\t[i] Not vulnerable - disallowed name\n")
                    continue

                # Check for common premium plugin indicators
                premium_indicators = ["pro", "premium", "business", "enterprise", "paid"]
                plugin_lower = plugin.lower()
                is_premium = any(
                    f"-{ind}-" in plugin_lower or  # Check middle
                    f"-{ind}" in plugin_lower or   # Check end
                    f"{ind}-" in plugin_lower      # Check start
                    for ind in premium_indicators
                )
                
                if is_premium:
                    with open("paid.txt", "a") as f:
                        f.write(f"{plugin}\n")
                    print(f"\t[i] Not vulnerable - premium plugin detected ({plugin})\n") 
                    continue

                # Check against known paid plugins list
                is_paid = check_paid_plugins(plugin)
                if is_paid:
                    with open("paid.txt", "a") as f:
                        f.write(f"{plugin}\n")
                    print(f"\t[i] Not vulnerable - paid plugin ({plugin})\n")
                    continue

                is_vulnerable = check_wordpress_org_plugin(plugin)
                if is_vulnerable:
                    print("\t[!] Vulnerable to WP Plugin Confusion attack\n")
                    print(f"\t[!] {url}/wp-content/plugins/{plugin}")
                    print(f"\t[!] https://wordpress.org/plugins/{plugin}\n")
                    vulnerable.append(f"{url}/wp-content/plugins/{plugin}")
                else:
                    print(f"\t[i] Not vulnerable - already claimed\n")

        # Collect results
        all_vulnerable.extend(vulnerable)
        processed_count += 1
        
        if vulnerable:
            vulnerable_count += 1
            print(f"[+] Found {len(vulnerable)} vulnerabilities for {url}")
        else:
            print(f"[i] No vulnerabilities found for {url}")
        
        print()  # Add spacing between targets

    # Handle output for all results
    if args.output:
        if all_vulnerable:
            with open(args.output, "w") as f:
                for item in all_vulnerable:
                    f.write("%s\n" % item)
            
            # Send results to Discord if enabled
            if args.discord:
                send_to_discord(args.output, f"WordPress Plugin Confusion vulnerabilities across {processed_count} targets ({len(all_vulnerable)} total found)")
        else:
            # Send log file to Discord even if no vulnerabilities found
            if args.discord:
                log_file = args.output.replace('.txt', '.log')
                with open(log_file, 'w') as f:
                    f.write(f"WordPress Plugin Confusion Scan Results\n")
                    f.write(f"=====================================\n")
                    f.write(f"Targets: {processed_count}\n")
                    f.write(f"Timestamp: {datetime.now()}\n")
                    f.write(f"No vulnerabilities found across all targets\n")
                send_to_discord(log_file, f"WordPress Plugin Confusion scan log for {processed_count} targets (no vulnerabilities)")
    
    # Print summary
    print(f"[i] Scan Summary:")
    print(f"[i] Targets processed: {processed_count}")
    print(f"[i] Targets with vulnerabilities: {vulnerable_count}")
    print(f"[i] Total vulnerabilities found: {len(all_vulnerable)}")


if __name__ == "__main__":
    print(banner())
    args = parse_args()
    main(args)
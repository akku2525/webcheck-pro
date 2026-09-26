#!/usr/bin/env python3
"""
WebCheck Pro
============
An all-in-one OSINT & web-recon dashboard tool for security testers.

Author  : Akash Mishra
License : For authorized security testing / research use only.

Usage:
    python3 webcheck.py -u example.com
    python3 webcheck.py -u https://example.com -o report.html
    python3 webcheck.py -u example.com --json results.json --open
"""

import argparse
import json
import os
import sys
import webbrowser

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.scanner import run_full_scan  # noqa: E402

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    GREEN, CYAN, YELLOW, RED, RESET, BOLD = (
        Fore.GREEN, Fore.CYAN, Fore.YELLOW, Fore.RED, Style.RESET_ALL, Style.BRIGHT
    )
except ImportError:
    GREEN = CYAN = YELLOW = RED = RESET = BOLD = ""

from jinja2 import Environment, FileSystemLoader

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")

BANNER = f"""{GREEN}{BOLD}
 ██╗    ██╗███████╗██████╗  ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
 ██║    ██║██╔════╝██╔══██╗██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
 ██║ █╗ ██║█████╗  ██████╔╝██║     ███████║█████╗  ██║     █████╔╝
 ██║███╗██║██╔══╝  ██╔══██╗██║     ██╔══██║██╔══╝  ██║     ██╔═██╗
 ╚███╔███╔╝███████╗██████╔╝╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
  ╚══╝╚══╝ ╚══════╝╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝
{RESET}{CYAN}          PRO — OSINT & Web Recon Dashboard{RESET}
{YELLOW}          Crafted by Akash Mishra{RESET}
"""


def print_step(step, index, total):
    bar_len = 28
    filled = int(bar_len * index / total) if total else bar_len
    bar = "█" * filled + "░" * (bar_len - filled)
    sys.stdout.write(f"\r{GREEN}[{bar}]{RESET} {index}/{total}  {CYAN}{step:<42}{RESET}")
    sys.stdout.flush()


def main():
    parser = argparse.ArgumentParser(
        prog="webcheck.py",
        description="WebCheck Pro — OSINT & Web Security Recon Dashboard (by Akash Mishra)",
    )
    parser.add_argument("-u", "--url", required=True, help="Target domain or URL, e.g. example.com")
    parser.add_argument("-o", "--output", default=None, help="Output HTML report path (default: reports/<domain>_<timestamp>.html)")
    parser.add_argument("--json", dest="json_out", default=None, help="Also save raw scan results as JSON to this path")
    parser.add_argument("--open", action="store_true", help="Open the HTML report in the default browser when done")
    parser.add_argument("--no-banner", action="store_true", help="Suppress the ASCII banner")
    parser.add_argument("--deep", action="store_true",
                         help="Enable deep/active mode: subdomain bruteforce, DNS zone-transfer test, "
                              "open-redirect probing, banner grabbing, and full sensitive-path list "
                              "(slower, more thorough)")
    parser.add_argument("--threads", type=int, default=20, help="Max concurrent worker threads (default: 20)")
    parser.add_argument("--screenshot", action="store_true",
                         help="Capture a headless-Chromium screenshot of the target and embed it in the report")
    parser.add_argument("--shodan-key", default=os.environ.get("SHODAN_API_KEY"),
                         help="Shodan API key (or set SHODAN_API_KEY env var) to enrich the scan with Shodan's "
                              "indexed data for the target IP")
    parser.add_argument("--censys-id", default=os.environ.get("CENSYS_API_ID"),
                         help="Censys API ID (or set CENSYS_API_ID env var)")
    parser.add_argument("--censys-secret", default=os.environ.get("CENSYS_API_SECRET"),
                         help="Censys API secret (or set CENSYS_API_SECRET env var)")
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    def progress_cb(step, index, total):
        print_step(step, index, total)

    mode = "DEEP (active)" if args.deep else "FAST"
    print(f"{YELLOW}[*] Starting {mode} recon scan against: {BOLD}{args.url}{RESET}\n")

    data = run_full_scan(
        args.url, progress_cb=progress_cb, deep=args.deep, threads=args.threads,
        shodan_key=args.shodan_key, censys_id=args.censys_id, censys_secret=args.censys_secret,
        screenshot=args.screenshot,
    )
    print("\n")

    # Determine output paths
    domain_safe = data.get("domain", "target").replace(":", "_")
    reports_dir = os.path.join(BASE_DIR, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    output_path = args.output or os.path.join(reports_dir, f"{domain_safe}_report.html")

    # Render HTML dashboard
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template("report_template.html")
    html = template.render(data=data)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"{GREEN}[+] HTML dashboard saved to:{RESET} {output_path}")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        print(f"{GREEN}[+] Raw JSON results saved to:{RESET} {args.json_out}")

    counts = data.get("findings", {}).get("counts", {})
    print(f"\n{CYAN}[✓] Scan complete. Quality score: {BOLD}{data.get('quality_score', 'N/A')}%{RESET}")
    print(f"{RED}    Critical: {counts.get('CRITICAL', 0)}{RESET}  "
          f"{RED}High: {counts.get('HIGH', 0)}{RESET}  "
          f"{YELLOW}Medium: {counts.get('MEDIUM', 0)}{RESET}  "
          f"Low: {counts.get('LOW', 0)}  Info: {counts.get('INFO', 0)}")
    print(f"{YELLOW}    WebCheck Pro — by Akash Mishra{RESET}\n")

    if args.open:
        webbrowser.open(f"file://{os.path.abspath(output_path)}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Scan interrupted by user.{RESET}")
        sys.exit(1)

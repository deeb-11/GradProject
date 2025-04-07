#!/usr/bin/env python3
"""
Main entry point for the Automated Pentesting Tool (non-AI).

Usage:
    python src/main.py --target example.com
    python src/main.py --target 192.168.1.50
    python src/main.py --target example.com --vuln-scan --exploit --privesc
"""

import argparse
import sys

from recon.recon_main import run_recon
from vulnscan.scan_main import run_vuln_scan
from exploit.exploit_main import run_exploit
from privesc.priv_esc import run_priv_esc

def main():
    # 1. Create a command-line parser
    parser = argparse.ArgumentParser(
        description="Automated Pentesting Tool (non-AI)."
    )
    
    # 2. Add arguments
    parser.add_argument(
        "--target",
        type=str,
        help="Target IP or domain name to scan and exploit.",
        required=True
    )
    parser.add_argument(
        "--vuln-scan",
        action="store_true",
        help="Run vulnerability scan stage."
    )
    parser.add_argument(
        "--exploit",
        action="store_true",
        help="Run exploitation stage."
    )
    parser.add_argument(
        "--privesc",
        action="store_true",
        help="Run privilege escalation stage."
    )
    
    # 3. Parse the arguments
    args = parser.parse_args()
    
    # 4. Retrieve the target from args
    target = args.target
    print(f"[MAIN] Starting automated pentest on target: {target}")
    
    # 5. Recon is typically always done
    recon_data = run_recon(target)
    
    # 6. Optional vulnerability scanning
    vuln_info = {}
    if args.vuln_scan:
        vuln_info = run_vuln_scan(target, recon_data)
    
    # 7. Optional exploitation
    exploit_result = {}
    if args.exploit:
        exploit_result = run_exploit(target, vuln_info)
    
    # 8. Optional privilege escalation
    if args.privesc and exploit_result.get("success"):
        run_priv_esc(exploit_result)
    elif args.privesc:
        print("[MAIN] Exploit was unsuccessful; skipping privilege escalation.")
    
    print("[MAIN] Pentest workflow complete.")

if __name__ == "__main__":
    main()

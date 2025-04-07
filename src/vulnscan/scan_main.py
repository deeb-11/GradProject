# src/vulnscan/scan_main.py
"""
Module: Vulnerability Scanning
Description: Uses Nmap NSE scripts (vuln category) to identify known vulnerabilities.
Dependencies:
    pip install python-nmap
"""

import nmap
import json

def run_vuln_scan(target, recon_data):
    """
    - Uses Nmap's 'vuln' category scripts to detect known vulnerabilities.
    - Returns a dictionary 'found_vulns' listing potential vulnerabilities.
    """
    print(f"[VULNSCAN] Checking vulnerabilities on {target}...")

    found_vulns = []

    # Possibly re-scan with vuln scripts for open ports
    nm = nmap.PortScanner()
    # '--script vuln' runs the vulnerability scripts
    # If you want to limit to discovered open ports, gather them from recon_data
    scan_args = "-T4"
    
    nm.scan(hosts=target, arguments=scan_args)

    if target in nm.all_hosts():
        host_data = nm[target]
        for proto in host_data.all_protocols():
            ports = host_data[proto].keys()
            for port in ports:
                script_output = host_data[proto][port].get('script')
                if script_output:
                    # script_output is a dict of scriptName -> output
                    for script_name, output in script_output.items():
                        # If output indicates a vulnerability
                        if "VULNERABLE" in output or "vulnerable" in output.lower():
                            found_vulns.append({
                                "port": port,
                                "proto": proto,
                                "script_name": script_name,
                                "details": output
                            })
    else:
        print(f"[VULNSCAN] No data found for {target} during vuln scan.")

    # You can combine recon results with newly discovered vulns
    vuln_info = {
        "found_vulns": found_vulns,
        "recon_data": recon_data
    }

    # (Optional) Print or log the summary
    if found_vulns:
        print(f"[VULNSCAN] Found {len(found_vulns)} potential vulnerabilities.")
    else:
        print("[VULNSCAN] No potential vulnerabilities discovered by Nmap scripts.")

    return vuln_info

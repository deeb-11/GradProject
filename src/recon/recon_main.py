import json
import nmap
import sublist3r

def run_recon(target):
    """
    Enumerates subdomains (if target is a domain) using Sublist3r (minus DNSdumpster)
    and performs an Nmap OS/Version detection scan.
    Returns a dictionary with subdomains, open ports, OS info, etc.
    """

    print(f"[RECON] Starting reconnaissance on {target}...")

    recon_data = {
        "target": target,
        "subdomains": [],
        "open_ports": [],
        "os_info": "",
        "nmap_output": "",
    }

    # If it's not an IP, treat the target as a domain -> subdomain enumeration
    if not is_ip_address(target):
        print("[RECON] Enumerating subdomains with Sublist3r, skipping DNSdumpster...")

        # Pass engines as a single comma-separated string
        # e.g. 'baidu,bing,google,ask,netcraft,virustotal,yahoo'
        subdomains = sublist3r.main(
            domain=target,
            threads=10,
            enable_bruteforce=False,
            savefile=None,
            ports=None,
            silent=True,
            verbose=False,
            engines='baidu,bing,google,ask,netcraft,virustotal,yahoo'
        )

        recon_data["subdomains"] = subdomains
        print(f"[RECON] Found {len(subdomains)} subdomains.")

    # Perform an Nmap scan with OS/Version detection
    print("[RECON] Running Nmap OS/Version detection...")
    nm = nmap.PortScanner()

    # Adjust arguments as desired
    nmap_args = "-A -T4 -Pn"
    scan_result = nm.scan(hosts=target, arguments=nmap_args)

    if target in nm.all_hosts():
        host_data = nm[target]
        # Collect open ports
        for proto in host_data.all_protocols():
            for port in host_data[proto].keys():
                state = host_data[proto][port]['state']
                if state == 'open':
                    service = host_data[proto][port].get('name', '')
                    version = host_data[proto][port].get('version', '')
                    recon_data["open_ports"].append({
                        "port": port,
                        "protocol": proto,
                        "service": service,
                        "version": version
                    })

        # OS info if available
        if 'osmatch' in host_data and host_data['osmatch']:
            recon_data["os_info"] = host_data['osmatch'][0]['name']

        # Save raw Nmap output in JSON format
        recon_data["nmap_output"] = json.dumps(scan_result, indent=2)
    else:
        print(f"[RECON] Nmap: No host data found for {target}")

    print("[RECON] Reconnaissance complete.")
    return recon_data

def is_ip_address(target_str):
    """
    Checks if a given string is likely an IPv4 address.
    """
    parts = target_str.split('.')
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return False

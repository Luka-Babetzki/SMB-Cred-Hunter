#! /usr/bin/env python3
"""
SMB CredHunter
+------------+
A tool for discovering hard-coded credentials across SMB network file shares.
Built for authorised penetration testing engagements only.

Usage:
    python smb_credhunter.py -t 192.168.1.0/24
    python smb_credhunter.py -t 192.168.1.10 -u admin -p password123
    python smb_credhunter.py -t targets.txt --output results.json
"""

# ===============================================
# IMPORTS
# ===============================================

from typing import Any


import os
import ipaddress
import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Thread

# ===============================================
# CONSTANTS
# ===============================================

BANNER = r"""
  ███████╗███╗   ███╗██████╗      ██████╗██████╗ ███████╗██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ██╔════╝████╗ ████║██╔══██╗    ██╔════╝██╔══██╗██╔════╝██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ███████╗██╔████╔██║██████╔╝    ██║     ██████╔╝█████╗  ██║  ██║███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ╚════██║██║╚██╔╝██║██╔══██╗    ██║     ██╔══██╗██╔══╝  ██║  ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ███████║██║ ╚═╝ ██║██████╔╝    ╚██████╗██║  ██║███████╗██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚══════╝╚═╝     ╚═╝╚═════╝      ╚═════╝╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
  SMB Share Credential Hunter | For authorised use only | By adver5e
"""












# ===============================================
# PHASE 1: TARGET PARSING
# ===============================================

def parse_targets(target_input):
    """..."""
    hosts = []

    if os.path.isfile(target_input):
        with open(target_input, "r") as f: # Open target_input in read mode, accessible as f locally.
            lines = [line.strip() for line in f
                if line.strip() and not line.startswitch('#')] # Skip blank lines and comments.
        for line in lines:
            hosts.extend(_expand_target(line))
    else:
        hosts.extend(_expand_target(target_input))
    return hosts


def _expand_target(target):
    """..."""
    try:
        network = ipaddress.ip_network(target, strict=False) # strict=False → 192.168.1.10/24 gets treated as 192.168.1.0/24 to prevent an error.
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return [target] if target else [] # Invalid CIDR given. Just return the single IP address.

# ===============================================
# PHASE 2: PORT SCANNING
# ===============================================

def scan_smb_ports(hosts, ports, timeout=3, threads=10):
    """..."""
    tasks = [(host, port) for host in hosts for port in ports]
    open_hosts = {} #

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(_check_port, host, port, timeout): (host, port)
            for host, port in tasks
        }
        for future in as_completed(futures):
            host, port, is_open = future.result()
            if is_open:
                exisiting = open_hosts.get(host)
                if exisiting is None or (port == 445 and exisiting != 445):
                    open_hosts[host] = port

    return list(open_hosts.items())


def _check_port(host, port, timeout):
    """..."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return host, port, (result == 0)
    except (socket.gaierror, OSError):
        return host, port, False

# ===============================================
# PHASE 3: SMB CONNECTION & SHARE ENUMERATION
# ===============================================









# ===============================================
# PHASE 4: SHARE SELECTION (prettytable)
# ===============================================











# ===============================================
# PHASE 5: FILE TRAVERSAL & CREDENTIAL HUNTING
# ===============================================












# ===============================================
# PHASE 6: REPORTING
# ===============================================










# ===============================================
# ARG PARSING
# ===============================================

def parse_args():
    parser = argparse.ArgumentParser(
        description = "Hunt for hard-coded credentials across SMB shares",
        formatter_class = argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-t", "--target", required=True,
        help = "Target IP, CIDR range, or path to targets file")
    parser.add_argument("-ports", nargs="+", type=int, default=[445, 139],
        help = "Ports to scan (default: 445,139)")
    parser.add_argument("--timeout", type=int, default=3,
        help = "Connection timeout in seconrds (default: 3)")
    parser.add_argument("--threads", type=int, default=10,
        help = "Concurrent scan threads (default: 10)")
    return parser.parse_args()
    










# ===============================================

def main():
    args = parse_args()
    print(BANNER)

    # --- Phase 1: Parse targets ---
    targets = parse_targets(args.target)
    if not targets:
        print("[-] No valid targets parsed. Existing...")
        return
    
#    print(f"[*] Loaded {len(targets)} targets(s): {targets}")

    # --- Phase 2: Scan for open SMB ports ---
    print(f"\n[*] Scanning for open SMB ports...")
    live_hosts = scan_smb_ports(targets, args.ports, args.timeout, args.threads)

    if not live_hosts:
        print("[-] No SMB hosts found. Exiting...")
        return
    
    print(f"[+] SMB detected on {len(live_hosts)} hosts(s)") # SUCCESS when running against one target. When running against full network, very slow!!




if __name__ == "__main__":
    main()
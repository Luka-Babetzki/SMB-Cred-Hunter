#! /usr/bin/env python3
"""
SMB Cred Hunter
+------------+
A tool for discovering hard-coded credentials across SMB network file shares.
Built for authorised penetration testing engagements only.

Usage:
    python smb_cred_hunter.py -t 192.168.1.0/24
    python smb_cred_hunter.py -t 192.168.1.10 -u admin -p password123
    python smb_cred_hunter.py -t targets.txt --output results.json
"""

# ===============================================
# IMPORTS
# ===============================================

import os
import ipaddress
import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from impacket.smbconnection import SMBConnection # Windows Defender blocks install of dependencies, try running in WSL or live USB linux distro on boot.
from prettytable import PrettyTable

# ===============================================
# CONSTANTS
# ===============================================

BANNER = r"""
  ███████╗███╗   ███╗██████╗      ██████╗██████╗ ███████╗██████╗     ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ██╔════╝████╗ ████║██╔══██╗    ██╔════╝██╔══██╗██╔════╝██╔══██╗    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ███████╗██╔████╔██║██████╔╝    ██║     ██████╔╝█████╗  ██║  ██║    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ╚════██║██║╚██╔╝██║██╔══██╗    ██║     ██╔══██╗██╔══╝  ██║  ██║    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ███████║██║ ╚═╝ ██║██████╔╝    ╚██████╗██║  ██║███████╗██████╔╝    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚══════╝╚═╝     ╚═╝╚═════╝      ╚═════╝╚═╝  ╚═╝╚══════╝╚═════╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
  SMB Share Credential Hunter | For authorised use only | By adver5e
"""

# Default shares to skip?
SKIP_SHARES = {"IPC$", "ADMIN$", "print$"}










# ===============================================
# PHASE 1: TARGET PARSING
# ===============================================

def parse_targets(target_input):
    """
    Turns target string or file path into flat list of IP strings.
    Accepts single IP, CIDR range, or path to targets file.
    Returns hosts
    """
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
    """
    Expand a single IP or CIDR string into an IP list of strings.
    "192.168.1.0/24 becomes ["192.168.1.1", "192.168.1.2", ...]"
    """
    try:
        network = ipaddress.ip_network(target, strict=False) # strict=False → 192.168.1.10/24 gets treated as 192.168.1.0/24 to prevent an error.
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return [target] if target else [] # Invalid CIDR given. Just return the single IP address.

# ===============================================
# PHASE 2: PORT SCANNING
# ===============================================

def scan_smb_ports(hosts, ports, timeout=3, threads=10):
    """
    Scan list of hosts for open SMB ports with raw TCP connect.
    Prefers port 445 over 139 if both are open one same host.
    Returns list of (host, port) tuples for hosts with SMB open.
    """
    tasks = [(host, port) for host in hosts for port in ports]
    open_hosts = {} # Host + preferred open port

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

    return list[tuple](open_hosts.items())


def _check_port(host, port, timeout):
    """
    Attempt full TCP connect to host:port.
    connect_ex() returns 0 for success, error code for fail.
    """
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

def enumerate_shares(host, port, username="", password="", domain="", timeout=3):
    """
    Connect to a host, authenticate & enumeration available shares. 
    Authenticates in this order: null session, guest, supplied creds.
    Returns two lists:
    - accessible: shares that can mount (tree connect succeeded)
    - inaccessible: shares that are visible but cannot mount (access denied)
    """
    conn = _smb_connect(host, port, timeout)
    if conn is None:
        return [], []

    # Attempt authentication on shares
    auth_strategies = [("", ""), ("guest", "")]
    if username:
        auth_strategies.append((username, password))

    authed = False
    for user, pwd in auth_strategies:
        try:
            conn.login(user, pwd, domain)
            authed = True
            break
        except Exception:
            pass

    if not authed:
        return [], []

    # List all exposed shares
    try:
        raw_shares = conn.listShares()
    except Exception:
        return [], []
    
    all_shares = []
    for share in raw_shares:
        # When handling Windows protocols (like SMB) strings are terminated by zero byte: \x00 (null terminator)
        # [:-1] slices off invisible null terminator so string share names can be compared without failing
        name = share["shi1_netname"][:-1]
        remark = share["shi1_remark"][:-1]
        # Bitmask:
            # share_type
                # 00 = disk share
                # 01 = printer
                # 10 = device
                # 11 = IPC
        # 1000 = hidden (ends with $)
        # 0001 = visible
        # mask is 0x3 = 0011
        share_type = share["shi1_type"]
        is_disk = (share_type & 0x3) == 0

        if name not in SKIP_SHARES and is_disk:
            all_shares.append({"name": name, "remark": remark or "-"})
    
    accessible = []
    inaccessible = []

    for share in all_shares:
        try:
            conn.connectTree(share["name"])
            accessible.append(share)
        except Exception:
            inaccessible.append(share["name"])

    return accessible, inaccessible


def _smb_connect(host, port, timeout):
    """
    Establish a raw SMBConnection without authentication.
    TCP + SMB dialect negotiation.
    """
    try:
        return SMBConnection(host, host, sess_port=port, timeout=timeout)
    except Exception:
        return None

# ===============================================
# PHASE 4: SHARE SELECTION (prettytable)
# ===============================================

def prompt_share_selection(accessible_shares, inaccessible_shares):
    """
    ...
    """
    rows = []
    idx = 1

    # ...
    for host, data in accessible_shares.items():
        port = data["port"]
        for share in data ["shares"]:
            rows.append({
                "idx": idx,
                "host": host,
                "port": port,
                "share": share["name"],
                "remark": share["remark"],
                "status": "accessible"
            })
            idx += 1
    
    # ...
    for host, shares in inaccessible_shares.items():
        for share_name in shares:
            rows.append({
                "idx": "-",
                "host": host,
                "port": "-",
                "share": share_name,
                "remark": "-",
                "status": "denied"
            })

    # ...
    table = PrettyTable()
    table.field_names = ["#", "Host", "Port", "Share", "Remark", "Status"]
    table.align["Share"] = "1"
    table.align["Remark"] = "1"

    for row in rows:
        status = "[+] accessible" if row["status"] == "accessible" else "[-] denied"
        table.add_row([
            row["idx"], row["host"], row["port"],
            row["share"], row["remark"], status
        ])

    print("\n[*] Discovered shares:\n")
    print(table)

    selectable = [r for r in rows if r["status"] == "accessible"]
    if not selectable:
        return []

    print("\n Enter share numbers to hunt, comma separated (e.g. 1,3)")
    print(" Or 'all' to hunt every accessible share")
    print(" Or 'q' to quit")

    while True:
        try:
            raw = input("\n > ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print()
            return[]

        if raw in ("", "q", "quit"):
            return []
        
        if raw == "all":
            return [(r["host"], r["port"], r["share"]) for r in selectable]

        try:
            chosen = {int(x.strip()) for x in raw.split(",")}
        except ValueError:
            print(" [!] Enter numbers, 'all', or 'q'")
            continue

        valid = {r["idx"] for r in selectable}
        invalid = chosen - valid
        if invalid:
            print(f" [!] Invalid share number(s): {sorted(invalid)}")
            continue

        return [
            (r["host"], r["port"], r["share"])
            for r in selectable if r["idx"] in chosen
        ]


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
    parser.add_argument("-u", "--username", default="",
        help="SMB username (default: null session)")
    parser.add_argument("-p", "--password", default="",
        help="SMB password")
    parser.add_argument("--domain", default="",
        help="SMB domain")
    
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
    
    ports = [int(p.strip()) for p in args.port.split(",")]
    print(f"[*] Loaded {len(targets)} targets(s) | Ports: {ports}")

    # --- Phase 2: Scan for open SMB ports ---
    print(f"\n[*] Scanning for open SMB ports...")
    live_hosts = scan_smb_ports(targets, args.ports, args.timeout, args.threads)

    if not live_hosts:
        print("[-] No SMB hosts found. Exiting...")
        return
    
    print(f"[+] SMB detected on {len(live_hosts)} hosts(s)") # SUCCESS when running against one target. When running against full network, very slow!!

    # --- Phase 3: Enumerate shares ---
    print(f"\n[*] Enumerating shares...")
    accessible_shares = {}
    inaccessible_shares = {}

    for host, port in live_hosts:
        print(f"[*] Connecting to {host}:{port}...")
        accessible, inaccessible = enumerate_shares(
            host, port,
            username=args.username,
            password=args.password,
            domain=args.domain,
            timeout=args.timeout
        )
        if accessible:
            accessible_shares[host] = {"port": port, "shares": accessible}
        if inaccessible:
            inaccessible_shares[host] = inaccessible
    
    if not accessible_shares:
        print("[-] No accessible shares found. Exiting...")
        return

    # --- Phase 4: ...
    selected = prompt_share_selection(accessible_shares, inaccessible_shares)

    if not selected:
        print("[!] No shares selected. Exiting")
        return

    




if __name__ == "__main__":
    main()
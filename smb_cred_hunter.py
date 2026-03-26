#! /usr/bin/env python3
"""
SMB Cred Hunter
+-------------+
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
import io
import re
import logging

from concurrent.futures import ThreadPoolExecutor, as_completed
from impacket.smbconnection import SMBConnection # //TODO: Install dependencies using WSL or Linux live usb boot
from prettytable import PrettyTable

logging.getLogger("impacket").setLevel(logging.CRITICAL) # Suppress impacket's internal logging

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
  SMB Share Credential Hunter | For authorised use only | By teard0wn
"""

# Default shares to skip
SKIP_SHARES = {"IPC$", "ADMIN$", "print$"}

# The max file tree depth the file traversal will go
MAX_DEPTH = 8

# Sources: MANSPIDER, Snaffler DefaultRules.
INTERESTING_EXTENSIONS = {
    # Environment & config
    ".env", ".cfg", ".conf", ".config", ".ini", ".toml",
    ".xml", ".yaml", ".yml", ".json", ".properties",

    # Infrastructure as code
    ".tf", ".tfvars",

    # Windows scripting
    ".ps1", ".psm1", ".psd1",   # PowerShell
    ".bat", ".cmd", ".vbs",     # batch / VBScript

    # General scripting
    ".sh", ".py", ".rb", ".pl",

    # Web app config
    ".php", ".asp", ".aspx",

    # Certificates & keys
    ".pem", ".key", ".ppk",             # private keys / PuTTY
    ".pfx", ".p12", ".pkcs12",          # cert bundles with private keys
    ".jks", ".keystore",                # Java keystores
    ".der", ".crt", ".cer",             # certificates

    # Password manager databases
    ".kdbx", ".kdb",                    # KeePass
    ".psafe3",                          # Password Safe
    ".agilekeychain", ".opvault",       # 1Password

    # Backups & exports
    ".bak", ".backup", ".old", ".sql", ".dump",

    # Registry exports
    ".reg",

    # RDP shortcut files (often store hostnames/usernames, sometimes passwords)
    ".rdp",

    # CI/CD pipeline files
    ".travis.yml",

    # Office / data files
    ".xlsx", ".xls", ".csv", ".docx", ".doc",

    # Misc text
    ".txt", ".log", ".md",
}

INTERESTING_FILENAMES = {
    # Web app config
    "web.config", "wp-config.php", "appsettings.json", "secrets.json",
    "config.php", "LocalSettings.php", "settings.py",
    "application.properties", "database.yml",

    # Containers & infrastructure
    "docker-compose.yml", "docker-compose.yaml", "dockerfile",
    "terraform.tfvars", ".env",

    # SSH keys
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "id_rsa.pub",   # reveals username/hostname even without the private key

    # AWS CLI credentials file
    "credentials",

    # Git credential storage
    ".git-credentials",

    # Package manager auth tokens (contain registry passwords/API keys)
    ".npmrc", ".pypirc",

    # CI/CD
    "jenkinsfile", ".travis.yml", ".gitlab-ci.yml",

    # Windows unattended install files
    "unattend.xml", "unattended.xml", "sysprep.xml", "sysprep.inf",

    # Group Policy Preferences — GPP credential vulnerability (MS14-025)
    "groups.xml", "scheduledtasks.xml", "services.xml", "datasources.xml",

    # Active Directory database
    "ntds.dit",

    # Windows credential hive pair
    "sam", "system",

    # Network device configs
    "running-config", "startup-config", "cisco.conf",

    # Unix credential files
    "passwd", "shadow", "master.passwd",

    # Web server auth
    ".htpasswd",
}

# Regex patterns that suggest a credential is present.
# Each tuple: (human-readable label, compiled regex)
# Ordered roughly by signal quality, with high confidence patterns first.
CREDENTIAL_PATTERNS = [
    # Private key headers
    ("Private key",
     re.compile(r'-----BEGIN .{0,10}PRIVATE KEY-----')),

    # AWS access key ID
    ("AWS access key ID",
     re.compile(r'(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])')),

    # AWS secret access key
    ("AWS secret key",
     re.compile(r'(?i)aws.{0,20}secret.{0,20}[=:]\s*["\']?([A-Za-z0-9/+]{40})["\']?')),

    # Generic password assignment
    ("Password assignment",
     re.compile(r'(?i)(password|passwd|pwd|pass)\s*[=:]\s*["\']?([^\s"\'<>{}\[\]\n]{4,})["\']?')),

    # Generic secret/token assignment
    ("Secret / token",
     re.compile(r'(?i)(secret|token|api_key|apikey|api_token|auth_token|access_token)\s*[=:]\s*["\']?([^\s"\'<>{}\[\]\n]{8,})["\']?')),

    # Generic username assignment
    ("Username assignment",
     re.compile(r'(?i)(username|user|uid|login|account)\s*[=:]\s*["\']?([^\s"\'<>{}\[\]\n]{3,})["\']?')),

    # Database connection URLs
    ("Database URL",
     re.compile(r'(?i)(mysql|postgresql|postgres|mongodb|redis|mssql|oracle):\/\/[^:]+:[^@\s]+@')),

    # .NET / Windows connection strings
    ("Connection string",
     re.compile(r'(?i)(Data Source|Initial Catalog|User Id|Password)\s*=')),

    # SMTP credentials
    ("SMTP credential",
     re.compile(r'(?i)(smtp.{0,10}(user|pass|password|login)|mail.{0,10}password)\s*[=:]\s*["\']?([^\s"\'<>\n]{4,})["\']?')),

    # PowerShell credential objects and net use commands
    ("PowerShell credential",
     re.compile(r'(?i)(ConvertTo-SecureString|net use .+ /user:.+)')),

    # GPP encrypted password field
    # These can be decrypted with gpp-decrypt
    ("GPP cpassword",
     re.compile(r'cpassword="([^"]+)"')),

    # NTLM / MD5 hash values
    ("Hash value",
     re.compile(r'(?i)(ntlm|lm|md5|sha1)[\s:=]+["\']?([a-fA-F0-9]{32,})["\']?')),

    # Bearer tokens in config (e.g. GitHub Actions, API configs)
    ("Bearer token",
     re.compile(r'(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}')),
]

# Lines matching any of these are almost certainly not real credentials.
# Checked before credential patterns. If a line matches here, skip it.
FALSE_POSITIVES = [
    re.compile(r'(?i)^\s*#'),                               # shell / Python comments
    re.compile(r'(?i)^\s*\/\/'),                            # JS / C++ comments
    re.compile(r'(?i)^\s*<!--'),                            # HTML / XML comments
    re.compile(r'(?i)^\s*\*'),                              # Javadoc / block comments
    re.compile(r'(?i)(example|sample|dummy|fake|test|demo)'),
    re.compile(r'(?i)(placeholder|changeme|your[_-]?(password|key|token|secret))'),
    re.compile(r'(?i)<PASSWORD>|<SECRET>|<TOKEN>|<API.?KEY>'),
    re.compile(r'(?i)^\s*(echo|print|log|console\.(log|warn|error))'),  # debug output lines
]


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
        """ //TODO: Move this theory into blog post
        # Bitmask:
            # share_type
                # 00 = disk share
                # 01 = printer
                # 10 = device
                # 11 = IPC
        # 1000 = hidden (ends with $)
        # 0001 = visible
        # mask is 0x3 = 0011
        """
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
    Display all discovered shares in a table, giving the user a choice of which to hunt.
    Returns a list of tuples (host, port, share_name).
    """
    rows = []
    idx = 1

    # Assign each share a number for selection
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
    
    # Show inaccessible share, but not selectable
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

    # Build + print the table
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

    # Keep prompting until valid answer is given
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

        # Parse comma separated numbers
        try:
            chosen = {int(x.strip()) for x in raw.split(",")}
        except ValueError:
            print(" [!] Enter numbers, 'all', or 'q'")
            continue

        # Validate against the actual indices
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

def hunt_share(conn, share_name, max_file_size_mb=5):
    """
    Recursively traverse a share, scanning interesting files for creds.
    Returns a list of findings dictionaries.
    """
    findings = []
    max_bytes = max_file_size_mb * 1024 * 1024
    _traverse(conn, share_name, "\\", findings, max_bytes, depth=0)
    return findings

def _traverse(conn, share_name, path, findings, max_bytes, depth):
    """
    Recursively list a directory. For each entry:
    - If a directory: call ourselves on it (recursion)
    - If an interesting file within size limit: scan it.
    - If depth = MAX_DEPTH: stop.
    """
    if depth > MAX_DEPTH:
        return

    try:
        # "\\*" is the SMB wildcard, lists everything in current directory
        entries = conn.listPath(share_name, path.rstrip("\\") + "\\*")
    except Exception:
        return

    for entry in entries:
        name = entry.get_longname()

        if name in (".", ".."): # "." is current directory. ".." is parent directory. Skip both, otherwise traversal will loop forever
            continue

        full_path = path.rstrip("\\") + "\\" + name

        if entry.is_directory():
            # Recurse into subdirectory, incredment depth counter
            _traverse(conn, share_name, full_path, findings, max_bytes, depth + 1)
    
        else:
            size = entry.get_filesize()
            if size <= max_bytes and _is_interesting(name):
                matches = _scan_file(conn, share_name, full_path)
                findings.extend(matches)

def _is_interesting(filename):
    """
    Return True if file is worth downloading and scanning.
    """
    lower = filename.lower()
    if lower in INTERESTING_FILENAMES:
        return True
    for ext in INTERESTING_EXTENSIONS:
        if lower.endswitch(ext):
            return True
    return False

def _scan_file(conn, share_name, file_path):
    """
    Download file into memory and scan each line for cred patterns.
    Never writes to disk, uses BytesIO as in-memory buffer.
    """
    buf = io.BytesIO()
    try:
        conn.getFile(share_name, file_path, buf.write)
    except Exception:
        return []
    
    buf.seek(0)
    try:
        content = buf.read().decode("utf-8", errors="ignore") # errors="ignore" skips bytes that are not valid UTF-8
    except Exception:
        return []

    findings = []
    for line_num, line in enumerate(content.splitlines(), start=1):
        if any(fp.search(line) for fp in FALSE_POSITIVES): # Skip lines that are almost certainly false positives
            continue

        for label, pattern in CREDENTIAL_PATTERNS:
            if pattern.search(line):
                findings.append({
                    "file": file_path,
                    "line": line_num,
                    "pattern": label,
                    "match": line.strip()[:200]
                })
                break # One finding per is limit*
    
    return findings


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
    parser.add_argument("--ports", default="445,139",
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
    parser.add_argument("--timeout", type=int, default=3,
        help="Connection timeout in seconds (default: 3)")
    parser.add_argument("--max-file-size", type=int, default=5,
        dest="max_file_size",
        help="Max file size to inspect in MB (default: 5)")
    return parser.parse_args()
    

# ===============================================
# MAIN
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

    # --- Phase 4: Shares table & selection ---
    selected = prompt_share_selection(accessible_shares, inaccessible_shares)

    if not selected:
        print("[!] No shares selected. Exiting")
        return

    # --- Phase 5: Hunt for credentials ---
    print(f"\n[*] Phase 3: Hunting for credentials...")
    all_findings = {}

    for host, port, share_name in selected:
        print(f"[*] Traversing \\\\{host}\\{share_name}...")

        conn = _smb_connect(host, port, args.timeout)
        if conn is None:
            print(f"[-] Could not reconnect to {host}")
            continue

        # Re-authenticate for the hunting connection
        authed = False 
        for user, pwd in [(args.username, args.password), ("", "")]:
            try:
                conn.login(user, pwd, args.domain)
                authed = True
                break
            except Exception:
                pass
        
        if not authed:
            print(f"[-] Auth failed for {host}")
            continue

        findings = hunt_share(conn, share_name, args.max_file_size)

        if findings:
            print(f"[+] {len(findings)} potential credential(s) found")
            if host not in all_findings:
                all_findings[host] = {}
            all_findings[host][share_name] = findings
        else:
            print(f"[~] Nothing interesting found")




if __name__ == "__main__":
    main()
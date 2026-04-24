#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║        ElliotSop Security — NetRecon v1.0                    ║
║   Network reconnaissance & service fingerprinting engine     ║
║   OSCP / Red Team Ops toolkit — github.com/00ElliotSop       ║
╚══════════════════════════════════════════════════════════════╝

Usage:
    python3 netrecon.py -t 192.168.1.0/24
    python3 netrecon.py -t 10.10.10.5 --full
    python3 netrecon.py -t targets.txt --threads 200 --output report.json

Requires:
    pip install requests colorama ipaddress

Note: Raw socket operations may require root/sudo on Linux.
      On Windows, run as Administrator.
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    print("[!] pip install colorama")
    sys.exit(1)

# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────

BANNER = f"""
{Fore.RED}
  ███╗   ██╗███████╗████████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██╔██╗ ██║█████╗     ██║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██║╚██╗██║██╔══╝     ██║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║ ╚████║███████╗   ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{Style.RESET_ALL}
{Fore.WHITE}  NetRecon v1.0 — ElliotSop Security LLC{Style.RESET_ALL}
{Fore.YELLOW}  Network Reconnaissance & Service Fingerprinting Engine{Style.RESET_ALL}
  {Fore.RED}github.com/00ElliotSop  |  elliotsop.com{Style.RESET_ALL}
  ─────────────────────────────────────────────────────────────
"""

# ─────────────────────────────────────────────
#  PORT / SERVICE DATABASE
# ─────────────────────────────────────────────

# Top ports with service labels and banner-grab hints
TOP_PORTS = {
    21:   ('FTP',        'ftp'),
    22:   ('SSH',        'ssh'),
    23:   ('Telnet',     'telnet'),
    25:   ('SMTP',       'smtp'),
    53:   ('DNS',        'dns'),
    80:   ('HTTP',       'http'),
    88:   ('Kerberos',   'kerberos'),
    110:  ('POP3',       'pop3'),
    111:  ('RPCbind',    'rpc'),
    135:  ('MSRPC',      'msrpc'),
    137:  ('NetBIOS-NS', 'netbios'),
    139:  ('NetBIOS-SS', 'netbios'),
    143:  ('IMAP',       'imap'),
    389:  ('LDAP',       'ldap'),
    443:  ('HTTPS',      'http'),
    445:  ('SMB',        'smb'),
    464:  ('Kpasswd',    'kerberos'),
    465:  ('SMTPS',      'smtp'),
    512:  ('rexec',      'rexec'),
    513:  ('rlogin',     'rlogin'),
    514:  ('rsh/syslog', 'rsh'),
    587:  ('SMTP/sub',   'smtp'),
    593:  ('MSRPC-HTTP', 'msrpc'),
    631:  ('IPP',        'ipp'),
    636:  ('LDAPS',      'ldap'),
    873:  ('rsync',      'rsync'),
    993:  ('IMAPS',      'imap'),
    995:  ('POP3S',      'pop3'),
    1080: ('SOCKS',      'socks'),
    1433: ('MSSQL',      'mssql'),
    1521: ('Oracle',     'oracle'),
    2049: ('NFS',        'nfs'),
    2375: ('Docker',     'docker'),
    2376: ('Docker-TLS', 'docker'),
    3000: ('Dev/Grafana','http'),
    3306: ('MySQL',      'mysql'),
    3389: ('RDP',        'rdp'),
    4444: ('Metasploit', 'msf'),
    4848: ('GlassFish',  'http'),
    5432: ('PostgreSQL', 'pgsql'),
    5985: ('WinRM-HTTP', 'winrm'),
    5986: ('WinRM-HTTPS','winrm'),
    6379: ('Redis',      'redis'),
    7001: ('WebLogic',   'http'),
    8000: ('HTTP-alt',   'http'),
    8080: ('HTTP-proxy', 'http'),
    8443: ('HTTPS-alt',  'http'),
    8888: ('Jupyter',    'http'),
    9200: ('Elasticsearch','http'),
    9300: ('ES-cluster', 'tcp'),
    27017:('MongoDB',    'mongo'),
}

# Extended list for full scan mode
EXTENDED_PORTS = list(range(1, 10001))


# ─────────────────────────────────────────────
#  SCANNING ENGINE
# ─────────────────────────────────────────────

def tcp_connect_scan(host: str, port: int, timeout: float = 1.0) -> bool:
    """TCP connect scan — reliable, works without raw sockets."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False


def banner_grab(host: str, port: int, timeout: float = 2.0) -> str:
    """Attempt to grab service banner."""
    service_hint = TOP_PORTS.get(port, ('unknown', 'tcp'))[1]
    probes = {
        'http':   b'HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n',
        'ftp':    None,
        'smtp':   None,
        'ssh':    None,
        'redis':  b'INFO\r\n',
        'mysql':  None,
        'default': b'\r\n',
    }

    probe = probes.get(service_hint, probes['default'])

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))

            if probe:
                payload = probe.replace(b'{}', host.encode()) if b'{}' in probe else probe
                s.sendall(payload)

            banner = s.recv(1024).decode('utf-8', errors='replace').strip()
            return banner[:256]  # Truncate long banners
    except Exception:
        return ''


def reverse_dns(ip: str) -> str:
    """Attempt PTR record lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ''


def ping_host(ip: str) -> bool:
    """ICMP ping check (uses system ping, works without root)."""
    flag = '-n' if sys.platform == 'win32' else '-c'
    timeout_flag = '-w' if sys.platform == 'win32' else '-W'
    try:
        result = subprocess.run(
            ['ping', flag, '1', timeout_flag, '1', ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3
        )
        return result.returncode == 0
    except Exception:
        return False


def scan_host(host: str, ports: list[int], timeout: float,
              grab_banners: bool, threads: int) -> dict:
    """Scan a single host — returns result dict."""
    open_ports = {}

    def check_port(port):
        if tcp_connect_scan(host, port, timeout):
            service_name = TOP_PORTS.get(port, ('Unknown', 'tcp'))[0]
            banner = ''
            if grab_banners:
                banner = banner_grab(host, port)
            return port, service_name, banner
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(check_port, p): p for p in ports}
        for f in concurrent.futures.as_completed(futures):
            result = f.result()
            if result:
                port, svc, banner = result
                open_ports[port] = {'service': svc, 'banner': banner}

    hostname = reverse_dns(host)
    alive = bool(open_ports) or ping_host(host)

    return {
        'host':       host,
        'hostname':   hostname,
        'alive':      alive,
        'open_ports': open_ports,
        'scanned_at': datetime.now().isoformat()
    }


# ─────────────────────────────────────────────
#  TARGET RESOLUTION
# ─────────────────────────────────────────────

def expand_targets(target_str: str) -> list[str]:
    """Expand CIDR, range, single IP, or hostname into list of IP strings."""
    targets = []
    target_str = target_str.strip()

    # CIDR notation
    try:
        net = ipaddress.ip_network(target_str, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        pass

    # IP range: 192.168.1.1-50
    range_match = re.match(r'^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$', target_str)
    if range_match:
        prefix, start, end = range_match.groups()
        return [f"{prefix}{i}" for i in range(int(start), int(end) + 1)]

    # Hostname or single IP
    try:
        resolved = socket.gethostbyname(target_str)
        return [resolved]
    except socket.gaierror:
        print(f"{Fore.RED}  [!] Cannot resolve: {target_str}{Style.RESET_ALL}")
        return []


def load_targets_from_file(filepath: str) -> list[str]:
    targets = []
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                targets += expand_targets(line)
    return list(set(targets))


# ─────────────────────────────────────────────
#  OUTPUT / REPORT
# ─────────────────────────────────────────────

def print_host_result(result: dict):
    host = result['host']
    hostname = result['hostname']
    open_ports = result['open_ports']
    alive = result['alive']

    status_color = Fore.GREEN if alive else Fore.RED
    status_label = 'UP' if alive else 'DOWN'

    host_display = f"{host}"
    if hostname and hostname != host:
        host_display += f" ({Fore.CYAN}{hostname}{Fore.WHITE})"

    print(f"\n  {status_color}[{status_label}]{Style.RESET_ALL} {Fore.WHITE}{host_display}{Style.RESET_ALL}")

    if open_ports:
        print(f"  {'PORT':<8} {'SERVICE':<15} {'BANNER'}")
        print(f"  {'─'*8} {'─'*15} {'─'*40}")
        for port in sorted(open_ports):
            svc = open_ports[port]['service']
            banner = open_ports[port]['banner']
            banner_short = (banner[:60] + '…') if len(banner) > 60 else banner
            banner_short = banner_short.replace('\n', ' ').replace('\r', '')
            print(f"  {Fore.GREEN}{port:<8}{Style.RESET_ALL} {Fore.YELLOW}{svc:<15}{Style.RESET_ALL} {Fore.WHITE}{banner_short}{Style.RESET_ALL}")
    elif alive:
        print(f"  {Fore.YELLOW}  Host is up — no open ports found in scanned range.{Style.RESET_ALL}")


def write_json_report(results: list[dict], filepath: str):
    with open(filepath, 'w') as f:
        json.dump({
            'tool':       'ElliotSop NetRecon v1.0',
            'website':    'elliotsop.com',
            'github':     'github.com/00ElliotSop',
            'generated':  datetime.now().isoformat(),
            'host_count': len(results),
            'results':    results
        }, f, indent=2)
    print(f"\n  {Fore.GREEN}[✔] JSON report written: {filepath}{Style.RESET_ALL}")


def write_text_report(results: list[dict], filepath: str):
    with open(filepath, 'w') as f:
        f.write("ElliotSop NetRecon v1.0 — Network Reconnaissance Report\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n\n")
        for r in results:
            f.write(f"Host: {r['host']}")
            if r['hostname']:
                f.write(f"  ({r['hostname']})")
            f.write(f"\nStatus: {'UP' if r['alive'] else 'DOWN'}\n")
            if r['open_ports']:
                f.write(f"{'PORT':<8} {'SERVICE':<15} BANNER\n")
                f.write('-' * 60 + '\n')
                for port in sorted(r['open_ports']):
                    svc = r['open_ports'][port]['service']
                    banner = r['open_ports'][port]['banner'][:60].replace('\n', ' ')
                    f.write(f"{port:<8} {svc:<15} {banner}\n")
            f.write('\n')
    print(f"  {Fore.GREEN}[✔] Text report written: {filepath}{Style.RESET_ALL}")


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description='ElliotSop NetRecon — Network Recon & Fingerprinting',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-t', '--target', required=True,
                        help='Target IP, CIDR, range (192.168.1.1-50), hostname, or file path')
    parser.add_argument('--full', action='store_true',
                        help='Scan ports 1-10000 (default: top ~80 service ports)')
    parser.add_argument('--ports', '-p',
                        help='Comma-separated port list or range e.g. 22,80,443 or 1-1024')
    parser.add_argument('--threads', type=int, default=150,
                        help='Threads per host (default: 150)')
    parser.add_argument('--timeout', type=float, default=1.0,
                        help='Socket timeout in seconds (default: 1.0)')
    parser.add_argument('--banners', '-b', action='store_true',
                        help='Grab service banners (slower)')
    parser.add_argument('--output', '-o',
                        help='Output file path. .json for JSON, otherwise text.')
    parser.add_argument('--host-threads', type=int, default=10,
                        help='Concurrent hosts to scan (default: 10)')
    args = parser.parse_args()

    # ── Resolve targets ────────────────────────────────────────
    target_arg = args.target
    if Path(target_arg).exists():
        targets = load_targets_from_file(target_arg)
    else:
        targets = expand_targets(target_arg)

    if not targets:
        print(f"{Fore.RED}  [!] No valid targets. Exiting.{Style.RESET_ALL}")
        sys.exit(1)

    # ── Resolve port list ──────────────────────────────────────
    if args.ports:
        ports = []
        for segment in args.ports.split(','):
            segment = segment.strip()
            if '-' in segment:
                start, end = segment.split('-')
                ports += list(range(int(start), int(end) + 1))
            else:
                ports.append(int(segment))
    elif args.full:
        ports = EXTENDED_PORTS
    else:
        ports = list(TOP_PORTS.keys())

    # ── Scan summary ───────────────────────────────────────────
    print(f"  Targets        : {Fore.CYAN}{len(targets)}{Style.RESET_ALL} host(s)")
    print(f"  Ports          : {Fore.CYAN}{len(ports)}{Style.RESET_ALL} ({min(ports)}-{max(ports)})")
    print(f"  Threads/host   : {Fore.CYAN}{args.threads}{Style.RESET_ALL}")
    print(f"  Concurrent hosts: {Fore.CYAN}{args.host_threads}{Style.RESET_ALL}")
    print(f"  Banner grab    : {Fore.CYAN}{args.banners}{Style.RESET_ALL}")
    print(f"  Timeout        : {Fore.CYAN}{args.timeout}s{Style.RESET_ALL}")
    print(f"\n  {Fore.YELLOW}[*] Scanning...{Style.RESET_ALL}")
    print(f"  {'─' * 60}")

    start_time = time.time()
    all_results = []

    def scan_one(host):
        result = scan_host(host, ports, args.timeout, args.banners, args.threads)
        print_host_result(result)
        return result

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.host_threads) as ex:
        futures = {ex.submit(scan_one, h): h for h in targets}
        for f in concurrent.futures.as_completed(futures):
            all_results.append(f.result())

    elapsed = time.time() - start_time

    # ── Summary ────────────────────────────────────────────────
    up_hosts = [r for r in all_results if r['alive']]
    hosts_with_ports = [r for r in all_results if r['open_ports']]
    total_open = sum(len(r['open_ports']) for r in all_results)

    print(f"\n  {'─' * 60}")
    print(f"  {Fore.GREEN}Scan complete in {elapsed:.1f}s{Style.RESET_ALL}")
    print(f"  Hosts scanned  : {len(all_results)}")
    print(f"  Hosts up       : {Fore.GREEN}{len(up_hosts)}{Style.RESET_ALL}")
    print(f"  With open ports: {Fore.YELLOW}{len(hosts_with_ports)}{Style.RESET_ALL}")
    print(f"  Total open ports: {Fore.RED}{total_open}{Style.RESET_ALL}")

    # ── Output ─────────────────────────────────────────────────
    if args.output:
        if args.output.endswith('.json'):
            write_json_report(all_results, args.output)
        else:
            write_text_report(all_results, args.output)

    print(f"\n  {Fore.RED}★ ElliotSop Security | elliotsop.com | github.com/00ElliotSop{Style.RESET_ALL}\n")


if __name__ == '__main__':
    main()

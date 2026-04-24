<div align="center">

```
 ███╗   ██╗███████╗████████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██╔██╗ ██║█████╗     ██║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██║╚██╗██║██╔══╝     ██║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║ ╚████║███████╗   ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
```

**NetRecon v1.0** — Network Reconnaissance & Service Fingerprinting Engine

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-red?style=flat-square)](LICENSE)
[![Author](https://img.shields.io/badge/Author-ElliotSop-black?style=flat-square)](https://elliotsop.com)
[![OSCP](https://img.shields.io/badge/OSCP-Certified-orange?style=flat-square)](https://elliotsop.com)

*Fast, concurrent network reconnaissance with service fingerprinting, banner grabbing, and structured reporting — built for red team operations.*

[elliotsop.com](https://elliotsop.com) · [GitHub](https://github.com/00ElliotSop) · [LinkedIn](https://linkedin.com/in/padeshina)

</div>

---

## Overview

NetRecon is a **fast, threaded network scanner** built for penetration testers who need more signal than a raw Nmap sweep and less noise than automated vulnerability scanners. It targets the ~80 highest-value service ports by default, grabs banners where possible, resolves PTR records, and outputs clean JSON or plaintext reports ready for engagement documentation.

No raw sockets required — runs without root/administrator privileges via TCP connect scan.

---

## Features

- **Flexible target input** — single IP, CIDR notation, IP ranges (`192.168.1.1-50`), hostnames, or a target file
- **Concurrent scanning** — configurable per-host thread pool and concurrent host count
- **~80 high-value ports by default** — covering all standard attack surface services
- **Full 1–10000 port scan** via `--full`
- **Custom port list** — comma-separated or range syntax (`22,80,443` or `1-1024`)
- **Banner grabbing** — HTTP, SMTP, FTP, SSH, Redis, MySQL with protocol-aware probes
- **Reverse DNS** — PTR record resolution per host
- **Structured output** — JSON (machine-readable) or plaintext (report-ready)
- **Zero external dependencies beyond `colorama`** — uses Python stdlib for all scanning

---

## Installation

```bash
git clone https://github.com/00ElliotSop/NetRecon
cd NetRecon
pip install -r requirements.txt
```

**requirements.txt**
```
colorama
```

---

## Usage

### Scan a single host (top service ports)
```bash
python3 netrecon.py -t 192.168.1.10
```

### Scan a /24 subnet
```bash
python3 netrecon.py -t 192.168.1.0/24
```

### IP range
```bash
python3 netrecon.py -t 10.10.10.1-50
```

### Full port scan (1–10000)
```bash
python3 netrecon.py -t 10.10.10.5 --full
```

### Custom ports with banner grabbing
```bash
python3 netrecon.py -t 10.10.10.5 -p 22,80,443,8080,8443 --banners
```

### Scan from target file with JSON output
```bash
python3 netrecon.py -t targets.txt --threads 200 --output report.json
```

### High-speed subnet sweep
```bash
python3 netrecon.py -t 10.10.0.0/16 --host-threads 50 --threads 300 --timeout 0.5
```

---

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `-t`, `--target` | required | IP, CIDR, range, hostname, or path to target file |
| `--full` | off | Scan ports 1–10000 instead of top service ports |
| `-p`, `--ports` | — | Custom port list: `22,80,443` or `1-1024` |
| `--threads` | 150 | Port-scanning threads per host |
| `--host-threads` | 10 | Concurrent hosts to scan simultaneously |
| `--timeout` | 1.0s | Socket connect timeout in seconds |
| `-b`, `--banners` | off | Enable service banner grabbing |
| `-o`, `--output` | — | Output file (`.json` → JSON, otherwise plaintext) |

---

## Default Port Coverage

NetRecon's default scan targets the ports that matter most on real engagements:

```
FTP(21)  SSH(22)  Telnet(23)  SMTP(25)  DNS(53)  HTTP(80)  Kerberos(88)
MSRPC(135)  NetBIOS(139)  LDAP(389)  HTTPS(443)  SMB(445)  LDAPS(636)
MSSQL(1433)  MySQL(3306)  RDP(3389)  WinRM(5985/5986)  Redis(6379)
PostgreSQL(5432)  Elasticsearch(9200)  MongoDB(27017)  Docker(2375)
... and ~60 more high-value services
```

---

## Sample Output

```
  [UP]  192.168.1.10  (dc01.corp.local)
  PORT     SERVICE         BANNER
  ──────── ─────────────── ────────────────────────────────────────
  22       SSH             SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
  80       HTTP            HTTP/1.1 200 OK Server: Apache/2.4.52
  135      MSRPC
  139      NetBIOS-SS
  389      LDAP
  445      SMB
  3389     RDP

  [UP]  192.168.1.11  (ws01.corp.local)
  PORT     SERVICE         BANNER
  ──────── ─────────────── ────────────────────────────────────────
  22       SSH             SSH-2.0-OpenSSH_8.4
  5985     WinRM-HTTP
```

```
  ────────────────────────────────────────────────────────────
  Scan complete in 14.3s
  Hosts scanned   : 254
  Hosts up        : 12
  With open ports : 12
  Total open ports: 47
```

---

## JSON Report Structure

```json
{
  "tool": "ElliotSop NetRecon v1.0",
  "generated": "2026-04-24T14:00:00",
  "host_count": 254,
  "results": [
    {
      "host": "192.168.1.10",
      "hostname": "dc01.corp.local",
      "alive": true,
      "open_ports": {
        "445": { "service": "SMB", "banner": "" },
        "389": { "service": "LDAP", "banner": "" }
      },
      "scanned_at": "2026-04-24T14:00:05"
    }
  ]
}
```

---

## Performance Tuning

| Scenario | Recommended Flags |
|----------|-------------------|
| Single host, thorough | `--full --banners --timeout 2.0` |
| /24 fast sweep | `--threads 200 --host-threads 20 --timeout 0.5` |
| /16 wide sweep | `--threads 300 --host-threads 50 --timeout 0.3` |
| Stealth / slow | `--threads 10 --host-threads 2 --timeout 3.0` |

---

## Legal

> **For authorised penetration testing engagements only.**  
> Scanning networks without explicit written permission is illegal in most jurisdictions.  
> ElliotSop Security LLC accepts no liability for misuse.

---

## Author

**Prince Adeshina** — OSCP · CRTP  
[elliotsop.com](https://elliotsop.com) · [contact@elliotsop.com](mailto:contact@elliotsop.com)  
ElliotSop Security LLC

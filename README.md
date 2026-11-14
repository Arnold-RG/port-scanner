# port-scanner

A TCP connect port scanner for Windows (PowerShell) and Linux (bash). Scan one
host, a small IP range or a CIDR block against a list or range of ports, with
timeouts, parallel connections, optional banner grabbing and CSV/JSON export.

| Script | Platform |
|--------|----------|
| `port-scan.ps1` | Windows PowerShell 5.1+ / PowerShell 7+ |
| `port-scan.sh`  | bash 4.3+ (Linux, WSL, macOS with newer bash) |

## How it works

- **TCP connect scan**: a full three-way handshake per port (no raw sockets,
  no admin/root rights). Ports are reported as:
  - `open` - the connection succeeded
  - `closed` - the host actively refused it (RST)
  - `filtered` - no answer before the timeout (not listed, to keep output short)
- **Parallelism**: a runspace pool (PowerShell) or a bounded set of background
  jobs (bash).
- **Banner grab** (`-Banner` / `-b`): reads the first line a service sends
  (SSH, FTP, SMTP...). On common web ports it sends `HEAD / HTTP/1.0` and shows
  the status line.

## Requirements

- **PowerShell:** Windows PowerShell 5.1 or PowerShell 7+. Nothing else.
- **bash:** bash 4.3+ with `/dev/tcp` support (standard on Linux), coreutils
  `timeout`, `seq`. Optional: `getent` for service names from `/etc/services`.

## Usage

### PowerShell

```powershell
Get-Help .\port-scan.ps1 -Full

.\port-scan.ps1 -Target 192.168.1.10
.\port-scan.ps1 -Target 192.168.1.10 -Ports 1-1024 -Threads 200 -TimeoutMs 500
.\port-scan.ps1 -Target 192.168.1.10-20 -Ports 22,80,443 -Banner -OutFile scan.json
.\port-scan.ps1 -Target 192.168.1.0/28 -Ports 3389 -OutFile rdp.csv
```

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `-Target` | (required) | host, IP, `a.b.c.x-y`, or CIDR `/22`-`/32` (max 1024 hosts) |
| `-Ports` | 20 common ports | `22,80,443`, `1-1024`, `20-25,80` |
| `-TimeoutMs` | 1000 | connect timeout (100-10000 ms) |
| `-Threads` | 100 | parallel connections (1-500) |
| `-Banner` | off | grab banners from open ports |
| `-OutFile` | - | write open ports to a file |
| `-Format` | from extension | `csv` or `json` |
| `-ShowClosed` | off | also list refused ports |

### bash

```bash
chmod +x port-scan.sh
./port-scan.sh -h

./port-scan.sh -t 192.168.1.10
./port-scan.sh -t 192.168.1.10 -p 1-1024 -j 200
./port-scan.sh -t 192.168.1.10-20 -p 22,80,443 -b -o scan.json
./port-scan.sh -t 192.168.1.0/28 -p 3389 -o rdp.csv
```

| Option | Default | Meaning |
|--------|---------|---------|
| `-t TARGET` | (required) | host, IP, `a.b.c.x-y`, or CIDR `/22`-`/32` |
| `-p PORTS` | 20 common ports | list and/or ranges |
| `-w SEC` | 1 | connect timeout (1-10 s) |
| `-j N` | 100 | parallel connections (1-500) |
| `-b` | off | banner grab |
| `-o FILE` | - | output file |
| `-f FMT` | from extension | `csv` or `json` |
| `-c` | off | also list closed ports |

## Example output

Real test run (from `tests/run-tests.sh`) on a Linux box: a local web server on
port 18000 and a test service on port 12222 that sends an SSH-style banner.

```
$ ./port-scan.sh -t 127.0.0.1 -p 1-1024,18000,12222 -b -o r.json
Scanning 1 host(s) x 1026 port(s) = 1026 probes (timeout 1s, 100 parallel)

HOST                 PORT    STATE     SERVICE        BANNER
127.0.0.1            12222   open      unknown        SSH-2.0-TestBanner_1.0
127.0.0.1            18000   open      unknown

2 open port(s) found in 4s.
Results (json) written to r.json
```

PowerShell 7 on the same box, with the HTTP banner:

```
PS> ./port-scan.ps1 -Target 127.0.0.1 -Ports 1-1024,8000,8080 -Banner -OutFile scan.json
Scanning 1 host(s) x 1026 port(s) = 1026 probes (timeout 1000 ms, 100 threads)

Host      Port State Service  Banner
----      ---- ----- -------  ------
127.0.0.1 8000 open  http-alt HTTP/1.0 200 OK
127.0.0.1 8080 open  http-alt HTTP/1.0 200 OK

2 open port(s) found in 2s.
Results (json) written to scan.json
```

JSON output (bash):

```json
[
  {"host": "127.0.0.1", "port": 8000, "state": "open", "service": "unknown", "banner": "HTTP/1.0 200 OK"},
  {"host": "127.0.0.1", "port": 8080, "state": "open", "service": "http-alt", "banner": "HTTP/1.0 200 OK"}
]
```

CSV columns: `host,port,state,service,banner`.

## Tests

```bash
bash tests/run-tests.sh   # starts two throwaway servers on 127.0.0.1 and scans them
```

CI (GitHub Actions) runs ShellCheck, PSScriptAnalyzer and the smoke tests on every push.

## Limitations

- TCP only (no UDP scan) and IPv4 ranges only (a hostname may resolve to IPv6).
- Connect scans are logged by the target and by IDS tools; this is not stealthy.
- `filtered` can mean a firewall drop or a host that is simply offline.
- Service names are guesses based on the port number, not fingerprinting.
- bash spawns a small process per probe; for very large scans use `nmap`.

## Legal and ethical use

Only scan hosts you own or are explicitly authorised to test. Unauthorised
port scanning may break your ISP's or employer's rules and, in many countries, the law.

## License

[MIT](LICENSE) - Copyright (c) 2026 Arnold Rurangwa

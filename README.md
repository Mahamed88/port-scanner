# TCP Port Scanner

A fast multithreaded TCP connect port scanner written in C++ from scratch. Built as a cybersecurity portfolio project to understand how network reconnaissance tools work at the socket level — and how defenders can detect them.

## Features

- Concurrent scanning via a custom thread pool — scans 1024 ports in under 1 second
- Service detection using the OS `/etc/services` database
- Banner grabbing in verbose mode — identifies software versions on open ports
- JSON output for piping into other tools or a SIEM
- Top ports mode — scans the 20 most commonly open ports by default
- Save output to file with `-oN`
- Clean colored terminal output — open ports in green, closed in red, filtered in yellow

## Demo
$ ./scanner 192.168.12.68 --top-ports 20 -v
Scanning 192.168.12.68
PORT            STATE           SERVICE         BANNER
22/tcp          OPEN            ssh             SSH-2.0-OpenSSH_9.9
80/tcp          CLOSED          http
443/tcp         FILTERED        https
Open: 1  Closed: 18  Filtered: 1
Duration: 0.011s

## Installation

**Requirements:** macOS or Linux, g++ with C++17 support

```bash
git clone https://github.com/Mahamed88/port-scanner.git
cd port-scanner
make
```

## Usage

```bash
# scan a port range
./scanner <target> -p <start>-<end>

# scan top 20 most common ports
./scanner <target> --top-ports 20

# verbose mode — shows service banners
./scanner <target> -p 1-1024 -v

# JSON output
./scanner <target> -p 1-1024 --json

# save output to file
./scanner <target> -p 1-1024 -oN output.txt

# combine flags
./scanner <target> --top-ports 20 -v -oN output.txt
./scanner <target> --top-ports 20 --json -oN results.json

# custom thread count
./scanner <target> -p 1-1024 -t 100
```

## How It Works

Each port scan attempts a full TCP connect using POSIX sockets. The scanner sets the socket to non-blocking mode and uses `select()` with a configurable timeout to determine port state:

- **OPEN** — target responds with SYN-ACK, connection succeeds
- **CLOSED** — target responds with RST, port is actively refused  
- **FILTERED** — no response within timeout, likely dropped by a firewall

A custom thread pool spawns a fixed number of worker threads that pull ports from a shared queue — this is what makes scanning 1024 ports take under a second instead of 34 minutes sequentially.

In verbose mode, a second connection is made to each open port to read the service banner — the string the service sends when you connect, which often reveals the software name and version.

## Project Structure
port-scanner/
├── main.cpp          # CLI argument parsing, output, orchestration
├── scanner.h         # Data structures and function declarations
├── scanner.cpp       # Socket logic, port scanning, banner grabbing
├── threadpool.h      # ThreadPool class declaration
├── threadpool.cpp    # Thread pool implementation
└── Makefile          # Build rules

## What I Learned

Building this from scratch forced me to understand the TCP three-way handshake at the byte level rather than just conceptually. The most interesting engineering problem was threading — scanning 1024 ports sequentially at a 2 second timeout would take 34 minutes, but with a thread pool of 50 workers it finishes in under 1 second. I also learned why defensive analysts need to understand offensive tools — once I built the scanner I could see exactly what its traffic looks like in Wireshark, which directly informs how to write better detection rules in a SIEM.

## Future Work

- Run against isolated Proxmox lab VMs and write Suricata detection rules that catch the scan pattern
- Add UDP scanning support
- SYN scan using raw sockets for stealthier reconnaissance
- OS fingerprinting based on TCP/IP stack behavior

## Legal

Only scan hosts you own or have explicit permission to scan. Running a port scanner against external hosts without authorization is illegal.

## License

MIT

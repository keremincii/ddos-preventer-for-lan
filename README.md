DDoS Preventer for LAN
This project is a lightweight iptables + ipset + asyncio-based transparent proxy that protects Linux servers against DDoS attacks on LAN/WAN environments.
Highlights
Captures inbound TCP traffic with iptables NAT and forwards it to local proxies
aiohttp-based HTTP reverse proxy for HTTP services
Generic TCP proxy for all other TCP services
Per-IP rate limit, burst limit, and concurrent connection limit
Offending IPs are added to an ipset blocklist
Kernel hardening:
SYN cookies
Enlarged conntrack table
UDP flood rate limit
SYN flood protection
Token-bucket limiter for minimal overhead
Auto port discovery via ss -lnt
/etc/ddos_preventer/whitelist.txt for trusted IPs/CIDRs
Requirements
Linux with iptables + ipset support
Root privileges (must run with sudo)
System packages: iptables, ipset, iproute2, procps
Python 3.9+
Python deps: aiohttp (install via pip install -r requirements.txt)
Architecture Overview
main.py: startup, signal handling, launches HTTP & TCP proxies, applies/cleans iptables & ipset rules
config.py: kernel parameters, default limits, per-port overrides, proxy listeners, log path
core/ipset_manager.py: manages ddos_blocklist and ddos_whitelist sets
core/iptables_manager.py: NAT DDOS_GATEWAY chain, redirects protected ports to proxies
core/iptables_hardening.py: kernel-level DDOS_FILTER chain, SYN/UDP defense, sysctl tunings
core/mitigation_manager.py: token-bucket rate limiting, connection counting, whitelist loading
handlers/http_handler.py: reverse proxy with SO_ORIGINAL_DST, applies limits, forwards headers
handlers/generic_tcp_handler.py: transparent TCP bridge with rate/connection limits
Configuration (config.py)
Default limits:
DEFAULT_RATE = 20         # requests per secondDEFAULT_BURST = 50        # short burst allowanceDEFAULT_CONN_LIMIT = 100  # parallel connections per IPDEFAULT_BLOCK_SEC = 30    # seconds in blocklist
Per-port overrides:
TARGET_PORTS = {    22: {'protocol': 'tcp', 'rate': 5,  'burst': 10,  'conn_limit': 10},    80: {'protocol': 'http', 'rate': 15, 'burst': 25},    443: {'protocol': 'tcp', 'rate': 100, 'burst': 200}}
protocol: http routes via HTTP proxy, tcp uses generic TCP proxy
Ports not listed can still be auto-discovered and protected with default limits
Running Manually
sudo python3 main.py
Startup sequence:
Applies sysctl (SYN cookies, conntrack max)
Creates ipset blocklist/whitelist
Adds iptables NAT/filter rules
Auto-discovers open TCP ports
HTTP proxy listening on 0.0.0.0:8081
Generic TCP proxy on 0.0.0.0:9000
Ctrl+C stops the proxies and cleans iptables/ipset state.
Systemd Service
Ship a unit file (example ddos-preventer.service):
sudo cp ddos-preventer.service /etc/systemd/system/sudo systemctl daemon-reloadsudo systemctl enable ddos-preventersudo systemctl start ddos-preventersudo systemctl status ddos-preventer
Stop with sudo systemctl stop ddos-preventer.
Whitelist
File: /etc/ddos_preventer/whitelist.txt
# ddos-preventer whitelist# one IP or CIDR per line# 192.168.1.10# 10.0.0.0/24# 2001:db8::/32
Each entry is automatically added to the ddos_whitelist ipset set
Whitelisted addresses bypass rate/connection limits and blocklisting
Logging
Default log path: /home/log/ddos-preventer.log (change in config.py if needed).
Security Notes
Must run as root due to iptables/ipset/sysctl usage
Test in staging before production; the tool inserts NAT and INPUT rules
Tune UDP and SYN limits if you handle high legitimate traffic
Contributing
Open issues or pull requests for bugs or enhancements. Follow existing coding style and logging conventions.
License
Add your preferred license file (e.g., MIT, Apache 2.0, GPL) to the repository and reference it here.

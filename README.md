DDoS Preventer for LAN

A lightweight iptables + ipset + asyncio-based transparent DDoS mitigation proxy for Linux servers.
Protects LAN/WAN environments with minimal overhead and automatic TCP port discovery.

Getting Started

This guide explains how you can install, configure, and run DDoS Preventer.

Prerequisites

This section lists what you need before using the software.

• Linux with iptables/ipset and Python 3.9+

System packages:

sudo apt install iptables ipset iproute2 procps -y


Python dependencies:

pip install -r requirements.txt

Installation

Below is how you can install and set up the project.
This project does not require external services.

1. Clone the repository
git clone https://github.com/yourusername/ddos-preventer.git
cd ddos-preventer

2. Configure defaults (config.py)

Default limits:

DEFAULT_RATE = 20
DEFAULT_BURST = 50
DEFAULT_CONN_LIMIT = 100
DEFAULT_BLOCK_SEC = 30


Per-port overrides:

TARGET_PORTS = {
 22:  {'protocol': 'tcp',  'rate': 5,  'burst': 10, 'conn_limit': 10},
 80:  {'protocol': 'http', 'rate': 15, 'burst': 25},
 443: {'protocol': 'tcp',  'rate': 100, 'burst': 200}
}

3. Optional: Edit whitelist

Path:

/etc/ddos_preventer/whitelist.txt


Example content:

192.168.1.10
10.0.0.0/24
2001:db8::/32

4. Run manually
sudo python3 main.py

Systemd Setup
Install service
sudo cp ddos-preventer.service /etc/systemd/system/
sudo systemctl daemon-reload

Enable & start
sudo systemctl enable ddos-preventer
sudo systemctl start ddos-preventer


Stop:

sudo systemctl stop ddos-preventer

Logging
/home/log/ddos-preventer.log

Architecture Overview
main.py                     → startup, proxy launch, iptables/ipset management
config.py                   → limits, overrides, listeners, paths
core/ipset_manager.py       → whitelist + blocklist sets
core/iptables_manager.py    → NAT redirect chain
core/iptables_hardening.py  → DDOS_FILTER and sysctl hardening
core/mitigation_manager.py  → rate limiting + conn counting
handlers/http_handler.py    → HTTP reverse proxy
handlers/generic_tcp_handler.py → Transparent TCP proxy

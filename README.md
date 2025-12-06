# DDoS Preventer for LAN

A lightweight iptables + ipset + asyncio-based transparent proxy that protects Linux servers against DDoS attacks in LAN/WAN environments.

⭐ Features

Captures inbound TCP traffic using iptables NAT

aiohttp-based HTTP reverse proxy

Generic TCP proxy for all other services

Per-IP rate limit, burst limit, concurrent connection limit

Offending IPs added to an ipset blocklist

Kernel hardening features:

SYN cookies

Enlarged conntrack table

UDP flood rate limiting

SYN flood protection

Low-overhead token-bucket limiter

Auto port discovery via ss -lnt

#### Installation

Follow this step to set up the project.

##### Clone the repository
```bash
git clone https://github.com/keremincii/ddos-preventer.git
cd ddos-preventer
```
##### 📦 Requirements

Linux with iptables + ipset support

Root privileges

Packages: iptables, ipset, iproute2, procps

Python ≥ 3.9

Dependencies:
```bash
pip install -r requirements.txt
```
##### ▶️ Running Manually
```bash
sudo python3 main.py
```

Startup sequence:

Apply sysctl hardening (SYN cookies, conntrack max)

Create ipset blocklist/whitelist

Add iptables NAT + filter rules

Auto-discover open TCP ports

Start HTTP proxy on 0.0.0.0:8081

Start generic TCP proxy on 0.0.0.0:9000

Stop with: 
```bash
Ctrl + C
```
```bash
##### 🏗 Architecture Overview
main.py                     → startup, signal handling, launches HTTP/TCP proxies, applies/cleans iptables & ipset
config.py                   → kernel params, default limits, per-port overrides, listeners, log paths
core/ipset_manager.py       → manages ddos_blocklist & ddos_whitelist
core/iptables_manager.py    → NAT DDOS_GATEWAY chain, redirection logic
core/iptables_hardening.py  → DDOS_FILTER chain, SYN/UDP defense, sysctl tuning
core/mitigation_manager.py  → token-bucket limiter, connection counting, whitelist loading
handlers/http_handler.py    → HTTP reverse proxy with SO_ORIGINAL_DST + rate limits
handlers/generic_tcp_handler.py → transparent TCP proxy with rate/connection limits
```
##### ⚙️ Configuration (config.py)

##### Default Limits

| Parameter          | Description                    |
|--------------------|--------------------------------|
| DEFAULT_RATE       | 20 Requests per second         |
| DEFAULT_BURST      | 50 Short burst allowance       |
| DEFAULT_CONN_LIMIT | 100 Parallel connections per IP|
| DEFAULT_BLOCK_SEC  | 30 Blocklist duration (seconds)|


##### Per-Port Overrides

```python
TARGET_PORTS = {
    22:  {'protocol': 'tcp',  'rate': 5,  'burst': 10, 'conn_limit': 10},
    80:  {'protocol': 'http', 'rate': 15, 'burst': 25},
    443: {'protocol': 'tcp',  'rate': 100, 'burst': 200}
}
```

protocol=http → handled by HTTP proxy  
protocol=tcp → handled by generic TCP proxy  

Ports not listed are auto-discovered and protected with default limits.



##### 🛠 Systemd Service

Install the unit file:
```bash
cd ddos-preventer-for-lan
sudo cp ddos-preventer.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ddos-preventer
sudo systemctl start ddos-preventer
sudo systemctl status ddos-preventer
```

Stop:
```bash
sudo systemctl stop ddos-preventer
```
##### 🤝 Whitelist

Path:
```bash
/etc/ddos_preventer/whitelist.txt
```
one IP or CIDR per line

192.168.1.10

10.0.0.0/24

2001:db8::/32


Entries are automatically added to the ddos_whitelist ipset

Whitelisted IPs bypass rate/connection limits and blocklisting

##### 📜 Logging

Default log file:

```bash
/home/log/ddos-preventer.log
```

You may change this in config.py.

##### 🔐 Security Notes

Must run as root

Test in staging before production

The tool inserts NAT and INPUT rules

Tune UDP/SYN limits if you expect large legitimate traffic

##### 👨‍💻 Contributing

Open issues or pull requests.
Follow the existing coding style and logging conventions.

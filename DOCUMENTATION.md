# DDoS Preventer for LAN - Documentation

## About the Project
**DDoS Preventer for LAN** is a lightweight `iptables + ipset + asyncio` based transparent proxy solution designed to protect Linux servers against DDoS attacks in LAN/WAN environments.

Its main purpose is to capture incoming traffic to the server via iptables, pass it through a Python-based proxy, and automatically block IP addresses that exceed specified rate limits and connection limits using `ipset`.

## Features
- **Traffic Capture**: Transparently captures incoming TCP traffic using `iptables` NAT tables.
- **HTTP Reverse Proxy**: High-performance HTTP proxy based on `aiohttp`.
- **Generic TCP Proxy**: General-purpose proxy for all other TCP protocols (SSH, Game servers, etc.).
- **Dynamic Blocking**: IP addresses exceeding limits are blocked at the kernel level using `ipset`.
- **Kernel Hardening**: Optimizes kernel parameters against SYN Flood and UDP Flood attacks (SYN cookies, conntrack max, etc.).
- **Auto Port Discovery**: Automatically detects open ports on the server using `ss -lnt` and takes them under protection.

---

## Installation

### Requirements
- **Operating System**: Linux (with iptables and ipset support)
- **Privileges**: Root privileges are required.
- **Packages**: `iptables`, `ipset`, `iproute2`, `procps`
- **Python**: Version 3.9 or higher

### Step-by-Step Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/keremincii/ddos-preventer-for-lan.git
   cd ddos-preventer-for-lan
   ```

2. **Install Dependencies:**
   ```bash
   pip3 install -r requirements.txt
   ```

3. **Install Systemd Service File (For Auto-Start):**
   ```bash
   sudo cp ddos-preventer.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable ddos-preventer
   ```

---

## Configuration (`config.py`)

Project settings are found in the `config.py` file. Important parameters are:

### Basic Limits
These limits apply to all ports unless otherwise specified:
- **`DEFAULT_RATE`**: Requests allowed per second (Ex: `20`).
- **`DEFAULT_BURST`**: Maximum instantaneous burst allowance (Ex: `50`).
- **`DEFAULT_CONN_LIMIT`**: Concurrent connection limit from a single IP (Ex: `100`).
- **`DEFAULT_BLOCK_SEC`**: Duration an offending IP remains blocked (in seconds, Ex: `30`).

### Port-Based Custom Settings
You can define special rules for specific ports by editing the `TARGET_PORTS` dictionary:

```python
TARGET_PORTS = {
    22:  {'protocol': 'tcp',  'rate': 5,  'burst': 10, 'conn_limit': 10}, # Strict rules for SSH
    80:  {'protocol': 'http', 'rate': 15, 'burst': 25},                  # HTTP traffic
    443: {'protocol': 'tcp',  'rate': 100, 'burst': 200}                 # HTTPS (TCP mode since it is encrypted)
}
```

### Kernel Protections
- **`ENABLE_SYN_FLOOD_PROTECTION`**: Enables/disables protection against SYN Flood attacks.
- **`KERNEL_CONNTRACK_MAX`**: Determines the size of the conntrack table (should be increased for high traffic).
- **`ENABLE_UDP_PROTECTION`**: Applies a general limit against UDP Flood attacks.

---

## Usage and Management

### Starting / Stopping the Service
The service file is located at `/etc/systemd/system/ddos-preventer.service`.

- **Start**: `sudo systemctl start ddos-preventer`
- **Stop**: `sudo systemctl stop ddos-preventer`
- **Restart**: `sudo systemctl restart ddos-preventer`
- **Check Status**: `sudo systemctl status ddos-preventer`

### Monitoring Logs
To follow application logs in real-time:

```bash
journalctl -u ddos-preventer -o cat -f
```
or directly from the log file (default):
```bash
tail -f /home/log/ddos-preventer.log
```
> The log file location can be changed via `DEFAULT_LOG_FILE` in `config.py`.

### Whitelist Management
Trusted IP addresses can bypass limits.
- **File Location**: `/etc/ddos_preventer/whitelist.txt`
- **Format**: One IP or CIDR block per line (Ex: `192.168.1.10` or `10.0.0.0/24`).

**To view the current whitelist:**
```bash
sudo ipset list ddos_whitelist
```

### Blocklist Management
IPs exhibiting suspicious behavior are automatically added here.

**To view blocked IPs:**
```bash
sudo ipset list ddos_blocklist
```

**To monitor instantaneous iptables rules:**
```bash
watch -n 0.5 "iptables -nvL DDOS_FILTER"
```

## Security Notes
- This tool must run with **root** privileges as it uses `iptables` and `ipset` commands.
- It is recommended to try it in a test environment before using it in a production environment.
- You must optimize UDP and SYN limits according to your own network traffic, otherwise legitimate traffic may be blocked.

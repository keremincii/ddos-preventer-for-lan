# core/mitigation_manager.py
import asyncio
import time
import logging
from collections import deque
from pathlib import Path
import os
import subprocess
import ipaddress
import config
from . import ipset_manager

logger = logging.getLogger("ddos-preventer")

WHITELIST_FILE = "/etc/ddos_preventer/whitelist.txt"

path = Path(WHITELIST_FILE)
if not path.exists():
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(
            "# ddos-preventer whitelist\n"
            "# one IP or CIDR per line\n"
            "# örnekler:\n"
            "# 192.168.1.10\n"
            "# 10.0.0.0/24\n"
            "# 2001:db8::/32\n"
        )
    os.chmod(path, 0o644)
    logger.info(f"Whitelist dosyası oluşturuldu: {path}")

class TokenBucket:
    """Her bir IP-Port çifti için hız limitini uygular."""
    def __init__(self, rate, capacity):
        self.rate = float(rate)
        self.capacity = float(capacity)
        self.tokens = float(capacity)
        self.last = time.time()

    def consume(self, amount=1.0):
        now = time.time()
        self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
        self.last = now
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False

class MitigationManager:
    """Tüm gelen bağlantılar için merkezi DDoS azaltma yöneticisi."""
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(MitigationManager, cls).__new__(cls, *args, **kwargs)
        return cls._instance
    
    def _auto_interface_whitelist(self):
        # 0–9 arası hariç tutulacak prefixler
        skip = {f"eth{i}" for i in range(10)}

        result = subprocess.run(["ip", "-4", "addr", "show"],
                                capture_output=True, text=True)

        if result.returncode != 0:
            return

        current_iface = None

        for line in result.stdout.splitlines():
            line = line.strip()

            # Yeni interface satırı (ör: "2: ens18: <BROADCAST,...>")
            if ":" in line and not line.startswith("inet"):
                current_iface = line.split(":")[1].strip()
                continue

            # IPv4 satırı mı?
            if line.startswith("inet ") and current_iface:
                # eth0–eth9 ise SKIP
                if current_iface in skip:
                    continue

                cidr = line.split()[1]  # ör: "10.8.0.2/24"
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                except:
                    continue

                # Tüm host IP'lerini whitelist’e ekle
                cidr_str = str(net)
                if cidr_str in self.whitelist:
                    continue
                self.whitelist.add(cidr_str)
                ipset_manager.add_whitelist(cidr_str)

                with open(WHITELIST_FILE, "a") as f:
                    f.write(cidr_str + "\n")


    def __init__(self):
        if hasattr(self, '_initialized'):
            return
        self._initialized = True

        logger.info("MitigationManager başlatılıyor (ipset & Port-based modu)...")
        self.block_sec = int(config.DEFAULT_BLOCK_SEC)

        self.buckets = {}
        self.locks = {}
        self.conns = {}
        self.recent = {}

        self.whitelist = set()
        self._load_whitelist()
        self._auto_interface_whitelist()

        self.metrics = {"total": 0, "allowed": 0, "blocked": 0, "blacklisted": 0}

    def _now(self):
        return time.time()

    def _get_lock(self, ip, port):
        key = (ip, port)
        if key not in self.locks:
            self.locks[key] = asyncio.Lock()
        return self.locks[key]

    def _get_recent(self, ip):
        if ip not in self.recent:
            self.recent[ip] = deque(maxlen=1000)
        return self.recent[ip]

    def _load_whitelist(self):
        """Whitelist dosyasını okur ve belleğe yükler."""
        try:
            path = Path(WHITELIST_FILE)
            if not path.exists():
                logger.info(f"Whitelist dosyası bulunamadı: {path}")
                return
            with open(path, "r") as f:
                for line in f:
                    ip = line.strip()
                    if ip and not ip.startswith("#"):
                        self.whitelist.add(ip)
                        ipset_manager.add_whitelist(ip)
            logger.info(f"Whitelist yüklendi ({len(self.whitelist)} IP).")
        except Exception as e:
            logger.error(f"Whitelist okunamadı: {e}")

    def is_blocked(self, ip):
        if ip in self.whitelist:
            return False
        return ipset_manager.contains(ip)

    async def clear_expired_entries(self):
        """1 saatten eski token ve bağlantı kayıtlarını temizler."""
        now = self._now()
        expired_keys = [k for k, bucket in self.buckets.items() if now - bucket.last > 3600]
        for k in expired_keys:
            self.buckets.pop(k, None)
            self.conns.pop(k, None)
            self.locks.pop(k, None)
            self.recent.pop(k[0], None)

        if expired_keys:
            logger.debug(f"{len(expired_keys)} adet eski IP/Port kaydı hafızadan temizlendi.")

    async def check_and_mitigate(self, ip, port):
        """IP ve port bazında hız limitini uygular."""
        if ip in self.whitelist:
            return True, "Whitelisted IP"

        self.metrics["total"] += 1
        if self.is_blocked(ip):
            self.metrics["blocked"] += 1
            return False, "IP blacklisted (ipset)"

        port_config = config.TARGET_PORTS.get(port, {})
        rate = port_config.get("rate", config.DEFAULT_RATE)
        burst = port_config.get("burst", config.DEFAULT_BURST)
        key = (ip, port)

        async with self._get_lock(ip, port):
            tb = self.buckets.get(key)
            if not tb:
                tb = TokenBucket(rate, burst)
                self.buckets[key] = tb

            r = self._get_recent(ip)
            r.append(self._now())

            if not tb.consume():
                if len([t for t in r if self._now() - t < 10]) > burst:
                    ipset_manager.add(ip, self.block_sec)
                    self.metrics["blacklisted"] += 1
                self.metrics["blocked"] += 1
                return False, f"Rate limit exceeded for port {port}"

        self.metrics["allowed"] += 1
        return True, "Allowed"

    async def increment_connection(self, ip, port):
        if ip in self.whitelist:
            return True

        port_config = config.TARGET_PORTS.get(port, {})
        conn_limit = port_config.get("conn_limit", config.DEFAULT_CONN_LIMIT)
        key = (ip, port)

        async with self._get_lock(ip, port):
            self.conns[key] = self.conns.get(key, 0) + 1
            if self.conns[key] > conn_limit:
                ipset_manager.add(ip, self.block_sec)
                self.metrics["blocked"] += 1
                return False
        return True

    async def decrement_connection(self, ip, port):
        key = (ip, port)
        if key not in self.locks:
            return
        async with self._get_lock(ip, port):
            self.conns[key] = max(0, self.conns.get(key, 1) - 1)

    async def run_background_tasks(self):
        """Temizlik ve heartbeat işlemleri."""
        heartbeat_file = Path("/tmp/ddos_preventer.heartbeat")
        while True:
            try:
                heartbeat_file.touch()
                await self.clear_expired_entries()
            except Exception as e:
                logger.exception("Arka plan temizlik görevinde hata: %s", e)
            await asyncio.sleep(10)

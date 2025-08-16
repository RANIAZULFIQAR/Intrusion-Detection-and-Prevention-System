# actions.py
import sys
import time
import subprocess
from typing import Set
from config import ENABLE_BLOCK, BLOCK_DURATION_SEC, MAX_BLOCK_RULES
from logger_util import setup_logger

logger = setup_logger()

class Quarantine:
    def __init__(self):
        self.blocked: Set[str] = set()
        self.expires = {}  # ip -> ts

    def is_blocked(self, ip: str) -> bool:
        exp = self.expires.get(ip)
        if exp and exp < time.time():
            self.unblock(ip)
            return False
        return ip in self.blocked

    def block(self, ip: str):
        if not ENABLE_BLOCK:
            return
        if len(self.blocked) >= MAX_BLOCK_RULES:
            logger.warning("Max block rules reached; not blocking new IPs.")
            return
        if self.is_blocked(ip):
            return
        ok = block_ip(ip)
        if ok:
            self.blocked.add(ip)
            self.expires[ip] = time.time() + BLOCK_DURATION_SEC
            logger.info(f"Blocked {ip} for {BLOCK_DURATION_SEC}s")

    def unblock(self, ip: str):
        ok = unblock_ip(ip)
        if ok:
            self.blocked.discard(ip)
            self.expires.pop(ip, None)
            logger.info(f"Unblocked {ip}")

def block_ip(ip: str) -> bool:
    try:
        if sys.platform.startswith("win"):
            # Windows Advanced Firewall
            subprocess.check_call([
                "netsh","advfirewall","firewall","add","rule",
                f"name=NetAV_Block_{ip}","dir=in","action=block",f"remoteip={ip}"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.check_call([
                "netsh","advfirewall","firewall","add","rule",
                f"name=NetAV_Block_{ip}_out","dir=out","action=block",f"remoteip={ip}"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            # Linux: iptables (requires root)
            subprocess.check_call(["iptables","-I","INPUT","-s",ip,"-j","DROP"])
            subprocess.check_call(["iptables","-I","OUTPUT","-d",ip,"-j","DROP"])
        return True
    except Exception:
        logger.exception(f"Failed to block {ip}")
        return False

def unblock_ip(ip: str) -> bool:
    try:
        if sys.platform.startswith("win"):
            subprocess.call(["netsh","advfirewall","firewall","delete","rule",f"name=NetAV_Block_{ip}"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.call(["netsh","advfirewall","firewall","delete","rule",f"name=NetAV_Block_{ip}_out"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.call(["iptables","-D","INPUT","-s",ip,"-j","DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.call(["iptables","-D","OUTPUT","-d",ip,"-j","DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        logger.exception(f"Failed to unblock {ip}")
        return False

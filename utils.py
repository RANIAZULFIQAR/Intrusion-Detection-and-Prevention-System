# utils.py
import ipaddress
import socket

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def is_localhost(ip: str) -> bool:
    return ip in ("127.0.0.1", "::1")

def resolve_proto(n: int) -> str:
    # best-effort
    return {6: "TCP", 17: "UDP", 1: "ICMP"}.get(n, str(n))

def get_local_ips():
    ips = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            ip = info[4][0]
            if ":" not in ip and ip != "127.0.0.1":
                ips.add(ip)
    except Exception:
        pass
    return ips

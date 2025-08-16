# features.py
import time
from collections import defaultdict, deque
from typing import Dict, Tuple, Optional
import numpy as np
from scapy.layers.inet import IP, TCP, UDP, ICMP
from utils import get_local_ips

FlowKey = Tuple[str, str, int, int, int]  # (src, dst, sport, dport, proto)

class FlowStats:
    __slots__ = (
        "first_ts", "last_ts", "pkt_lens", "iat", "pkt_count", "byte_count",
        "tcp_flags", "src_port", "dst_port", "proto", "dir_outbound", "last_seen"
    )
    def __init__(self, src_port, dst_port, proto, dir_outbound):
        now = time.time()
        self.first_ts = now
        self.last_ts = now
        self.last_seen = now
        self.pkt_lens = []
        self.iat = []
        self.pkt_count = 0
        self.byte_count = 0
        self.tcp_flags = {"S":0,"A":0,"P":0,"R":0,"F":0}
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto  # 6 TCP, 17 UDP, 1 ICMP, etc.
        self.dir_outbound = dir_outbound

    def update(self, pkt_len, ts, flags: Optional[str]):
        if self.pkt_count > 0:
            self.iat.append(ts - self.last_ts)
        self.pkt_count += 1
        self.byte_count += pkt_len
        self.pkt_lens.append(pkt_len)
        self.last_ts = ts
        self.last_seen = ts
        if flags:
            for f in self.tcp_flags:
                if f in flags:
                    self.tcp_flags[f] += 1

    def to_vector(self) -> Dict[str, float]:
        if self.pkt_lens:
            arr = np.array(self.pkt_lens)
            mean_len = float(np.mean(arr))
            std_len = float(np.std(arr, ddof=0))
            min_len = float(np.min(arr))
            max_len = float(np.max(arr))
        else:
            mean_len = std_len = min_len = max_len = 0.0

        if self.iat:
            arr_iat = np.array(self.iat)
            mean_iat = float(np.mean(arr_iat))
            std_iat = float(np.std(arr_iat, ddof=0))
        else:
            mean_iat = std_iat = 0.0

        duration = max(self.last_ts - self.first_ts, 1e-6)

        return {
            "pkt_count": float(self.pkt_count),
            "byte_count": float(self.byte_count),
            "duration": float(duration),
            "mean_pkt_len": mean_len,
            "std_pkt_len": std_len,
            "min_pkt_len": min_len,
            "max_pkt_len": max_len,
            "mean_iat": mean_iat,
            "std_iat": std_iat,
            "tcp_flag_syn": float(self.tcp_flags["S"]),
            "tcp_flag_ack": float(self.tcp_flags["A"]),
            "tcp_flag_psh": float(self.tcp_flags["P"]),
            "tcp_flag_rst": float(self.tcp_flags["R"]),
            "tcp_flag_fin": float(self.tcp_flags["F"]),
            "src_port": float(self.src_port or 0),
            "dst_port": float(self.dst_port or 0),
            "proto_tcp": 1.0 if self.proto == 6 else 0.0,
            "proto_udp": 1.0 if self.proto == 17 else 0.0,
            "proto_icmp": 1.0 if self.proto == 1 else 0.0,
            "dir_outbound": 1.0 if self.dir_outbound else 0.0,
        }

class FlowTable:
    def __init__(self, local_ips=None):
        self.table: Dict[FlowKey, FlowStats] = {}
        self.local_ips = local_ips or get_local_ips()

    def _dir_outbound(self, src_ip: str) -> int:
        return 1 if src_ip in self.local_ips else 0

    def upsert(self, ip_layer, l4) -> FlowStats:
        src, dst = ip_layer.src, ip_layer.dst
        proto = ip_layer.proto
        sport = getattr(l4, "sport", 0) if l4 else 0
        dport = getattr(l4, "dport", 0) if l4 else 0
        key: FlowKey = (src, dst, sport, dport, proto)
        if key not in self.table:
            self.table[key] = FlowStats(sport, dport, proto, self._dir_outbound(src))
        return self.table[key]

    def flush_inactive(self, timeout_sec: int):
        now = time.time()
        to_del = [k for k,v in self.table.items() if now - v.last_seen > timeout_sec]
        for k in to_del:
            self.table.pop(k, None)
        return len(to_del)

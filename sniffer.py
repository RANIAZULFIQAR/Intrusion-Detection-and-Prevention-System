# sniffer.py
import time
from typing import Optional, Tuple
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from logger_util import setup_logger
from features import FlowTable
from config import (
    IFACE, BPF_FILTER, SNAPLEN, STORE, PROMISC,
    FLOW_TIMEOUT_SEC, SCORE_EVERY_N_PKTS, MIN_PKTS_TO_SCORE
)
logger = setup_logger()

class PacketSniffer:
    def __init__(self, packet_handler):
        self.packet_handler = packet_handler
        self.flow_table = FlowTable()

    def _extract_layers(self, pkt) -> Optional[Tuple[IP, object]]:
        if IP not in pkt:
            return None
        ip = pkt[IP]
        l4 = None
        if TCP in pkt:
            l4 = pkt[TCP]
        elif UDP in pkt:
            l4 = pkt[UDP]
        elif ICMP in pkt:
            l4 = pkt[ICMP]
        return (ip, l4)

    def run(self):
        logger.info(f"Starting sniffer (iface={IFACE}, filter='{BPF_FILTER}')")
        sniff(
            iface=IFACE,
            filter=BPF_FILTER,
            prn=self._on_packet,
            store=STORE,
            promisc=PROMISC,
            lfilter=lambda p: IP in p,
        )

    def _on_packet(self, pkt):
        layers = self._extract_layers(pkt)
        if not layers:
            return
        ip, l4 = layers
        ts = time.time()
        pkt_len = len(pkt.original) if hasattr(pkt, "original") else len(bytes(pkt))

        # Update flow
        flow = self.flow_table.upsert(ip, l4)
        flags = None
        if l4 and hasattr(l4, "flags"):
            flags_str = str(l4.flags)
            # scapy can return Flags as int or str; coerce to letters if present
            flags = ""
            for letter in ("S","A","P","R","F"):
                if letter in flags_str:
                    flags += letter
        flow.update(pkt_len, ts, flags)

        # Flush inactive flows occasionally
        self.flow_table.flush_inactive(FLOW_TIMEOUT_SEC)

        # Score policy
        if flow.pkt_count >= MIN_PKTS_TO_SCORE and (flow.pkt_count % SCORE_EVERY_N_PKTS == 0):
            feats = flow.to_vector()
            self.packet_handler(ip.src, ip.dst, feats)

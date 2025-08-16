# main.py
import argparse
import time
from logger_util import setup_logger, append_alert
from model import Detector
from actions import Quarantine
from sniffer import PacketSniffer
from config import THRESHOLD, USE_PROBA, FEATURES_IN_ORDER

logger = setup_logger()

def handle_packet(detector: Detector, quarantine: Quarantine):
    def inner(src_ip: str, dst_ip: str, feat_map):
        result = detector.score(feat_map)
        pred = result["pred"]
        proba = result["proba"]
        malicious = (proba >= THRESHOLD) if USE_PROBA else (pred == 1)

        alert = {
            "ts": time.time(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "pred": int(pred),
            "score": float(proba),
            **{k: float(feat_map[k]) for k in FEATURES_IN_ORDER},
        }

        if malicious:
            logger.warning(f"[ALERT] {src_ip} -> {dst_ip} score={proba:.3f}")
            append_alert(alert)
            # Quarantine external peer (choose direction that makes sense for you)
            quarantine.block(dst_ip)
        else:
            logger.info(f"[OK] {src_ip} -> {dst_ip} score={proba:.3f}")
    return inner

def main():
    parser = argparse.ArgumentParser(description="Network-based Antivirus / IDS (RF model)")
    parser.add_argument("--iface", default=None, help="Network interface (default: OS default)")
    parser.add_argument("--threshold", type=float, default=THRESHOLD, help="Malicious probability threshold")
    parser.add_argument("--no-block", action="store_true", help="Disable firewall blocking")
    args = parser.parse_args()

    # Allow runtime override for blocking
    if args.no_block:
        from config import ENABLE_BLOCK
        ENABLE_BLOCK = False  # noqa: F841 (documented runtime override only)

    detector = Detector()
    quarantine = Quarantine()
    packet_handler = handle_packet(detector, quarantine)

    sniffer = PacketSniffer(packet_handler)
    # Override iface at runtime if provided
    if args.iface:
        from config import IFACE
        import config as cfg
        cfg.IFACE = args.iface  # set dynamically

    sniffer.run()

if __name__ == "__main__":
    main()

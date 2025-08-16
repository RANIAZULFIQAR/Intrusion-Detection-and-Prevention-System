# config.py
from pathlib import Path

# Model paths
MODEL_PATH = Path(r"C:\\Users\\LENOVO\\net_av\\models\\malware_detector.pkl")      # REQUIRED
SCALER_PATH = Path(r"C:\\Users\\LENOVO\\net_av\\models\\scaler.pkl")       # OPTIONAL (set to None if unused)

# Sniffer
BPF_FILTER = "ip"                  # Keep it broad; you can narrow (e.g., "tcp or udp")
IFACE = "Wi-Fi"                       # None = default interface; else "Ethernet0", "eth0", etc.
SNAPLEN = 0                        # 0 = entire packet
STORE = False
PROMISC = True

# Flow windowing
FLOW_TIMEOUT_SEC = 15              # Flush a flow if no packets for N seconds
MIN_PKTS_TO_SCORE = 3              # Don’t score on super tiny flows (noise)
SCORE_EVERY_N_PKTS = 10            # Also score when flow hits N packets

# Prediction
THRESHOLD = 0.5                    # If using predict_proba; else use class == 1
USE_PROBA = True                   # Set False if your model lacks predict_proba()
FEATURES_IN_ORDER = [
    # MUST match your model’s training order exactly
    "pkt_count",
    "byte_count",
    "duration",
    "mean_pkt_len",
    "std_pkt_len",
    "min_pkt_len",
    "max_pkt_len",
    "mean_iat",
    "std_iat",
    "tcp_flag_syn",
    "tcp_flag_ack",
    "tcp_flag_psh",
    "tcp_flag_rst",
    "tcp_flag_fin",
    "src_port",
    "dst_port",
    "proto_tcp",
    "proto_udp",
    "proto_icmp",
    "dir_outbound",  # 1 if local->remote, else 0
]

# Actions
ENABLE_BLOCK = True                # Toggle active blocking
BLOCK_DURATION_SEC = 900           # 15 minutes
MAX_BLOCK_RULES = 500              # safety cap

# Logging
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
ALERTS_CSV = LOG_DIR / "alerts.csv"
APP_LOG = LOG_DIR / "app.log"

# logger_util.py
import logging
from logging.handlers import RotatingFileHandler
import pandas as pd
from pathlib import Path
from typing import Dict, Any
from config import APP_LOG, ALERTS_CSV

def setup_logger():
    logger = logging.getLogger("net_av")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = RotatingFileHandler(APP_LOG, maxBytes=2_000_000, backupCount=3)
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        handler.setFormatter(fmt)
        logger.addHandler(handler)
        console = logging.StreamHandler()
        console.setFormatter(fmt)
        logger.addHandler(console)
    return logger

def append_alert(row: Dict[str, Any]):
    df = pd.DataFrame([row])
    header = not Path(ALERTS_CSV).exists()
    df.to_csv(ALERTS_CSV, mode="a", header=header, index=False)

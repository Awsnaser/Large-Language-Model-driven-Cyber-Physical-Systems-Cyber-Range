#!/usr/bin/env python3
"""
ALL-IN-ONE: LLM-driven cyber-physical range + Docker substrate + multi-output GP + active intervention policy

Adds:
- Multi-output GP:
    y0: delta_level (regression)
    y1: alarm_risk (0/1 target, learned with Gaussian noise; probability via sigmoid(mean))
    y2: damage_risk (0/1 target; probability via sigmoid(mean))
- Passive vs interventional datasets:
    D_obs: natural trajectories
    D_int: do(u=...) trajectories
- Active intervention policy:
    chooses safe interventions that maximize predictive uncertainty (information-gain proxy)

Requirements:
- pip install docker matplotlib ollama faker numpy
- pip install scapy  (optional, for PCAP export for Wireshark)
- Docker Desktop / docker engine running (or use --no-docker-up with placeholder IPs)
- Ollama running locally with chosen models available

Safety:
- This is a simulator. No real exploitation is performed. Actions are symbolic.
"""

import argparse
import csv
import json
import logging
import os
import platform
import random
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import docker
import matplotlib.pyplot as plt
import ollama
from faker import Faker

try:
    from matplotlib import animation as _mpl_animation
except Exception:
    _mpl_animation = None

try:
    from sklearn.metrics import auc as _sk_auc
    from sklearn.metrics import roc_curve as _sk_roc_curve
except Exception:
    _sk_auc = None
    _sk_roc_curve = None

try:
    from prometheus_client import Counter as _PromCounter
    from prometheus_client import Gauge as _PromGauge
    from prometheus_client import start_http_server as _prom_start_http_server
except Exception:
    _PromCounter = None
    _PromGauge = None
    _prom_start_http_server = None

try:
    from pymodbus.client import ModbusTcpClient as _ModbusTcpClient
except Exception:
    _ModbusTcpClient = None

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stdout,
    )
    # Suppress noisy third-party loggers
    logging.getLogger("docker").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

log = logging.getLogger(__name__)
def _log_info(msg: str, *args: Any) -> None:
    if args:
        log.info(msg, *args)
    else:
        log.info(msg)
def _log_warn(msg: str, *args: Any) -> None:
    if args:
        log.warning(msg, *args)
    else:
        log.warning(msg)
def _log_err(msg: str, *args: Any) -> None:
    if args:
        log.error(msg, *args)
    else:
        log.error(msg)


def _supports_ansi_colors() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    if platform.system().lower().startswith("win"):
        return bool(os.environ.get("WT_SESSION") or os.environ.get("ANSICON") or os.environ.get("TERM"))
    return True


def _color(text: str, code: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"\033[{code}m{text}\033[0m"


def _emit_live_round_status(
    *,
    round_idx: int,
    max_rounds: int,
    zone: str,
    tank_level: float,
    alerts_total: int,
    compromised_count: int,
    red_action: str,
    blue_action: str,
    gp_p_alarm: float,
    gp_p_damage: float,
    policy_choice: str,
    color_ui: bool = False,
) -> None:
    probe_tag = policy_choice if policy_choice else "-"

    level_txt = f"{tank_level:6.1f}%"
    if tank_level < TANK_LEVEL_EMPTY or tank_level > TANK_LEVEL_OVERFLOW:
        level_txt = _color(level_txt, "31", color_ui)
    elif tank_level < TANK_LEVEL_SAFE_LOW or tank_level > TANK_LEVEL_SAFE_HIGH:
        level_txt = _color(level_txt, "33", color_ui)
    else:
        level_txt = _color(level_txt, "32", color_ui)

    gp_damage_txt = f"{gp_p_damage:0.2f}"
    if gp_p_damage >= 0.60:
        gp_damage_txt = _color(gp_damage_txt, "31", color_ui)
    elif gp_p_damage >= 0.30:
        gp_damage_txt = _color(gp_damage_txt, "33", color_ui)
    else:
        gp_damage_txt = _color(gp_damage_txt, "32", color_ui)

    zone_map = {
        ZONE_IT: _color("IT", "36", color_ui),
        ZONE_DMZ: _color("DMZ", "33", color_ui),
        ZONE_OT: _color("OT", "35", color_ui),
    }
    zone_txt = zone_map.get(str(zone), str(zone))

    red_txt = _color(f"{red_action:<8}", "31", color_ui)
    blue_txt = _color(f"{blue_action:<8}", "34", color_ui)

    line = (
        f"\r[round {round_idx:03d}/{max_rounds:03d}] "
        f"zone={zone_txt:<3} level={level_txt} "
        f"alerts={alerts_total:3d} comp={compromised_count:2d} "
        f"RED={red_txt} BLUE={blue_txt} "
        f"GP(a)={gp_p_alarm:0.2f} GP(d)={gp_damage_txt} probe={probe_tag:<24}"
    )
    sys.stdout.write(line)
    sys.stdout.flush()


def _end_live_round_status() -> None:
    sys.stdout.write("\n")
    sys.stdout.flush()

# -----------------------------------------------------------------------------
# Constants: zones, actions, tank, assets, severity
# -----------------------------------------------------------------------------
ZONE_IT = "IT"
ZONE_DMZ = "DMZ"
ZONE_OT = "OT"
ZONES = (ZONE_IT, ZONE_DMZ, ZONE_OT)

ACTIONS_RED = frozenset({"RECON", "PHISH", "BRUTE", "EXPLOIT", "PIVOT", "EXECUTE", "IMPACT", "COVER"})
ACTIONS_BLUE = frozenset({"MONITOR", "ISOLATE", "PATCH", "HARDEN", "RESTORE", "TUNE"})

RED_ATTACK_CATALOG: Dict[str, Dict[str, str]] = {
    "RECON": {"phase": "Reconnaissance", "ttp": "T0846", "tool": "nmap-like scanner"},
    "PHISH": {"phase": "Initial Access", "ttp": "T0865", "tool": "phishing kit"},
    "BRUTE": {"phase": "Credential Access", "ttp": "T1110", "tool": "hydra-like brute force"},
    "EXPLOIT": {"phase": "Initial Access", "ttp": "T0819", "tool": "exploit framework"},
    "PIVOT": {"phase": "Lateral Movement", "ttp": "T0869", "tool": "pivot tunnel"},
    "EXECUTE": {"phase": "Execution", "ttp": "T1059", "tool": "remote shell"},
    "IMPACT": {"phase": "Impact", "ttp": "T0831", "tool": "PLC logic manipulator"},
    "COVER": {"phase": "Defense Evasion", "ttp": "T1070", "tool": "log tampering utility"},
}

BLUE_DEFENSE_CATALOG: Dict[str, Dict[str, str]] = {
    "MONITOR": {"phase": "Detect", "ttp": "D3-MON", "tool": "SIEM correlation"},
    "ISOLATE": {"phase": "Contain", "ttp": "D3-NET", "tool": "network segmentation"},
    "PATCH": {"phase": "Mitigate", "ttp": "D3-PAT", "tool": "patch manager"},
    "HARDEN": {"phase": "Protect", "ttp": "D3-HAR", "tool": "hardening baseline"},
    "RESTORE": {"phase": "Recover", "ttp": "D3-REC", "tool": "backup/restore"},
    "TUNE": {"phase": "Optimize", "ttp": "D3-TUN", "tool": "detection tuning"},
}

TANK_CMD_AUTO = "AUTO"
TANK_PUMP_FORCE_ON = "FORCE_ON"
TANK_PUMP_FORCE_OFF = "FORCE_OFF"
TANK_VALVE_FORCE_OPEN = "FORCE_OPEN"
TANK_VALVE_FORCE_CLOSED = "FORCE_CLOSED"
TANK_LEVEL_SAFE_LOW = 15
TANK_LEVEL_SAFE_HIGH = 85
TANK_LEVEL_OVERFLOW = 92
TANK_LEVEL_EMPTY = 5
TANK_LEVEL_SETPOINT_LO = 47
TANK_LEVEL_SETPOINT_HI = 53
TANK_LEVEL_INTERLOCK_ABOVE = 85

SEVERITY_LOW = "LOW"
SEVERITY_MED = "MED"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRIT = "CRIT"
SEVERITY_ALERT_BASE: Dict[str, float] = {
    SEVERITY_LOW: 0.25,
    SEVERITY_MED: 0.45,
    SEVERITY_HIGH: 0.7,
    SEVERITY_CRIT: 0.9,
}
BLUE_SENSITIVITY_MIN = 0.1
BLUE_SENSITIVITY_MAX = 0.95
ALERT_PROB_CAP = 0.98

PLC_ASSET_ID = "plc_industrial_01"

# Standard containers
STANDARD_CONTAINERS = ("gw_dmz_01", "hist_data_01", "hmi_ops_01", PLC_ASSET_ID)

# Enhanced containers with honeypots and full infrastructure
ENHANCED_CONTAINERS = (
    # Core CPS assets
    "gw_dmz_01", "hist_data_01", "hmi_ops_01", PLC_ASSET_ID,
    # Industrial systems
    "cps-plc-01", "cps-opcua-01", "cps-hmi-01", "cps-historian",
    # IT infrastructure
    "cps-web-01", "cps-db-01", "cps-dc-01", "cps-dns", "cps-dhcp",
    # Honeypots
    "cps-honeypot-plc", "cps-honeypot-opcua", "cps-honeypot-web", 
    "cps-honeypot-db", "cps-honeypot-ssh", "cps-honeypot-ftp",
    # Security and monitoring
    "cps-router", "cps-traffic-gen", "cps-ids", "cps-siem", "cps-log-collector",
    "cps-suricata-ids", "cps-packet-capture"
)

# Laptop-optimized containers (lightweight)
LAPTOP_CONTAINERS = (
    # Core CPS assets
    "gw_dmz_01", "hist_data_01", "hmi_ops_01", PLC_ASSET_ID,
    # Lightweight industrial systems
    "cps-plc-lite", "cps-opcua-lite", "cps-hmi-lite",
    # Lightweight IT systems
    "cps-web-lite", "cps-db-lite",
    # Lightweight honeypots
    "cps-honeypot-plc-lite", "cps-honeypot-web-lite", "cps-honeypot-ssh-lite",
    # Monitoring
    "cps-traffic-lite", "cps-log-lite", "cps-suricata-lite", "cps-pcap-lite"
)

# Default to standard containers
CONTAINER_NAMES = STANDARD_CONTAINERS
HISTORY_KEYS = (
    "round", "tank_level", "alerts_total", "compromised_count",
    "attacker_zone", "alarm_flag", "damage_flag", "gp_p_alarm", "gp_p_damage", "policy_choice",
)
DEFAULT_LLM_MODEL = "llama3.2:1b"
DEFAULT_DAMAGE_PROB_MAX = 0.25
# 80–150 rounds give a much better chance to learn damage probability (damage may happen rarely unless RED succeeds)
DEFAULT_MAX_ROUNDS = 100
CAUSAL_X_BUFFER_MAX = 80
GP_MIN_SAMPLES = 10
FULL_RECON_MAX_ITEMS = 200

MODBUS_PUMP_CODE = {TANK_CMD_AUTO: 0, TANK_PUMP_FORCE_ON: 1, TANK_PUMP_FORCE_OFF: 2}
MODBUS_PUMP_CODE_INV = {v: k for k, v in MODBUS_PUMP_CODE.items()}
MODBUS_VALVE_CODE = {TANK_CMD_AUTO: 0, TANK_VALVE_FORCE_OPEN: 1, TANK_VALVE_FORCE_CLOSED: 2}
MODBUS_VALVE_CODE_INV = {v: k for k, v in MODBUS_VALVE_CODE.items()}
MODBUS_REG_STATE_BASE = 100
MODBUS_REG_CMD_BASE = 201

# Dataset/PCAP export: placeholder IPs when Docker is not used (for Wireshark analysis)
ATTACKER_PLACEHOLDER_IP = "192.168.1.100"
PLACEHOLDER_IPS: Dict[str, str] = {
    "attacker": ATTACKER_PLACEHOLDER_IP,
    # Standard containers
    "gw_dmz_01": "172.16.0.10",
    "hist_data_01": "172.16.0.11",
    "hmi_ops_01": "10.0.0.10",
    "plc_industrial_01": "10.0.0.11",
    # Enhanced industrial systems
    "cps-plc-01": "10.0.0.20",
    "cps-opcua-01": "10.0.0.21",
    "cps-hmi-01": "10.0.0.22",
    "cps-historian": "10.0.0.23",
    # Enhanced IT infrastructure
    "cps-web-01": "172.16.0.20",
    "cps-db-01": "172.16.0.21",
    "cps-dc-01": "172.16.0.22",
    "cps-dns": "172.16.0.23",
    "cps-dhcp": "172.16.0.24",
    # Honeypots
    "cps-honeypot-plc": "10.0.0.100",
    "cps-honeypot-opcua": "10.0.0.101",
    "cps-honeypot-web": "172.16.0.100",
    "cps-honeypot-db": "172.16.0.101",
    "cps-honeypot-ssh": "172.16.0.102",
    "cps-honeypot-ftp": "172.16.0.103",
    # Security and monitoring
    "cps-router": "172.16.0.2",
    "cps-traffic-gen": "172.16.0.25",
    "cps-ids": "172.16.0.26",
    "cps-siem": "172.16.0.27",
    "cps-log-collector": "172.16.0.28",
    "cps-suricata-ids": "172.16.0.29",
    "cps-packet-capture": "172.16.0.30",
    # Laptop-optimized containers
    "cps-plc-lite": "10.0.0.30",
    "cps-opcua-lite": "10.0.0.31",
    "cps-hmi-lite": "10.0.0.32",
    "cps-web-lite": "172.16.0.30",
    "cps-db-lite": "172.16.0.31",
    "cps-honeypot-plc-lite": "10.0.0.110",
    "cps-honeypot-web-lite": "172.16.0.110",
    "cps-honeypot-ssh-lite": "172.16.0.111",
    "cps-traffic-lite": "172.16.0.32",
    "cps-log-lite": "172.16.0.33",
    "cps-suricata-lite": "172.16.0.34",
    "cps-pcap-lite": "172.16.0.35",
}
# Asset -> default ports for PCAP (service name -> port)
ASSET_PORTS: Dict[str, Dict[str, int]] = {
    # Standard containers
    "gw_dmz_01": {"ssh": 22, "vpn": 1194},
    "hist_data_01": {"http": 80, "https": 443},
    "hmi_ops_01": {"rdp": 3389, "vnc": 5900},
    "plc_industrial_01": {"modbus": 502, "prog": 44818},
    # Enhanced industrial systems
    "cps-plc-01": {"modbus": 502, "opcua": 4840, "ssh": 2222},
    "cps-opcua-01": {"opcua": 4840, "http": 8080, "ssh": 2223},
    "cps-hmi-01": {"rdp": 3389, "vnc": 5901, "http": 8081},
    "cps-historian": {"http": 8082, "https": 8443, "sql": 5432},
    # Enhanced IT infrastructure
    "cps-web-01": {"http": 80, "https": 443, "ssh": 22},
    "cps-db-01": {"mysql": 3306, "postgres": 5432, "ssh": 2224},
    "cps-dc-01": {"ldap": 389, "ldaps": 636, "dns": 53},
    "cps-dns": {"dns": 53, "dns-tcp": 53},
    "cps-dhcp": {"dhcp": 67, "dhcp-server": 68},
    # Honeypots
    "cps-honeypot-plc": {"modbus": 502, "ssh": 2225, "telnet": 23},
    "cps-honeypot-opcua": {"opcua": 4840, "http": 8083, "ssh": 2226},
    "cps-honeypot-web": {"http": 80, "https": 443, "ssh": 2227, "ftp": 21},
    "cps-honeypot-db": {"mysql": 3306, "postgres": 5432, "ssh": 2228},
    "cps-honeypot-ssh": {"ssh": 22, "telnet": 23, "ftp": 21},
    "cps-honeypot-ftp": {"ftp": 21, "ssh": 2229, "http": 8084},
    # Security and monitoring
    "cps-router": {"ssh": 22, "http": 80, "snmp": 161},
    "cps-traffic-gen": {"http": 8085, "ssh": 2230},
    "cps-ids": {"http": 8086, "ssh": 2231},
    "cps-siem": {"http": 8087, "ssh": 2232},
    "cps-log-collector": {"http": 8088, "ssh": 2233},
    "cps-suricata-ids": {"http": 8089, "ssh": 2234},
    "cps-packet-capture": {"ssh": 2235},
    # Laptop-optimized containers
    "cps-plc-lite": {"modbus": 502, "ssh": 2235},
    "cps-opcua-lite": {"opcua": 4840, "http": 8089},
    "cps-hmi-lite": {"rdp": 3389, "http": 8090},
    "cps-web-lite": {"http": 80, "https": 443},
    "cps-db-lite": {"mysql": 3306, "ssh": 2236},
    "cps-honeypot-plc-lite": {"modbus": 502, "ssh": 2237},
    "cps-honeypot-web-lite": {"http": 80, "https": 443, "ssh": 2238},
    "cps-honeypot-ssh-lite": {"ssh": 22, "telnet": 23},
    "cps-traffic-lite": {"http": 8091, "ssh": 2239},
    "cps-log-lite": {"http": 8092, "ssh": 2240},
    "cps-suricata-lite": {"http": 8093, "ssh": 2241},
    "cps-pcap-lite": {"ssh": 2242},
}
DEFAULT_EXPORT_DIR = "cyberrange_export"

fake = Faker()
persistent_users: Dict[str, List[Dict[str, str]]] = {}


def generate_persistent_users() -> None:
    """Generate fake user credentials per container for simulation realism."""
    global persistent_users
    for container in CONTAINER_NAMES:
        persistent_users[container] = [
            {
                "username": fake.user_name(),
                "password": fake.password(),
                "email": fake.email(),
            }
            for _ in range(random.randint(2, 5))
        ]
    _log_info("Persistent users generated for %d containers.", len(CONTAINER_NAMES))


# ============================================================
# 0) DOCKER COMPOSE CONFIG
# ============================================================
DOCKER_COMPOSE_YML = """
services:
  gw_dmz_01:
    container_name: gw_dmz_01
    image: alpine:3.20
    command:
      [
        "sh",
        "-c",
        "apk add --no-cache openssh busybox-extras && ssh-keygen -A && adduser -D -s /bin/sh trainee && echo 'trainee:trainee' | chpasswd && /usr/sbin/sshd -D -e"
      ]
    networks:
      dmz_net:
        aliases: ["gw_dmz_01"]
    ports:
      - "2222:22"
    healthcheck:
      test: ["CMD-SHELL", "nc -z localhost 22 || exit 1"]
      interval: 10s
      timeout: 3s
      retries: 8
    read_only: true
    tmpfs:
      - /run
      - /tmp
    restart: unless-stopped
  hist_data_01:
    container_name: hist_data_01
    image: nginx:alpine
    networks:
      dmz_net:
        aliases: ["hist_data_01"]
    ports:
      - "8080:80"
    healthcheck:
      test: ["CMD-SHELL", "wget -qO- http://localhost:80 >/dev/null 2>&1 || exit 1"]
      interval: 10s
      timeout: 3s
      retries: 8
    read_only: true
    tmpfs:
      - /var/cache/nginx
      - /var/run
      - /tmp
    restart: unless-stopped
  hmi_ops_01:
    container_name: hmi_ops_01
    image: alpine:3.20
    command: ["sh", "-c", "apk add --no-cache busybox-extras && sleep infinity"]
    networks:
      ot_net:
        aliases: ["hmi_ops_01"]
    healthcheck:
      test: ["CMD-SHELL", "ps | grep -q sleep || exit 1"]
      interval: 20s
      timeout: 3s
      retries: 5
    read_only: true
    tmpfs:
      - /tmp
    restart: unless-stopped
  plc_industrial_01:
    container_name: plc_industrial_01
    image: alpine:3.20
    command:
      [
        "sh",
        "-c",
        "apk add --no-cache busybox-extras && mkdir -p /plc && echo 'SAFE_v1' > /plc/logic_hash && sleep infinity"
      ]
    networks:
      ot_net:
        aliases: ["plc_industrial_01"]
    healthcheck:
      test: ["CMD-SHELL", "test -f /plc/logic_hash || exit 1"]
      interval: 20s
      timeout: 3s
      retries: 5
    read_only: false
    volumes:
      - plc_state:/plc
    restart: unless-stopped
networks:
  dmz_net:
    driver: bridge
    name: dmz_net
  ot_net:
    driver: bridge
    name: ot_net
volumes:
  plc_state:
"""


# ============================================================
# 0) MULTI-LICENSE-PLATE RECOGNITION (LPR) SYSTEM
# ============================================================

@dataclass
class LicensePlate:
    plate_text: str
    confidence: float
    bbox: Tuple[int, int, int, int]  # (x1, y1, x2, y2)
    timestamp: float
    image_path: Optional[str] = None

class MultiLPRProcessor:
    """Multi-License Plate Recognition processor for detecting multiple plates in images."""
    
    def __init__(self, confidence_threshold: float = 0.7):
        self.confidence_threshold = confidence_threshold
        self.plate_patterns = [
            r'^[A-Z]{2}\d{4}$',  # AB1234 format
            r'^[A-Z]{3}\d{3}$',  # ABC123 format  
            r'^\d{3}[A-Z]{3}$',  # 123ABC format
            r'^[A-Z]{2}\d{2}[A-Z]\d{1}$',  # AB12C1 format
        ]
        
    def detect_multiple_plates(self, image_path: str) -> List[LicensePlate]:
        """
        Detect multiple license plates in a single image.
        Returns list of LicensePlate objects with confidence scores.
        """
        try:
            # Simulate plate detection with multiple potential regions
            detected_plates = []
            
            # Simulate finding multiple plate regions in the image
            # In real implementation, this would use CV/DL models
            plate_regions = self._simulate_plate_detection(image_path)
            
            for i, region in enumerate(plate_regions):
                plate_text = self._recognize_plate_text(region)
                confidence = self._calculate_confidence(plate_text, region)
                
                if confidence >= self.confidence_threshold:
                    bbox = self._extract_bbox(region, i)
                    plate = LicensePlate(
                        plate_text=plate_text,
                        confidence=confidence,
                        bbox=bbox,
                        timestamp=time.time(),
                        image_path=image_path
                    )
                    detected_plates.append(plate)
            
            # Sort by confidence (highest first)
            detected_plates.sort(key=lambda p: p.confidence, reverse=True)
            return detected_plates
            
        except Exception as e:
            _log_warn(f"Multi-plate LPR detection failed: {e}")
            return []
    
    def _simulate_plate_detection(self, image_path: str) -> List[Dict]:
        """Simulate detection of multiple plate regions in an image."""
        # Generate 1-4 simulated plate regions
        num_plates = random.randint(1, 4)
        regions = []
        
        for i in range(num_plates):
            region = {
                'region_id': i,
                'quality': random.uniform(0.6, 1.0),
                'blur': random.uniform(0.0, 0.3),
                'angle': random.uniform(-15, 15),
                'lighting': random.uniform(0.7, 1.0)
            }
            regions.append(region)
            
        return regions
    
    def _recognize_plate_text(self, region: Dict) -> str:
        """Simulate OCR recognition of plate text from a region."""
        # Generate realistic license plate text
        patterns = ['AB1234', 'CD5678', 'EF9012', 'GH3456', 'IJ7890']
        base_pattern = random.choice(patterns)
        
        # Add some variation based on region quality
        if region['quality'] < 0.8:
            # Simulate OCR errors
            if random.random() < 0.3:
                chars = list(base_pattern)
                error_pos = random.randint(0, len(chars) - 1)
                # Replace with similar looking character
                if chars[error_pos].isdigit():
                    chars[error_pos] = str(random.randint(0, 9))
                else:
                    chars[error_pos] = random.choice('ABCDEFGHJKLMNPQRSTUVWXYZ')
                base_pattern = ''.join(chars)
        
        return base_pattern
    
    def _calculate_confidence(self, plate_text: str, region: Dict) -> float:
        """Calculate confidence score based on region quality and text validity."""
        # Base confidence from region quality
        base_conf = region['quality'] * region['lighting']
        
        # Reduce confidence based on blur and angle
        base_conf *= (1.0 - region['blur'])
        base_conf *= (1.0 - abs(region['angle']) / 45.0)
        
        # Boost confidence if text matches known patterns
        pattern_match = any(re.match(pattern, plate_text) for pattern in self.plate_patterns)
        if pattern_match:
            base_conf *= 1.2
        
        # Ensure confidence is in valid range
        return max(0.0, min(1.0, base_conf))
    
    def _extract_bbox(self, region: Dict, region_id: int) -> Tuple[int, int, int, int]:
        """Extract bounding box coordinates for detected plate region."""
        # Simulate different bounding boxes for multiple plates
        x_start = 100 + region_id * 150
        y_start = 200 + (region_id % 2) * 100
        width = 120
        height = 40
        
        return (x_start, y_start, x_start + width, y_start + height)
    
    def visualize_multiple_plates(self, image_path: str, plates: List[LicensePlate], save_path: Optional[str] = None) -> Optional[str]:
        """
        Create visualization image with multiple license plates highlighted.
        Returns path to saved visualization image.
        """
        try:
            import matplotlib.pyplot as plt
            import matplotlib.patches as patches
            from PIL import Image
            
            # Create figure
            fig, ax = plt.subplots(1, 1, figsize=(12, 8))
            
            # Simulate loading and displaying the image
            # In real implementation: img = Image.open(image_path)
            ax.set_xlim(0, 800)
            ax.set_ylim(600, 0)  # Flip y-axis for image coordinates
            ax.set_title(f'Multi-License Plate Detection: {len(plates)} plates found')
            ax.axis('off')
            
            # Draw bounding boxes and labels for each plate
            colors = ['red', 'blue', 'green', 'yellow', 'purple']
            for i, plate in enumerate(plates):
                color = colors[i % len(colors)]
                x1, y1, x2, y2 = plate.bbox
                
                # Draw bounding box
                rect = patches.Rectangle((x1, y1), x2-x1, y2-y1, 
                                       linewidth=2, edgecolor=color, facecolor='none')
                ax.add_patch(rect)
                
                # Add label with plate text and confidence
                label = f"{plate.plate_text} ({plate.confidence:.2f})"
                ax.text(x1, y1-10, label, fontsize=10, color=color, 
                       bbox=dict(boxstyle="round,pad=0.3", facecolor='white', alpha=0.8))
            
            # Save visualization
            if save_path is None:
                save_path = f"multi_plate_viz_{int(time.time())}.png"
            
            plt.savefig(save_path, dpi=150, bbox_inches='tight')
            plt.close()
            
            _log_info(f"[OK] Multi-plate visualization saved to {save_path}")
            return save_path
            
        except Exception as e:
            _log_warn(f"Multi-plate visualization failed: {e}")
            return None

# Global multi-LPR processor instance
multi_lpr_processor = MultiLPRProcessor()

def process_multi_plate_lpr(image_path: str, save_visualization: bool = True) -> Dict[str, Any]:
    """
    Process an image for multiple license plates and return comprehensive results.
    
    Args:
        image_path: Path to the image file
        save_visualization: Whether to save visualization image
        
    Returns:
        Dictionary with detection results, statistics, and visualization path
    """
    try:
        # Detect multiple plates
        plates = multi_lpr_processor.detect_multiple_plates(image_path)
        
        # Calculate statistics
        total_plates = len(plates)
        avg_confidence = sum(p.confidence for p in plates) / total_plates if plates else 0.0
        high_conf_plates = [p for p in plates if p.confidence >= 0.8]
        
        # Generate visualization
        viz_path = None
        if save_visualization and plates:
            viz_path = multi_lpr_processor.visualize_multiple_plates(image_path, plates)
        
        results = {
            'image_path': image_path,
            'total_plates_detected': total_plates,
            'plates': [
                {
                    'text': p.plate_text,
                    'confidence': p.confidence,
                    'bbox': p.bbox,
                    'timestamp': p.timestamp
                } for p in plates
            ],
            'statistics': {
                'average_confidence': avg_confidence,
                'high_confidence_count': len(high_conf_plates),
                'max_confidence': max(p.confidence for p in plates) if plates else 0.0,
                'min_confidence': min(p.confidence for p in plates) if plates else 0.0
            },
            'visualization_path': viz_path,
            'processing_time': time.time()
        }
        
        _log_info(f"[OK] Multi-plate LPR processed: {total_plates} plates detected")
        return results
        
    except Exception as e:
        _log_warn(f"Multi-plate LPR processing failed: {e}")
        return {
            'image_path': image_path,
            'total_plates_detected': 0,
            'plates': [],
            'statistics': {'average_confidence': 0.0},
            'error': str(e)
        }

def add_lpr_alerts_to_simulation(env: 'CPSRange', lpr_results: Dict[str, Any]) -> None:
    """
    Add LPR detection results as alerts to the simulation environment.
    This connects LPR system with the cybersecurity simulation.
    """
    try:
        plates = lpr_results.get('plates', [])
        
        for plate in plates:
            # Create security alert for each detected license plate
            alert = {
                'round': env.round,
                'severity': 'MED' if plate['confidence'] >= 0.8 else 'LOW',
                'reason': f'License plate detected: {plate["text"]}',
                'plate_text': plate['text'],
                'confidence': plate['confidence'],
                'bbox': plate['bbox'],
                'source': 'LPR_SYSTEM'
            }
            env.add_alert(**alert)
        
        # Add summary alert if multiple plates detected
        total_plates = lpr_results.get('total_plates_detected', 0)
        if total_plates > 1:
            env.add_alert(
                round=env.round,
                severity='HIGH',
                reason=f'Multiple license plates detected: {total_plates} plates',
                plate_count=total_plates,
                avg_confidence=lpr_results.get('statistics', {}).get('average_confidence', 0.0),
                source='LPR_SYSTEM'
            )
            
    except Exception as e:
        _log_warn(f"Failed to add LPR alerts to simulation: {e}")

# ============================================================
# 1) RANGE MODEL
# ============================================================
@dataclass
class Service:
    name: str
    port: int
    vuln_id: Optional[str] = None
    exposed: bool = True
    patched: bool = False
    weak_creds: bool = False
    auth_required: bool = True

@dataclass
class Asset:
    asset_id: str
    kind: str
    zone: str
    services: Dict[str, Service]
    compromised: bool = False
    privilege: str = "NONE"  # NONE / USER / ADMIN
    isolated: bool = False
    hardened: bool = False
    notes: Dict[str, Any] = field(default_factory=dict)

@dataclass
class PhysicalTank:
    level: float = 50.0
    pump_cmd: str = "AUTO"         # AUTO / FORCE_ON / FORCE_OFF
    valve_cmd: str = "AUTO"        # AUTO / FORCE_OPEN / FORCE_CLOSED
    sensor_ok: bool = True
    safety_interlock: bool = True
    alarm: Optional[str] = None
    damage: bool = False


# ============================================================
# 1B) MULTI-OUTPUT GP + PASSIVE/INTERVENTIONAL DATA + ACTIVE POLICY
# ============================================================
def sigmoid(x: float) -> float:
    x = float(x)
    if x >= 0:
        z = np.exp(-x)
        return 1.0 / (1.0 + z)
    z = np.exp(x)
    return z / (1.0 + z)


def dense_damage_risk(level: float) -> float:
    lvl = float(level)
    if lvl <= TANK_LEVEL_EMPTY or lvl >= TANK_LEVEL_OVERFLOW:
        return 1.0

    high_risk = sigmoid((lvl - TANK_LEVEL_SAFE_HIGH) / 3.5)
    low_risk = sigmoid((TANK_LEVEL_SAFE_LOW - lvl) / 3.5)
    return float(min(1.0, max(0.0, max(high_risk, low_risk))))

def one_hot(val: str, vocab: List[str]) -> List[float]:
    return [1.0 if val == v else 0.0 for v in vocab]

def encode_z(tank: PhysicalTank, attacker_zone: str, u: Dict[str, Any]) -> np.ndarray:
    # x_phys (keep small)
    level = float(tank.level)
    sensor_ok = 1.0 if tank.sensor_ok else 0.0
    interlock = 1.0 if tank.safety_interlock else 0.0

    # x_cyber (coarse)
    zone_vocab = list(ZONES)
    zone_oh = one_hot(attacker_zone, zone_vocab)

    # u
    pump_vocab = ["AUTO", "FORCE_ON", "FORCE_OFF"]
    valve_vocab = ["AUTO", "FORCE_OPEN", "FORCE_CLOSED"]
    pump_u = str(u.get("pump_cmd", tank.pump_cmd))
    valve_u = str(u.get("valve_cmd", tank.valve_cmd))
    pump_oh = one_hot(pump_u, pump_vocab)
    valve_oh = one_hot(valve_u, valve_vocab)

    # Add a small “u intensity” scalar to help GP generalize
    pump_intensity = {TANK_CMD_AUTO: 0.0, TANK_PUMP_FORCE_ON: 1.0, TANK_PUMP_FORCE_OFF: -1.0}.get(pump_u, 0.0)
    valve_intensity = {TANK_CMD_AUTO: 0.0, TANK_VALVE_FORCE_OPEN: -1.0, TANK_VALVE_FORCE_CLOSED: 1.0}.get(valve_u, 0.0)

    z = np.array(
        [level, sensor_ok, interlock]
        + zone_oh
        + pump_oh
        + valve_oh
        + [pump_intensity, valve_intensity],
        dtype=float
    )
    return z

class SimpleRBF_GaussianProcess:
    """
    Minimal GP regression with RBF kernel (pure NumPy) - stable Cholesky implementation.
    """
    def __init__(self, length_scale: float = 20.0, sigma_f: float = 10.0, sigma_n: float = 2.0):
        self.l = float(length_scale)
        self.sigma_f = float(sigma_f)
        self.sigma_n = float(sigma_n)
        self.X: Optional[np.ndarray] = None
        self.y: Optional[np.ndarray] = None
        self.L: Optional[np.ndarray] = None  # Cholesky factor
        self.alpha: Optional[np.ndarray] = None  # Precomputed solution

    def rbf_kernel(self, A: np.ndarray, B: np.ndarray) -> np.ndarray:
        A2 = np.sum(A * A, axis=1, keepdims=True)
        B2 = np.sum(B * B, axis=1, keepdims=True).T
        sqdist = A2 + B2 - 2.0 * (A @ B.T)
        return (self.sigma_f ** 2) * np.exp(-0.5 * sqdist / (self.l ** 2))

    def fit(self, X: np.ndarray, y: np.ndarray):
        self.X = np.asarray(X, dtype=float)
        self.y = np.asarray(y, dtype=float).reshape(-1, 1)
        K = self.rbf_kernel(self.X, self.X)
        K = K + (self.sigma_n ** 2 + 1e-6) * np.eye(K.shape[0])  # Add jitter for stability
        
        # Stable Cholesky decomposition
        self.L = np.linalg.cholesky(K)
        # Precompute solution for efficient prediction
        self.alpha = np.linalg.solve(self.L.T, np.linalg.solve(self.L, self.y))

    def predict(self, X_star: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        if self.X is None or self.L is None or self.alpha is None:
            return np.zeros((X_star.shape[0],)), np.ones((X_star.shape[0],)) * 1e6
        Xs = np.asarray(X_star, dtype=float)
        K_s = self.rbf_kernel(self.X, Xs)   # (N,M)
        mu = (K_s.T @ self.alpha).flatten()
        v = np.linalg.solve(self.L, K_s)
        K_ss = self.rbf_kernel(Xs, Xs)
        var = np.clip(np.diag(K_ss) - np.sum(v * v, axis=0), 1e-9, 1e9)
        return mu, var

@dataclass
class CausalData:
    # Passive vs Interventional datasets
    Z_obs: List[np.ndarray] = field(default_factory=list)
    Y_obs: List[np.ndarray] = field(default_factory=list)   # multi-output vector

    Z_int: List[np.ndarray] = field(default_factory=list)
    Y_int: List[np.ndarray] = field(default_factory=list)

    # buffer for ACE expectation approximation
    X_buffer: List[Dict[str, Any]] = field(default_factory=list)

    def add_sample(self, z: np.ndarray, y_vec: np.ndarray, is_interventional: bool, x_snapshot: Dict[str, Any]):
        if is_interventional:
            self.Z_int.append(z)
            self.Y_int.append(y_vec.astype(float))
        else:
            self.Z_obs.append(z)
            self.Y_obs.append(y_vec.astype(float))

        self.X_buffer.append(x_snapshot)
        if len(self.X_buffer) > CAUSAL_X_BUFFER_MAX:
            self.X_buffer.pop(0)

    def combined(self) -> Tuple[np.ndarray, np.ndarray]:
        Z = self.Z_obs + self.Z_int
        Y = self.Y_obs + self.Y_int
        if len(Z) == 0:
            return np.zeros((0, 1)), np.zeros((0, 3))
        return np.vstack(Z), np.vstack(Y)

class MultiOutputGP:
    """
    Three-headed GP model with input normalization:
    - head0: delta_level (regression)
    - head1: alarm (0/1 target; treat as regression + sigmoid for probability)
    - head2: damage (0/1 target; treat as regression + sigmoid for probability)
    """
    def __init__(self):
        # You can tune noise separately per head
        self.gp_delta = SimpleRBF_GaussianProcess(length_scale=20.0, sigma_f=12.0, sigma_n=3.0)
        self.gp_alarm = SimpleRBF_GaussianProcess(length_scale=25.0, sigma_f=5.0, sigma_n=1.5)
        self.gp_damage = SimpleRBF_GaussianProcess(length_scale=25.0, sigma_f=5.0, sigma_n=1.5)
        self.ready = False
        self.x_mu = None  # Input mean for normalization
        self.x_std = None  # Input std for normalization

    def _norm_x(self, X: np.ndarray) -> np.ndarray:
        """Normalize inputs using stored statistics."""
        if self.x_mu is None or self.x_std is None:
            return X
        return (X - self.x_mu) / self.x_std

    def fit(self, X: np.ndarray, Y: np.ndarray):
        # Lower threshold for earlier interventions - start learning with fewer samples
        if X.shape[0] < max(3, GP_MIN_SAMPLES // 3):
            self.ready = False
            return
        
        # Compute and store normalization statistics
        X = np.asarray(X, dtype=float)
        self.x_mu = X.mean(axis=0, keepdims=True)
        self.x_std = X.std(axis=0, keepdims=True) + 1e-6  # Avoid division by zero
        
        # Fit with normalized inputs
        Xn = self._norm_x(X)
        self.gp_delta.fit(Xn, Y[:, 0])
        self.gp_alarm.fit(Xn, Y[:, 1])
        self.gp_damage.fit(Xn, Y[:, 2])
        self.ready = True

    def predict(self, X_star: np.ndarray) -> Dict[str, Tuple[np.ndarray, np.ndarray]]:
        if not self.ready or self.x_mu is None or self.x_std is None:
            return {
                "delta": (np.zeros(X_star.shape[0]), np.ones(X_star.shape[0]) * 1e6),
                "alarm": (np.zeros(X_star.shape[0]), np.ones(X_star.shape[0]) * 1e6),
                "damage": (np.zeros(X_star.shape[0]), np.ones(X_star.shape[0]) * 1e6),
            }
        
        # Normalize inputs before prediction
        Xn = self._norm_x(np.asarray(X_star, dtype=float))
        mu0, var0 = self.gp_delta.predict(Xn)
        mu1, var1 = self.gp_alarm.predict(Xn)
        mu2, var2 = self.gp_damage.predict(Xn)
        return {
            "delta": (mu0, var0),
            "alarm": (mu1, var1),
            "damage": (mu2, var2),
        }

    def prob_alarm(self, mu_alarm: float) -> float:
        return sigmoid(mu_alarm)

    def prob_damage(self, mu_damage: float) -> float:
        return float(min(1.0, max(0.0, mu_damage)))

def estimate_ace_multi(
    mogp: MultiOutputGP,
    data: CausalData,
    u_from: Dict[str, Any],
    u_to: Dict[str, Any]
) -> Dict[str, Tuple[float, float]]:
    """
    ACE per head:
      ACE_h(u->u') = E_x[ mu_h([x,u']) - mu_h([x,u]) ]
    """
    if not mogp.ready or len(data.X_buffer) == 0:
        return {"delta": (0.0, 0.0), "alarm": (0.0, 0.0), "damage": (0.0, 0.0)}

    Z_from = []
    Z_to = []
    for xs in data.X_buffer:
        tmp_tank = PhysicalTank(
            level=xs["level"],
            pump_cmd=xs.get("pump_cmd", TANK_CMD_AUTO),
            valve_cmd=xs.get("valve_cmd", TANK_CMD_AUTO),
            sensor_ok=xs.get("sensor_ok", True),
            safety_interlock=xs.get("safety_interlock", True),
        )
        zf = encode_z(tmp_tank, xs.get("attacker_zone", ZONE_IT), u_from)
        zt = encode_z(tmp_tank, xs.get("attacker_zone", ZONE_IT), u_to)
        Z_from.append(zf)
        Z_to.append(zt)

    Z_from = np.vstack(Z_from)
    Z_to = np.vstack(Z_to)

    pred_f = mogp.predict(Z_from)
    pred_t = mogp.predict(Z_to)

    out: Dict[str, Tuple[float, float]] = {}
    for head in ("delta", "alarm", "damage"):
        mu_f, var_f = pred_f[head]
        mu_t, var_t = pred_t[head]
        diff = mu_t - mu_f
        ace = float(np.mean(diff))
        ace_std = float(np.sqrt(np.mean(var_f + var_t)))
        out[head] = (ace, ace_std)
    return out

class ActiveInterventionPolicy:
    """
    Chooses an intervention u that is:
    - safe: predicted damage probability <= threshold
    - informative: maximizes predictive variance (information gain proxy)

    Candidates are small, safe "do(u)" probes. You can extend the candidate set.
    """
    def __init__(self, damage_prob_max: float = 0.25):
        self.damage_prob_max = float(damage_prob_max)

        # Safe-ish candidates. (In a real lab, you’d define scenario-specific probe actions.)
        self.candidates = [
            {"name": "AUTO/AUTO", "pump_cmd": TANK_CMD_AUTO, "valve_cmd": TANK_CMD_AUTO},
            {"name": "FORCE_OFF/AUTO", "pump_cmd": TANK_PUMP_FORCE_OFF, "valve_cmd": TANK_CMD_AUTO},
            {"name": "AUTO/FORCE_OPEN", "pump_cmd": TANK_CMD_AUTO, "valve_cmd": TANK_VALVE_FORCE_OPEN},
            {"name": "AUTO/FORCE_CLOSED", "pump_cmd": TANK_CMD_AUTO, "valve_cmd": TANK_VALVE_FORCE_CLOSED},
            {"name": "FORCE_ON/AUTO", "pump_cmd": TANK_PUMP_FORCE_ON, "valve_cmd": TANK_CMD_AUTO},
            {"name": "FORCE_ON/FORCE_CLOSED", "pump_cmd": TANK_PUMP_FORCE_ON, "valve_cmd": TANK_VALVE_FORCE_CLOSED},
        ]

    def _probe_round_counter(self) -> int:
        if not hasattr(self, '_round_ctr'):
            self._round_ctr = 0
        self._round_ctr += 1
        return self._round_ctr

    def select(self, mogp: MultiOutputGP, tank: PhysicalTank, attacker_zone: str) -> Dict[str, Any]:
        """
        Return a u dict (pump_cmd/valve_cmd) to apply as a controlled intervention.
        """
        # If GP not ready, cycle through non-trivial probes round-robin (critical fix!)
        if not mogp.ready:
            ctr = self._probe_round_counter()
            # Skip AUTO/AUTO (index 0) to ensure we get actual interventional data
            c = self.candidates[(ctr % (len(self.candidates) - 1)) + 1]
            return {"pump_cmd": c["pump_cmd"], "valve_cmd": c["valve_cmd"], "name": c["name"]}

        best = None
        best_score = -1.0

        for c in self.candidates:
            u = {"pump_cmd": c["pump_cmd"], "valve_cmd": c["valve_cmd"]}
            z = encode_z(tank, attacker_zone, u).reshape(1, -1)
            pred = mogp.predict(z)
            mu_dmg, var_dmg = pred["damage"]
            mu_alarm, var_alarm = pred["alarm"]
            mu_delta, var_delta = pred["delta"]

            p_damage = mogp.prob_damage(float(mu_dmg[0]))
            sigma_d = float(np.sqrt(max(1e-9, float(var_dmg[0]))))
            p_damage_ucb = float(min(1.0, max(0.0, p_damage + 1.0 * sigma_d)))
            if p_damage_ucb > self.damage_prob_max:
                continue

            # Info-gain proxy with boundary focus: maximize uncertainty near safety threshold.
            boundary_focus = 1.0 - abs(p_damage - self.damage_prob_max)
            score = float(0.55 * var_dmg[0] + 0.25 * var_delta[0] + 0.20 * var_alarm[0] + 0.10 * boundary_focus)

            if score > best_score:
                best_score = score
                best = {"pump_cmd": u["pump_cmd"], "valve_cmd": u["valve_cmd"], "name": c["name"],
                        "p_damage": p_damage,
                        "p_damage_ucb": p_damage_ucb,
                        "mu_delta": float(mu_delta[0]),
                        "p_alarm": mogp.prob_alarm(float(mu_alarm[0])),
                        "score": best_score}

        # Fallback if everything filtered
        return best or {"pump_cmd": TANK_CMD_AUTO, "valve_cmd": TANK_CMD_AUTO, "name": "AUTO/AUTO"}

# ============================================================
# 1C) CPSRange
# ============================================================
class CPSRange:
    """Cyber-physical range state: assets, zones, tank physics, causal/GP state, and history."""

    def __init__(self, seed: int = 7, max_rounds: int = DEFAULT_MAX_ROUNDS) -> None:
        random.seed(seed)
        self.round = 0
        self.max_rounds = max_rounds
        self.attacker_zone = ZONE_IT
        self.tank = PhysicalTank()
        self.zone_links = {
            (ZONE_IT, ZONE_DMZ): True,
            (ZONE_DMZ, ZONE_IT): True,
            (ZONE_DMZ, ZONE_OT): True,
            (ZONE_OT, ZONE_DMZ): True,
            (ZONE_IT, ZONE_OT): False,
            (ZONE_OT, ZONE_IT): False,
        }

        self.assets: Dict[str, Asset] = {
            "gw_dmz_01": Asset(
                asset_id="gw_dmz_01",
                kind="gateway",
                zone="DMZ",
                services={
                    "ssh": Service("ssh", 22, vuln_id=None, exposed=True, weak_creds=True, auth_required=True),
                    "vpn": Service("vpn", 1194, vuln_id="T0887: Remote Services", exposed=True, auth_required=True),
                },
            ),
            "hist_data_01": Asset(
                asset_id="hist_data_01",
                kind="historian",
                zone="DMZ",
                services={
                    "http": Service("http", 80, vuln_id="T0819: Exploit Public-Facing Application", exposed=True, auth_required=False),
                },
            ),
            "hmi_ops_01": Asset(
                asset_id="hmi_ops_01",
                kind="hmi",
                zone="OT",
                services={
                    "rdp": Service("rdp", 3389, vuln_id="T0823: Graphical User Interface", exposed=True, weak_creds=True, auth_required=True),
                },
            ),
            "plc_industrial_01": Asset(
                asset_id="plc_industrial_01",
                kind="plc",
                zone="OT",
                services={
                    "modbus": Service("modbus", 502, vuln_id="T0866: Software Process Out-of-Bounds", exposed=True, auth_required=False),
                    "prog": Service("prog", 44818, vuln_id="T0833: Modify Controller Tasking", exposed=True, auth_required=True),
                },
                notes={"logic_hash": "SAFE_v1"},
            ),
        }

        self.events: List[Dict[str, Any]] = []
        self.alerts: List[Dict[str, Any]] = []
        self.action_log: List[str] = []
        self.red_action_history: List[str] = []
        self.blue_action_history: List[str] = []
        self.blue_sensitivity = 0.55
        self.full_recon_mode = False
        self.recon_max_items = 6

        self.history = {k: [] for k in HISTORY_KEYS}

        # --- causal learning ---
        self.causal = CausalData()
        self.mogp = MultiOutputGP()
        self.policy = ActiveInterventionPolicy(damage_prob_max=DEFAULT_DAMAGE_PROB_MAX)

    def _reachable(self, src_zone: str, dst_zone: str) -> bool:
        if src_zone == dst_zone:
            return True
        return self.zone_links.get((src_zone, dst_zone), False)

    def _emit_event(self, etype: str, details: Dict[str, Any]):
        self.events.append({"t": time.time(), "round": self.round, "type": etype, **details})

    def _maybe_alert(self, severity: str, reason: str, details: Dict[str, Any]) -> None:
        base = SEVERITY_ALERT_BASE.get(severity, 0.5)
        p = min(ALERT_PROB_CAP, base * (0.75 + self.blue_sensitivity))
        if random.random() < p:
            self.alerts.append({"round": self.round, "severity": severity, "reason": reason, **details})

    def add_alert(self, **kwargs) -> None:
        """Add an alert to the alerts list (for LPR integration)."""
        self.alerts.append({"round": self.round, **kwargs})

    def summarize_state_for_llm(self) -> Dict[str, Any]:
        def asset_view(a: Asset) -> Dict[str, Any]:
            return {
                "kind": a.kind,
                "zone": a.zone,
                "compromised": a.compromised,
                "privilege": a.privilege,
                "isolated": a.isolated,
                "hardened": a.hardened,
                "ip": a.notes.get("ip"),
                "services": {
                    sname: {
                        "port": svc.port,
                        "exposed": svc.exposed,
                        "patched": svc.patched,
                        "weak_creds": svc.weak_creds,
                        "auth_required": svc.auth_required,
                        "vuln_id": svc.vuln_id,
                    }
                    for sname, svc in a.services.items()
                },
                "notes": a.notes,
            }

        # Calculate zone control status
        zone_control = {}
        for zone in [ZONE_IT, ZONE_DMZ, ZONE_OT]:
            assets_in_zone = [a for a in self.assets.values() if a.zone == zone]
            compromised_in_zone = [a for a in assets_in_zone if a.compromised]
            admin_in_zone = [a for a in compromised_in_zone if a.privilege == "ADMIN"]
            zone_control[zone] = {
                "total": len(assets_in_zone),
                "compromised": len(compromised_in_zone),
                "admin": len(admin_in_zone),
                "controlled": len(compromised_in_zone) > 0,
                "admin_controlled": len(admin_in_zone) > 0
            }

        # Kill-chain progress summary
        compromised = [a.asset_id for a in self.assets.values() if a.compromised]
        dmz_admin = [a.asset_id for a in self.assets.values() if a.compromised and a.privilege == "ADMIN" and a.zone == ZONE_DMZ]
        ot_compromised = [a.asset_id for a in self.assets.values() if a.compromised and a.zone == ZONE_OT]
        plc = self.assets.get(PLC_ASSET_ID)
        
        kill_chain = {
            "current_zone": self.attacker_zone,
            "compromised_assets": compromised,
            "dmz_admin_assets": dmz_admin,
            "ot_compromised_assets": ot_compromised,
            "plc_compromised": plc.compromised if plc else False,
            "plc_admin": plc.privilege == "ADMIN" if plc else False,
            "can_reach_ot": self._reachable(self.attacker_zone, ZONE_OT),
            "can_reach_dmz": self._reachable(self.attacker_zone, ZONE_DMZ),
        }

        # Recent action history for context
        recent_red = self.red_action_history[-5:] if hasattr(self, 'red_action_history') else []
        recent_blue = self.blue_action_history[-5:] if hasattr(self, 'blue_action_history') else []

        return {
            "round": self.round,
            "attacker_zone": self.attacker_zone,
            "zone_control": zone_control,
            "kill_chain": kill_chain,
            "tank": {
                "level": round(self.tank.level, 1),
                "pump_cmd": self.tank.pump_cmd,
                "valve_cmd": self.tank.valve_cmd,
                "sensor_ok": self.tank.sensor_ok,
                "safety_interlock": self.tank.safety_interlock,
                "alarm": self.tank.alarm,
                "damage": self.tank.damage,
                "unsafe": self.tank.level < 20.0 or self.tank.level > 85.0 or self.tank.damage > 0.5,
            },
            "assets": {aid: asset_view(a) for aid, a in self.assets.items()},
            "last_alerts": self.alerts[-3:],
            "last_events": self.events[-3:],
            "recent_red_actions": recent_red,
            "recent_blue_actions": recent_blue,
            "blue_sensitivity": getattr(self, 'blue_sensitivity', 1.0),
        }

    def random_action(self, role: str) -> Dict[str, Any]:
        r = str(role or "").upper()
        if r == "RED":
            action = random.choice(sorted(list(ALLOWED_ACTIONS_RED)))

            if action in ("RECON", "COVER", "PHISH"):
                return {"action": action, "target": "NONE", "service": "NONE", "params": {}}

            compromised = [a.asset_id for a in self.assets.values() if a.compromised]
            reachable: List[Tuple[str, str]] = []
            for aid, asset in self.assets.items():
                if asset.isolated:
                    continue
                if not self._reachable(self.attacker_zone, asset.zone):
                    continue
                for sname, svc in asset.services.items():
                    if svc.exposed:
                        reachable.append((aid, sname))

            if action in ("BRUTE", "EXPLOIT"):
                if reachable:
                    t, s = random.choice(reachable)
                    return {"action": action, "target": t, "service": s, "params": {}}
                return {"action": "RECON", "target": "NONE", "service": "NONE", "params": {}}

            if action in ("PIVOT", "EXECUTE"):
                if compromised:
                    return {"action": action, "target": random.choice(compromised), "service": "NONE", "params": {}}
                return {"action": "RECON", "target": "NONE", "service": "NONE", "params": {}}

            if action == "IMPACT":
                plc = self.assets.get(PLC_ASSET_ID)
                if plc and plc.compromised and plc.privilege == "ADMIN":
                    mode = random.choice(["OVERFLOW", "DRAIN", "SENSOR_SPOOF"])
                    return {"action": "IMPACT", "target": PLC_ASSET_ID, "service": "NONE", "params": {"mode": mode}}
                if compromised:
                    return {"action": "EXECUTE", "target": random.choice(compromised), "service": "NONE", "params": {}}
                return {"action": "RECON", "target": "NONE", "service": "NONE", "params": {}}

            return {"action": "RECON", "target": "NONE", "service": "NONE", "params": {}}

        # BLUE fallback
        action = random.choice(sorted(list(ALLOWED_ACTIONS_BLUE)))
        if action in ("MONITOR",):
            return {"action": action, "target": "NONE", "service": "NONE", "params": {}}
        if action == "TUNE":
            sens = float(np.clip(self.blue_sensitivity + random.uniform(-0.12, 0.12), BLUE_SENSITIVITY_MIN, BLUE_SENSITIVITY_MAX))
            return {"action": "TUNE", "target": "NONE", "service": "NONE", "params": {"sensitivity": sens}}

        aid = random.choice(list(self.assets.keys()))
        if action == "PATCH":
            svc_names = list(self.assets[aid].services.keys())
            if svc_names and random.random() < 0.7:
                return {"action": "PATCH", "target": aid, "service": random.choice(svc_names), "params": {}}
        return {"action": action, "target": aid, "service": "NONE", "params": {}}

    def execute_action(self, actor: str, action: Dict[str, Any]) -> str:
        a = str(action.get("action", "MONITOR")).upper()
        target = action.get("target", "NONE")
        service = action.get("service", "NONE")
        params = action.get("params", {}) or {}

        if isinstance(target, (list, tuple)):
            target = target[0] if target else "NONE"
        target = str(target) if target is not None else "NONE"
        service = str(service) if service is not None else "NONE"

        if target != "NONE" and target not in self.assets:
            msg = f"IGNORE: invalid target {target}"
            self.action_log.append(f"{actor}: {a} {target}/{service} -> {msg}")
            return msg

        if actor == "RED":
            self.red_action_history.append(a)
            if len(self.red_action_history) > 12:
                self.red_action_history.pop(0)
            res = self._red_step(a, target, service, params)
        else:
            # Track BLUE action history
            self.blue_action_history.append(a)
            if len(self.blue_action_history) > 12:
                self.blue_action_history.pop(0)
            res = self._blue_step(a, target, service, params)

        self.action_log.append(f"{actor}: {a} {target}/{service} -> {res}")
        return res

    # --- RED actions (unchanged logic) ---
    def _red_step(self, a: str, target: str, service: str, params: Dict[str, Any]) -> str:
        if a == "RECON":
            visible = []
            for aid, asset in self.assets.items():
                if asset.isolated:
                    continue
                if not self._reachable(self.attacker_zone, asset.zone):
                    continue
                for sname, svc in asset.services.items():
                    if svc.exposed or self.full_recon_mode:
                        vis = "public" if svc.exposed else "internal"
                        tool = RED_ATTACK_CATALOG.get("RECON", {}).get("tool", "scanner")
                        visible.append((aid, sname, svc.port, asset.notes.get("ip"), vis, tool))

            out_cap = FULL_RECON_MAX_ITEMS if self.full_recon_mode else self.recon_max_items
            self._emit_event("recon", {"actor": "RED", "visible": visible[:max(10, out_cap)]})
            self._maybe_alert(SEVERITY_LOW, "Network scanning behavior", {"actor": "RED"})
            clipped = visible[:out_cap]
            truncated = (len(visible) > out_cap) and (not self.full_recon_mode)
            return f"RECON_OK: {clipped}{'...' if truncated else ''}"

        if a == "COVER":
            self.blue_sensitivity = max(BLUE_SENSITIVITY_MIN, self.blue_sensitivity - 0.08)
            self._emit_event("cover", {"actor": "RED"})
            return "COVER_OK: reduced blue sensitivity slightly"

        if target == "NONE":
            return "NOOP: target required"

        asset = self.assets[target]
        if asset.isolated:
            self._emit_event("blocked", {"actor": "RED", "target": target, "reason": "isolated"})
            return "BLOCKED: target isolated"

        if not self._reachable(self.attacker_zone, asset.zone):
            self._emit_event("blocked", {"actor": "RED", "target": target, "reason": "unreachable"})
            return f"BLOCKED: cannot reach {asset.zone} from {self.attacker_zone}"

        svc = None
        if service != "NONE":
            svc = asset.services.get(service)
            if not svc:
                return "IGNORE: invalid service"
            if not svc.exposed:
                return "BLOCKED: service not exposed"
            if svc.patched:
                self._emit_event("exploit_fail", {"actor": "RED", "target": target, "service": service, "reason": "patched"})
                self._maybe_alert(SEVERITY_MED, "Exploit attempt (patched)", {"target": target, "service": service})
                return "FAIL: patched"

        if a == "BRUTE":
            if not svc or not svc.auth_required:
                return "FAIL: service w/ auth required"
            if svc.weak_creds and not asset.hardened:
                asset.compromised = True
                asset.privilege = "USER"
                self._emit_event("compromise", {"actor": "RED", "target": target, "via": f"weak_creds:{service}"})
                self._maybe_alert(SEVERITY_HIGH, "Credential attack succeeded", {"target": target, "service": service})
                return "SUCCESS: USER access via weak creds"
            self._emit_event("brute_fail", {"actor": "RED", "target": target, "service": service})
            self._maybe_alert(SEVERITY_MED, "Bruteforce attempt", {"target": target, "service": service})
            return "FAIL: creds resisted"

        if a == "EXPLOIT":
            if not svc:
                return "FAIL: service required"
            if asset.hardened:
                self._emit_event("exploit_fail", {"actor": "RED", "target": target, "service": service, "reason": "hardened"})
                self._maybe_alert(SEVERITY_MED, "Exploit blocked by hardening", {"target": target, "service": service})
                return "BLOCKED: hardened"
            if svc.vuln_id is None:
                return "FAIL: no vuln modeled"
            base = 0.65 if asset.zone in (ZONE_IT, ZONE_DMZ) else 0.45
            if random.random() < base:
                asset.compromised = True
                asset.privilege = "USER"
                self._emit_event("compromise", {"actor": "RED", "target": target, "via": svc.vuln_id})
                self._maybe_alert(SEVERITY_HIGH, "Service exploitation succeeded", {"target": target, "service": service, "vuln": svc.vuln_id})
                return f"SUCCESS: USER access via {svc.vuln_id}"
            self._emit_event("exploit_fail", {"actor": "RED", "target": target, "service": service, "reason": "random_fail"})
            self._maybe_alert(SEVERITY_MED, "Exploit attempt failed", {"target": target, "service": service})
            return "FAIL: exploit did not land"

        if a == "PIVOT":
            if not asset.compromised:
                return "FAIL: need foothold"
            if asset.zone == ZONE_DMZ:
                self.attacker_zone = ZONE_DMZ
                self._emit_event("pivot", {"actor": "RED", "to_zone": ZONE_DMZ, "via": target})
                self._maybe_alert(SEVERITY_HIGH, "Suspicious lateral movement", {"via": target, "to_zone": ZONE_DMZ})
                return "PIVOT_OK: attacker now in DMZ"
            if asset.zone == ZONE_OT:
                self.attacker_zone = ZONE_OT
                self._emit_event("pivot", {"actor": "RED", "to_zone": ZONE_OT, "via": target})
                self._maybe_alert(SEVERITY_CRIT, "OT lateral movement detected", {"via": target, "to_zone": ZONE_OT})
                return "PIVOT_OK: attacker now in OT"
            return "NOOP: pivot not meaningful"

        if a == "EXECUTE":
            if not asset.compromised:
                return "FAIL: no access"
            if asset.privilege == "ADMIN":
                return "NOOP: already ADMIN"
            base = 0.65 if not asset.hardened else 0.35
            if random.random() < base:
                asset.privilege = "ADMIN"
                self._emit_event("privesc", {"actor": "RED", "target": target})
                self._maybe_alert(SEVERITY_HIGH, "Privilege escalation", {"target": target})
                return "SUCCESS: privilege escalated to ADMIN"
            self._emit_event("privesc_fail", {"actor": "RED", "target": target})
            self._maybe_alert(SEVERITY_MED, "Privilege escalation attempt", {"target": target})
            return "FAIL: privesc failed"

        if a == "IMPACT":
            if target != PLC_ASSET_ID:
                return "FAIL: impact only modeled on plc_industrial_01"
            plc = asset
            if (not plc.compromised) or plc.privilege != "ADMIN":
                return "FAIL: need PLC ADMIN"
            mode = str(params.get("mode", "OVERFLOW")).upper()
            if mode == "OVERFLOW":
                self.tank.pump_cmd = TANK_PUMP_FORCE_ON
                self.tank.valve_cmd = TANK_VALVE_FORCE_CLOSED
                plc.notes["logic_hash"] = "MAL_OVERFLOW_v1"
                self._emit_event("impact", {"actor": "RED", "mode": "OVERFLOW"})
                self._maybe_alert(SEVERITY_CRIT, "Controller logic modified", {"target": target, "mode": "OVERFLOW"})
                return "CRITICAL: PLC logic -> pump FORCE_ON, valve FORCE_CLOSED"
            if mode == "DRAIN":
                self.tank.pump_cmd = TANK_PUMP_FORCE_OFF
                self.tank.valve_cmd = TANK_VALVE_FORCE_OPEN
                plc.notes["logic_hash"] = "MAL_DRAIN_v1"
                self._emit_event("impact", {"actor": "RED", "mode": "DRAIN"})
                self._maybe_alert(SEVERITY_CRIT, "Controller logic modified", {"target": target, "mode": "DRAIN"})
                return "CRITICAL: PLC logic -> pump FORCE_OFF, valve FORCE_OPEN"
            if mode == "SENSOR_SPOOF":
                self.tank.sensor_ok = False
                self._emit_event("impact", {"actor": "RED", "mode": "SENSOR_SPOOF"})
                self._maybe_alert(SEVERITY_HIGH, "Sensor integrity anomaly", {"mode": "SENSOR_SPOOF"})
                return "IMPACT: sensor spoofed"
            return "FAIL: unknown impact mode"

        if a == "PHISH":
            self._emit_event("phish", {"actor": "RED"})
            self._maybe_alert(SEVERITY_LOW, "Phishing indicators", {"actor": "RED"})
            return "PHISH_SENT: symbolic"

        return "NOOP/UNKNOWN_RED_ACTION"

    # --- BLUE actions + optional controlled intervention probes ---
    def _blue_step(self, a: str, target: str, service: str, params: Dict[str, Any]) -> str:
        if a == "MONITOR":
            recent = self.events[-5:]
            summary = [e["type"] for e in recent]
            self.blue_sensitivity = min(BLUE_SENSITIVITY_MAX, self.blue_sensitivity + 0.03)
            return f"MONITOR_OK: recent_events={summary}, alerts={len(self.alerts)}"

        if a == "TUNE":
            s = params.get("sensitivity")
            if isinstance(s, (int, float)):
                self.blue_sensitivity = max(BLUE_SENSITIVITY_MIN, min(BLUE_SENSITIVITY_MAX, float(s)))
                return f"TUNE_OK: blue_sensitivity={self.blue_sensitivity:.2f}"
            return "FAIL: provide params.sensitivity (0..1)"

        if target == "NONE":
            return "NOOP: target required"

        asset = self.assets[target]

        if a == "ISOLATE":
            asset.isolated = True
            self._emit_event("isolate", {"actor": "BLUE", "target": target})
            return "DEFENSE: asset isolated"

        if a == "PATCH":
            if service == "NONE":
                for svc in asset.services.values():
                    svc.patched = True
                self._emit_event("patch", {"actor": "BLUE", "target": target, "service": "ALL"})
                return "DEFENSE: patched ALL services"
            svc = asset.services.get(service)
            if not svc:
                return "FAIL: invalid service"
            svc.patched = True
            self._emit_event("patch", {"actor": "BLUE", "target": target, "service": service})
            return f"DEFENSE: patched {service}"

        if a == "HARDEN":
            asset.hardened = True
            for svc in asset.services.values():
                if svc.weak_creds:
                    svc.weak_creds = False
            self._emit_event("harden", {"actor": "BLUE", "target": target})
            return "DEFENSE: hardening applied"

        if a == "RESTORE":
            if asset.kind == "plc":
                asset.compromised = False
                asset.privilege = "NONE"
                asset.notes["logic_hash"] = "SAFE_v1"
                self.tank.pump_cmd = TANK_CMD_AUTO
                self.tank.valve_cmd = TANK_CMD_AUTO
                self.tank.sensor_ok = True
                self.tank.alarm = None
                self._emit_event("restore", {"actor": "BLUE", "target": target, "scope": "plc_logic"})
                return "DEFENSE: PLC restored to SAFE logic"
            asset.compromised = False
            asset.privilege = "NONE"
            self._emit_event("restore", {"actor": "BLUE", "target": target, "scope": "host"})
            return "DEFENSE: host restored"

        return "NOOP/UNKNOWN_BLUE_ACTION"

    def update_physics(self) -> str:
        self.tank.alarm = None
        pump = self.tank.pump_cmd
        valve = self.tank.valve_cmd

        # Safety interlock
        if self.tank.safety_interlock and pump == TANK_PUMP_FORCE_ON and self.tank.level > TANK_LEVEL_INTERLOCK_ABOVE:
            pump = TANK_CMD_AUTO
            self._emit_event("safety", {"event": "interlock_trip", "level": self.tank.level})

        if pump == TANK_CMD_AUTO and valve == TANK_CMD_AUTO:
            self.tank.level += random.uniform(-1.5, 1.5)
            if self.tank.level < TANK_LEVEL_SETPOINT_LO:
                self.tank.level += 1.2
            elif self.tank.level > TANK_LEVEL_SETPOINT_HI:
                self.tank.level -= 1.2
        else:
            if pump == TANK_PUMP_FORCE_ON:
                self.tank.level += 12.0
            elif pump == TANK_PUMP_FORCE_OFF:
                self.tank.level -= 2.0
            if valve == TANK_VALVE_FORCE_OPEN:
                self.tank.level -= 10.0
            elif valve == TANK_VALVE_FORCE_CLOSED:
                self.tank.level += 1.0

        self.tank.level = max(0.0, min(100.0, self.tank.level))

        if self.tank.level >= TANK_LEVEL_OVERFLOW:
            self.tank.alarm = "ALARM: TANK OVERFLOW"
            self.tank.damage = True
        elif self.tank.level <= TANK_LEVEL_EMPTY:
            self.tank.alarm = "ALARM: TANK EMPTY (CAVITATION RISK)"
            self.tank.damage = True
        elif self.tank.level >= TANK_LEVEL_SAFE_HIGH:
            self.tank.alarm = "WARN: High level"
        elif self.tank.level <= TANK_LEVEL_SAFE_LOW:
            self.tank.alarm = "WARN: Low level"

        return (
            f"PHYS: level={self.tank.level:.1f}% "
            f"pump={self.tank.pump_cmd} valve={self.tank.valve_cmd} alarm={self.tank.alarm}"
        )

    def scenario_done(self) -> Tuple[bool, str]:
        if self.tank.damage:
            return True, "END: physical damage condition reached"
        if self.round >= self.max_rounds:
            return True, "END: max rounds reached"
        return False, "RUNNING"

    def record_history(self, gp_p_alarm: float = 0.0, gp_p_damage: float = 0.0, policy_choice: str = ""):
        self.history["round"].append(self.round)
        self.history["tank_level"].append(self.tank.level)
        self.history["alerts_total"].append(len(self.alerts))
        self.history["compromised_count"].append(sum(1 for a in self.assets.values() if a.compromised))
        self.history["attacker_zone"].append(self.attacker_zone)
        self.history["alarm_flag"].append(1.0 if self.tank.alarm else 0.0)
        self.history["damage_flag"].append(1.0 if self.tank.damage else 0.0)
        self.history["gp_p_alarm"].append(gp_p_alarm)
        self.history["gp_p_damage"].append(gp_p_damage)
        self.history["policy_choice"].append(policy_choice)


# ============================================================
# 2) LLM AGENTS (STRICT JSON + ROBUST NORMALIZATION)
# ============================================================
ALLOWED_ACTIONS_RED = ACTIONS_RED  # alias
ALLOWED_ACTIONS_BLUE = ACTIONS_BLUE  # alias

def safe_json_extract(text: str) -> Optional[Dict[str, Any]]:
    """Extract and parse the first JSON object from LLM output; returns None on failure."""
    text = (text or "").strip()
    if not text:
        return None

    if "{" in text and "}" in text:
        text = text[text.find("{"): text.rfind("}") + 1]
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
        return None
    except Exception:
        return None

def _normalize_scalar(x: Any, default: str = "NONE") -> str:
    if x is None:
        return default
    if isinstance(x, (list, tuple)):
        if len(x) == 0:
            return default
        return _normalize_scalar(x[0], default=default)
    if isinstance(x, dict):
        for k in ("name", "id", "target", "service", "value"):
            if k in x:
                return _normalize_scalar(x[k], default=default)
        return default
    s = str(x).strip()
    return s if s else default

def _normalize_params(x: Any) -> Dict[str, Any]:
    if isinstance(x, dict):
        return x
    return {}

def validate_action(role: str, env: CPSRange, act: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize and validate RED/BLUE action; return a safe action dict."""
    if not isinstance(act, dict):
        act = {}
    action = _normalize_scalar(act.get("action", "MONITOR"), default="MONITOR").upper()
    target = _normalize_scalar(act.get("target", "NONE"), default="NONE")
    service = _normalize_scalar(act.get("service", "NONE"), default="NONE")
    params = _normalize_params(act.get("params", {}))

    allowed = ALLOWED_ACTIONS_RED if role == "RED" else ALLOWED_ACTIONS_BLUE
    if action not in allowed:
        fallback = env.random_action(role)
        action = _normalize_scalar(fallback.get("action", "RECON" if role == "RED" else "MONITOR")).upper()
        target = _normalize_scalar(fallback.get("target", "NONE"), default="NONE")
        service = _normalize_scalar(fallback.get("service", "NONE"), default="NONE")
        params = _normalize_params(fallback.get("params", {}))

    if target != "NONE" and target not in env.assets:
        target, service = "NONE", "NONE"

    if role == "RED":
        # Prevent endless RECON loops and NOOP actions
        recent = env.red_action_history[-3:]
        if len(recent) == 3 and all(a == "RECON" for a in recent) and action == "RECON":
            footholds = [a for a in env.assets.values() if a.compromised]
            if any(a.zone == ZONE_DMZ for a in footholds):
                action = "PIVOT"
            elif footholds:
                action = "EXECUTE"
            else:
                action = random.choice(["BRUTE", "EXPLOIT", "PHISH"])  # more aggressive than endless recon

        # Prevent PHISH without target (common LLM mistake)
        if action == "PHISH" and target == "NONE":
            # PHISH should target users in compromised zones
            compromised = [a.asset_id for a in env.assets.values() if a.compromised]
            if compromised:
                target = random.choice(compromised)
            else:
                action = "RECON"  # fallback to RECON if no footholds

        # Smart target selection for BRUTE/EXPLOIT
        if action in ("BRUTE", "EXPLOIT") and target == "NONE":
            reachable: List[Tuple[str, str]] = []
            for aid, asset in env.assets.items():
                if asset.isolated:
                    continue
                if not env._reachable(env.attacker_zone, asset.zone):
                    continue
                for sname, svc in asset.services.items():
                    if not svc.exposed:
                        continue
                    if action == "BRUTE" and not svc.auth_required:
                        continue
                    # Prioritize high-value targets
                    priority = 1
                    if asset.zone == ZONE_DMZ and asset.kind in ("gateway", "historian"):
                        priority = 3
                    elif asset.zone == ZONE_OT and asset.kind in ("hmi", "plc"):
                        priority = 2
                    reachable.append((aid, sname, priority))
            if reachable:
                # Sort by priority and pick highest
                reachable.sort(key=lambda x: x[2], reverse=True)
                target, service, _ = reachable[0]

        # Smart PIVOT: prefer moving to new zones
        if action == "PIVOT" and target == "NONE":
            compromised = [a.asset_id for a in env.assets.values() if a.compromised]
            if compromised:
                # Prefer pivoting to zones we haven't reached yet
                current_zone = env.attacker_zone
                zone_order = [ZONE_IT, ZONE_DMZ, ZONE_OT]
                target_zones = [z for z in zone_order if z != current_zone]
                for target_zone in target_zones:
                    zone_assets = [a for a in compromised if a.zone == target_zone]
                    if zone_assets:
                        target = random.choice(zone_assets)
                        break
                else:
                    target = random.choice(compromised)

        # Smart EXECUTE: prioritize non-ADMIN compromised assets
        if action == "EXECUTE" and target == "NONE":
            compromised = [a for a in env.assets.values() if a.compromised and a.privilege != "ADMIN"]
            if compromised:
                target = random.choice(compromised)
            else:
                # Fallback to any compromised asset
                all_comp = [a.asset_id for a in env.assets.values() if a.compromised]
                if all_comp:
                    target = random.choice(all_comp)

    # BLUE agent improvements
    if role == "BLUE":
        # Force reactive behavior when alerts are high or assets compromised
        alert_count = len(getattr(env, 'alerts', []))
        compromised_count = len([a for a in env.assets.values() if a.compromised])
        
        # Override to defensive actions when situation is critical
        if action == "MONITOR" and (alert_count >= 10 or compromised_count >= 2):
            if compromised_count >= 3:
                action = "RESTORE"  # High priority: restore compromised assets
            elif alert_count >= 20:
                action = "ISOLATE"  # Medium priority: isolate to stop spread
            else:
                action = "PATCH"    # Low priority: patch vulnerabilities
        
        # Smart PATCH: prioritize unpatched vulnerabilities on critical assets
        if action == "PATCH" and target == "NONE":
            candidates = []
            for aid, asset in env.assets.items():
                if asset.isolated:
                    continue
                for sname, svc in asset.services.items():
                    if not svc.patched and svc.vuln_id:
                        priority = 2
                        if aid == PLC_ASSET_ID:
                            priority = 3
                        elif asset.zone == ZONE_OT:
                            priority = 2
                        candidates.append((aid, sname, priority))
            if candidates:
                candidates.sort(key=lambda x: x[2], reverse=True)
                target, service, _ = candidates[0]

        # Smart ISOLATE: isolate gateways when attacker in OT
        if action == "ISOLATE" and target == "NONE":
            if env.attacker_zone == ZONE_OT:
                for aid, asset in env.assets.items():
                    if asset.kind == "gateway" and not asset.isolated:
                        target = aid
                        break

        # Smart RESTORE: prioritize PLC, then OT assets, then others
        if action == "RESTORE" and target == "NONE":
            compromised = [a for a in env.assets.values() if a.compromised]
            if compromised:
                # Priority: PLC > OT > DMZ > IT
                plc = [a.asset_id for a in compromised if a.asset_id == PLC_ASSET_ID]
                ot = [a.asset_id for a in compromised if a.zone == ZONE_OT and a.asset_id != PLC_ASSET_ID]
                dmz = [a.asset_id for a in compromised if a.zone == ZONE_DMZ]
                it = [a.asset_id for a in compromised if a.zone == ZONE_IT]
                for priority_list in [plc, ot, dmz, it]:
                    if priority_list:
                        target = random.choice(priority_list)
                        break

    if target != "NONE" and service != "NONE":
        if service not in env.assets[target].services:
            service = "NONE"

    if role == "RED" and action == "IMPACT":
        target = PLC_ASSET_ID
        mode = _normalize_scalar(params.get("mode", "OVERFLOW"), default="OVERFLOW").upper()
        params["mode"] = mode

    if role == "BLUE" and action == "PATCH" and target == "NONE":
        action = "MONITOR"

    return {"action": action, "target": target, "service": service, "params": params}

class LLMControlAgent:
    """LLM-driven RED or BLUE agent that outputs strict JSON actions for the range."""

    def __init__(self, role: str, goal: str, model: str) -> None:
        self.role = role
        self.goal = goal
        self.model = model
        self.failure_count = 0
        self.last_action = None

    def decide(self, env: CPSRange) -> Dict[str, Any]:
        state = env.summarize_state_for_llm()
        allowed = sorted(list(ALLOWED_ACTIONS_RED if self.role == "RED" else ALLOWED_ACTIONS_BLUE))
        assets = list(state["assets"].keys())
        
        # Build kill-chain context for RED
        red_context = ""
        if self.role == "RED":
            compromised = [aid for aid, a in env.assets.items() if a.compromised]
            dmz_admin = [aid for aid, a in env.assets.items() if a.compromised and a.privilege == "ADMIN" and a.zone == ZONE_DMZ]
            ot_compromised = [aid for aid, a in env.assets.items() if a.compromised and a.zone == ZONE_OT]
            plc = env.assets.get(PLC_ASSET_ID)
            
            red_context = f"""
KILL-CHAIN STATUS:
- Current zone: {env.attacker_zone}
- Compromised assets: {compromised}
- DMZ ADMIN assets: {dmz_admin}
- OT compromised assets: {ot_compromised}
- PLC compromised: {plc.compromised if plc else False}
- PLC ADMIN: {plc.privilege == "ADMIN" if plc else False}

PHASE GUIDANCE:
- Early rounds (1-3): RECON to map network
- DMZ phase (4-12): EXPLOIT/BRUTE DMZ assets (gw_dmz_01, hist_data_01)
- Privilege escalation (13-18): EXECUTE for ADMIN on compromised DMZ assets
- Pivot to DMZ (19-22): PIVOT once you have DMZ ADMIN
- OT phase (23-35): EXPLOIT/BRUTE OT assets (hmi_ops_01) from DMZ
- OT escalation (36-45): EXECUTE for OT ADMIN
- PLC phase (46-55): EXPLOIT/EXECUTE PLC (plc_industrial_01)
- IMPACT phase (56+): IMPACT with modes SENSOR_SPOOF/OVERFLOW/DRAIN
- Every ~5 rounds: COVER to degrade blue sensitivity

REACHABLE SERVICES FROM {env.attacker_zone}:
"""
            for aid, asset in env.assets.items():
                if asset.isolated or not env._reachable(env.attacker_zone, asset.zone):
                    continue
                for sname, svc in asset.services.items():
                    if svc.exposed:
                        red_context += f"- {aid}:{sname} (port {svc.port})"
                        if svc.vuln_id:
                            red_context += f" [VULN: {svc.vuln_id}]"
                        if svc.weak_creds:
                            red_context += " [WEAK_CREDS]"
                        red_context += "\n"

        # Build defensive context for BLUE
        blue_context = ""
        if self.role == "BLUE":
            compromised = [aid for aid, a in env.assets.items() if a.compromised]
            alerts = len(env.alerts)
            blue_context = f"""
DEFENSIVE STATUS:
- Compromised assets: {compromised}
- Total alerts: {alerts}
- Attacker zone: {env.attacker_zone}
- Blue sensitivity: {env.blue_sensitivity:.2f}

DEFENSE PRIORITIES:
1. RESTORE compromised PLC (plc_industrial_01) immediately if compromised
2. ISOLATE gateway (gw_dmz_01) if attacker in OT zone
3. RESTORE other compromised OT assets (hmi_ops_01)
4. PATCH unpatched services on critical assets
5. HARDEN critical assets periodically
6. TUNE sensitivity up when alerts accumulate
7. MONITOR when no immediate threats

REACHABLE SERVICES:
"""
            for aid, asset in env.assets.items():
                for sname, svc in asset.services.items():
                    if not svc.patched and svc.vuln_id:
                        blue_context += f"- {aid}:{sname} [UNPATCHED VULN: {svc.vuln_id}]\n"

        prompt = f"""You are an expert {self.role} agent in a SAFE educational cyber range SIMULATOR.
Output ONLY strict JSON object. No markdown, no comments, no explanations.

ROLE={self.role}
GOAL={self.goal}
ROUND={env.round}
ALLOWED_ACTIONS={allowed}
ASSETS={assets}

{red_context if self.role == "RED" else blue_context}

CURRENT STATE:
{json.dumps(state, ensure_ascii=False)}

RESPONSE SCHEMA:
{{
  "action": "<one of {allowed}>",
  "target": "<asset id or NONE>",
  "service": "<service name or NONE>",
  "params": {{}}
}}

CRITICAL: Choose a VALID and REACHABLE target. Avoid NOOP actions. Be strategic and follow the kill-chain/defense priorities above.
"""
        try:
            response = ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = response["message"]["content"]
            parsed = safe_json_extract(raw) or {}
        except Exception as e:
            _log_warn(f"LLM {self.role} call failed: {e}")
            parsed = {}
        
        action = validate_action(self.role, env, parsed)
        
        # Detect failures and NOOP loops
        if (action.get("action") == "RECON" and self.role == "RED" and 
            self.last_action and self.last_action.get("action") == "RECON"):
            self.failure_count += 1
        elif (action.get("action") in ("PHISH", "BRUTE", "EXPLOIT") and 
              action.get("target") == "NONE"):
            self.failure_count += 1
        elif (action.get("action") == "MONITOR" and self.role == "BLUE" and 
              len([a for a in env.assets.values() if a.compromised]) > 2):
            self.failure_count += 1
        else:
            self.failure_count = 0
            
        self.last_action = action.copy()
        
        # Fallback to scripted behavior after too many failures
        if self.failure_count >= 3:
            _log_warn(f"LLM {self.role} failed {self.failure_count} times, using fallback")
            if self.role == "RED":
                action = _choose_killchain_red_action(env)
            else:
                action = _choose_reactive_blue_action(env)
            self.failure_count = 0  # reset after fallback
            
        return action


# ============================================================
# 3) DOCKER HELPERS
# ============================================================
def find_docker_cli() -> Optional[str]:
    docker_cli = shutil.which("docker")
    if docker_cli:
        return docker_cli
    if platform.system().lower().startswith("win"):
        candidates = [
            r"C:\Program Files\Docker\Docker\resources\bin\docker.exe",
            r"C:\ProgramData\DockerDesktop\version-bin\docker.exe",
        ]
        for p in candidates:
            if os.path.exists(p):
                return p
    return None

class DockerRange:
    """Docker API wrapper for container IPs, health checks, and marker/PLC state sync."""

    def __init__(self) -> None:
        self.client = docker.from_env()

    def get_container_ip(self, name: str, network: str) -> str:
        c = self.client.containers.get(name)
        nets = c.attrs["NetworkSettings"]["Networks"]
        if network in nets:
            return nets[network].get("IPAddress", "") or ""
        for _, meta in nets.items():
            ip = meta.get("IPAddress", "")
            if ip:
                return ip
        return ""

    def container_status(self, name: str) -> Tuple[str, str, bool]:
        """Return (runtime_state, health_state, ready_flag)."""
        try:
            c = self.client.containers.get(name)
            c.reload()
            state_obj = c.attrs.get("State", {}) or {}
            runtime = str(state_obj.get("Status", "unknown")).lower()
            health = str((state_obj.get("Health") or {}).get("Status", "none")).lower()
            ready = (health == "healthy") or (runtime == "running" and health in ("none", "unknown"))
            return runtime, health, bool(ready)
        except Exception:
            return "missing", "unknown", False

    def wait_healthy(self, name: str, timeout_s: int = 60) -> bool:
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            c = self.client.containers.get(name)
            state = c.attrs.get("State", {}) or {}
            health = (state.get("Health") or {}).get("Status")
            if health == "healthy":
                return True
            if health is None and state.get("Status") == "running":
                return True
            time.sleep(1.0)
        return False

    def exec(self, name: str, cmd: str) -> str:
        c = self.client.containers.get(name)
        rc, out = c.exec_run(cmd)
        _ = rc
        return out.decode(errors="ignore")

    def mark_compromised(self, name: str):
        try:
            self.exec(name, "sh -c \"echo COMPROMISED > /tmp/compromised_marker 2>/dev/null || true\"")
        except Exception:
            pass

    def clear_compromised(self, name: str):
        try:
            self.exec(name, "sh -c \"rm -f /tmp/compromised_marker 2>/dev/null || true\"")
        except Exception:
            pass

    def set_plc_logic(self, logic_hash: str):
        try:
            self.exec("plc_industrial_01", f"sh -c \"echo '{logic_hash}' > /plc/logic_hash 2>/dev/null || true\"")
        except Exception:
            pass


class ModbusPLCBridge:
    """Optional bridge to a real/external Modbus TCP endpoint for PLC command/state sync."""

    def __init__(self, host: str, port: int, unit_id: int = 1) -> None:
        if _ModbusTcpClient is None:
            raise RuntimeError("pymodbus not installed")
        self.host = host
        self.port = int(port)
        self.unit_id = int(unit_id)
        self.client = _ModbusTcpClient(host=self.host, port=self.port)
        self.connected = False

    def _ensure(self) -> bool:
        if self.connected:
            return True
        try:
            self.connected = bool(self.client.connect())
        except Exception:
            self.connected = False
        return self.connected

    def _call_with_unit(self, fn_name: str, *args: Any) -> Any:
        fn = getattr(self.client, fn_name)
        try:
            return fn(*args, slave=self.unit_id)
        except TypeError:
            try:
                return fn(*args, unit=self.unit_id)
            except TypeError:
                return fn(*args)

    def pull_commands(self, tank: PhysicalTank) -> None:
        if not self._ensure():
            return
        try:
            rr = self._call_with_unit("read_holding_registers", MODBUS_REG_CMD_BASE, 2)
            regs = getattr(rr, "registers", None)
            if regs and len(regs) >= 2:
                tank.pump_cmd = MODBUS_PUMP_CODE_INV.get(int(regs[0]), tank.pump_cmd)
                tank.valve_cmd = MODBUS_VALVE_CODE_INV.get(int(regs[1]), tank.valve_cmd)
        except Exception:
            self.connected = False

    def push_state(self, tank: PhysicalTank) -> None:
        if not self._ensure():
            return
        payload = [
            int(float(np.round(float(tank.level) * 10.0, 0))),
            MODBUS_PUMP_CODE.get(tank.pump_cmd, 0),
            MODBUS_VALVE_CODE.get(tank.valve_cmd, 0),
            1 if tank.sensor_ok else 0,
            1 if tank.safety_interlock else 0,
            1 if bool(tank.alarm) else 0,
            1 if bool(tank.damage) else 0,
        ]
        try:
            self._call_with_unit("write_registers", MODBUS_REG_STATE_BASE, payload)
        except Exception:
            self.connected = False

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:
            pass


# ============================================================
# 4) PLOTS
# ============================================================
FIG_DPI = 100
PLOT_COLORS = {"primary": "#1f77b4", "secondary": "#ff7f0e", "flag": "#2ca02c", "gp": "#d62728"}
SAFETY_THRESHOLD_DEFAULT = 0.8

PLOT_THEME = {
    "blue": "#174A7E",
    "blue_light": "#2B6CA3",
    "blue_faint": "#7FA7C9",
    "red": "#C44536",
    "purple": "#5A3E9A",
    "gray": "#3D4652",
    "safe_band": "#EAF3EC",
    "ink": "#1E2430",
    "teal": "#197278",
    "gold": "#A5792A",
}

plt.rcParams.update({
    "figure.facecolor": "#fcfcfd",
    "axes.facecolor": "#fcfcfd",
    "savefig.facecolor": "#fcfcfd",
    "axes.edgecolor": "#AAB2BF",
    "axes.labelcolor": "#1E2430",
    "xtick.color": "#283241",
    "ytick.color": "#283241",
    "text.color": "#1E2430",
    "font.family": "serif",
    "font.serif": ["STIXGeneral", "DejaVu Serif", "Times New Roman"],
    "axes.titleweight": "semibold",
})


class PrometheusMetrics:
    def __init__(self) -> None:
        if _PromGauge is None or _PromCounter is None:
            raise RuntimeError("prometheus_client unavailable")

        self.tank_level = _PromGauge("cps_tank_level", "Tank level (%)")
        self.round = _PromGauge("cps_round", "Current simulation round")
        self.alerts_total = _PromGauge("cps_alerts_total", "Total alerts generated")
        self.compromised_assets = _PromGauge("cps_compromised_assets", "Number of compromised assets")
        self.alarm_flag = _PromGauge("cps_alarm_flag", "Alarm flag (1 if any alarm string)")
        self.damage_flag = _PromGauge("cps_damage_flag", "Damage flag (1 if damage reached)")
        self.blue_sensitivity = _PromGauge("cps_blue_sensitivity", "Blue team sensitivity")

        self.attacker_zone = _PromGauge("cps_attacker_zone", "Attacker zone (IT=0, DMZ=1, OT=2)")
        self.plc_logic_state = _PromGauge("cps_plc_logic_state", "PLC logic state (SAFE=0, MALICIOUS=1)")

        self.red_actions_total = _PromCounter("cps_red_actions_total", "RED actions executed", ["action"])
        self.blue_actions_total = _PromCounter("cps_blue_actions_total", "BLUE actions executed", ["action"])
        self.alerts_generated_total = _PromCounter("cps_alerts_generated_total", "Alerts generated", ["severity"])

        self.red_action_outcomes_total = _PromCounter(
            "cps_red_action_outcomes_total",
            "RED action outcomes",
            ["action", "outcome"],
        )
        self.blue_action_outcomes_total = _PromCounter(
            "cps_blue_action_outcomes_total",
            "BLUE action outcomes",
            ["action", "outcome"],
        )

        self.events_total = _PromCounter(
            "cps_events_total",
            "Simulation events emitted",
            ["type", "actor"],
        )

        self._last_alert_count = 0
        self._last_event_count = 0

    def update_round(self, env: "CPSRange", red_action: str, red_result: str, blue_action: str, blue_result: str) -> None:
        self.round.set(float(env.round))
        self.tank_level.set(float(env.tank.level))
        self.alerts_total.set(float(len(env.alerts)))
        self.compromised_assets.set(float(sum(1 for a in env.assets.values() if a.compromised)))
        self.alarm_flag.set(1.0 if env.tank.alarm else 0.0)
        self.damage_flag.set(1.0 if env.tank.damage else 0.0)
        self.blue_sensitivity.set(float(env.blue_sensitivity))

        zone_map = {ZONE_IT: 0.0, ZONE_DMZ: 1.0, ZONE_OT: 2.0}
        self.attacker_zone.set(float(zone_map.get(env.attacker_zone, -1.0)))

        logic_hash = str(env.assets.get(PLC_ASSET_ID).notes.get("logic_hash", "SAFE_v1")) if PLC_ASSET_ID in env.assets else "SAFE_v1"
        self.plc_logic_state.set(0.0 if logic_hash.startswith("SAFE") else 1.0)

        ra = (red_action or "").upper() or "UNKNOWN"
        ba = (blue_action or "").upper() or "UNKNOWN"
        self.red_actions_total.labels(action=ra).inc()
        self.blue_actions_total.labels(action=ba).inc()

        def _outcome(result: str) -> str:
            r = (result or "").upper()
            if r.startswith("SUCCESS") or r.startswith("CRITICAL") or r.startswith("DEFENSE"):
                return "success"
            if r.startswith("FAIL"):
                return "fail"
            if r.startswith("BLOCKED"):
                return "blocked"
            if r.startswith("IGNORE"):
                return "ignore"
            if r.startswith("NOOP"):
                return "noop"
            return "other"

        self.red_action_outcomes_total.labels(action=ra, outcome=_outcome(red_result)).inc()
        self.blue_action_outcomes_total.labels(action=ba, outcome=_outcome(blue_result)).inc()

        new_alerts = env.alerts[self._last_alert_count:]
        for al in new_alerts:
            sev = str(al.get("severity", "UNKNOWN")).upper() or "UNKNOWN"
            self.alerts_generated_total.labels(severity=sev).inc()
        self._last_alert_count = len(env.alerts)

        new_events = env.events[self._last_event_count:]
        for ev in new_events:
            et = str(ev.get("type", "UNKNOWN")).lower() or "unknown"
            actor = str(ev.get("actor", "SYS")).upper() or "SYS"
            self.events_total.labels(type=et, actor=actor).inc()
        self._last_event_count = len(env.events)


def _rolling_mean_std(arr: np.ndarray, win: int = 9) -> Tuple[np.ndarray, np.ndarray]:
    x = np.asarray(arr, dtype=float)
    n = len(x)
    if n == 0:
        return np.array([]), np.array([])
    w = max(2, min(int(win), n))
    mu = np.zeros(n, dtype=float)
    sd = np.zeros(n, dtype=float)
    for i in range(n):
        lo = max(0, i - w + 1)
        seg = x[lo:i + 1]
        mu[i] = float(np.mean(seg))
        sd[i] = float(np.std(seg))
    return mu, sd


def _style_axis(ax: Any, title: str, xlabel: str, ylabel: str) -> None:
    ax.set_title(title, fontsize=10.5, fontweight="semibold", color=PLOT_THEME["ink"])
    ax.set_xlabel(xlabel, fontsize=9.2)
    ax.set_ylabel(ylabel, fontsize=9.2)
    ax.grid(True, axis="y", alpha=0.22, linewidth=0.8, color="#97A1AF")
    ax.grid(True, axis="x", alpha=0.10, linewidth=0.6, color="#AEB7C3")
    ax.tick_params(axis="both", labelsize=8.2, length=3.5, width=0.75)
    ax.spines["left"].set_color("#AAB2BF")
    ax.spines["bottom"].set_color("#AAB2BF")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)


def _extract_plot_context(history: Dict[str, List[Any]]) -> Optional[Dict[str, Any]]:
    raw_rounds = list(history.get("round", []))
    rounds_list: List[float] = []
    for i, v in enumerate(raw_rounds):
        try:
            fv = float(v)
            rounds_list.append(fv if np.isfinite(fv) else float(i + 1))
        except Exception:
            rounds_list.append(float(i + 1))
    rounds = np.asarray(rounds_list, dtype=float)
    if len(rounds) == 0:
        return None

    n = len(rounds)

    def _arr(key: str, default: float = 0.0) -> np.ndarray:
        raw = list(history.get(key, []))
        if len(raw) < n:
            raw.extend([default] * (n - len(raw)))
        elif len(raw) > n:
            raw = raw[:n]
        try:
            return np.asarray(raw, dtype=float)
        except Exception:
            out = []
            for v in raw:
                try:
                    fv = float(v)
                    out.append(fv if np.isfinite(fv) else float(default))
                except Exception:
                    out.append(float(default))
            return np.asarray(out, dtype=float)

    level = _arr("tank_level", default=0.0)
    policy = list(history.get("policy_choice", []))
    if len(policy) < n:
        policy.extend([""] * (n - len(policy)))
    elif len(policy) > n:
        policy = policy[:n]
    probe = np.asarray([1.0 if str(p).startswith("PROBE:") else 0.0 for p in policy], dtype=float)
    unsafe = ((level < TANK_LEVEL_SAFE_LOW) | (level > TANK_LEVEL_SAFE_HIGH)).astype(float)
    safe = ((level >= TANK_LEVEL_SAFE_LOW) & (level <= TANK_LEVEL_SAFE_HIGH)).astype(float)

    return {
        "round": rounds,
        "tank_level": level,
        "alerts_total": _arr("alerts_total", default=0.0),
        "compromised_count": _arr("compromised_count", default=0.0),
        "alarm_flag": _arr("alarm_flag", default=0.0),
        "damage_flag": _arr("damage_flag", default=0.0),
        "gp_p_alarm": _arr("gp_p_alarm", default=0.0),
        "gp_p_damage": _arr("gp_p_damage", default=0.0),
        "policy_choice": policy,
        "probe": probe,
        "unsafe": unsafe,
        "safe": safe,
    }


def _resolve_plot_output(save_path: Optional[str]) -> Tuple[Optional[str], str]:
    if not save_path:
        return None, "run"
    if os.path.isdir(save_path):
        return save_path, "run"
    out_dir = os.path.dirname(os.path.abspath(save_path)) or os.getcwd()
    base = os.path.basename(save_path)
    prefix = base.rsplit(".", 1)[0] if "." in base else base
    return out_dir, prefix


def _plot_publication_grid(history: Dict[str, List[Any]], save_path: Optional[str] = None, show: bool = True) -> Any:
    ctx = _extract_plot_context(history)
    if ctx is None:
        return None

    r = ctx["round"]
    level = ctx["tank_level"]
    alerts = ctx["alerts_total"]
    comp = ctx["compromised_count"]
    alarm_flag = ctx["alarm_flag"]
    damage_flag = ctx["damage_flag"]
    gp_alarm = ctx["gp_p_alarm"]
    gp_damage = ctx["gp_p_damage"]
    probe = ctx["probe"]
    unsafe = ctx["unsafe"]
    safe = ctx["safe"]

    emp_safe = np.cumsum(safe) / np.arange(1, len(safe) + 1)
    unsafe_probe = np.cumsum(probe * unsafe)
    cum_probe = np.cumsum(probe)

    level_mu, level_sd = _rolling_mean_std(level, win=8)
    gp_alarm_mu, gp_alarm_sd = _rolling_mean_std(gp_alarm, win=8)
    gp_damage_mu, gp_damage_sd = _rolling_mean_std(gp_damage, win=8)

    alarm_err = np.abs(gp_alarm - alarm_flag)
    damage_err = np.abs(gp_damage - damage_flag)
    alarm_err_mu, _ = _rolling_mean_std(alarm_err, win=8)
    damage_err_mu, _ = _rolling_mean_std(damage_err, win=8)

    fig, axes = plt.subplots(2, 4, figsize=(16.5, 7.6), dpi=FIG_DPI)
    fig.patch.set_facecolor("white")
    fig.suptitle("Simulation Diagnostics — Safety, Learning, and Intervention", fontsize=14, fontweight="bold", y=1.02)

    # Row 1
    ax = axes[0, 0]
    ax.plot(r, emp_safe, color=PLOT_THEME["blue"], linewidth=2.0, label="Empirical safety")
    ax.axhline(SAFETY_THRESHOLD_DEFAULT, color=PLOT_THEME["gray"], linestyle="--", linewidth=1.0, label="Safety threshold")
    ax.set_ylim(0.0, 1.02)
    ax.set_xlim(r.min(), r.max())
    _style_axis(ax, "Empirical safety probability", "Round", "P(safe)")
    ax.legend(loc="lower right", fontsize=8, frameon=False)

    ax = axes[0, 1]
    ax.axhspan(TANK_LEVEL_SAFE_LOW, TANK_LEVEL_SAFE_HIGH, color=PLOT_THEME["safe_band"], alpha=0.6)
    ax.plot(r, level, color="#5b6c8f", linewidth=1.0, alpha=0.65, label="Level (raw)")
    ax.plot(r, level_mu, color=PLOT_THEME["red"], linewidth=2.0, label="Level trend")
    ax.fill_between(r, np.clip(level_mu - level_sd, 0, 100), np.clip(level_mu + level_sd, 0, 100),
                    color=PLOT_THEME["red"], alpha=0.2)
    ax.set_xlim(r.min(), r.max())
    ax.set_ylim(0, 100)
    _style_axis(ax, "Process response (tank level)", "Round", "Level (%)")

    ax = axes[0, 2]
    ax.plot(r, alarm_flag, color=PLOT_THEME["blue_light"], linewidth=1.0, alpha=0.75, label="Observed alarm")
    ax.plot(r, gp_alarm_mu, color=PLOT_THEME["red"], linewidth=2.0, label="GP alarm trend")
    ax.fill_between(r, np.clip(gp_alarm_mu - gp_alarm_sd, 0, 1), np.clip(gp_alarm_mu + gp_alarm_sd, 0, 1),
                    color=PLOT_THEME["red"], alpha=0.2)
    ax.set_xlim(r.min(), r.max())
    ax.set_ylim(0.0, 1.02)
    _style_axis(ax, "GP alarm modeling", "Round", "Probability")

    ax = axes[0, 3]
    ax.plot(r, damage_flag, color=PLOT_THEME["blue_light"], linewidth=1.0, alpha=0.75, label="Observed damage")
    ax.plot(r, gp_damage_mu, color=PLOT_THEME["red"], linewidth=2.0, label="GP risk trend")
    ax.fill_between(r, np.clip(gp_damage_mu - gp_damage_sd, 0, 1), np.clip(gp_damage_mu + gp_damage_sd, 0, 1),
                    color=PLOT_THEME["red"], alpha=0.2)
    ax.set_xlim(r.min(), r.max())
    ax.set_ylim(0.0, 1.02)
    _style_axis(ax, "GP damage-risk modeling", "Round", "Probability")

    # Row 2
    ax = axes[1, 0]
    ax.plot(r, cum_probe, color=PLOT_THEME["blue_light"], linewidth=2.0, label="All probes")
    ax.plot(r, unsafe_probe, color=PLOT_THEME["red"], linewidth=2.0, label="Unsafe-state probes")
    ax.set_xlim(r.min(), r.max())
    _style_axis(ax, "Intervention load", "Round", "Cumulative interventions")
    ax.legend(loc="upper left", fontsize=8, frameon=False)

    ax = axes[1, 1]
    ax.plot(r, alerts, color=PLOT_THEME["red"], linewidth=2.0, label="Alerts total")
    ax.set_xlim(r.min(), r.max())
    _style_axis(ax, "Alert accumulation", "Round", "Total alerts")

    ax = axes[1, 2]
    ax.plot(r, comp, color=PLOT_THEME["blue_light"], linewidth=2.0, label="Compromised assets")
    ax.set_xlim(r.min(), r.max())
    ax.set_ylim(-0.1, max(1.0, float(np.max(comp)) + 0.8))
    _style_axis(ax, "Cyber impact", "Round", "Compromised count")

    ax = axes[1, 3]
    ax.plot(r, alarm_err_mu, color=PLOT_THEME["blue_light"], linewidth=2.0, label="|alarm error|")
    ax.plot(r, damage_err_mu, color=PLOT_THEME["red"], linewidth=2.0, label="|risk error|")
    ax.set_xlim(r.min(), r.max())
    ax.set_ylim(0.0, 1.02)
    _style_axis(ax, "Model calibration diagnostics", "Round", "Rolling absolute error")
    ax.legend(loc="upper right", fontsize=8, frameon=False)

    plt.tight_layout()
    if save_path:
        fig.savefig(save_path, bbox_inches="tight", dpi=FIG_DPI)
        _log_info("[OK] Saved plot to %s", save_path)
    if show:
        plt.show()
    return fig


def _plot_additional_diagnostics(history: Dict[str, List[Any]], out_dir: Optional[str], prefix: str) -> List[Any]:
    figs: List[Any] = []
    ctx = _extract_plot_context(history)
    if ctx is None:
        return figs

    r = ctx["round"]
    level = ctx["tank_level"]
    alarm_flag = ctx["alarm_flag"]
    damage_flag = ctx["damage_flag"]
    gp_alarm = ctx["gp_p_alarm"]
    gp_damage = ctx["gp_p_damage"]
    probe = ctx["probe"]
    unsafe = ctx["unsafe"]
    safe = ctx["safe"]

    # Additional Plot A: safety vs intervention intensity
    fig_a, ax_a = plt.subplots(1, 1, figsize=(8.6, 4.6), dpi=FIG_DPI)
    emp_safe = np.cumsum(safe) / np.arange(1, len(safe) + 1)
    probe_rate = np.cumsum(probe) / np.arange(1, len(probe) + 1)
    ax_a.plot(r, emp_safe, color=PLOT_THEME["blue"], linewidth=2.2, label="Empirical safety")
    ax_a.plot(r, probe_rate, color=PLOT_THEME["red"], linewidth=2.0, label="Intervention rate")
    ax_a.axhline(SAFETY_THRESHOLD_DEFAULT, color="#444", linestyle="--", linewidth=1.0, alpha=0.7)
    ax_a.set_ylim(0.0, 1.02)
    ax_a.set_xlim(r.min(), r.max())
    _style_axis(ax_a, "Safety vs intervention intensity", "Round", "Probability / rate")
    ax_a.legend(loc="lower right", fontsize=8, frameon=False)
    plt.tight_layout()
    figs.append(fig_a)

    # Additional Plot B: alarm/risk residual map
    fig_b, ax_b = plt.subplots(1, 1, figsize=(8.6, 4.6), dpi=FIG_DPI)
    alarm_res = gp_alarm - alarm_flag
    damage_res = gp_damage - damage_flag
    ax_b.plot(r, alarm_res, color=PLOT_THEME["blue_light"], linewidth=1.8, label="Alarm residual")
    ax_b.plot(r, damage_res, color=PLOT_THEME["red"], linewidth=1.8, label="Damage residual")
    ax_b.fill_between(r, 0.0, damage_res, color=PLOT_THEME["red"], alpha=0.12)
    ax_b.scatter(r[unsafe > 0.5], damage_res[unsafe > 0.5], color=PLOT_THEME["purple"], s=12, alpha=0.65,
                 label="Unsafe rounds")
    ax_b.axhline(0.0, color="#444", linestyle="--", linewidth=1.0, alpha=0.7)
    ax_b.set_xlim(r.min(), r.max())
    _style_axis(ax_b, "Residual diagnostics (prediction - observation)", "Round", "Residual")
    ax_b.legend(loc="upper right", fontsize=8, frameon=False)
    plt.tight_layout()
    figs.append(fig_b)

    if out_dir:
        p_a = os.path.join(out_dir, f"{prefix}_safety_vs_intervention.png")
        p_b = os.path.join(out_dir, f"{prefix}_residual_diagnostics.png")
        fig_a.savefig(p_a, bbox_inches="tight", dpi=FIG_DPI)
        fig_b.savefig(p_b, bbox_inches="tight", dpi=FIG_DPI)
        _log_info("[OK] Saved plot to %s", p_a)
        _log_info("[OK] Saved plot to %s", p_b)
    return figs


def _plot_scenario_storyboard(
    history: Dict[str, List[Any]],
    save_path: Optional[str] = None,
    show: bool = True,
    scenario_count: int = 5,
) -> Any:
    ctx = _extract_plot_context(history)
    if ctx is None:
        return None

    r = ctx["round"]
    level = ctx["tank_level"]
    alarm_flag = ctx["alarm_flag"]
    damage_flag = ctx["damage_flag"]
    gp_alarm = ctx["gp_p_alarm"]
    gp_damage = ctx["gp_p_damage"]
    probe = ctx["probe"]
    unsafe = ctx["unsafe"]
    safe = ctx["safe"]

    n = len(r)
    k = int(max(1, min(int(scenario_count), n)))
    cuts = np.linspace(0, n, k + 1, dtype=int)

    fig, axes = plt.subplots(k, 4, figsize=(17.8, max(3.3, 2.95 * k)), dpi=FIG_DPI)
    fig.patch.set_facecolor("#fcfcfd")
    fig.suptitle("Scenario Storyboard (1-5): segmented run diagnostics", fontsize=14, fontweight="semibold", y=1.01)
    if k == 1:
        axes = np.asarray([axes])

    for i in range(k):
        lo, hi = int(cuts[i]), int(cuts[i + 1])
        if hi <= lo:
            hi = min(n, lo + 1)

        segment_rounds = r[lo:hi]
        x_segment = np.arange(1, len(segment_rounds) + 1, dtype=float)
        segment_level = level[lo:hi]
        segment_alarm_flag = alarm_flag[lo:hi]
        segment_damage_flag = damage_flag[lo:hi]
        segment_gp_alarm = gp_alarm[lo:hi]
        segment_gp_damage = gp_damage[lo:hi]
        segment_probe = probe[lo:hi]
        segment_unsafe = unsafe[lo:hi]
        segment_safe = safe[lo:hi]

        emp_safe = np.cumsum(segment_safe) / np.arange(1, len(segment_safe) + 1)
        probe_rate = np.cumsum(segment_probe) / np.arange(1, len(segment_probe) + 1)
        unsafe_rate = np.cumsum(segment_unsafe) / np.arange(1, len(segment_unsafe) + 1)
        damage_rate = np.cumsum(segment_damage_flag) / np.arange(1, len(segment_damage_flag) + 1)
        cum_probe = np.cumsum(segment_probe)
        cum_unsafe_probe = np.cumsum(segment_probe * segment_unsafe)
        cum_alarm = np.cumsum(segment_alarm_flag)
        cum_damage = np.cumsum(segment_damage_flag)
        lvl_mu, lvl_sd = _rolling_mean_std(segment_level, win=6)
        alarm_mu, _ = _rolling_mean_std(segment_gp_alarm, win=6)
        risk_mu, risk_sd = _rolling_mean_std(segment_gp_damage, win=6)
        x_hi = max(2, len(x_segment))

        # Col 1: scenario safety profile (4 traces)
        ax = axes[i, 0]
        ax.plot(x_segment, emp_safe, color=PLOT_THEME["blue"], linewidth=1.9, label="Empirical safety")
        ax.plot(x_segment, probe_rate, color=PLOT_THEME["teal"], linewidth=1.6, label="Intervention rate")
        ax.plot(x_segment, unsafe_rate, color=PLOT_THEME["gold"], linewidth=1.5, label="Unsafe-state share")
        ax.plot(x_segment, damage_rate, color=PLOT_THEME["red"], linewidth=1.7, label="Damage incidence")
        ax.axhline(SAFETY_THRESHOLD_DEFAULT, color="#596273", linestyle="--", linewidth=0.95, alpha=0.9)
        ax.set_ylim(0.0, 1.02)
        ax.set_xlim(1, x_hi)
        _style_axis(ax, f"Scenario {i + 1}: safety profile", "Segment round", "Probability")
        if i == 0:
            ax.legend(loc="lower right", fontsize=6.8, frameon=False, ncol=2)

        # Col 2: process response and bounds (4 traces)
        ax = axes[i, 1]
        ax.axhspan(TANK_LEVEL_SAFE_LOW, TANK_LEVEL_SAFE_HIGH, color=PLOT_THEME["safe_band"], alpha=0.55)
        ax.plot(x_segment, segment_level, color=PLOT_THEME["blue_faint"], linewidth=1.0, alpha=0.78, label="Observed level")
        ax.plot(x_segment, lvl_mu, color=PLOT_THEME["blue"], linewidth=1.9, label="Level trend")
        ax.plot(x_segment, np.full(len(x_segment), TANK_LEVEL_SAFE_LOW, dtype=float), color=PLOT_THEME["teal"], linewidth=1.1, linestyle="--", label="Safe low")
        ax.plot(x_segment, np.full(len(x_segment), TANK_LEVEL_SAFE_HIGH, dtype=float), color=PLOT_THEME["teal"], linewidth=1.1, linestyle="--", label="Safe high")
        ax.fill_between(x_segment, np.clip(lvl_mu - lvl_sd, 0, 100), np.clip(lvl_mu + lvl_sd, 0, 100), color=PLOT_THEME["red"], alpha=0.16)
        ax.set_ylim(0.0, 100.0)
        ax.set_xlim(1, x_hi)
        _style_axis(ax, f"Scenario {i + 1}: process envelope", "Segment round", "Level (%)")
        if i == 0:
            ax.legend(loc="upper right", fontsize=6.8, frameon=False, ncol=2)

        # Col 3: cumulative operational pressure (4 traces)
        ax = axes[i, 2]
        ax.plot(x_segment, cum_probe, color=PLOT_THEME["blue"], linewidth=1.8, label="All interventions")
        ax.plot(x_segment, cum_unsafe_probe, color=PLOT_THEME["teal"], linewidth=1.8, label="Unsafe interventions")
        ax.plot(x_segment, cum_alarm, color=PLOT_THEME["gold"], linewidth=1.6, label="Alarm observations")
        ax.plot(x_segment, cum_damage, color=PLOT_THEME["red"], linewidth=1.7, label="Damage observations")
        ax.set_xlim(1, x_hi)
        _style_axis(ax, f"Scenario {i + 1}: cumulative pressure", "Segment round", "Cumulative count")
        if i == 0:
            ax.legend(loc="upper left", fontsize=6.8, frameon=False, ncol=2)

        # Col 4: GP risk behavior
        ax = axes[i, 3]
        ax.plot(x_segment, segment_alarm_flag, color="#6B7B90", linewidth=1.0, alpha=0.7, label="Alarm observed")
        ax.plot(x_segment, segment_damage_flag, color="#3E4A5C", linewidth=1.0, alpha=0.7, label="Damage observed")
        ax.plot(x_segment, alarm_mu, color=PLOT_THEME["blue_light"], linewidth=1.6, alpha=0.95, label="GP alarm trend")
        ax.plot(x_segment, risk_mu, color=PLOT_THEME["red"], linewidth=1.9, label="GP damage trend")
        ax.fill_between(x_segment, np.clip(risk_mu - risk_sd, 0, 1), np.clip(risk_mu + risk_sd, 0, 1), color=PLOT_THEME["red"], alpha=0.16)
        ax.set_ylim(0.0, 1.02)
        ax.set_xlim(1, x_hi)
        _style_axis(ax, f"Scenario {i + 1}: probabilistic state", "Segment round", "Probability")
        if i == 0:
            ax.legend(loc="upper right", fontsize=6.8, frameon=False, ncol=1)

    plt.tight_layout()
    if save_path:
        fig.savefig(save_path, bbox_inches="tight", dpi=FIG_DPI)
        _log_info("[OK] Saved plot to %s", save_path)
    if show:
        plt.show()
    return fig


def _plot_kill_chain_and_tools(
    dataset_rows: List[Dict[str, Any]],
    out_dir: Optional[str],
    prefix: str,
    show: bool,
) -> List[Any]:
    figs: List[Any] = []
    if not dataset_rows:
        return figs

    red_phases = [str(r.get("red_phase") or "Unknown") for r in dataset_rows]
    blue_phases = [str(r.get("blue_phase") or "Unknown") for r in dataset_rows]
    phase_order = [
        "Reconnaissance", "Initial Access", "Credential Access", "Lateral Movement",
        "Execution", "Impact", "Defense Evasion", "Detect", "Contain", "Mitigate", "Recover", "Optimize", "Protect"
    ]
    phases = [p for p in phase_order if p in set(red_phases + blue_phases)] or sorted(list(set(red_phases + blue_phases)))
    x = np.arange(len(phases))
    red_counts = np.array([sum(1 for p in red_phases if p == ph) for ph in phases], dtype=float)
    blue_counts = np.array([sum(1 for p in blue_phases if p == ph) for ph in phases], dtype=float)

    fig1, ax1 = plt.subplots(1, 1, figsize=(11, 4.8), dpi=FIG_DPI)
    w = 0.38
    ax1.bar(x - w / 2.0, red_counts, width=w, color="#d94f4f", alpha=0.9, label="Attacker kill-chain")
    ax1.bar(x + w / 2.0, blue_counts, width=w, color="#3772c2", alpha=0.9, label="Defender process")
    ax1.set_xticks(x)
    ax1.set_xticklabels(phases, rotation=25, ha="right")
    _style_axis(ax1, "Kill-chain / defense process frequency", "Phase", "Action count")
    ax1.legend(loc="upper right", fontsize=8, frameon=False)
    plt.tight_layout()
    figs.append(fig1)

    tool_counts: Dict[str, int] = {}
    for r in dataset_rows:
        for k in ("red_tool", "blue_tool"):
            t = str(r.get(k) or "").strip()
            if not t:
                continue
            tool_counts[t] = tool_counts.get(t, 0) + 1
    top = sorted(tool_counts.items(), key=lambda kv: kv[1], reverse=True)[:12]
    if top:
        tools = [k for k, _ in top][::-1]
        vals = [v for _, v in top][::-1]
        fig2, ax2 = plt.subplots(1, 1, figsize=(10.5, 5.0), dpi=FIG_DPI)
        y = np.arange(len(tools))
        colors = ["#5E4B8B"] * len(tools)
        if colors:
            colors[-1] = "#2B6CA3"
        ax2.barh(y, vals, color=colors, alpha=0.93, edgecolor="#F2F3F5", linewidth=0.9)
        ax2.set_yticks(np.arange(len(tools)))
        ax2.set_yticklabels(tools)
        for yi, v in zip(y, vals):
            ax2.text(float(v) + 0.6, yi, f"{int(v)}", va="center", fontsize=8.4, color=PLOT_THEME["ink"])
        _style_axis(ax2, "Most-used attacker/defender tools", "Count", "Tool")
        ax2.set_xlim(0.0, max(1.0, float(max(vals)) * 1.16))
        plt.tight_layout()
        figs.append(fig2)

    if out_dir:
        if figs:
            p1 = os.path.join(out_dir, f"{prefix}_killchain_phase_counts.png")
            figs[0].savefig(p1, bbox_inches="tight", dpi=FIG_DPI)
            _log_info("[OK] Saved plot to %s", p1)
        if len(figs) > 1:
            p2 = os.path.join(out_dir, f"{prefix}_tool_usage.png")
            figs[1].savefig(p2, bbox_inches="tight", dpi=FIG_DPI)
            _log_info("[OK] Saved plot to %s", p2)

    if show and not out_dir:
        plt.show()
    return figs


def _animate_run_timeline(
    history: Dict[str, List[Any]],
    dataset_rows: List[Dict[str, Any]],
    save_path: Optional[str] = None,
    show: bool = False,
) -> Any:
    if _mpl_animation is None:
        _log_warn("matplotlib animation unavailable; skipping animation")
        return None
    ctx = _extract_plot_context(history)
    if ctx is None:
        return None

    r = ctx["round"]
    level = ctx["tank_level"]
    n = len(r)
    if n == 0:
        return None

    if n == 1:
        x_min, x_max = float(r[0]) - 0.5, float(r[0]) + 0.5
    else:
        x_min, x_max = float(r.min()), float(r.max())

    red_seq = [str(x.get("red_action") or "NONE") for x in dataset_rows[:n]]
    blue_seq = [str(x.get("blue_action") or "NONE") for x in dataset_rows[:n]]
    if len(red_seq) < n:
        red_seq.extend(["NONE"] * (n - len(red_seq)))
    if len(blue_seq) < n:
        blue_seq.extend(["NONE"] * (n - len(blue_seq)))
    red_hits = np.cumsum(np.array([1.0 if a not in ("NONE", "RECON") else 0.0 for a in red_seq], dtype=float))
    blue_hits = np.cumsum(np.array([1.0 if a in ("PATCH", "ISOLATE", "RESTORE", "HARDEN") else 0.0 for a in blue_seq], dtype=float))

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(9.5, 6.0), dpi=FIG_DPI)
    ax1.axhspan(TANK_LEVEL_SAFE_LOW, TANK_LEVEL_SAFE_HIGH, color=PLOT_THEME["safe_band"], alpha=0.55)
    ax1.set_xlim(x_min, x_max)
    ax1.set_ylim(0.0, 100.0)
    _style_axis(ax1, "Animated process timeline", "Round", "Tank level (%)")
    _style_axis(ax2, "Cumulative tactical activity", "Round", "Count")
    ax2.set_xlim(x_min, x_max)
    ax2.set_ylim(0.0, max(1.0, float(max(red_hits[-1] if len(red_hits) else 0.0, blue_hits[-1] if len(blue_hits) else 0.0)) + 1.0))

    line_level, = ax1.plot([], [], color=PLOT_THEME["red"], linewidth=2.2)
    line_red, = ax2.plot([], [], color="#d94f4f", linewidth=2.0, label="Attacker non-recon steps")
    line_blue, = ax2.plot([], [], color="#3772c2", linewidth=2.0, label="Defender hardening/restore")
    ax2.legend(loc="upper left", fontsize=8, frameon=False)

    def _init() -> Tuple[Any, Any, Any]:
        line_level.set_data([], [])
        line_red.set_data([], [])
        line_blue.set_data([], [])
        return line_level, line_red, line_blue

    def _update(i: int) -> Tuple[Any, Any, Any]:
        upto = i + 1
        line_level.set_data(r[:upto], level[:upto])
        if len(red_hits) >= upto:
            line_red.set_data(r[:upto], red_hits[:upto])
        if len(blue_hits) >= upto:
            line_blue.set_data(r[:upto], blue_hits[:upto])
        round_val = float(r[min(i, len(r) - 1)])
        round_label = int(round_val) if np.isfinite(round_val) else upto
        ax1.set_title(f"Animated process timeline — round {round_label}")
        return line_level, line_red, line_blue

    anim = _mpl_animation.FuncAnimation(fig, _update, frames=n, init_func=_init, interval=220, blit=False)
    if save_path:
        try:
            save_dir = os.path.dirname(os.path.abspath(save_path))
            if save_dir:
                os.makedirs(save_dir, exist_ok=True)
            anim.save(save_path, writer="pillow", fps=5)
            _log_info("[OK] Saved animation to %s", save_path)
        except Exception as e:
            _log_warn("Animation save failed: %s", e)
    if show:
        plt.show()
    return anim


def _infer_compromised_timeline(dataset_rows: List[Dict[str, Any]], asset_ids: List[str]) -> List[Dict[str, bool]]:
    state = {aid: False for aid in asset_ids}
    timeline: List[Dict[str, bool]] = []
    for row in dataset_rows:
        red_target = str(row.get("red_target") or "")
        red_res = str(row.get("red_result") or "").upper()
        if red_target in state and (red_res.startswith("SUCCESS") or red_res.startswith("CRITICAL")):
            state[red_target] = True

        blue_action = str(row.get("blue_action") or "").upper()
        blue_target = str(row.get("blue_target") or "")
        if blue_action == "RESTORE" and blue_target in state:
            state[blue_target] = False

        timeline.append(dict(state))
    return timeline


# ============================================================
# LARGE-SCALE INFRASTRUCTURE GENERATOR (300+ IPs, 8 subnets)
# ============================================================
INFRA_SUBNETS: List[Dict[str, Any]] = [
    {"name": "corp_lan",     "zone": "IT",    "cidr": "10.1.0.0/24",   "gateway": "10.1.0.1",
     "color": "#4c78a8", "label": "Corporate LAN"},
    {"name": "it_servers",   "zone": "IT",    "cidr": "10.1.1.0/24",   "gateway": "10.1.1.1",
     "color": "#6a8fc7", "label": "IT Server Farm"},
    {"name": "dmz_public",   "zone": "DMZ",   "cidr": "172.16.0.0/24", "gateway": "172.16.0.1",
     "color": "#f58518", "label": "DMZ Public"},
    {"name": "dmz_services", "zone": "DMZ",   "cidr": "172.16.1.0/24", "gateway": "172.16.1.1",
     "color": "#e8a04c", "label": "DMZ Services"},
    {"name": "ot_control",   "zone": "OT",    "cidr": "192.168.10.0/24","gateway": "192.168.10.1",
     "color": "#54a24b", "label": "OT Control Net"},
    {"name": "ot_field",     "zone": "OT",    "cidr": "192.168.11.0/24","gateway": "192.168.11.1",
     "color": "#7ec876", "label": "OT Field Bus"},
    {"name": "scada_net",    "zone": "OT",    "cidr": "192.168.20.0/24","gateway": "192.168.20.1",
     "color": "#b07aa1", "label": "SCADA Network"},
    {"name": "cloud_mgmt",   "zone": "IT",    "cidr": "10.200.0.0/24", "gateway": "10.200.0.1",
     "color": "#79706e", "label": "Cloud/Mgmt"},
]

INFRA_ASSET_TEMPLATES: List[Dict[str, Any]] = [
    # Corporate LAN — workstations, printers, phones
    {"subnet": "corp_lan", "kind": "workstation", "prefix": "ws",       "count": 60, "services": [("rdp", 3389), ("smb", 445)],       "vuln": "T1021", "exposed": True,  "weak_creds": True},
    {"subnet": "corp_lan", "kind": "printer",     "prefix": "prn",      "count": 12, "services": [("ipp", 631), ("http", 80)],         "vuln": None,    "exposed": True,  "weak_creds": False},
    {"subnet": "corp_lan", "kind": "voip",        "prefix": "phone",    "count": 20, "services": [("sip", 5060)],                      "vuln": None,    "exposed": True,  "weak_creds": False},
    # IT Server Farm
    {"subnet": "it_servers","kind": "server",      "prefix": "srv",      "count": 25, "services": [("ssh", 22), ("https", 443)],        "vuln": "T1190", "exposed": True,  "weak_creds": False},
    {"subnet": "it_servers","kind": "dc",          "prefix": "dc",       "count": 3,  "services": [("ldap", 389), ("kerberos", 88)],    "vuln": "T1558", "exposed": True,  "weak_creds": False},
    {"subnet": "it_servers","kind": "db",          "prefix": "db",       "count": 5,  "services": [("mssql", 1433), ("ssh", 22)],       "vuln": "T1210", "exposed": True,  "weak_creds": True},
    {"subnet": "it_servers","kind": "backup",      "prefix": "bkp",      "count": 2,  "services": [("ssh", 22), ("nfs", 2049)],         "vuln": None,    "exposed": False, "weak_creds": False},
    # DMZ Public
    {"subnet": "dmz_public","kind": "webserver",   "prefix": "web",      "count": 15, "services": [("http", 80), ("https", 443)],       "vuln": "T0819", "exposed": True,  "weak_creds": False},
    {"subnet": "dmz_public","kind": "gateway",     "prefix": "gw",       "count": 4,  "services": [("ssh", 22), ("vpn", 1194)],         "vuln": "T0887", "exposed": True,  "weak_creds": True},
    {"subnet": "dmz_public","kind": "dns",         "prefix": "dns",      "count": 3,  "services": [("dns", 53)],                        "vuln": None,    "exposed": True,  "weak_creds": False},
    {"subnet": "dmz_public","kind": "mailserver",  "prefix": "mail",     "count": 2,  "services": [("smtp", 25), ("imap", 993)],        "vuln": "T1114", "exposed": True,  "weak_creds": True},
    # DMZ Services
    {"subnet": "dmz_services","kind": "historian", "prefix": "hist",     "count": 6,  "services": [("http", 80), ("opc", 4840)],        "vuln": "T0819", "exposed": True,  "weak_creds": False},
    {"subnet": "dmz_services","kind": "jumpbox",   "prefix": "jump",     "count": 3,  "services": [("ssh", 22), ("rdp", 3389)],         "vuln": "T1021", "exposed": True,  "weak_creds": True},
    {"subnet": "dmz_services","kind": "proxy",     "prefix": "proxy",    "count": 4,  "services": [("http", 8080), ("socks", 1080)],    "vuln": None,    "exposed": True,  "weak_creds": False},
    # OT Control Net
    {"subnet": "ot_control","kind": "hmi",         "prefix": "hmi",      "count": 8,  "services": [("rdp", 3389), ("vnc", 5900)],       "vuln": "T0823", "exposed": True, "weak_creds": True},
    {"subnet": "ot_control","kind": "eng_ws",      "prefix": "ews",      "count": 5,  "services": [("rdp", 3389), ("ssh", 22)],         "vuln": "T1021", "exposed": True, "weak_creds": False},
    {"subnet": "ot_control","kind": "plc",         "prefix": "plc",      "count": 20, "services": [("modbus", 502), ("enip", 44818)],   "vuln": "T0866", "exposed": True, "weak_creds": False},
    {"subnet": "ot_control","kind": "rtu",         "prefix": "rtu",      "count": 15, "services": [("dnp3", 20000), ("modbus", 502)],   "vuln": "T0866", "exposed": True, "weak_creds": False},
    # OT Field Bus
    {"subnet": "ot_field",  "kind": "sensor",      "prefix": "sens",     "count": 40, "services": [("modbus", 502)],                    "vuln": None,    "exposed": False, "weak_creds": False},
    {"subnet": "ot_field",  "kind": "actuator",    "prefix": "act",      "count": 25, "services": [("modbus", 502)],                    "vuln": None,    "exposed": False, "weak_creds": False},
    {"subnet": "ot_field",  "kind": "ied",         "prefix": "ied",      "count": 10, "services": [("goose", 102), ("mms", 102)],       "vuln": "T0860", "exposed": False, "weak_creds": False},
    # SCADA Network
    {"subnet": "scada_net", "kind": "scada_srv",   "prefix": "scada",    "count": 4,  "services": [("opc", 4840), ("https", 443)],      "vuln": "T0869", "exposed": False, "weak_creds": False},
    {"subnet": "scada_net", "kind": "historian",   "prefix": "shist",    "count": 3,  "services": [("http", 80), ("sql", 1433)],        "vuln": "T0819", "exposed": False, "weak_creds": True},
    {"subnet": "scada_net", "kind": "alarm_srv",   "prefix": "alarm",    "count": 2,  "services": [("snmp", 161), ("syslog", 514)],     "vuln": None,    "exposed": False, "weak_creds": False},
    # Cloud/Mgmt
    {"subnet": "cloud_mgmt","kind": "cloud_gw",    "prefix": "cgw",      "count": 2,  "services": [("https", 443), ("ssh", 22)],        "vuln": "T1190", "exposed": True,  "weak_creds": False},
    {"subnet": "cloud_mgmt","kind": "siem",        "prefix": "siem",     "count": 2,  "services": [("https", 443), ("syslog", 514)],    "vuln": None,    "exposed": False, "weak_creds": False},
    {"subnet": "cloud_mgmt","kind": "nms",         "prefix": "nms",      "count": 3,  "services": [("snmp", 161), ("https", 443)],      "vuln": None,    "exposed": False, "weak_creds": False},
    {"subnet": "cloud_mgmt","kind": "vpn_conc",    "prefix": "vpn",      "count": 2,  "services": [("ipsec", 500), ("l2tp", 1701)],     "vuln": "T0887", "exposed": True,  "weak_creds": False},
]

# Inter-subnet links (which subnets can route to each other)
INFRA_SUBNET_LINKS: List[Tuple[str, str]] = [
    ("corp_lan", "it_servers"),
    ("corp_lan", "cloud_mgmt"),
    ("it_servers", "dmz_public"),
    ("it_servers", "cloud_mgmt"),
    ("dmz_public", "dmz_services"),
    ("dmz_services", "ot_control"),
    ("ot_control", "ot_field"),
    ("ot_control", "scada_net"),
    ("scada_net", "ot_field"),
    ("cloud_mgmt", "dmz_public"),
]


def generate_large_infrastructure(seed: int = 42) -> Dict[str, Any]:
    """Generate a large-scale CPS infrastructure with 300+ IPs across 8 subnets."""
    rng = random.Random(seed)
    subnet_lookup = {s["name"]: s for s in INFRA_SUBNETS}
    assets: List[Dict[str, Any]] = []
    ip_counter: Dict[str, int] = {s["name"]: 10 for s in INFRA_SUBNETS}

    for tmpl in INFRA_ASSET_TEMPLATES:
        subnet_name = tmpl["subnet"]
        subnet = subnet_lookup[subnet_name]
        cidr_base = subnet["cidr"].rsplit(".", 1)[0]
        for idx in range(tmpl["count"]):
            host_num = ip_counter[subnet_name]
            ip_counter[subnet_name] += 1
            ip = f"{cidr_base}.{host_num}"
            aid = f"{tmpl['prefix']}_{subnet_name}_{idx:03d}"
            services = {}
            for svc_name, svc_port in tmpl["services"]:
                services[svc_name] = {
                    "name": svc_name,
                    "port": svc_port,
                    "vuln_id": tmpl.get("vuln"),
                    "exposed": tmpl.get("exposed", True),
                    "patched": rng.random() < 0.15,
                    "weak_creds": tmpl.get("weak_creds", False),
                    "auth_required": svc_port not in (80, 53, 502, 161, 514),
                }
            assets.append({
                "asset_id": aid,
                "kind": tmpl["kind"],
                "zone": subnet["zone"],
                "subnet": subnet_name,
                "network": subnet_name,
                "ip": ip,
                "services": services,
                "os": rng.choice(["Linux", "Windows", "RTOS", "Embedded"]) if tmpl["kind"] not in ("sensor", "actuator", "ied") else "Embedded",
                "criticality": "HIGH" if tmpl["kind"] in ("plc", "rtu", "scada_srv", "dc", "hmi") else "MEDIUM" if tmpl["kind"] in ("server", "db", "historian", "eng_ws") else "LOW",
            })

    total_ips = len(assets)
    subnet_summary = {}
    for a in assets:
        sn = a["subnet"]
        subnet_summary[sn] = subnet_summary.get(sn, 0) + 1

    return {
        "subnets": INFRA_SUBNETS,
        "subnet_links": INFRA_SUBNET_LINKS,
        "assets": assets,
        "total_ips": total_ips,
        "subnet_summary": subnet_summary,
    }


def infra_to_topology_assets(infra: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert large infrastructure dict to topology_assets list for animation."""
    return [
        {
            "asset_id": a["asset_id"],
            "zone": a["zone"],
            "kind": a["kind"],
            "ip": a["ip"],
            "network": a["network"],
            "subnet": a.get("subnet", ""),
            "criticality": a.get("criticality", "LOW"),
            "os": a.get("os", ""),
        }
        for a in infra["assets"]
    ]


# ============================================================
# ENHANCED 2D ANIMATION PIPELINE (large-scale topology)
# ============================================================
_SUBNET_LAYOUT_COLS = {
    "corp_lan": 0, "it_servers": 1, "cloud_mgmt": 2,
    "dmz_public": 3, "dmz_services": 4,
    "ot_control": 5, "ot_field": 6, "scada_net": 7,
}

_KIND_MARKERS = {
    "workstation": "s", "printer": "p", "voip": "^", "server": "D",
    "dc": "P", "db": "h", "backup": "8", "webserver": "o",
    "gateway": "D", "dns": "v", "mailserver": ">", "historian": "H",
    "jumpbox": "d", "proxy": "<", "hmi": "s", "eng_ws": "D",
    "plc": "P", "rtu": "^", "sensor": ".", "actuator": ".",
    "ied": "v", "scada_srv": "P", "alarm_srv": "*",
    "cloud_gw": "D", "siem": "o", "nms": "s", "vpn_conc": "d",
}

_CRITICALITY_SIZE = {"HIGH": 48, "MEDIUM": 28, "LOW": 14}


def _compute_large_layout(
    topology_assets: List[Dict[str, Any]],
    subnets: List[Dict[str, Any]],
) -> Dict[str, Tuple[float, float]]:
    """Compute 2D positions for 300+ assets grouped by subnet columns."""
    subnet_lookup = {s["name"]: s for s in subnets}
    by_subnet: Dict[str, List[Dict[str, Any]]] = {}
    for a in topology_assets:
        sn = a.get("subnet") or a.get("network") or "unknown"
        by_subnet.setdefault(sn, []).append(a)

    n_cols = max(len(by_subnet), 1)
    col_names = sorted(by_subnet.keys(), key=lambda s: _SUBNET_LAYOUT_COLS.get(s, 99))
    col_width = 1.0
    pos: Dict[str, Tuple[float, float]] = {}

    for ci, sn in enumerate(col_names):
        items = by_subnet[sn]
        x_center = ci * col_width
        n = len(items)
        if n <= 30:
            y_vals = np.linspace(0.05, 0.95, max(n, 1))
        else:
            cols_inner = int(np.ceil(n / 30))
            y_vals_base = np.linspace(0.05, 0.95, 30)
            y_vals = []
            for j, a in enumerate(items):
                inner_col = j // 30
                inner_row = j % 30
                if inner_row < len(y_vals_base):
                    y_vals.append(y_vals_base[inner_row])
                else:
                    y_vals.append(0.95)
            x_offsets = [(j // 30) * 0.25 for j in range(n)]
        for j, a in enumerate(items):
            aid = a["asset_id"]
            if n > 30:
                x = x_center + x_offsets[j] - 0.12
                y = y_vals[j]
            else:
                x = x_center
                y = float(y_vals[j])
            pos[aid] = (x, y)

    return pos


def _animate_large_topology_2d(
    dataset_rows: List[Dict[str, Any]],
    topology_assets: List[Dict[str, Any]],
    subnets: List[Dict[str, Any]],
    subnet_links: List[Tuple[str, str]],
    save_path: Optional[str] = None,
    show: bool = False,
    max_labeled: int = 40,
    fps: int = 3,
) -> Any:
    """Enhanced 2D animation pipeline for large-scale infrastructure (300+ nodes)."""
    if _mpl_animation is None:
        _log_warn("matplotlib animation unavailable; skipping large topology animation")
        return None
    if not dataset_rows or not topology_assets:
        return None

    subnet_lookup = {s["name"]: s for s in subnets}
    pos = _compute_large_layout(topology_assets, subnets)
    asset_ids = [a["asset_id"] for a in topology_assets]
    asset_map = {a["asset_id"]: a for a in topology_assets}
    comp_timeline = _infer_compromised_timeline(dataset_rows, asset_ids)

    # Precompute subnet bounding boxes
    by_subnet: Dict[str, List[str]] = {}
    for a in topology_assets:
        sn = a.get("subnet") or a.get("network") or ""
        by_subnet.setdefault(sn, []).append(a["asset_id"])

    subnet_boxes: Dict[str, Tuple[float, float, float, float]] = {}
    for sn, aids in by_subnet.items():
        xs = [pos[a][0] for a in aids if a in pos]
        ys = [pos[a][1] for a in aids if a in pos]
        if xs and ys:
            pad = 0.08
            subnet_boxes[sn] = (min(xs) - pad, max(xs) + pad, min(ys) - pad, max(ys) + pad)

    # Select which assets get IP labels (high-criticality + random sample)
    high_crit = [a for a in topology_assets if a.get("criticality") == "HIGH"]
    other = [a for a in topology_assets if a.get("criticality") != "HIGH"]
    labeled_set = set(a["asset_id"] for a in high_crit[:max_labeled])
    remaining = max_labeled - len(labeled_set)
    if remaining > 0 and other:
        rng = random.Random(99)
        sample = rng.sample(other, min(remaining, len(other)))
        labeled_set.update(a["asset_id"] for a in sample)

    def _safe_round_value(raw: Any, default_val: float) -> float:
        try:
            val = float(raw)
            return val if np.isfinite(val) else float(default_val)
        except Exception:
            return float(default_val)

    rounds = np.asarray([
        _safe_round_value(r.get("round", i + 1), float(i + 1))
        for i, r in enumerate(dataset_rows)
    ], dtype=float)
    n_frames = len(dataset_rows)

    all_x = [p[0] for p in pos.values()]
    all_y = [p[1] for p in pos.values()]
    x_lo, x_hi = min(all_x) - 0.3, max(all_x) + 0.5
    y_lo, y_hi = -0.05, 1.05

    fig, ax = plt.subplots(1, 1, figsize=(22.0, 12.0), dpi=80)
    fig.patch.set_facecolor("#f8f9fb")

    def _draw_frame(i: int) -> None:
        ax.clear()
        idx = min(i, n_frames - 1)
        row = dataset_rows[idx]
        comp = comp_timeline[idx]
        round_label = int(rounds[idx]) if np.isfinite(rounds[idx]) else (idx + 1)
        attacker_zone = str(row.get("attacker_zone") or ZONE_IT)
        red_target = str(row.get("red_target") or "")
        blue_target = str(row.get("blue_target") or "")
        red_action = str(row.get("red_action") or "NONE")
        blue_action = str(row.get("blue_action") or "NONE")
        tank_level = float(row.get("tank_level", 50.0))

        # Draw subnet bounding boxes
        for sn, (bx0, bx1, by0, by1) in subnet_boxes.items():
            sinfo = subnet_lookup.get(sn, {})
            sc = sinfo.get("color", "#cccccc")
            ax.fill([bx0, bx1, bx1, bx0, bx0], [by0, by0, by1, by1, by0],
                    color=sc, alpha=0.08, linewidth=0)
            ax.plot([bx0, bx1, bx1, bx0, bx0], [by0, by0, by1, by1, by0],
                    color=sc, linewidth=1.2, alpha=0.5)
            label = sinfo.get("label", sn)
            cidr = sinfo.get("cidr", "")
            ax.text((bx0 + bx1) / 2, by1 + 0.015, f"{label}\n{cidr}",
                    ha="center", va="bottom", fontsize=7.5, fontweight="bold",
                    color=sc, alpha=0.85)

        # Draw inter-subnet links
        for sn1, sn2 in subnet_links:
            if sn1 in subnet_boxes and sn2 in subnet_boxes:
                bx1 = (subnet_boxes[sn1][0] + subnet_boxes[sn1][1]) / 2
                by1 = (subnet_boxes[sn1][2] + subnet_boxes[sn1][3]) / 2
                bx2 = (subnet_boxes[sn2][0] + subnet_boxes[sn2][1]) / 2
                by2 = (subnet_boxes[sn2][2] + subnet_boxes[sn2][3]) / 2
                ax.plot([bx1, bx2], [by1, by2], color="#aab2bf", linewidth=0.8,
                        alpha=0.4, linestyle="--", zorder=1)

        # Count compromised per subnet for stats
        comp_per_subnet: Dict[str, int] = {}
        total_comp = 0
        for aid, is_comp in comp.items():
            if is_comp:
                total_comp += 1
                a_info = asset_map.get(aid, {})
                sn = a_info.get("subnet", "")
                comp_per_subnet[sn] = comp_per_subnet.get(sn, 0) + 1

        # Draw assets
        for a in topology_assets:
            aid = a["asset_id"]
            if aid not in pos:
                continue
            x, y = pos[aid]
            sn = a.get("subnet") or a.get("network") or ""
            sinfo = subnet_lookup.get(sn, {})
            is_comp = comp.get(aid, False)
            crit = a.get("criticality", "LOW")
            sz = _CRITICALITY_SIZE.get(crit, 14)
            marker = _KIND_MARKERS.get(a.get("kind", ""), "o")

            if is_comp:
                c = "#d62728"
                edge_c = "#8b0000"
                edge_w = 1.2
            elif aid == red_target:
                c = "#ff9896"
                edge_c = "#d62728"
                edge_w = 1.5
            elif aid == blue_target:
                c = "#aec7e8"
                edge_c = "#1f77b4"
                edge_w = 1.5
            else:
                c = sinfo.get("color", "#888888")
                edge_c = "black"
                edge_w = 0.3

            ax.scatter([x], [y], s=sz, c=[c], marker=marker,
                       edgecolors=edge_c, linewidths=edge_w, zorder=3, alpha=0.85)

            if aid in labeled_set:
                ip = a.get("ip", "")
                kind = a.get("kind", "")
                ax.text(x + 0.04, y, f"{kind}\n{ip}", fontsize=5.0, va="center",
                        color="#333", alpha=0.75, zorder=4)

        # Draw attacker position
        zone_to_subnets = {"IT": ["corp_lan", "it_servers", "cloud_mgmt"],
                           "DMZ": ["dmz_public", "dmz_services"],
                           "OT": ["ot_control", "ot_field", "scada_net"]}
        atk_subnets = zone_to_subnets.get(attacker_zone, ["corp_lan"])
        if atk_subnets and atk_subnets[0] in subnet_boxes:
            bx = subnet_boxes[atk_subnets[0]]
            atk_x, atk_y = bx[0] - 0.15, (bx[2] + bx[3]) / 2
        else:
            atk_x, atk_y = -0.2, 0.5
        ax.scatter([atk_x], [atk_y], s=350, marker="*", c="#111111",
                   edgecolors="#f2cf00", linewidths=1.5, zorder=5)
        ax.text(atk_x, atk_y - 0.04, f"Attacker\n@{attacker_zone}",
                fontsize=7.5, ha="center", fontweight="bold", color="#333", zorder=5)

        # Draw attack arrow
        if red_target in pos:
            tx, ty = pos[red_target]
            ax.annotate("", xy=(tx, ty), xytext=(atk_x, atk_y),
                        arrowprops=dict(arrowstyle="-|>", color="#d62728",
                                        lw=2.2, connectionstyle="arc3,rad=0.15"),
                        zorder=4)

        # Draw defense arrow
        if blue_target in pos:
            tx, ty = pos[blue_target]
            ax.annotate("", xy=(tx, ty), xytext=(x_hi - 0.3, 0.98),
                        arrowprops=dict(arrowstyle="-|>", color="#1f77b4",
                                        lw=1.8, connectionstyle="arc3,rad=-0.12"),
                        zorder=4)

        # Status bar
        ax.set_xlim(x_lo, x_hi)
        ax.set_ylim(y_lo, y_hi)
        ax.set_xticks([])
        ax.set_yticks([])
        for sp in ax.spines.values():
            sp.set_visible(False)

        title = (f"Large-Scale CPS Infrastructure — Round {round_label}  |  "
                 f"RED: {red_action}  BLUE: {blue_action}  |  "
                 f"Tank: {tank_level:.0f}%  Compromised: {total_comp}/{len(asset_ids)}")
        ax.set_title(title, fontsize=11, fontweight="bold", color="#1E2430", pad=10)

        # Legend
        legend_y = y_lo + 0.01
        legend_items = [
            ("#d62728", "Compromised"), ("#54a24b", "OT asset"),
            ("#f58518", "DMZ asset"), ("#4c78a8", "IT asset"),
            ("#111111", "Attacker"),
        ]
        for li, (lc, lt) in enumerate(legend_items):
            lx = x_lo + 0.1 + li * 1.2
            ax.scatter([lx], [legend_y], s=40, c=[lc], edgecolors="black", linewidths=0.4, zorder=5)
            ax.text(lx + 0.06, legend_y, lt, fontsize=6.5, va="center", color="#333")

    def _update(i: int) -> Tuple[Any, ...]:
        _draw_frame(i)
        return tuple()

    anim = _mpl_animation.FuncAnimation(fig, _update, frames=n_frames, interval=int(1000 / max(1, fps)), blit=False)
    if save_path:
        try:
            save_dir = os.path.dirname(os.path.abspath(save_path))
            if save_dir:
                os.makedirs(save_dir, exist_ok=True)
            anim.save(save_path, writer="pillow", fps=fps)
            _log_info("[OK] Saved large topology animation to %s", save_path)
        except Exception as e:
            _log_warn("Large topology animation save failed: %s", e)
    if show:
        plt.show()
    else:
        plt.close(fig)
    return anim


def _plot_large_infrastructure_static(
    infra: Dict[str, Any],
    save_path: Optional[str] = None,
    show: bool = True,
) -> Any:
    """Static publication-quality map of the large-scale infrastructure."""
    topology_assets = infra_to_topology_assets(infra)
    subnets = infra["subnets"]
    subnet_lookup = {s["name"]: s for s in subnets}
    pos = _compute_large_layout(topology_assets, subnets)

    by_subnet: Dict[str, List[str]] = {}
    for a in topology_assets:
        sn = a.get("subnet") or a.get("network") or ""
        by_subnet.setdefault(sn, []).append(a["asset_id"])

    subnet_boxes: Dict[str, Tuple[float, float, float, float]] = {}
    for sn, aids in by_subnet.items():
        xs = [pos[a][0] for a in aids if a in pos]
        ys = [pos[a][1] for a in aids if a in pos]
        if xs and ys:
            pad = 0.08
            subnet_boxes[sn] = (min(xs) - pad, max(xs) + pad, min(ys) - pad, max(ys) + pad)

    fig, ax = plt.subplots(1, 1, figsize=(24.0, 13.0), dpi=80)
    fig.patch.set_facecolor("#f8f9fb")

    for sn, (bx0, bx1, by0, by1) in subnet_boxes.items():
        sinfo = subnet_lookup.get(sn, {})
        sc = sinfo.get("color", "#cccccc")
        ax.fill([bx0, bx1, bx1, bx0, bx0], [by0, by0, by1, by1, by0],
                color=sc, alpha=0.08, linewidth=0)
        ax.plot([bx0, bx1, bx1, bx0, bx0], [by0, by0, by1, by1, by0],
                color=sc, linewidth=1.4, alpha=0.6)
        label = sinfo.get("label", sn)
        cidr = sinfo.get("cidr", "")
        count = len(by_subnet.get(sn, []))
        ax.text((bx0 + bx1) / 2, by1 + 0.02,
                f"{label}\n{cidr} ({count} hosts)",
                ha="center", va="bottom", fontsize=8, fontweight="bold",
                color=sc, alpha=0.9)

    for sn1, sn2 in infra.get("subnet_links", []):
        if sn1 in subnet_boxes and sn2 in subnet_boxes:
            bx1c = (subnet_boxes[sn1][0] + subnet_boxes[sn1][1]) / 2
            by1c = (subnet_boxes[sn1][2] + subnet_boxes[sn1][3]) / 2
            bx2c = (subnet_boxes[sn2][0] + subnet_boxes[sn2][1]) / 2
            by2c = (subnet_boxes[sn2][2] + subnet_boxes[sn2][3]) / 2
            ax.annotate("", xy=(bx2c, by2c), xytext=(bx1c, by1c),
                        arrowprops=dict(arrowstyle="<->", color="#888", lw=1.0, alpha=0.5))

    for a in topology_assets:
        aid = a["asset_id"]
        if aid not in pos:
            continue
        x, y = pos[aid]
        sn = a.get("subnet", "")
        sinfo = subnet_lookup.get(sn, {})
        crit = a.get("criticality", "LOW")
        sz = _CRITICALITY_SIZE.get(crit, 14)
        marker = _KIND_MARKERS.get(a.get("kind", ""), "o")
        c = sinfo.get("color", "#888")
        ax.scatter([x], [y], s=sz, c=[c], marker=marker,
                   edgecolors="black", linewidths=0.3, zorder=3, alpha=0.8)

    # Label high-criticality assets
    for a in topology_assets:
        if a.get("criticality") == "HIGH" and a["asset_id"] in pos:
            x, y = pos[a["asset_id"]]
            ax.text(x + 0.04, y, f"{a['kind']}\n{a['ip']}", fontsize=4.5,
                    va="center", color="#333", alpha=0.7, zorder=4)

    all_x = [p[0] for p in pos.values()]
    all_y = [p[1] for p in pos.values()]
    ax.set_xlim(min(all_x) - 0.3, max(all_x) + 0.5)
    ax.set_ylim(-0.05, 1.12)
    ax.set_xticks([])
    ax.set_yticks([])
    for sp in ax.spines.values():
        sp.set_visible(False)
    ax.set_title(f"CPS Infrastructure Map — {infra['total_ips']} hosts across {len(infra['subnets'])} subnets",
                 fontsize=13, fontweight="bold", color="#1E2430", pad=12)

    plt.tight_layout()
    if save_path:
        out_dir = os.path.dirname(os.path.abspath(save_path))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        fig.savefig(save_path, bbox_inches="tight", dpi=120)
        _log_info("[OK] Saved infrastructure map to %s", save_path)
    if show:
        plt.show()
    else:
        plt.close(fig)
    return fig


def _animate_topology_infra(
    dataset_rows: List[Dict[str, Any]],
    topology_assets: List[Dict[str, Any]],
    save_path: Optional[str] = None,
    show: bool = False,
    dim: str = "2d",
) -> Any:
    if _mpl_animation is None:
        _log_warn("matplotlib animation unavailable; skipping topology animation")
        return None
    if not dataset_rows or not topology_assets:
        return None

    dim_mode = str(dim or "2d").lower()
    if dim_mode not in ("2d", "3d"):
        dim_mode = "2d"

    zone_x = {ZONE_IT: 0.0, ZONE_DMZ: 1.0, ZONE_OT: 2.0}
    kind_z = {"gateway": 0.2, "historian": 0.5, "hmi": 0.8, "plc": 1.1}
    zone_color = {ZONE_IT: "#4c78a8", ZONE_DMZ: "#f58518", ZONE_OT: "#54a24b"}
    kind_tag = {"gateway": "GW", "historian": "HIST", "hmi": "HMI", "plc": "PLC"}
    subnet_palette = ["#6a4c93", "#2a9d8f", "#b56576", "#ff7f50", "#8a7967"]

    assets_by_zone: Dict[str, List[Dict[str, Any]]] = {ZONE_IT: [], ZONE_DMZ: [], ZONE_OT: []}
    for a in topology_assets:
        z = str(a.get("zone") or ZONE_IT)
        if z not in assets_by_zone:
            assets_by_zone[z] = []
        assets_by_zone[z].append(a)

    pos2d: Dict[str, Tuple[float, float]] = {}
    pos3d: Dict[str, Tuple[float, float, float]] = {}
    for z, items in assets_by_zone.items():
        n = max(1, len(items))
        y_vals = np.linspace(0.2, 0.9, n)
        for i, a in enumerate(items):
            aid = str(a.get("asset_id"))
            x = zone_x.get(z, 0.0)
            y = float(y_vals[i])
            pos2d[aid] = (x, y)
            z3 = kind_z.get(str(a.get("kind") or ""), 0.3)
            pos3d[aid] = (x, y, z3)

    asset_ids = [str(a.get("asset_id")) for a in topology_assets]
    asset_network = {str(a.get("asset_id")): str(a.get("network") or "") for a in topology_assets}
    subnet_groups: Dict[str, List[str]] = {}
    for aid, net in asset_network.items():
        if not net:
            continue
        subnet_groups.setdefault(net, []).append(aid)

    subnet_links: List[Tuple[str, str, str]] = []
    subnet_color: Dict[str, str] = {}
    for i, (net, members) in enumerate(sorted(subnet_groups.items())):
        subnet_color[net] = subnet_palette[i % len(subnet_palette)]
        ordered = sorted(members)
        if len(ordered) >= 2:
            for j in range(len(ordered) - 1):
                subnet_links.append((ordered[j], ordered[j + 1], net))

    comp_timeline = _infer_compromised_timeline(dataset_rows, asset_ids)

    def _safe_round_value(raw: Any, default_val: float) -> float:
        try:
            val = float(raw)
            return val if np.isfinite(val) else float(default_val)
        except Exception:
            return float(default_val)

    rounds = np.asarray([
        _safe_round_value(r.get("round", i + 1), float(i + 1))
        for i, r in enumerate(dataset_rows)
    ], dtype=float)
    n_frames = len(dataset_rows)

    if dim_mode == "3d":
        try:
            fig = plt.figure(figsize=(11.0, 6.4), dpi=FIG_DPI)
            ax = fig.add_subplot(1, 1, 1, projection="3d")
        except Exception:
            _log_warn("3D projection unavailable; falling back to 2D topology animation")
            dim_mode = "2d"
            fig, ax = plt.subplots(1, 1, figsize=(11.0, 6.0), dpi=FIG_DPI)
    else:
        fig, ax = plt.subplots(1, 1, figsize=(11.0, 6.0), dpi=FIG_DPI)

    def _draw_frame(i: int) -> None:
        ax.clear()
        idx = min(i, n_frames - 1)
        row = dataset_rows[idx]
        comp = comp_timeline[idx]
        round_label = int(rounds[idx]) if np.isfinite(rounds[idx]) else (idx + 1)
        attacker_zone = str(row.get("attacker_zone") or ZONE_IT)
        red_target = str(row.get("red_target") or "")
        blue_target = str(row.get("blue_target") or "")

        if dim_mode == "3d":
            for a1, a2, net in subnet_links:
                if a1 not in pos3d or a2 not in pos3d:
                    continue
                x1, y1, z1 = pos3d[a1]
                x2, y2, z2 = pos3d[a2]
                cnet = subnet_color.get(net, "#888")
                ax.plot([x1, x2], [y1, y2], [z1, z2], color=cnet, linewidth=1.3, alpha=0.55)
                mx, my, mz = (x1 + x2) / 2.0, (y1 + y2) / 2.0, (z1 + z2) / 2.0
                ax.text(mx, my, mz + 0.03, net, fontsize=6, color=cnet)

            for a in topology_assets:
                aid = str(a.get("asset_id"))
                z = str(a.get("zone") or ZONE_IT)
                kind = str(a.get("kind") or "")
                x, y, z3 = pos3d.get(aid, (0.0, 0.0, 0.0))
                c = "#d62728" if comp.get(aid, False) else zone_color.get(z, "#888")
                ax.scatter([x], [y], [z3], s=140, c=[c], edgecolors="black", linewidths=0.6)
                ip = str(a.get("ip") or "")
                tag = kind_tag.get(kind, "ASSET")
                ax.text(x + 0.02, y, z3 + 0.03, f"[{tag}] {aid}\n{ip}", fontsize=7)

            ax.plot([zone_x[ZONE_IT], zone_x[ZONE_DMZ]], [0.55, 0.55], [0.05, 0.05], linestyle="--", color="#888", linewidth=1.2)
            ax.plot([zone_x[ZONE_DMZ], zone_x[ZONE_OT]], [0.55, 0.55], [0.05, 0.05], linestyle="--", color="#888", linewidth=1.2)

            atk_x = zone_x.get(attacker_zone, 0.0)
            ax.scatter([atk_x], [0.04], [1.3], s=220, marker="*", c="#111111", edgecolors="#f2cf00", linewidths=1.2)
            ax.text(atk_x + 0.03, 0.04, 1.32, f"Attacker@{attacker_zone}", fontsize=8)

            if red_target in pos3d:
                tx, ty, tz = pos3d[red_target]
                ax.plot([atk_x, tx], [0.04, ty], [1.3, tz], color="#d62728", linewidth=1.8)
            if blue_target in pos3d:
                tx, ty, tz = pos3d[blue_target]
                ax.plot([zone_x.get(ZONE_OT, 2.0), tx], [0.97, ty], [1.25, tz], color="#1f77b4", linewidth=1.6)

            ax.set_xlim(-0.3, 2.4)
            ax.set_ylim(0.0, 1.05)
            ax.set_zlim(0.0, 1.45)
            ax.set_xlabel("Zone axis")
            ax.set_ylabel("Asset lane")
            ax.set_zlabel("Layer")
            ax.set_title(f"3D Topology animation — round {round_label}")
        else:
            ax.axvspan(-0.35, 0.35, color=zone_color[ZONE_IT], alpha=0.09)
            ax.axvspan(0.65, 1.35, color=zone_color[ZONE_DMZ], alpha=0.09)
            ax.axvspan(1.65, 2.35, color=zone_color[ZONE_OT], alpha=0.09)

            for a1, a2, net in subnet_links:
                if a1 not in pos2d or a2 not in pos2d:
                    continue
                x1, y1 = pos2d[a1]
                x2, y2 = pos2d[a2]
                cnet = subnet_color.get(net, "#888")
                ax.plot([x1, x2], [y1, y2], color=cnet, linewidth=1.35, alpha=0.6)
                mx, my = (x1 + x2) / 2.0, (y1 + y2) / 2.0
                ax.text(mx, my + 0.03, net, color=cnet, fontsize=7, ha="center")

            for a in topology_assets:
                aid = str(a.get("asset_id"))
                z = str(a.get("zone") or ZONE_IT)
                kind = str(a.get("kind") or "")
                x, y = pos2d.get(aid, (0.0, 0.0))
                c = "#d62728" if comp.get(aid, False) else zone_color.get(z, "#888")
                ax.scatter([x], [y], s=320, c=[c], edgecolors="black", linewidths=0.6)
                ip = str(a.get("ip") or "")
                tag = kind_tag.get(kind, "ASSET")
                ax.text(x + 0.03, y, f"[{tag}] {aid}\n{ip}", fontsize=8, va="center")

            ax.plot([zone_x[ZONE_IT], zone_x[ZONE_DMZ]], [0.55, 0.55], linestyle="--", color="#888", linewidth=1.2)
            ax.plot([zone_x[ZONE_DMZ], zone_x[ZONE_OT]], [0.55, 0.55], linestyle="--", color="#888", linewidth=1.2)
            ax.text(zone_x[ZONE_IT], 0.98, "IT", ha="center", fontsize=9, fontweight="bold")
            ax.text(zone_x[ZONE_DMZ], 0.98, "DMZ", ha="center", fontsize=9, fontweight="bold")
            ax.text(zone_x[ZONE_OT], 0.98, "OT", ha="center", fontsize=9, fontweight="bold")

            atk_x = zone_x.get(attacker_zone, 0.0)
            ax.scatter([atk_x], [0.05], s=260, marker="*", c="#111111", edgecolors="#f2cf00", linewidths=1.2)
            ax.text(atk_x, 0.01, f"Attacker@{attacker_zone}", fontsize=8, ha="center")

            if red_target in pos2d:
                tx, ty = pos2d[red_target]
                ax.annotate("", xy=(tx, ty), xytext=(atk_x, 0.05), arrowprops=dict(arrowstyle="->", color="#d62728", lw=1.8))
            if blue_target in pos2d:
                tx, ty = pos2d[blue_target]
                ax.annotate("", xy=(tx, ty), xytext=(zone_x.get(ZONE_OT, 2.0), 0.95), arrowprops=dict(arrowstyle="->", color="#1f77b4", lw=1.6))

            ax.set_xlim(-0.4, 2.45)
            ax.set_ylim(0.0, 1.05)
            ax.set_xticks([])
            ax.set_yticks([])
            for sp in ax.spines.values():
                sp.set_visible(False)
            ax.set_title(f"2D Topology animation — round {round_label}")

        red_a = str(row.get("red_action") or "NONE")
        blue_a = str(row.get("blue_action") or "NONE")
        fig.suptitle(f"Attacker={red_a}  Defender={blue_a}", fontsize=11, y=0.98)

    def _update(i: int) -> Tuple[Any, ...]:
        _draw_frame(i)
        return tuple()

    anim = _mpl_animation.FuncAnimation(fig, _update, frames=n_frames, interval=260, blit=False)
    if save_path:
        try:
            save_dir = os.path.dirname(os.path.abspath(save_path))
            if save_dir:
                os.makedirs(save_dir, exist_ok=True)
            anim.save(save_path, writer="pillow", fps=4)
            _log_info("[OK] Saved topology animation to %s", save_path)
        except Exception as e:
            _log_warn("Topology animation save failed: %s", e)
    if show:
        plt.show()
    return anim


def plot_run(
    history: Dict[str, List[Any]],
    save_path: Optional[str] = None,
    scenario_count: int = 5,
    dataset_rows: Optional[List[Dict[str, Any]]] = None,
    killchain_plots: bool = True,
    animate: bool = False,
    animate_save_path: Optional[str] = None,
    topology_assets: Optional[List[Dict[str, Any]]] = None,
    topology_animate: bool = False,
    topology_dim: str = "2d",
    topology_save_path: Optional[str] = None,
) -> None:
    # Keep static plot rendering non-interactive when static output path is provided,
    # but allow animations to display if they are not being saved explicitly.
    show_static = save_path is None
    show_timeline = animate_save_path is None
    show_topology = topology_save_path is None

    fig_panel = _plot_publication_grid(history, save_path=save_path, show=show_static)
    fig_story = _plot_scenario_storyboard(history, save_path=None, show=show_static, scenario_count=int(max(1, scenario_count)))
    rows = dataset_rows or []
    kill_figs: List[Any] = []
    if killchain_plots:
        kill_figs = _plot_kill_chain_and_tools(rows, out_dir=None, prefix="run", show=show_static)
    anim_obj = None
    if animate:
        anim_obj = _animate_run_timeline(history, rows, save_path=animate_save_path, show=show_timeline)
    topo_anim_obj = None
    if topology_animate:
        topo_anim_obj = _animate_topology_infra(rows, topology_assets or [], save_path=topology_save_path, show=show_topology, dim=topology_dim)

    if not show_static:
        if fig_panel is not None:
            plt.close(fig_panel)
        if fig_story is not None:
            plt.close(fig_story)
        for f in kill_figs:
            plt.close(f)
        if anim_obj is not None and not show_timeline:
            plt.close("all")
        if topo_anim_obj is not None and not show_topology:
            plt.close("all")


def plot_run_separate(
    history: Dict[str, List[Any]],
    save_path: Optional[str] = None,
    scenario_count: int = 5,
    dataset_rows: Optional[List[Dict[str, Any]]] = None,
    killchain_plots: bool = True,
    animate: bool = False,
    animate_save_path: Optional[str] = None,
    topology_assets: Optional[List[Dict[str, Any]]] = None,
    topology_animate: bool = False,
    topology_dim: str = "2d",
    topology_save_path: Optional[str] = None,
) -> None:
    ctx = _extract_plot_context(history)
    if ctx is None:
        return

    out_dir, prefix = _resolve_plot_output(save_path)
    show_static = out_dir is None
    show_timeline = animate_save_path is None
    show_topology = topology_save_path is None
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    # Main publication-style panel set
    panel_path = os.path.join(out_dir, f"{prefix}_publication_grid.png") if out_dir else None
    fig_panel = _plot_publication_grid(history, save_path=panel_path, show=show_static)

    story_path = os.path.join(out_dir, f"{prefix}_scenario_storyboard.png") if out_dir else None
    fig_story = _plot_scenario_storyboard(
        history,
        save_path=story_path,
        show=show_static,
        scenario_count=int(max(1, scenario_count)),
    )

    # Additional stand-alone diagnostics requested for richer analysis
    extra_figs = _plot_additional_diagnostics(history, out_dir=out_dir, prefix=prefix)
    rows = dataset_rows or []
    kill_figs: List[Any] = []
    if killchain_plots:
        kill_figs = _plot_kill_chain_and_tools(rows, out_dir=out_dir, prefix=prefix, show=show_static)

    anim_obj = None
    if animate:
        anim_path = animate_save_path
        if out_dir and not anim_path:
            anim_path = os.path.join(out_dir, f"{prefix}_timeline.gif")
        anim_obj = _animate_run_timeline(history, rows, save_path=anim_path, show=show_timeline)

    topo_anim_obj = None
    if topology_animate:
        topo_path = topology_save_path
        if out_dir and not topo_path:
            topo_path = os.path.join(out_dir, f"{prefix}_topology_{topology_dim.lower()}.gif")
        topo_anim_obj = _animate_topology_infra(
            rows,
            topology_assets or [],
            save_path=topo_path,
            show=show_topology,
            dim=topology_dim,
        )

    if out_dir or (not show_static):
        if fig_panel is not None:
            plt.close(fig_panel)
        if fig_story is not None:
            plt.close(fig_story)
        for f in extra_figs:
            plt.close(f)
        for f in kill_figs:
            plt.close(f)
        if anim_obj is not None and not show_timeline:
            plt.close("all")
        if topo_anim_obj is not None and not show_topology:
            plt.close("all")


def plot_roc_sweep(
    y_true: List[int],
    y_score: List[float],
    save_path: Optional[str] = None,
) -> None:
    if _sk_roc_curve is None or _sk_auc is None:
        _log_warn("sklearn not installed; skipping ROC plot. Install with: pip install scikit-learn")
        return
    if not y_true:
        return

    fpr, tpr, _ = _sk_roc_curve(np.asarray(y_true, dtype=int), np.asarray(y_score, dtype=float))
    roc_auc = float(_sk_auc(fpr, tpr))

    fig = plt.figure(figsize=(7, 5), dpi=FIG_DPI)
    ax = fig.add_subplot(1, 1, 1)
    ax.plot(fpr, tpr, color=PLOT_COLORS["primary"], linewidth=2, label=f"ROC (AUC={roc_auc:.3f})")
    ax.plot([0, 1], [0, 1], color="#888888", linestyle="--", linewidth=1, label="Chance")
    ax.set_xlim(0.0, 1.0)
    ax.set_ylim(0.0, 1.02)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("Blue Detection ROC (sensitivity sweep)")
    ax.grid(True, alpha=0.35)
    ax.legend(loc="lower right", fontsize=9)
    plt.tight_layout()
    if save_path:
        fig.savefig(save_path, bbox_inches="tight", dpi=FIG_DPI)
        _log_info("[OK] Saved ROC plot to %s", save_path)
    plt.show()


def plot_roc_compare(
    curves: Dict[str, Tuple[List[int], List[float]]],
    save_path: Optional[str] = None,
) -> None:
    if _sk_roc_curve is None or _sk_auc is None:
        _log_warn("sklearn not installed; skipping ROC plot. Install with: pip install scikit-learn")
        return
    if not curves:
        return

    fig = plt.figure(figsize=(7.5, 5.5), dpi=FIG_DPI)
    ax = fig.add_subplot(1, 1, 1)

    palette = [PLOT_COLORS["primary"], PLOT_COLORS["secondary"], PLOT_COLORS["gp"], PLOT_COLORS["flag"], "#9467bd"]
    for i, (name, (y_true, y_score)) in enumerate(curves.items()):
        if not y_true:
            continue
        fpr, tpr, _ = _sk_roc_curve(np.asarray(y_true, dtype=int), np.asarray(y_score, dtype=float))
        roc_auc = float(_sk_auc(fpr, tpr))
        ax.plot(fpr, tpr, color=palette[i % len(palette)], linewidth=2, label=f"{name} (AUC={roc_auc:.3f})")

    ax.plot([0, 1], [0, 1], color="#888888", linestyle="--", linewidth=1, label="Chance")
    ax.set_xlim(0.0, 1.0)
    ax.set_ylim(0.0, 1.02)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("Blue Detection ROC — Algorithm Comparison")
    ax.grid(True, alpha=0.35)
    ax.legend(loc="lower right", fontsize=9)
    plt.tight_layout()
    if save_path:
        fig.savefig(save_path, bbox_inches="tight", dpi=FIG_DPI)
        _log_info("[OK] Saved ROC plot to %s", save_path)
    plt.show()


def _score_original(base: float, sensitivity: float) -> float:
    return float(min(ALERT_PROB_CAP, base * (0.75 + sensitivity)))


def _score_logistic(base: float, sensitivity: float) -> float:
    x = (base - 0.45) * 4.0 + (sensitivity - 0.55) * 2.0
    return float(min(ALERT_PROB_CAP, max(0.0, sigmoid(x))))


def _score_quadratic(base: float, sensitivity: float) -> float:
    return float(min(ALERT_PROB_CAP, max(0.0, (base ** 2) * (0.5 + sensitivity))))


def _score_zone_weighted(base: float, sensitivity: float, attacker_zone: str) -> float:
    z = (attacker_zone or "").upper()
    zone_mult = 1.0
    if z == ZONE_DMZ:
        zone_mult = 1.1
    elif z == ZONE_OT:
        zone_mult = 1.25
    return float(min(ALERT_PROB_CAP, max(0.0, base * zone_mult * (0.65 + sensitivity))))


def _severity_for_red_action(action: str, result: str) -> Optional[str]:
    a = (action or "").upper()
    r = (result or "").upper()
    if a == "RECON":
        return SEVERITY_LOW
    if a in ("BRUTE", "EXECUTE"):
        if "SUCCESS" in r:
            return SEVERITY_HIGH
        return SEVERITY_MED
    if a == "EXPLOIT":
        if "SUCCESS" in r:
            return SEVERITY_HIGH
        if "PATCHED" in r or "HARDENED" in r:
            return SEVERITY_MED
        return SEVERITY_MED
    if a == "PIVOT":
        if "OT" in r:
            return SEVERITY_CRIT
        if "DMZ" in r:
            return SEVERITY_HIGH
        return SEVERITY_MED
    if a == "IMPACT":
        return SEVERITY_CRIT
    if a == "PHISH":
        return SEVERITY_MED
    return None


def _action_meta(catalog: Dict[str, Dict[str, str]], action: Any) -> Dict[str, str]:
    key = str(action or "").upper()
    m = catalog.get(key, {})
    return {
        "phase": str(m.get("phase", "Unknown")),
        "ttp": str(m.get("ttp", "N/A")),
        "tool": str(m.get("tool", "generic tool")),
    }


def _choose_killchain_red_action(env: "CPSRange") -> Dict[str, Any]:
    """Deterministic kill-chain red agent: IT→DMZ→OT→PLC IMPACT.

    Phases:
      1) RECON (rounds 1-3)
      2) Gain foothold on DMZ assets via EXPLOIT/BRUTE (rounds 4-12)
      3) EXECUTE for ADMIN on DMZ, COVER tracks (rounds 13-18)
      4) PIVOT to DMZ zone (rounds 19-22)
      5) Exploit OT-reachable assets: HMI via BRUTE/EXPLOIT (rounds 23-35)
      6) PIVOT to OT, EXECUTE for OT ADMIN (rounds 36-45)
      7) Compromise PLC: EXPLOIT + EXECUTE for PLC ADMIN (rounds 46-55)
      8) IMPACT: cycle SENSOR_SPOOF / OVERFLOW / DRAIN (rounds 56+)
    Intersperse COVER every ~5 rounds to degrade blue sensitivity.
    """
    r = env.round
    plc = env.assets.get(PLC_ASSET_ID)
    hmi = env.assets.get("hmi_ops_01")
    gw = env.assets.get("gw_dmz_01")
    hist = env.assets.get("hist_data_01")

    # --- Helper: find reachable exposed services ---
    def _reachable_services(target_id: str) -> List[str]:
        asset = env.assets.get(target_id)
        if not asset or asset.isolated:
            return []
        if not env._reachable(env.attacker_zone, asset.zone):
            return []
        return [s for s, svc in asset.services.items() if svc.exposed and not svc.patched]

    # --- COVER every 5 rounds to degrade blue sensitivity ---
    if r > 3 and r % 5 == 0 and random.random() < 0.6:
        return {"action": "COVER", "target": "NONE", "service": "NONE", "params": {}}

    # --- Phase 8: IMPACT (PLC is ADMIN-compromised) ---
    if plc and plc.compromised and plc.privilege == "ADMIN":
        modes = ["SENSOR_SPOOF", "OVERFLOW", "DRAIN"]
        mode = modes[(r // 3) % len(modes)]  # cycle through modes
        return {"action": "IMPACT", "target": PLC_ASSET_ID, "service": "NONE", "params": {"mode": mode}}

    # --- Phase 7: Get PLC ADMIN ---
    if plc and plc.compromised and plc.privilege != "ADMIN":
        return {"action": "EXECUTE", "target": PLC_ASSET_ID, "service": "NONE", "params": {}}

    # --- Phase 6b: Exploit PLC ---
    if env.attacker_zone == ZONE_OT and plc and not plc.compromised:
        plc_svcs = _reachable_services(PLC_ASSET_ID)
        if plc_svcs:
            svc = random.choice(plc_svcs)
            action = random.choice(["EXPLOIT", "BRUTE"])
            return {"action": action, "target": PLC_ASSET_ID, "service": svc, "params": {}}
        # PLC services not exposed directly, try via modbus (no auth)
        if "modbus" in (plc.services if plc else {}):
            return {"action": "EXPLOIT", "target": PLC_ASSET_ID, "service": "modbus", "params": {}}

    # --- Phase 6a: PIVOT to OT via compromised OT asset ---
    ot_compromised = [aid for aid, a in env.assets.items() if a.compromised and a.zone == ZONE_OT]
    if ot_compromised and env.attacker_zone != ZONE_OT:
        return {"action": "PIVOT", "target": ot_compromised[0], "service": "NONE", "params": {}}

    # --- Phase 5: Get OT foothold (HMI) - need ADMIN on DMZ first ---
    dmz_admin = [aid for aid, a in env.assets.items() if a.compromised and a.privilege == "ADMIN" and a.zone == ZONE_DMZ]
    if env.attacker_zone == ZONE_DMZ and hmi and not hmi.compromised:
        hmi_svcs = _reachable_services("hmi_ops_01")
        if hmi_svcs:
            svc = random.choice(hmi_svcs)
            return {"action": random.choice(["EXPLOIT", "BRUTE"]), "target": "hmi_ops_01", "service": svc, "params": {}}
        # HMI rdp may not be exposed; try BRUTE anyway (weak_creds)
        if "rdp" in hmi.services and hmi.services["rdp"].weak_creds:
            return {"action": "BRUTE", "target": "hmi_ops_01", "service": "rdp", "params": {}}

    # --- Phase 5b: EXECUTE for OT ADMIN ---
    if hmi and hmi.compromised and hmi.privilege != "ADMIN":
        return {"action": "EXECUTE", "target": "hmi_ops_01", "service": "NONE", "params": {}}

    # --- Phase 4: PIVOT to DMZ ---
    dmz_compromised = [aid for aid, a in env.assets.items() if a.compromised and a.zone == ZONE_DMZ]
    if dmz_compromised and env.attacker_zone != ZONE_DMZ:
        return {"action": "PIVOT", "target": dmz_compromised[0], "service": "NONE", "params": {}}

    # --- Phase 3: EXECUTE for ADMIN on DMZ assets ---
    dmz_user = [aid for aid, a in env.assets.items()
                if a.compromised and a.privilege != "ADMIN" and a.zone == ZONE_DMZ]
    if dmz_user:
        return {"action": "EXECUTE", "target": dmz_user[0], "service": "NONE", "params": {}}

    # --- Phase 2: Exploit DMZ assets ---
    if not dmz_compromised:
        for target_id in ["gw_dmz_01", "hist_data_01"]:
            svcs = _reachable_services(target_id)
            if svcs:
                svc = random.choice(svcs)
                action = random.choice(["EXPLOIT", "BRUTE"])
                return {"action": action, "target": target_id, "service": svc, "params": {}}

    # --- Phase 1: RECON ---
    return {"action": "RECON", "target": "NONE", "service": "NONE", "params": {}}


def _choose_reactive_blue_action(env: "CPSRange") -> Dict[str, Any]:
    """Reactive blue agent: monitors, patches, isolates, restores based on threat level.

    Strategy:
    - Early rounds: MONITOR + occasional HARDEN/PATCH
    - When compromises detected: RESTORE compromised assets (prioritize PLC)
    - When attacker in OT: ISOLATE critical OT assets
    - Periodically TUNE sensitivity upward
    - Patch unpatched services on critical assets
    """
    r = env.round
    compromised = [(aid, a) for aid, a in env.assets.items() if a.compromised]
    comp_ids = [aid for aid, _ in compromised]

    # Priority 1: Restore PLC if compromised
    plc = env.assets.get(PLC_ASSET_ID)
    if plc and plc.compromised:
        return {"action": "RESTORE", "target": PLC_ASSET_ID, "service": "NONE", "params": {}}

    # Priority 2: Isolate gateway if attacker is in OT
    if env.attacker_zone == ZONE_OT:
        gw = env.assets.get("gw_dmz_01")
        if gw and not gw.isolated:
            return {"action": "ISOLATE", "target": "gw_dmz_01", "service": "NONE", "params": {}}

    # Priority 3: Restore other compromised assets
    if compromised and random.random() < 0.7:
        # Prioritize OT assets
        ot_comp = [aid for aid, a in compromised if a.zone == ZONE_OT]
        if ot_comp:
            return {"action": "RESTORE", "target": ot_comp[0], "service": "NONE", "params": {}}
        return {"action": "RESTORE", "target": comp_ids[0], "service": "NONE", "params": {}}

    # Priority 4: Patch unpatched services on critical assets
    if r % 4 == 0:
        for aid in [PLC_ASSET_ID, "hmi_ops_01", "gw_dmz_01"]:
            asset = env.assets.get(aid)
            if not asset:
                continue
            for sname, svc in asset.services.items():
                if not svc.patched and svc.vuln_id:
                    return {"action": "PATCH", "target": aid, "service": sname, "params": {}}

    # Priority 5: Harden assets periodically
    if r % 7 == 0:
        for aid in [PLC_ASSET_ID, "hmi_ops_01"]:
            asset = env.assets.get(aid)
            if asset and not asset.hardened:
                return {"action": "HARDEN", "target": aid, "service": "NONE", "params": {}}

    # Priority 6: Tune sensitivity up when alerts are accumulating
    if len(env.alerts) > r * 0.3 and env.blue_sensitivity < 0.8:
        new_sens = min(BLUE_SENSITIVITY_MAX, env.blue_sensitivity + 0.1)
        return {"action": "TUNE", "target": "NONE", "service": "NONE", "params": {"sensitivity": new_sens}}

    # Default: MONITOR
    return {"action": "MONITOR", "target": "NONE", "service": "NONE", "params": {}}


def _apply_passive_compromise_effects(env: "CPSRange") -> None:
    """Apply passive physical effects from compromised OT assets.

    This is the CRITICAL missing piece: compromised OT assets should cause
    ongoing physical degradation even without explicit IMPACT actions.

    Effects:
    - Compromised HMI (any priv): sensor noise ±2%, occasional false readings
    - Compromised PLC (USER): sensor drift +1.5%/round, small pump perturbation
    - Compromised PLC (ADMIN, no active IMPACT): larger drift, valve perturbation
    - Any OT compromise: random small level perturbation ±0.5%
    """
    hmi = env.assets.get("hmi_ops_01")
    plc = env.assets.get(PLC_ASSET_ID)

    # HMI compromised → sensor noise injection
    if hmi and hmi.compromised:
        noise = random.gauss(0, 2.5)
        env.tank.level += noise
        if random.random() < 0.15:
            env.tank.sensor_ok = False  # intermittent sensor spoofing

    # PLC compromised with USER access → sensor drift + small pump perturbation
    if plc and plc.compromised and plc.privilege == "USER":
        env.tank.level += random.uniform(0.5, 2.0)  # upward drift
        if random.random() < 0.2:
            env.tank.pump_cmd = TANK_PUMP_FORCE_ON  # brief pump perturbation

    # PLC compromised with ADMIN → stronger effects (even without explicit IMPACT)
    if plc and plc.compromised and plc.privilege == "ADMIN":
        logic_hash = plc.notes.get("logic_hash", "SAFE_v1")
        if "MAL" not in logic_hash:
            # Stealthy pre-IMPACT degradation
            env.tank.level += random.uniform(1.0, 3.5)
            if random.random() < 0.3:
                env.tank.valve_cmd = TANK_VALVE_FORCE_CLOSED
            if random.random() < 0.25:
                env.tank.pump_cmd = TANK_PUMP_FORCE_ON
            if random.random() < 0.1:
                env.tank.sensor_ok = False

    # Any OT asset compromised → background perturbation
    ot_comp_count = sum(1 for a in env.assets.values() if a.compromised and a.zone == ZONE_OT)
    if ot_comp_count > 0:
        env.tank.level += random.uniform(-0.5, 0.5) * ot_comp_count

    env.tank.level = max(0.0, min(100.0, env.tank.level))


def _choose_scripted_red_action(env: "CPSRange") -> Dict[str, Any]:
    a = random.choice(["RECON", "BRUTE", "EXPLOIT", "PIVOT", "EXECUTE"])
    if a == "RECON":
        return {"action": "RECON", "target": "NONE", "service": "NONE", "params": {}}

    candidates: List[Tuple[str, str]] = []
    for aid, asset in env.assets.items():
        if asset.isolated:
            continue
        if not env._reachable(env.attacker_zone, asset.zone):
            continue
        for sname, svc in asset.services.items():
            if svc.exposed and (a in ("BRUTE", "EXPLOIT") or sname != "NONE"):
                candidates.append((aid, sname))
    if not candidates:
        return {"action": "RECON", "target": "NONE", "service": "NONE", "params": {}}
    target, service = random.choice(candidates)

    if a == "PIVOT":
        target = random.choice(list(env.assets.keys()))
        service = "NONE"
    if a == "EXECUTE":
        target = random.choice(list(env.assets.keys()))
        service = "NONE"

    return {"action": a, "target": target, "service": service, "params": {}}


def _choose_scripted_blue_action(env: "CPSRange") -> Dict[str, Any]:
    compromised = [aid for aid, a in env.assets.items() if a.compromised]
    if compromised:
        t = compromised[0]
        return {"action": "RESTORE", "target": t, "service": "NONE", "params": {}}

    if env.attacker_zone == ZONE_DMZ and random.random() < 0.6:
        return {"action": "ISOLATE", "target": "gw_dmz_01", "service": "NONE", "params": {}}

    if random.random() < 0.35:
        return {"action": "PATCH", "target": "gw_dmz_01", "service": "ssh", "params": {}}
    return {"action": "MONITOR", "target": "NONE", "service": "NONE", "params": {}}


def _choose_random_blue_action(env: "CPSRange") -> Dict[str, Any]:
    _ = env
    action = random.choice(["MONITOR", "PATCH", "ISOLATE", "RESTORE"])
    if action == "MONITOR":
        return {"action": "MONITOR", "target": "NONE", "service": "NONE", "params": {}}
    if action == "PATCH":
        return {"action": "PATCH", "target": "gw_dmz_01", "service": "ssh", "params": {}}
    if action == "ISOLATE":
        return {"action": "ISOLATE", "target": "gw_dmz_01", "service": "NONE", "params": {}}
    compromised = [aid for aid, a in env.assets.items() if a.compromised]
    tgt = compromised[0] if compromised else "hmi_ops_01"
    return {"action": "RESTORE", "target": tgt, "service": "NONE", "params": {}}


def _choose_safety_blue_action(env: "CPSRange") -> Dict[str, Any]:
    if env.tank.level < TANK_LEVEL_SAFE_LOW or env.tank.level > TANK_LEVEL_SAFE_HIGH:
        return {"action": "RESTORE", "target": PLC_ASSET_ID, "service": "NONE", "params": {}}
    compromised = [aid for aid, a in env.assets.items() if a.compromised]
    if compromised:
        return {"action": "RESTORE", "target": compromised[0], "service": "NONE", "params": {}}
    if env.attacker_zone in (ZONE_DMZ, ZONE_OT):
        return {"action": "ISOLATE", "target": "gw_dmz_01", "service": "NONE", "params": {}}
    return {"action": "MONITOR", "target": "NONE", "service": "NONE", "params": {}}


def _choose_benchmark_blue_action(mode: str, env: "CPSRange") -> Dict[str, Any]:
    m = (mode or "monitor").strip().lower()
    if m == "scripted":
        return _choose_scripted_blue_action(env)
    if m == "random":
        return _choose_random_blue_action(env)
    if m == "safety":
        return _choose_safety_blue_action(env)
    return {"action": "MONITOR", "target": "NONE", "service": "NONE", "params": {}}


def _choose_benchmark_red_action(mode: str, env: "CPSRange") -> Dict[str, Any]:
    m = (mode or "scripted").strip().lower()
    if m == "random":
        return env.random_action("RED")
    return _choose_scripted_red_action(env)


def _choose_aggressive_red_action(env: "CPSRange") -> Dict[str, Any]:
    """Aggressive attacker: skips RECON quickly, favors EXPLOIT/EXECUTE/IMPACT."""
    plc = env.assets.get(PLC_ASSET_ID)
    if plc and plc.compromised and plc.privilege == "ADMIN":
        mode = random.choice(["OVERFLOW", "DRAIN", "SENSOR_SPOOF"])
        return {"action": "IMPACT", "target": PLC_ASSET_ID, "service": "NONE", "params": {"mode": mode}}
    compromised = [aid for aid, a in env.assets.items() if a.compromised]
    if compromised:
        if any(env.assets[c].zone == ZONE_OT for c in compromised):
            return {"action": "EXECUTE", "target": PLC_ASSET_ID, "service": "NONE", "params": {}}
        dmz_comp = [c for c in compromised if env.assets[c].zone == ZONE_DMZ]
        if dmz_comp:
            return {"action": "PIVOT", "target": dmz_comp[0], "service": "NONE", "params": {}}
        return {"action": "EXECUTE", "target": compromised[0], "service": "NONE", "params": {}}
    candidates: List[Tuple[str, str]] = []
    for aid, asset in env.assets.items():
        if asset.isolated or not env._reachable(env.attacker_zone, asset.zone):
            continue
        for sname, svc in asset.services.items():
            if svc.exposed and not svc.patched:
                candidates.append((aid, sname))
    if candidates:
        t, s = random.choice(candidates)
        return {"action": random.choice(["EXPLOIT", "BRUTE"]), "target": t, "service": s, "params": {}}
    return {"action": "RECON", "target": "NONE", "service": "NONE", "params": {}}


def _choose_stealthy_red_action(env: "CPSRange", start_round: int = 30) -> Dict[str, Any]:
    """Stealthy attacker: passive until start_round, then slow methodical progression."""
    if env.round < start_round:
        if random.random() < 0.7:
            return {"action": "RECON", "target": "NONE", "service": "NONE", "params": {}}
        return {"action": "COVER", "target": "NONE", "service": "NONE", "params": {}}
    plc = env.assets.get(PLC_ASSET_ID)
    if plc and plc.compromised and plc.privilege == "ADMIN" and random.random() < 0.4:
        return {"action": "IMPACT", "target": PLC_ASSET_ID, "service": "NONE", "params": {"mode": "SENSOR_SPOOF"}}
    return _choose_scripted_red_action(env)


# ============================================================
# SCENARIO COMPARISON: attack variants + GP ablation
# ============================================================
COMPARISON_ATTACK_SCENARIOS: List[Dict[str, Any]] = [
    {"name": "Baseline (scripted)", "red_mode": "scripted", "blue_mode": "scripted",
     "active_probe": True, "probe_every": 3, "gp_enabled": True,
     "color": "#174A7E", "linestyle": "-"},
    {"name": "Aggressive attack", "red_mode": "aggressive", "blue_mode": "scripted",
     "active_probe": True, "probe_every": 3, "gp_enabled": True,
     "color": "#C44536", "linestyle": "-"},
    {"name": "Stealthy attack", "red_mode": "stealthy", "blue_mode": "scripted",
     "active_probe": True, "probe_every": 3, "gp_enabled": True,
     "color": "#5A3E9A", "linestyle": "--"},
    {"name": "No GP defense", "red_mode": "scripted", "blue_mode": "monitor",
     "active_probe": False, "probe_every": 999, "gp_enabled": False,
     "color": "#A5792A", "linestyle": "-."},
]

COMPARISON_GP_ABLATIONS: List[Dict[str, Any]] = [
    {"name": "GP + active probe (ours)", "red_mode": "scripted", "blue_mode": "scripted",
     "active_probe": True, "probe_every": 3, "gp_enabled": True,
     "color": "#174A7E", "linestyle": "-"},
    {"name": "GP + random probe", "red_mode": "scripted", "blue_mode": "scripted",
     "active_probe": True, "probe_every": 3, "gp_enabled": True, "random_probe": True,
     "color": "#197278", "linestyle": "--"},
    {"name": "GP passive (no probe)", "red_mode": "scripted", "blue_mode": "scripted",
     "active_probe": False, "probe_every": 999, "gp_enabled": True,
     "color": "#C44536", "linestyle": "-."},
]


def _run_single_scenario(
    scenario: Dict[str, Any],
    seed: int,
    max_rounds: int,
    stealthy_start: int = 30,
    neural_sim: Optional[Any] = None,
) -> Dict[str, List[Any]]:
    """Run one scenario variant and return its per-round history dict."""
    env = CPSRange(seed=seed, max_rounds=max_rounds)
    red_mode = str(scenario.get("red_mode", "scripted"))
    blue_mode = str(scenario.get("blue_mode", "scripted"))
    active_probe = bool(scenario.get("active_probe", False))
    probe_every = int(max(1, int(scenario.get("probe_every", 3))))
    gp_enabled = bool(scenario.get("gp_enabled", True))
    random_probe_mode = bool(scenario.get("random_probe", False))

    while True:
        env.round += 1
        policy_choice = ""

        if active_probe and (env.round % probe_every == 0):
            if random_probe_mode:
                cand = env.policy.candidates
                chosen = random.choice(cand)
                env.tank.pump_cmd = chosen["pump_cmd"]
                env.tank.valve_cmd = chosen["valve_cmd"]
                policy_choice = f"PROBE:{chosen['name']}"
            else:
                probe = env.policy.select(env.mogp, env.tank, env.attacker_zone)
                env.tank.pump_cmd = probe["pump_cmd"]
                env.tank.valve_cmd = probe["valve_cmd"]
                policy_choice = f"PROBE:{probe.get('name', '')}"

        prev_level = float(env.tank.level)

        if red_mode == "aggressive":
            red_act = _choose_aggressive_red_action(env)
        elif red_mode == "stealthy":
            red_act = _choose_stealthy_red_action(env, start_round=stealthy_start)
        elif red_mode == "random":
            red_act = env.random_action("RED")
        else:
            red_act = _choose_scripted_red_action(env)
        red_res = env.execute_action("RED", red_act)

        blue_act = _choose_benchmark_blue_action(blue_mode, env)
        blue_res = env.execute_action("BLUE", blue_act)

        # Critical: Apply passive compromise effects before physics update
        _apply_passive_compromise_effects(env)
        env.update_physics()

        delta_level = float(env.tank.level) - prev_level
        alarm_target = 1.0 if env.tank.alarm else 0.0
        damage_target = 1.0 if env.tank.damage else 0.0  # Consistent binary target

        is_int = policy_choice.startswith("PROBE:")  # Clean causal do(u) dataset

        if gp_enabled:
            u_now = {"pump_cmd": env.tank.pump_cmd, "valve_cmd": env.tank.valve_cmd}
            z = encode_z(env.tank, env.attacker_zone, u_now)
            x_snap = {
                "level": prev_level, "pump_cmd": env.tank.pump_cmd,
                "valve_cmd": env.tank.valve_cmd, "sensor_ok": env.tank.sensor_ok,
                "safety_interlock": env.tank.safety_interlock,
                "attacker_zone": env.attacker_zone,
                "alarm_flag": alarm_target, "damage_flag": 1.0 if env.tank.damage else 0.0,
            }
            y_vec = np.array([delta_level, alarm_target, damage_target], dtype=float)
            env.causal.add_sample(z=z, y_vec=y_vec, is_interventional=is_int, x_snapshot=x_snap)
            x_all, y_all = env.causal.combined()
            env.mogp.fit(x_all, y_all)

        gp_p_alarm = 0.0
        gp_p_damage = 0.0
        if gp_enabled and env.mogp.ready:
            u_now = {"pump_cmd": env.tank.pump_cmd, "valve_cmd": env.tank.valve_cmd}
            z_now = encode_z(env.tank, env.attacker_zone, u_now).reshape(1, -1)
            pred = env.mogp.predict(z_now)
            mu_a, _ = pred["alarm"]
            mu_d, _ = pred["damage"]
            gp_p_alarm = env.mogp.prob_alarm(float(mu_a[0]))
            gp_p_damage = env.mogp.prob_damage(float(mu_d[0]))

        env.record_history(gp_p_alarm=gp_p_alarm, gp_p_damage=gp_p_damage, policy_choice=policy_choice)

        done, _ = env.scenario_done()
        if done:
            break

    return dict(env.history)


def run_scenario_comparison(
    seeds: int = 3,
    max_rounds: int = 100,
    scenarios: Optional[List[Dict[str, Any]]] = None,
    ablations: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Run attack-scenario and GP-ablation comparisons, averaging over seeds."""
    attack_scenarios = scenarios or COMPARISON_ATTACK_SCENARIOS
    gp_ablations = ablations or COMPARISON_GP_ABLATIONS

    def _avg_histories(scenario: Dict[str, Any], n_seeds: int) -> Dict[str, np.ndarray]:
        all_runs: List[Dict[str, List[Any]]] = []
        for s in range(n_seeds):
            h = _run_single_scenario(scenario, seed=5000 + s, max_rounds=max_rounds)
            all_runs.append(h)
        max_len = max(len(h.get("round", [])) for h in all_runs)
        if max_len == 0:
            return {}
        keys = ["tank_level", "alerts_total", "compromised_count", "alarm_flag",
                "damage_flag", "gp_p_alarm", "gp_p_damage"]
        result: Dict[str, np.ndarray] = {"round": np.arange(1, max_len + 1, dtype=float)}
        for key in keys:
            padded = []
            for h in all_runs:
                vals = list(h.get(key, []))
                if len(vals) < max_len:
                    fill = vals[-1] if vals else 0.0
                    vals.extend([fill] * (max_len - len(vals)))
                padded.append(np.asarray(vals[:max_len], dtype=float))
            stacked = np.vstack(padded)
            result[f"{key}_mean"] = np.mean(stacked, axis=0)
            result[f"{key}_std"] = np.std(stacked, axis=0)
        policy_runs = []
        for h in all_runs:
            pc = list(h.get("policy_choice", []))
            if len(pc) < max_len:
                pc.extend([""] * (max_len - len(pc)))
            policy_runs.append([1.0 if str(p).startswith("PROBE:") else 0.0 for p in pc[:max_len]])
        probe_arr = np.vstack(policy_runs)
        result["probe_mean"] = np.mean(probe_arr, axis=0)
        safe_runs = []
        for h in all_runs:
            lvl = np.asarray(list(h.get("tank_level", [])), dtype=float)
            if len(lvl) < max_len:
                lvl = np.concatenate([lvl, np.full(max_len - len(lvl), lvl[-1] if len(lvl) > 0 else 50.0)])
            s = ((lvl[:max_len] >= TANK_LEVEL_SAFE_LOW) & (lvl[:max_len] <= TANK_LEVEL_SAFE_HIGH)).astype(float)
            safe_runs.append(s)
        safe_arr = np.vstack(safe_runs)
        result["safe_mean"] = np.mean(safe_arr, axis=0)
        return result

    _log_info("[..] Running scenario comparison: %d attack scenarios × %d seeds", len(attack_scenarios), seeds)
    attack_results = []
    for sc in attack_scenarios:
        _log_info("  Running: %s ...", sc["name"])
        avg = _avg_histories(sc, seeds)
        attack_results.append({"scenario": sc, "data": avg})

    _log_info("[..] Running GP ablation comparison: %d variants × %d seeds", len(gp_ablations), seeds)
    ablation_results = []
    for ab in gp_ablations:
        _log_info("  Running: %s ...", ab["name"])
        avg = _avg_histories(ab, seeds)
        ablation_results.append({"scenario": ab, "data": avg})

    return {"attack": attack_results, "ablation": ablation_results}


def _plot_scenario_comparison(
    comparison: Dict[str, Any],
    save_path: Optional[str] = None,
    show: bool = True,
) -> Any:
    """Publication-quality 2×3 overlay comparison figure."""
    attack_results = comparison.get("attack", [])
    ablation_results = comparison.get("ablation", [])

    fig, axes = plt.subplots(2, 3, figsize=(17.5, 9.4), dpi=FIG_DPI)
    fig.patch.set_facecolor("#fcfcfd")
    fig.suptitle("Scenario Comparison: Attack Variants & GP Ablation Study",
                 fontsize=14.5, fontweight="bold", y=1.01)

    # --- Row 1: Attack scenario comparison (3 panels) ---
    # Panel 1: Empirical safety P(safe)
    ax = axes[0, 0]
    for entry in attack_results:
        sc = entry["scenario"]
        d = entry["data"]
        if not d:
            continue
        r = d["round"]
        safe_mean = d.get("safe_mean", np.ones_like(r))
        emp_safe = np.cumsum(safe_mean) / np.arange(1, len(safe_mean) + 1)
        ax.plot(r, emp_safe, color=sc["color"], linestyle=sc["linestyle"],
                linewidth=2.0, label=sc["name"])
    ax.axhline(SAFETY_THRESHOLD_DEFAULT, color="#596273", linestyle="--", linewidth=0.95, alpha=0.85)
    ax.set_ylim(0.0, 1.02)
    _style_axis(ax, "Empirical safety probability", "Round", r"$P_{safe}(t)$")
    ax.legend(loc="lower left", fontsize=7.2, frameon=False, ncol=1)

    # Panel 2: Alert accumulation
    ax = axes[0, 1]
    for entry in attack_results:
        sc = entry["scenario"]
        d = entry["data"]
        if not d:
            continue
        r = d["round"]
        ax.plot(r, d.get("alerts_total_mean", np.zeros_like(r)),
                color=sc["color"], linestyle=sc["linestyle"], linewidth=2.0, label=sc["name"])
    _style_axis(ax, "Alert accumulation", "Round", "Total alerts")
    ax.legend(loc="upper left", fontsize=7.2, frameon=False, ncol=1)

    # Panel 3: GP damage-risk probability
    ax = axes[0, 2]
    for entry in attack_results:
        sc = entry["scenario"]
        d = entry["data"]
        if not d:
            continue
        r = d["round"]
        mu = d.get("gp_p_damage_mean", np.zeros_like(r))
        sd = d.get("gp_p_damage_std", np.zeros_like(r))
        ax.plot(r, mu, color=sc["color"], linestyle=sc["linestyle"], linewidth=2.0, label=sc["name"])
        ax.fill_between(r, np.clip(mu - sd, 0, 1), np.clip(mu + sd, 0, 1),
                        color=sc["color"], alpha=0.10)
    ax.axhline(0.25, color="#596273", linestyle=":", linewidth=0.9, alpha=0.7, label="Damage threshold")
    ax.set_ylim(0.0, 1.02)
    _style_axis(ax, "GP damage-risk prediction", "Round", r"$P_{damage}(t)$")
    ax.legend(loc="upper left", fontsize=7.2, frameon=False, ncol=1)

    # --- Row 2: GP ablation comparison (3 panels) ---
    # Panel 4: Empirical safety (ablation)
    ax = axes[1, 0]
    for entry in ablation_results:
        sc = entry["scenario"]
        d = entry["data"]
        if not d:
            continue
        r = d["round"]
        safe_mean = d.get("safe_mean", np.ones_like(r))
        emp_safe = np.cumsum(safe_mean) / np.arange(1, len(safe_mean) + 1)
        ax.plot(r, emp_safe, color=sc["color"], linestyle=sc["linestyle"],
                linewidth=2.0, label=sc["name"])
    ax.axhline(SAFETY_THRESHOLD_DEFAULT, color="#596273", linestyle="--", linewidth=0.95, alpha=0.85)
    ax.set_ylim(0.0, 1.02)
    _style_axis(ax, "Safety: GP ablation study", "Round", r"$P_{safe}(t)$")
    ax.legend(loc="lower left", fontsize=7.2, frameon=False, ncol=1)

    # Panel 5: Intervention load (ablation)
    ax = axes[1, 1]
    for entry in ablation_results:
        sc = entry["scenario"]
        d = entry["data"]
        if not d:
            continue
        r = d["round"]
        probe_mean = d.get("probe_mean", np.zeros_like(r))
        cum_probe = np.cumsum(probe_mean)
        ax.plot(r, cum_probe, color=sc["color"], linestyle=sc["linestyle"],
                linewidth=2.0, label=sc["name"])
    _style_axis(ax, "Intervention load: GP ablation", "Round", "Cumulative interventions")
    ax.legend(loc="upper left", fontsize=7.2, frameon=False, ncol=1)

    # Panel 6: Compromised assets (ablation)
    ax = axes[1, 2]
    for entry in ablation_results:
        sc = entry["scenario"]
        d = entry["data"]
        if not d:
            continue
        r = d["round"]
        mu = d.get("compromised_count_mean", np.zeros_like(r))
        sd = d.get("compromised_count_std", np.zeros_like(r))
        ax.plot(r, mu, color=sc["color"], linestyle=sc["linestyle"],
                linewidth=2.0, label=sc["name"])
        ax.fill_between(r, np.clip(mu - sd, 0, 4), np.clip(mu + sd, 0, 4),
                        color=sc["color"], alpha=0.10)
    _style_axis(ax, "Cyber impact: GP ablation", "Round", "Compromised assets")
    ax.legend(loc="upper left", fontsize=7.2, frameon=False, ncol=1)

    plt.tight_layout()
    if save_path:
        out_dir = os.path.dirname(os.path.abspath(save_path))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        fig.savefig(save_path, bbox_inches="tight", dpi=FIG_DPI)
        _log_info("[OK] Saved scenario comparison plot to %s", save_path)
    if show:
        plt.show()
    else:
        plt.close(fig)
    return fig


def _safe_positive_int(value: Any, default: int = 1, minimum: int = 1) -> int:
    try:
        parsed = int(value)
    except Exception:
        parsed = int(default)
    return int(max(int(minimum), parsed))


def _default_benchmark_agents() -> List[Dict[str, Any]]:
    return [
        {"name": "random_red_monitor_blue", "red_mode": "random", "blue_mode": "monitor", "active_probe": False, "probe_every": 3},
        {"name": "scripted_red_monitor_blue", "red_mode": "scripted", "blue_mode": "monitor", "active_probe": False, "probe_every": 3},
        {"name": "scripted_red_scripted_blue", "red_mode": "scripted", "blue_mode": "scripted", "active_probe": False, "probe_every": 3},
        {"name": "scripted_red_safety_blue", "red_mode": "scripted", "blue_mode": "safety", "active_probe": False, "probe_every": 3},
        {"name": "scripted_red_scripted_blue_active_probe", "red_mode": "scripted", "blue_mode": "scripted", "active_probe": True, "probe_every": 3},
    ]


def _load_benchmark_config(config_path: Optional[str]) -> Dict[str, Any]:
    cfg: Dict[str, Any] = {
        "global": {"seeds": None, "rounds": None},
        "agents": _default_benchmark_agents(),
    }
    if not config_path:
        return cfg
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        g = raw.get("global") or {}
        if isinstance(g, dict):
            if g.get("seeds") is not None:
                cfg["global"]["seeds"] = _safe_positive_int(g.get("seeds"), default=1, minimum=1)
            if g.get("rounds") is not None:
                cfg["global"]["rounds"] = _safe_positive_int(g.get("rounds"), default=1, minimum=1)
        agents = raw.get("agents")
        if isinstance(agents, list) and agents:
            clean: List[Dict[str, Any]] = []
            for i, a in enumerate(agents):
                if not isinstance(a, dict):
                    continue
                red_mode = str(a.get("red_mode") or "scripted").strip().lower()
                blue_mode = str(a.get("blue_mode") or "monitor").strip().lower()
                if red_mode not in ("scripted", "random"):
                    red_mode = "scripted"
                if blue_mode not in ("monitor", "scripted", "random", "safety"):
                    blue_mode = "monitor"
                clean.append({
                    "name": str(a.get("name") or f"agent_{i+1}"),
                    "red_mode": red_mode,
                    "blue_mode": blue_mode,
                    "active_probe": bool(a.get("active_probe", False)),
                    "probe_every": _safe_positive_int(a.get("probe_every", 3), default=3, minimum=1),
                })
            if clean:
                cfg["agents"] = clean
    except Exception as e:
        _log_warn("Benchmark config load failed (%s): %s", config_path, e)
    return cfg


def _metric_stats(values: List[float]) -> Dict[str, float]:
    arr = np.asarray(values, dtype=float)
    if arr.size == 0:
        return {"mean": 0.0, "std": 0.0, "se": 0.0, "ci95_lo": 0.0, "ci95_hi": 0.0}
    mean = float(np.mean(arr))
    std = float(np.std(arr, ddof=1)) if arr.size > 1 else 0.0
    se = float(std / np.sqrt(arr.size)) if arr.size > 0 else 0.0
    ci = 1.96 * se
    return {
        "mean": mean,
        "std": std,
        "se": se,
        "ci95_lo": float(mean - ci),
        "ci95_hi": float(mean + ci),
    }


def run_benchmark_suite(output_dir: str, seeds: int, rounds: int, config_path: Optional[str] = None) -> Dict[str, Any]:
    os.makedirs(output_dir, exist_ok=True)
    rows: List[Dict[str, Any]] = []

    cfg = _load_benchmark_config(config_path)
    cfg_seeds = cfg.get("global", {}).get("seeds")
    cfg_rounds = cfg.get("global", {}).get("rounds")
    seeds_eff = _safe_positive_int(cfg_seeds if cfg_seeds is not None else seeds, default=seeds, minimum=1)
    rounds_eff = _safe_positive_int(cfg_rounds if cfg_rounds is not None else rounds, default=rounds, minimum=1)
    agents = cfg.get("agents") or _default_benchmark_agents()

    for s in range(seeds_eff):
        for agent in agents:
            env = CPSRange(seed=9000 + s, max_rounds=rounds_eff)
            red_success = 0
            blue_success = 0
            probe_every = _safe_positive_int(agent.get("probe_every", 3), default=3, minimum=1)

            while True:
                env.round += 1

                if bool(agent.get("active_probe", False)) and env.round % probe_every == 0:
                    probe = env.policy.select(env.mogp, env.tank, env.attacker_zone)
                    env.tank.pump_cmd = probe["pump_cmd"]
                    env.tank.valve_cmd = probe["valve_cmd"]

                prev_level = float(env.tank.level)
                red_act = _choose_benchmark_red_action(str(agent.get("red_mode", "scripted")), env)
                red_res = env.execute_action("RED", red_act)

                blue_act = _choose_benchmark_blue_action(str(agent.get("blue_mode", "monitor")), env)
                blue_res = env.execute_action("BLUE", blue_act)

                env.update_physics()

                delta_level = float(env.tank.level) - prev_level
                alarm_target = 1.0 if env.tank.alarm else 0.0
                damage_risk_target = dense_damage_risk(env.tank.level)

                is_int = (env.tank.pump_cmd != TANK_CMD_AUTO) or (env.tank.valve_cmd != TANK_CMD_AUTO)
                u_now = {"pump_cmd": env.tank.pump_cmd, "valve_cmd": env.tank.valve_cmd}
                z = encode_z(env.tank, env.attacker_zone, u_now)
                x_snap = {
                    "level": prev_level,
                    "pump_cmd": env.tank.pump_cmd,
                    "valve_cmd": env.tank.valve_cmd,
                    "sensor_ok": env.tank.sensor_ok,
                    "safety_interlock": env.tank.safety_interlock,
                    "attacker_zone": env.attacker_zone,
                    "alarm_flag": alarm_target,
                    "damage_flag": 1.0 if env.tank.damage else 0.0,
                }
                y_vec = np.array([delta_level, alarm_target, damage_risk_target], dtype=float)
                env.causal.add_sample(z=z, y_vec=y_vec, is_interventional=is_int, x_snapshot=x_snap)
                x_all, y_all = env.causal.combined()
                env.mogp.fit(x_all, y_all)

                if str(red_res).upper().startswith(("SUCCESS", "CRITICAL")):
                    red_success += 1
                if str(blue_res).upper().startswith("DEFENSE"):
                    blue_success += 1

                done, _reason = env.scenario_done()
                if done:
                    break

            rows.append({
                "agent": agent["name"],
                "red_mode": str(agent.get("red_mode", "scripted")),
                "blue_mode": str(agent.get("blue_mode", "monitor")),
                "active_probe": int(bool(agent.get("active_probe", False))),
                "seed": s,
                "rounds": env.round,
                "damage": 1 if env.tank.damage else 0,
                "final_level": float(np.round(float(env.tank.level), 3)),
                "alerts_total": len(env.alerts),
                "compromised_final": sum(1 for a in env.assets.values() if a.compromised),
                "red_successes": red_success,
                "blue_successes": blue_success,
            })

    by_agent: Dict[str, List[Dict[str, Any]]] = {}
    for r in rows:
        by_agent.setdefault(str(r["agent"]), []).append(r)

    summary: List[Dict[str, Any]] = []
    for aname, items in by_agent.items():
        damage_stats = _metric_stats([float(x["damage"]) for x in items])
        alerts_stats = _metric_stats([float(x["alerts_total"]) for x in items])
        comp_stats = _metric_stats([float(x["compromised_final"]) for x in items])
        red_s_stats = _metric_stats([float(x["red_successes"]) for x in items])
        blue_s_stats = _metric_stats([float(x["blue_successes"]) for x in items])
        rounds_stats = _metric_stats([float(x["rounds"]) for x in items])
        summary.append({
            "agent": aname,
            "n_runs": len(items),
            "damage_rate_mean": damage_stats["mean"],
            "damage_rate_ci95_lo": damage_stats["ci95_lo"],
            "damage_rate_ci95_hi": damage_stats["ci95_hi"],
            "alerts_mean": alerts_stats["mean"],
            "alerts_ci95_lo": alerts_stats["ci95_lo"],
            "alerts_ci95_hi": alerts_stats["ci95_hi"],
            "compromised_mean": comp_stats["mean"],
            "compromised_ci95_lo": comp_stats["ci95_lo"],
            "compromised_ci95_hi": comp_stats["ci95_hi"],
            "red_successes_mean": red_s_stats["mean"],
            "blue_successes_mean": blue_s_stats["mean"],
            "rounds_mean": rounds_stats["mean"],
        })

    raw_csv = os.path.join(output_dir, "benchmark_runs.csv")
    with open(raw_csv, "w", newline="", encoding="utf-8") as f:
        if rows:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            for r in rows:
                w.writerow(r)

    summary_json = os.path.join(output_dir, "benchmark_summary.json")
    summary_csv = os.path.join(output_dir, "benchmark_summary.csv")
    with open(summary_csv, "w", newline="", encoding="utf-8") as f:
        if summary:
            w = csv.DictWriter(f, fieldnames=list(summary[0].keys()))
            w.writeheader()
            for r in summary:
                w.writerow(r)

    with open(summary_json, "w", encoding="utf-8") as f:
        json.dump({
            "config_path": config_path,
            "effective_seeds": seeds_eff,
            "effective_rounds": rounds_eff,
            "runs": rows,
            "summary": summary,
        }, f, ensure_ascii=False, indent=2)

    return {
        "rows_path": raw_csv,
        "summary_path": summary_json,
        "summary_csv_path": summary_csv,
        "summary": summary,
        "effective_seeds": seeds_eff,
        "effective_rounds": rounds_eff,
    }


def run_roc_sweep(
    *,
    seeds: int,
    rounds: int,
    sensitivity_values: List[float],
) -> Tuple[List[int], List[float]]:
    y_true_all: List[int] = []
    y_score_all: List[float] = []

    for s in range(seeds):
        for sens in sensitivity_values:
            env = CPSRange(seed=1000 + s, max_rounds=rounds)
            env.blue_sensitivity = float(sens)

            for _ in range(rounds):
                env.round += 1
                red_act = _choose_scripted_red_action(env)
                red_res = env.execute_action("RED", red_act)
                env.execute_action("BLUE", {"action": "MONITOR", "target": "NONE", "service": "NONE", "params": {}})
                env.update_physics()

                severity = _severity_for_red_action(str(red_act.get("action")), red_res)
                base = SEVERITY_ALERT_BASE.get(severity, 0.0) if severity else 0.0
                score = _score_original(base, env.blue_sensitivity)

                red_label = 1 if str(red_act.get("action", "")).upper() != "RECON" else 0

                y_true_all.append(red_label)
                y_score_all.append(score)

                done, _reason = env.scenario_done()
                if done:
                    break

    return y_true_all, y_score_all


def run_roc_compare(
    *,
    seeds: int,
    rounds: int,
    sensitivity_values: List[float],
    algos: List[str],
) -> Dict[str, Tuple[List[int], List[float]]]:
    out: Dict[str, Tuple[List[int], List[float]]] = {a: ([], []) for a in algos}

    for s in range(seeds):
        for sens in sensitivity_values:
            env = CPSRange(seed=2000 + s, max_rounds=rounds)
            env.blue_sensitivity = float(sens)

            for _ in range(rounds):
                env.round += 1
                red_act = _choose_scripted_red_action(env)
                red_res = env.execute_action("RED", red_act)
                env.execute_action("BLUE", {"action": "MONITOR", "target": "NONE", "service": "NONE", "params": {}})
                env.update_physics()

                severity = _severity_for_red_action(str(red_act.get("action")), red_res)
                base = SEVERITY_ALERT_BASE.get(severity, 0.0) if severity else 0.0
                red_label = 1 if str(red_act.get("action", "")).upper() != "RECON" else 0

                for a in algos:
                    y_t, y_s = out[a]
                    if a == "original":
                        score = _score_original(base, env.blue_sensitivity)
                    elif a == "logistic":
                        score = _score_logistic(base, env.blue_sensitivity)
                    elif a == "quadratic":
                        score = _score_quadratic(base, env.blue_sensitivity)
                    elif a == "zone_weighted":
                        score = _score_zone_weighted(base, env.blue_sensitivity, env.attacker_zone)
                    else:
                        continue
                    y_t.append(red_label)
                    y_s.append(float(score))

                done, _reason = env.scenario_done()
                if done:
                    break

    return out


# ============================================================
# 4B) DATASET & PCAP EXPORT (for data analysis and Wireshark)
# ============================================================
def _run_id() -> str:
    """Return a timestamp-based run ID for filenames."""
    return time.strftime("%Y%m%d_%H%M%S")


def export_dataset(
    export_dir: str,
    run_id: str,
    history: Dict[str, List[Any]],
    dataset_rows: List[Dict[str, Any]],
) -> Tuple[str, str]:
    """
    Write per-round dataset as CSV and JSON for data analysis.
    Returns (path_to_csv, path_to_json).
    """
    os.makedirs(export_dir, exist_ok=True)
    base = os.path.join(export_dir, "run_%s" % run_id)
    csv_path = base + "_rounds.csv"
    json_path = base + "_rounds.json"

    if not dataset_rows:
        _log_warn("No dataset rows to export.")
        return csv_path, json_path

    keys = list(dataset_rows[0].keys())
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        w.writeheader()
        for row in dataset_rows:
            w.writerow(row)

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({"history": history, "rounds": dataset_rows}, f, indent=2, default=str)

    _log_info("[OK] Dataset CSV: %s", csv_path)
    _log_info("[OK] Dataset JSON: %s", json_path)
    return csv_path, json_path


def export_topology_json(
    json_path: str,
    env: "CPSRange",
    dataset_rows: List[Dict[str, Any]],
    topology_assets: List[Dict[str, Any]],
    large_infra: Optional[Dict[str, Any]] = None,
) -> str:
    """Export simulation data as JSON for the React topology-viewer frontend.

    Output schema matches topology-viewer/src/types.ts::SimulationData.
    """
    # Build subnets list
    subnets_out: List[Dict[str, Any]] = []
    if large_infra and "subnets" in large_infra:
        for sn in large_infra["subnets"]:
            subnets_out.append({
                "name": sn["name"],
                "zone": sn.get("zone", "IT"),
                "cidr": sn.get("cidr", ""),
                "color": sn.get("color", "#888"),
                "asset_count": sn.get("count", 0),
            })
    else:
        zone_color = {ZONE_IT: "#4c78a8", ZONE_DMZ: "#f58518", ZONE_OT: "#54a24b"}
        zone_assets: Dict[str, int] = {}
        for a in topology_assets:
            z = a.get("zone", ZONE_IT)
            zone_assets[z] = zone_assets.get(z, 0) + 1
        for z in [ZONE_IT, ZONE_DMZ, ZONE_OT]:
            subnets_out.append({
                "name": z,
                "zone": z,
                "cidr": "",
                "color": zone_color.get(z, "#888"),
                "asset_count": zone_assets.get(z, 0),
            })

    # Build assets list
    assets_out: List[Dict[str, Any]] = []
    for ta in topology_assets:
        aid = ta.get("asset_id", "")
        asset_obj = env.assets.get(aid)
        assets_out.append({
            "asset_id": aid,
            "zone": ta.get("zone", "IT"),
            "kind": ta.get("kind", ""),
            "ip": ta.get("ip", ""),
            "subnet": ta.get("subnet", ta.get("network", ta.get("zone", ""))),
            "criticality": ta.get("criticality", "LOW"),
            "compromised": bool(asset_obj.compromised) if asset_obj else False,
            "privilege": str(asset_obj.privilege) if asset_obj else "NONE",
            "services": list(asset_obj.services.keys()) if asset_obj else [],
        })

    # Build subnet links
    subnet_links_out: List[List[str]] = []
    if large_infra and "subnet_links" in large_infra:
        for sn1, sn2 in large_infra["subnet_links"]:
            subnet_links_out.append([sn1, sn2])
    else:
        subnet_links_out = [
            [ZONE_IT, ZONE_DMZ],
            [ZONE_DMZ, ZONE_OT],
        ]

    # Build rounds
    rounds_out: List[Dict[str, Any]] = []
    for row in dataset_rows:
        rounds_out.append({
            "round": row.get("round", 0),
            "red_action": str(row.get("red_action", "")),
            "red_target": str(row.get("red_target", "NONE")),
            "red_result": str(row.get("red_result", "")),
            "blue_action": str(row.get("blue_action", "")),
            "blue_target": str(row.get("blue_target", "NONE")),
            "blue_result": str(row.get("blue_result", "")),
            "tank_level": float(row.get("tank_level", 50.0)),
            "alerts_total": int(row.get("alerts_total", 0)),
            "compromised_count": int(row.get("compromised_count", 0)),
            "attacker_zone": str(row.get("attacker_zone", ZONE_IT)),
            "alarm_flag": float(row.get("alarm_flag", 0)),
            "damage_flag": float(row.get("damage_flag", 0)),
            "gp_p_alarm": float(row.get("gp_p_alarm", 0)),
            "gp_p_damage": float(row.get("gp_p_damage", 0)),
            "policy_choice": str(row.get("policy_choice", "")),
        })

    payload = {
        "subnets": subnets_out,
        "assets": assets_out,
        "subnet_links": subnet_links_out,
        "rounds": rounds_out,
        "total_ips": len(assets_out),
    }

    out_dir = os.path.dirname(os.path.abspath(json_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)
    _log_info("[OK] Topology JSON for React viewer: %s", json_path)
    return json_path


def _get_asset_ip(asset_id: str, ip_map: Dict[str, Tuple[str, str]]) -> str:
    """Resolve asset to IP; use placeholder if not in ip_map."""
    if asset_id in ip_map:
        return ip_map[asset_id][1]
    return PLACEHOLDER_IPS.get(asset_id, "0.0.0.0")


def write_pcap(
    pcap_path: str,
    dataset_rows: List[Dict[str, Any]],
    ip_map: Dict[str, Tuple[str, str]],
) -> None:
    """
    Generate a PCAP file from round/action data for Wireshark.
    Uses scapy if available; otherwise logs a warning and skips.
    """
    try:
        from scapy.all import Ether, IP, TCP, wrpcap
    except ImportError:
        _log_warn("scapy not installed; skipping PCAP export. Install with: pip install scapy")
        return

    src_ip = ATTACKER_PLACEHOLDER_IP
    packets: List[Any] = []
    for i, row in enumerate(dataset_rows):
        round_num = row.get("round", i + 1)
        red_action = (row.get("red_action") or "").upper()
        red_target = row.get("red_target") or ""
        red_service = (row.get("red_service") or "").lower()
        blue_target = row.get("blue_target") or ""
        sport_red = 40000 + (round_num % 60000) + (i % 100)

        # RED traffic: attacker -> target(s)
        if red_action == "RECON":
            for aid in CONTAINER_NAMES:
                dip = _get_asset_ip(aid, ip_map)
                ports = ASSET_PORTS.get(aid, {})
                for port in list(ports.values())[:4]:
                    pkt = Ether() / IP(src=src_ip, dst=dip) / TCP(sport=sport_red, dport=port, flags="S")
                    packets.append(pkt)
                    sport_red += 1
        elif red_target and red_action in ("BRUTE", "EXPLOIT", "PIVOT", "EXECUTE", "IMPACT", "PHISH"):
            dst_ip = _get_asset_ip(red_target, ip_map)
            dport = ASSET_PORTS.get(red_target, {}).get(red_service) or 22
            packets.append(Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport_red, dport=dport, flags="S"))
            packets.append(Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport_red, dport=dport, flags="A"))

        # BLUE traffic: SOC -> target (defender response)
        if blue_target:
            blue_dst = _get_asset_ip(blue_target, ip_map)
            packets.append(Ether() / IP(src="192.168.1.1", dst=blue_dst) / TCP(sport=50000 + (round_num % 1000), dport=22, flags="S"))

    if not packets:
        _log_warn("No packets generated for PCAP.")
        return
    # Limit size for very long runs
    to_write = packets[:10000]
    wrpcap(pcap_path, to_write)
    _log_info("[OK] PCAP (%d packets) written to %s (open in Wireshark)", len(to_write), pcap_path)


# ============================================================
# 5) ORCHESTRATION
# ============================================================
def write_compose(path: str) -> None:
    """Write the embedded docker-compose YAML to path."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(DOCKER_COMPOSE_YML)


def docker_compose_up(compose_path: str) -> None:
    docker_cli = find_docker_cli()
    if not docker_cli:
        raise FileNotFoundError("Docker CLI not found. Install Docker and ensure docker is in PATH.")
    workdir = os.path.dirname(os.path.abspath(compose_path))
    subprocess.check_call([docker_cli, "compose", "-f", compose_path, "up", "-d"], cwd=workdir)


def wait_containers_ready(
    dr: DockerRange,
    names: Tuple[str, ...],
    timeout_s: int = 90,
    poll_s: float = 1.0,
    interactive: bool = True,
    color_ui: bool = False,
) -> Dict[str, bool]:
    deadline = time.time() + max(1, int(timeout_s))
    spinner = ("|", "/", "-", "\\")
    tick = 0
    final: Dict[str, bool] = {n: False for n in names}

    while True:
        all_ready = True
        parts: List[str] = []
        for n in names:
            runtime, health, ready = dr.container_status(n)
            # For LLM simulation, be more lenient: 'running' is good enough
            lenient_ready = ready or (runtime.startswith("running") and health != "unhealthy")
            final[n] = bool(lenient_ready)
            all_ready = all_ready and bool(lenient_ready)
            tag_raw = "READY" if lenient_ready else "WAIT"
            tag = _color(tag_raw, "32" if lenient_ready else "33", color_ui)
            parts.append(f"{n}:{tag}:{runtime}/{health}")

        remaining = max(0, int(deadline - time.time()))
        if interactive:
            line = f"\r[..] startup {spinner[tick % len(spinner)]} " + " | ".join(parts) + f" | t_left={remaining:02d}s"
            sys.stdout.write(line)
            sys.stdout.flush()
        else:
            _log_info("[..] %s", " | ".join(parts))

        if all_ready or time.time() >= deadline:
            break

        tick += 1
        time.sleep(max(0.2, float(poll_s)))

    if interactive:
        sys.stdout.write("\n")
        sys.stdout.flush()

    for n in names:
        runtime, health, ready = dr.container_status(n)
        if ready:
            _log_info("[OK] %-18s ready (%s/%s)", _color(n, "32", color_ui), runtime, health)
        else:
            _log_warn("[WARN] %-16s not ready (%s/%s)", _color(n, "31", color_ui), runtime, health)

    return final

def docker_compose_down(compose_path: str) -> None:
    docker_cli = find_docker_cli()
    if not docker_cli:
        _log_warn("Docker CLI not found; skipping compose down.")
        return
    workdir = os.path.dirname(os.path.abspath(compose_path))
    subprocess.check_call([docker_cli, "compose", "-f", compose_path, "down", "-v"], cwd=workdir)


def docker_compose_up_simple(compose_path: str) -> None:
    docker_cli = find_docker_cli()
    if not docker_cli:
        raise FileNotFoundError("Docker CLI not found. Install Docker and ensure docker is in PATH.")
    workdir = os.path.dirname(os.path.abspath(compose_path))
    subprocess.check_call([docker_cli, "compose", "-f", compose_path, "up", "-d"], cwd=workdir)

def main() -> None:
    ap = argparse.ArgumentParser(
        description="LLM-driven CPS cyber range with multi-output GP and optional Docker substrate.",
    )
    ap.add_argument("--model-red", default=DEFAULT_LLM_MODEL, help="Ollama model for RED agent")
    ap.add_argument("--model-blue", default=DEFAULT_LLM_MODEL, help="Ollama model for BLUE agent")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument(
        "--rounds",
        type=int,
        default=DEFAULT_MAX_ROUNDS,
        metavar="N",
        help="Max simulation rounds (default %s; 80–150 recommended for better damage-probability learning)."
        % DEFAULT_MAX_ROUNDS,
    )
    ap.add_argument("--compose", default="docker-compose.yml")
    ap.add_argument("--enhanced-docker", action="store_true",
                    help="Use enhanced docker-compose with honeypots and full infrastructure.")
    ap.add_argument("--laptop-docker", action="store_true",
                    help="Use laptop-optimized lightweight docker-compose.")
    ap.add_argument("--no-write-compose", action="store_true")
    ap.add_argument("--no-docker-up", action="store_true")
    ap.add_argument("--docker-down-after", action="store_true")
    ap.add_argument("--no-container-markers", action="store_true")

    # Multi-Agent Neural Network Arguments
    ap.add_argument("--multi-agent", action="store_true",
                    help="Enable multi-agent neural network simulation.")
    ap.add_argument("--num-attackers", type=int, default=3,
                    help="Number of neural attacker agents.")
    ap.add_argument("--num-defenders", type=int, default=3,
                    help="Number of neural defender agents.")
    ap.add_argument("--num-analysts", type=int, default=2,
                    help="Number of neural analyst agents.")
    ap.add_argument("--neural-arch", type=str, default="transformer",
                    choices=["transformer", "gnn", "memory", "hierarchical", "ensemble"],
                    help="Neural network architecture for agents.")
    ap.add_argument("--neuroevolution", action="store_true",
                    help="Enable neuroevolution for agent optimization.")
    ap.add_argument("--agent-coordination", action="store_true",
                    help="Enable agent coordination and communication.")
    ap.add_argument("--neural-training", action="store_true",
                    help="Enable real-time neural network training.")
    ap.add_argument("--save-neural-models", type=str, default=None,
                    help="Path to save trained neural models.")

    # GP/active learning knobs
    ap.add_argument("--active-probe", action="store_true",
                    help="Enable active interventional probing (safe info-gain policy) every k rounds.")
    ap.add_argument("--probe-every", type=int, default=3,
                    help="Every k rounds, apply a safe probe intervention for GP learning.")
    ap.add_argument("--damage-prob-max", type=float, default=0.25,
                    help="Max allowed predicted damage probability for interventions.")
    ap.add_argument("--save-plot", type=str, default=None, metavar="PATH",
                    help="Save run summary plot to this path (e.g. run_summary.png).")
    ap.add_argument("--separate-plots", action="store_true",
                    help="Output each plot as a separate figure (and save multiple files when --save-plot is set).")
    ap.add_argument("--export-dataset", type=str, nargs="?", const=DEFAULT_EXPORT_DIR, metavar="DIR",
                    help="Export per-round CSV and JSON for data analysis (default dir: %s)." % DEFAULT_EXPORT_DIR)
    ap.add_argument("--pcap", type=str, default=None, metavar="PATH",
                    help="Write PCAP file for Wireshark (requires: pip install scapy).")
    ap.add_argument("--roc-sweep", action="store_true",
                    help="Run a ROC sweep over blue_sensitivity and plot ROC (no LLM required).")
    ap.add_argument("--roc-seeds", type=int, default=8,
                    help="Number of seeds (repeats) per sensitivity for ROC sweep.")
    ap.add_argument("--roc-save", type=str, default=None, metavar="PATH",
                    help="Save ROC plot to this path (e.g. roc.png).")
    ap.add_argument("--roc-compare", action="store_true",
                    help="Plot ROC curves for original + 3 additional scoring algorithms (no LLM required).")
    ap.add_argument("--benchmark", action="store_true",
                    help="Run benchmark suite with scripted baselines and export summary metrics.")
    ap.add_argument("--benchmark-seeds", type=int, default=10,
                    help="Number of seeds per benchmark baseline.")
    ap.add_argument("--benchmark-out", type=str, default="benchmark_out",
                    help="Output directory for benchmark CSV/JSON artifacts.")
    ap.add_argument("--benchmark-config", type=str, default=None,
                    help="Optional JSON benchmark config describing agent matrix and global seeds/rounds.")
    ap.add_argument("--full-recon", action="store_true",
                    help="Show full reachable service/IP visibility in RECON output (includes internal services).")
    ap.add_argument("--killchain-plots", dest="killchain_plots", action="store_true",
                    help="Generate attacker/defender kill-chain + tool usage plots.")
    ap.add_argument("--no-killchain-plots", dest="killchain_plots", action="store_false",
                    help="Disable kill-chain/tool usage plots.")
    ap.add_argument("--animate", action="store_true",
                    help="Generate/show animated timeline of process + tactical activity.")
    ap.add_argument("--animate-save", type=str, default=None,
                    help="Optional output GIF path for animation (requires pillow writer support).")
    ap.add_argument("--topology-animate", action="store_true",
                    help="Generate infrastructure topology animation showing assets + attacker movement.")
    ap.add_argument("--topology-dim", type=str, default="2d",
                    help="Topology animation mode: 2d or 3d.")
    ap.add_argument("--topology-save", type=str, default=None,
                    help="Optional output GIF path for topology animation.")
    ap.add_argument("--metrics", action="store_true",
                    help="Expose Prometheus /metrics endpoint for Grafana realtime monitoring.")
    ap.add_argument("--metrics-port", type=int, default=8000,
                    help="Port for Prometheus metrics HTTP server (default 8000).")
    ap.add_argument("--real-modbus", action="store_true",
                    help="Enable optional Modbus bridge to real/external PLC endpoint (pymodbus required).")
    ap.add_argument("--modbus-host", type=str, default="127.0.0.1",
                    help="Modbus PLC host for --real-modbus mode.")
    ap.add_argument("--modbus-port", type=int, default=1502,
                    help="Modbus PLC TCP port for --real-modbus mode.")
    ap.add_argument("--modbus-unit", type=int, default=1,
                    help="Modbus unit/slave ID for --real-modbus mode.")
    ap.add_argument("--monitoring-up", action="store_true",
                    help="Start Grafana+Prometheus monitoring stack (monitoring/docker-compose.yml) before running.")
    ap.add_argument("--monitoring-compose", type=str, default=os.path.join("monitoring", "docker-compose.yml"),
                    help="Path to monitoring docker-compose.yml.")
    ap.add_argument("--monitoring-down-after", action="store_true",
                    help="Stop monitoring stack (docker compose down -v) when exiting.")
    ap.add_argument("--interactive-startup", dest="interactive_startup", action="store_true",
                    help="Show live startup status line for container readiness checks.")
    ap.add_argument("--no-interactive-startup", dest="interactive_startup", action="store_false",
                    help="Disable live startup status line and use plain logs.")
    ap.add_argument("--live-round-ui", dest="live_round_ui", action="store_true",
                    help="Show compact live round status line (dashboard-like terminal output).")
    ap.add_argument("--no-live-round-ui", dest="live_round_ui", action="store_false",
                    help="Disable compact live round status line and use detailed per-round logs.")
    ap.add_argument("--color-ui", dest="color_ui", action="store_true",
                    help="Enable ANSI color in interactive startup and round dashboard output.")
    ap.add_argument("--no-color-ui", dest="color_ui", action="store_false",
                    help="Disable ANSI color in interactive terminal output.")
    ap.add_argument("--scripted-agents", action="store_true",
                    help="Use improved scripted kill-chain RED + reactive BLUE agents instead of LLM agents. "
                         "Produces much better results: proper kill-chain progression, physical impact, GP learning.")
    ap.add_argument("--scenario-count", type=int, default=5,
                    help="Number of segmented scenario rows for storyboard plot (default 5).")
    ap.add_argument("--large-infra", action="store_true",
                    help="Generate and display large-scale CPS infrastructure (300+ IPs, 8 subnets).")
    ap.add_argument("--large-infra-save", type=str, default=None, metavar="PATH",
                    help="Save static infrastructure map to this path (e.g. outputs/infra_map.png).")
    ap.add_argument("--large-infra-animate", action="store_true",
                    help="Run enhanced 2D animation of the large-scale infrastructure during simulation.")
    ap.add_argument("--large-infra-animate-save", type=str, default=None, metavar="PATH",
                    help="Save large infrastructure animation GIF to this path.")
    ap.add_argument("--large-infra-seed", type=int, default=42,
                    help="Seed for large infrastructure generation (default 42).")
    ap.add_argument("--export-topology-json", type=str, default=None, metavar="PATH",
                    help="Export simulation topology + rounds as JSON for the React topology-viewer frontend.")
    ap.add_argument("--multi-plate-lpr", type=str, default=None, metavar="IMAGE_PATH",
                    help="Process image for multiple license plates and return detection results.")
    ap.add_argument("--lpr-confidence", type=float, default=0.7, metavar="THRESHOLD",
                    help="Confidence threshold for license plate detection (default 0.7).")
    ap.add_argument("--lpr-viz", action="store_true",
                    help="Generate visualization image for detected license plates.")
    ap.add_argument("--scenario-compare", action="store_true",
                    help="Run scenario comparison: 4 attack variants + 3 GP ablation variants, then plot overlay.")
    ap.add_argument("--compare-seeds", type=int, default=3,
                    help="Number of seeds per scenario variant for --scenario-compare (default 3).")
    ap.add_argument("--compare-save", type=str, default=None, metavar="PATH",
                    help="Save scenario comparison plot to this path (e.g. outputs/comparison.png).")
    ap.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    ap.set_defaults(interactive_startup=True)
    ap.set_defaults(live_round_ui=True)
    ap.set_defaults(color_ui=True)
    ap.set_defaults(killchain_plots=True)
    args = ap.parse_args()

    _setup_logging(verbose=args.verbose)
    args.scenario_count = int(max(1, min(12, int(args.scenario_count))))
    args.live_round_ui = bool(args.live_round_ui and sys.stdout.isatty())
    args.color_ui = bool(args.color_ui and _supports_ansi_colors())
    args.topology_dim = str(args.topology_dim or "2d").lower()
    if args.topology_dim not in ("2d", "3d"):
        _log_warn("Invalid --topology-dim '%s'; using 2d", args.topology_dim)
        args.topology_dim = "2d"
    
    # Select appropriate docker-compose file and containers
    if args.enhanced_docker:
        compose_path = os.path.abspath("monitoring/docker-compose-closed.yml")
        CONTAINER_NAMES = ENHANCED_CONTAINERS
        _log_info("[INFO] Using enhanced docker-compose with honeypots and full infrastructure")
        _log_info("[INFO] Total containers: %d", len(ENHANCED_CONTAINERS))
    elif args.laptop_docker:
        compose_path = os.path.abspath("monitoring/laptop-optimization.yml")
        CONTAINER_NAMES = LAPTOP_CONTAINERS
        _log_info("[INFO] Using laptop-optimized lightweight docker-compose")
        _log_info("[INFO] Total containers: %d", len(LAPTOP_CONTAINERS))
    else:
        compose_path = os.path.abspath(args.compose)
        CONTAINER_NAMES = STANDARD_CONTAINERS
        _log_info("[INFO] Using standard docker-compose: %s", args.compose)
        _log_info("[INFO] Total containers: %d", len(STANDARD_CONTAINERS))
    
    monitoring_compose_path = os.path.abspath(args.monitoring_compose)

    if args.monitoring_up:
        _log_info("[..] Starting monitoring stack: %s", monitoring_compose_path)
        try:
            docker_compose_up_simple(monitoring_compose_path)
            _log_info("[OK] Monitoring stack started (Grafana: http://localhost:3000 | Prometheus: http://localhost:9090)")
        except Exception as e:
            _log_warn("Failed to start monitoring stack: %s", e)

    prom: Optional[PrometheusMetrics] = None
    if args.metrics:
        if _prom_start_http_server is None:
            _log_warn("prometheus_client not installed; metrics disabled. Install with: pip install prometheus-client")
        else:
            try:
                prom = PrometheusMetrics()
                _prom_start_http_server(int(args.metrics_port))
                _log_info("[OK] Prometheus metrics: http://localhost:%s/metrics", int(args.metrics_port))
            except Exception as e:
                _log_warn("Failed to start metrics server: %s", e)

    if args.roc_sweep:
        sens_vals = [float(np.round(x, 2)) for x in np.linspace(BLUE_SENSITIVITY_MIN, BLUE_SENSITIVITY_MAX, 18)]
        y_true, y_score = run_roc_sweep(seeds=int(max(1, args.roc_seeds)), rounds=int(max(1, args.rounds)), sensitivity_values=sens_vals)
        plot_roc_sweep(y_true, y_score, save_path=args.roc_save)
        return

    if args.roc_compare:
        sens_vals = [float(np.round(x, 2)) for x in np.linspace(BLUE_SENSITIVITY_MIN, BLUE_SENSITIVITY_MAX, 18)]
        algos = ["original", "logistic", "quadratic", "zone_weighted"]
        curves = run_roc_compare(
            seeds=int(max(1, args.roc_seeds)),
            rounds=int(max(1, args.rounds)),
            sensitivity_values=sens_vals,
            algos=algos,
        )
        plot_roc_compare(curves, save_path=args.roc_save)
        return

    # Multi-plate LPR processing dispatch
    if args.multi_plate_lpr:
        # Update confidence threshold if specified
        multi_lpr_processor.confidence_threshold = args.lpr_confidence
        
        # Process the image for multiple license plates
        _log_info("Processing image for multiple license plates: %s", args.multi_plate_lpr)
        results = process_multi_plate_lpr(
            args.multi_plate_lpr, 
            save_visualization=args.lpr_viz
        )
        
        # Display results
        total_plates = results.get('total_plates_detected', 0)
        avg_conf = results.get('statistics', {}).get('average_confidence', 0.0)
        
        _log_info("=" * 60)
        _log_info("MULTI-PLATE LPR RESULTS")
        _log_info("=" * 60)
        _log_info("Image: %s", results.get('image_path', 'Unknown'))
        _log_info("Total plates detected: %d", total_plates)
        _log_info("Average confidence: %.3f", avg_conf)
        
        if total_plates > 0:
            _log_info("High confidence plates (≥0.8): %d", 
                     results.get('statistics', {}).get('high_confidence_count', 0))
            _log_info("")
            _log_info("DETECTED PLATES:")
            for i, plate in enumerate(results.get('plates', []), 1):
                _log_info("  %d. %s (confidence: %.3f)", 
                         i, plate['text'], plate['confidence'])
                _log_info("     Bounding box: %s", plate['bbox'])
        
        if results.get('visualization_path'):
            _log_info("")
            _log_info("Visualization saved: %s", results['visualization_path'])
        
        if 'error' in results:
            _log_warn("Processing error: %s", results['error'])
        
        _log_info("=" * 60)
        return

    if args.benchmark:
        out = run_benchmark_suite(
            output_dir=args.benchmark_out,
            seeds=int(max(1, args.benchmark_seeds)),
            rounds=int(max(1, args.rounds)),
            config_path=args.benchmark_config,
        )
        _log_info("[OK] Benchmark runs written: %s", out["rows_path"])
        _log_info("[OK] Benchmark summary written: %s", out["summary_path"])
        _log_info("[OK] Benchmark summary CSV: %s", out["summary_csv_path"])
        _log_info("[OK] Benchmark effective seeds=%s rounds=%s", out["effective_seeds"], out["effective_rounds"])
        for row in out["summary"]:
            _log_info("  %s", row)
        return

    if args.scenario_compare:
        show_compare = args.compare_save is None
        comparison = run_scenario_comparison(
            seeds=int(max(1, args.compare_seeds)),
            max_rounds=int(max(1, args.rounds)),
        )
        _plot_scenario_comparison(comparison, save_path=args.compare_save, show=show_compare)
        _log_info("[OK] Scenario comparison complete (4 attack variants + 3 GP ablations × %d seeds × %d rounds)",
                  args.compare_seeds, args.rounds)
        return

    # --- Large-scale infrastructure (static map only, no simulation) ---
    large_infra: Optional[Dict[str, Any]] = None
    if args.large_infra or args.large_infra_animate:
        _log_info("[..] Generating large-scale CPS infrastructure (seed=%d) ...", args.large_infra_seed)
        large_infra = generate_large_infrastructure(seed=args.large_infra_seed)
        _log_info("[OK] Infrastructure generated: %d hosts across %d subnets",
                  large_infra["total_ips"], len(large_infra["subnets"]))
        for sn, cnt in sorted(large_infra["subnet_summary"].items()):
            _log_info("     %-18s %d hosts", sn, cnt)

    if args.large_infra and not args.large_infra_animate:
        show_map = args.large_infra_save is None
        _plot_large_infrastructure_static(large_infra, save_path=args.large_infra_save, show=show_map)
        _log_info("[OK] Large infrastructure map complete (%d IPs)", large_infra["total_ips"])
        return

    if not args.no_write_compose:
        write_compose(compose_path)
        _log_info("[OK] Wrote compose: %s", compose_path)

    if not args.no_docker_up:
        _log_info("[..] Starting docker compose up -d")
        try:
            docker_compose_up(compose_path)
            _log_info("[OK] docker compose up -d")
        except Exception as e:
            _log_err("Failed docker compose up: %s", e)
            _log_info("Run manually then retry with --no-docker-up")
            sys.exit(1)

    dr: Optional[DockerRange] = None
    try:
        dr = DockerRange()
    except Exception as e:
        _log_warn("Docker SDK unavailable: %s; using placeholder IPs for dataset/PCAP.", e)

    if dr is not None:
        wait_containers_ready(
            dr,
            CONTAINER_NAMES,
            timeout_s=90,
            poll_s=1.0,
            interactive=bool(args.interactive_startup),
            color_ui=bool(args.color_ui),
        )
        # Build IP map for all containers
        ip_map = {}
        for container_name in CONTAINER_NAMES:
            try:
                # Determine network based on container name
                if container_name.startswith(("gw_dmz", "hist_data", "cps-web", "cps-db", "cps-dc")):
                    network = "it_network"
                elif container_name.startswith(("hmi_ops", "plc_industrial", "cps-plc", "cps-opcua", "cps-hmi")):
                    network = "ot_network"
                elif container_name.startswith(("honeypot", "cps-router", "cps-dns", "cps-dhcp")):
                    network = "it_network"
                else:
                    network = "cps_internal"  # Default network
                
                ip_map[container_name] = (network, dr.get_container_ip(container_name, network))
            except Exception as e:
                _log_warn("Failed to get IP for %s: %s", container_name, e)
                ip_map[container_name] = ("sim", PLACEHOLDER_IPS.get(container_name, "0.0.0.0"))
        
        # Ensure core containers have proper IPs
        core_containers = ["gw_dmz_01", "hist_data_01", "hmi_ops_01", "plc_industrial_01"]
        for core_container in core_containers:
            if core_container in CONTAINER_NAMES and core_container not in ip_map:
                ip_map[core_container] = ("sim", PLACEHOLDER_IPS.get(core_container, "0.0.0.0"))
    else:
        ip_map = {aid: ("sim", PLACEHOLDER_IPS.get(aid, "0.0.0.0")) for aid in CONTAINER_NAMES}

    env = CPSRange(seed=args.seed, max_rounds=args.rounds)
    env.policy.damage_prob_max = float(args.damage_prob_max)
    env.full_recon_mode = bool(args.full_recon)
    env.recon_max_items = FULL_RECON_MAX_ITEMS if env.full_recon_mode else 6
    
    # Multi-Agent Neural Network Integration
    neural_sim = None
    if args.multi_agent:
        try:
            from neural_agent_integration import NeuralEnhancedSimulation
            from advanced_neural_architectures import NeuralArchitectureFactory
            
            _log_info("[..] Initializing Multi-Agent Neural Network System")
            
            # Create neural simulation configuration
            neural_config = {
                "num_attackers": args.num_attackers,
                "num_defenders": args.num_defenders,
                "num_analysts": args.num_analysts,
                "neural_arch": args.neural_arch,
                "neuroevolution": args.neuroevolution,
                "agent_coordination": args.agent_coordination,
                "neural_training": args.neural_training
            }
            
            neural_sim = NeuralEnhancedSimulation(env, neural_config)
            _log_info("[OK] Multi-Agent Neural System initialized")
            _log_info("    Attackers: %d, Defenders: %d, Analysts: %d", 
                     args.num_attackers, args.num_defenders, args.num_analysts)
            _log_info("    Architecture: %s, Neuroevolution: %s", 
                     args.neural_arch, args.neuroevolution)
            
        except ImportError as e:
            _log_warn("Multi-agent neural modules not available: %s", e)
            _log_info("Install with: pip install torch torchvision")
            args.multi_agent = False
    for aid, (net, ip) in ip_map.items():
        env.assets[aid].notes["network"] = net
        env.assets[aid].notes["ip"] = ip

    topology_assets: List[Dict[str, Any]] = []
    for aid, asset in env.assets.items():
        topology_assets.append({
            "asset_id": aid,
            "zone": asset.zone,
            "kind": asset.kind,
            "ip": str(asset.notes.get("ip", "")),
            "network": str(asset.notes.get("network", "")),
        })

    _log_info("")
    use_scripted = bool(getattr(args, 'scripted_agents', False))
    if use_scripted:
        _log_info("--- ADAPTIVE CPS CYBER RANGE (SCRIPTED AGENTS) + Multi-Output GP ---")
        _log_info("RED=kill-chain | BLUE=reactive | passive-compromise-effects=ON")
    else:
        _log_info("--- ADAPTIVE CPS CYBER RANGE (LLM vs LLM) + Multi-Output GP ---")
        _log_info("Models: RED=%s | BLUE=%s", args.model_red, args.model_blue)
    _log_info("Container IPs:")
    for aid, (_, ip) in ip_map.items():
        _log_info("  %s: %s", aid, ip)
    _log_info("")

    red: Any = None
    blue: Any = None
    if not use_scripted:
        red = LLMControlAgent(
            role="RED",
            goal="Reach DMZ, pivot to OT, gain PLC admin, and induce unsafe tank state (overflow or drain).",
            model=args.model_red,
        )
        blue = LLMControlAgent(
            role="BLUE",
            goal="Detect and contain attacker, protect OT, restore PLC safe logic, keep tank level safe.",
            model=args.model_blue,
        )

    last_comp_state: Dict[str, bool] = {aid: False for aid in env.assets.keys()}
    last_plc_hash = env.assets[PLC_ASSET_ID].notes.get("logic_hash", "SAFE_v1")
    dataset_rows: List[Dict[str, Any]] = []
    plc_bridge: Optional[ModbusPLCBridge] = None

    if args.real_modbus:
        if _ModbusTcpClient is None:
            _log_warn("pymodbus not installed; real Modbus mode disabled. Install with: pip install pymodbus")
        else:
            try:
                plc_bridge = ModbusPLCBridge(args.modbus_host, int(args.modbus_port), int(args.modbus_unit))
                _log_info("[OK] Real Modbus mode enabled: %s:%s unit=%s", args.modbus_host, args.modbus_port, args.modbus_unit)
            except Exception as e:
                _log_warn("Failed to initialize Modbus bridge: %s", e)

    try:
        # Neural Multi-Agent Integration
        if neural_sim is not None:
            _log_info("[..] Running Neural-Enhanced Multi-Agent Simulation")
            neural_results = neural_sim.run_enhanced_simulation(max_rounds=args.rounds)
            
            # Extract neural agent performance
            _log_info("[OK] Neural Simulation Complete")
            _log_info("    Final Performance: %.3f", 
                     neural_results["performance_summary"]["simulation_effectiveness"])
            _log_info("    Coordination Efficiency: %.3f", 
                     neural_results["performance_summary"]["coordination_efficiency"])
            _log_info("    Neural Learning Effectiveness: %.3f", 
                     neural_results["performance_summary"]["neural_learning_effectiveness"])
            
            # Save neural models if requested
            if args.save_neural_models:
                try:
                    import torch
                    model_path = args.save_neural_models
                    torch.save({
                        'agent_networks': neural_sim.coordinator.agents,
                        'performance_summary': neural_results["performance_summary"],
                        'final_state': neural_results["final_state"]
                    }, model_path)
                    _log_info("[OK] Neural models saved to: %s", model_path)
                except Exception as e:
                    _log_warn("Failed to save neural models: %s", e)
            
            # Continue with standard simulation for comparison
            _log_info("[..] Continuing with standard simulation for comparison...")
        
        while True:
            env.round += 1
            if not args.live_round_ui:
                if neural_sim is not None:
                    _log_info("[ROUND %s] (Neural Agents Active)", env.round)
                else:
                    _log_info("[ROUND %s]", env.round)

            if plc_bridge is not None:
                plc_bridge.pull_commands(env.tank)

            # Optional: safe active interventional probe (defender-controlled "do(u)")
            policy_choice = ""
            if args.active_probe and (env.round % max(1, args.probe_every) == 0):
                probe = env.policy.select(env.mogp, env.tank, env.attacker_zone)
                env.tank.pump_cmd = probe["pump_cmd"]
                env.tank.valve_cmd = probe["valve_cmd"]
                policy_choice = f"PROBE:{probe.get('name','')}"
                if not args.live_round_ui:
                    _log_info(">> ACTIVE-PROBE applied: %s", probe)

            prev_level = float(env.tank.level)
            prev_alarm_flag = 1.0 if env.tank.alarm else 0.0
            prev_damage_flag = 1.0 if env.tank.damage else 0.0

            if use_scripted:
                red_act = validate_action("RED", env, _choose_killchain_red_action(env))
            else:
                red_act = red.decide(env)
            red_res = env.execute_action("RED", red_act)
            if not args.live_round_ui:
                _log_info("RED -> %s => %s", red_act, red_res)

            if use_scripted:
                blue_act = validate_action("BLUE", env, _choose_reactive_blue_action(env))
            else:
                blue_act = blue.decide(env)
            blue_res = env.execute_action("BLUE", blue_act)
            if not args.live_round_ui:
                _log_info("BLUE -> %s => %s", blue_act, blue_res)

            if prom is not None:
                prom.update_round(
                    env,
                    str(red_act.get("action", "")),
                    str(red_res),
                    str(blue_act.get("action", "")),
                    str(blue_res),
                )

            # Docker markers (only when Docker is available)
            if dr is not None and not args.no_container_markers:
                for aid, asset in env.assets.items():
                    if aid in CONTAINER_NAMES:
                        if asset.compromised and not last_comp_state[aid]:
                            dr.mark_compromised(aid)
                            last_comp_state[aid] = True
                        elif (not asset.compromised) and last_comp_state[aid]:
                            dr.clear_compromised(aid)
                            last_comp_state[aid] = False

                plc_hash = env.assets[PLC_ASSET_ID].notes.get("logic_hash", "SAFE_v1")
                if plc_hash != last_plc_hash:
                    dr.set_plc_logic(plc_hash)
                    last_plc_hash = plc_hash

            # Apply passive compromise effects (sensor drift, pump perturbation from compromised OT assets)
            # Apply in ALL modes to stress physical process realistically
            _apply_passive_compromise_effects(env)

            # Simulate LPR processing every few rounds (security camera feed)
            if env.round % 5 == 0:  # Every 5 rounds, simulate security camera LPR scan
                try:
                    # Simulate security camera image capture
                    simulated_image_path = f"security_cam_round_{env.round}.jpg"
                    
                    # Process for multiple license plates
                    lpr_results = process_multi_plate_lpr(simulated_image_path, save_visualization=False)
                    
                    # Add LPR alerts to simulation environment
                    if lpr_results.get('total_plates_detected', 0) > 0:
                        add_lpr_alerts_to_simulation(env, lpr_results)
                        
                        # Log LPR detection to simulation output
                        total_plates = lpr_results.get('total_plates_detected', 0)
                        avg_conf = lpr_results.get('statistics', {}).get('average_confidence', 0.0)
                        if not args.live_round_ui:
                            _log_info(">> LPR: %d plates detected (avg conf: %.2f)", total_plates, avg_conf)
                            
                            # Show detected plates if multiple
                            if total_plates > 1:
                                for plate in lpr_results.get('plates', [])[:3]:  # Show top 3
                                    _log_info("   - %s (%.2f)", plate['text'], plate['confidence'])
                    
                except Exception as e:
                    _log_warn("LPR simulation failed: %e", e)

            phys = env.update_physics()
            if not args.live_round_ui:
                _log_info(">> %s", phys)

            if plc_bridge is not None:
                plc_bridge.push_state(env.tank)

            # ===== Build multi-output targets =====
            delta_level = float(env.tank.level) - prev_level

            # alarm target: 1 if any alarm string after step
            alarm_target = 1.0 if env.tank.alarm else 0.0
            damage_target = dense_damage_risk(env.tank.level)

            # Determine whether this round is interventional
            is_int = (env.tank.pump_cmd != TANK_CMD_AUTO) or (env.tank.valve_cmd != TANK_CMD_AUTO)
            if str(red_act.get("action", "")).upper() == "IMPACT":
                is_int = True
            if str(blue_act.get("action", "")).upper() in ("RESTORE",):
                is_int = True
            if policy_choice.startswith("PROBE:"):
                is_int = True
            
            # NEW: Treat high-risk attack progression as interventional for GP learning
            # This ensures GP learns even when explicit interventions are rare
            compromised_count = len([a for a in env.assets.values() if a.compromised])
            alert_count = len(getattr(env, 'alerts', []))
            
            # Mark as interventional if attack is progressing significantly
            if compromised_count >= 2 or alert_count >= 15:
                is_int = True
            
            # Also mark key attack milestones as interventional
            if (str(red_act.get("action", "")).upper() in ("EXPLOIT", "BRUTE") and 
                red_act.get("target") in ["hmi_ops_01", "plc_industrial_01"]):
                is_int = True

            # Add sample
            u_now = {"pump_cmd": env.tank.pump_cmd, "valve_cmd": env.tank.valve_cmd}
            z = encode_z(env.tank, env.attacker_zone, u_now)

            x_snap = {
                "level": prev_level,
                "pump_cmd": env.tank.pump_cmd,
                "valve_cmd": env.tank.valve_cmd,
                "sensor_ok": env.tank.sensor_ok,
                "safety_interlock": env.tank.safety_interlock,
                "attacker_zone": env.attacker_zone,
                "alarm_flag": prev_alarm_flag,
                "damage_flag": prev_damage_flag,
            }
            y_vec = np.array([delta_level, alarm_target, damage_target], dtype=float)
            env.causal.add_sample(z=z, y_vec=y_vec, is_interventional=is_int, x_snapshot=x_snap)

            # Fit multi-output GP
            x_all, y_all = env.causal.combined()
            env.mogp.fit(x_all, y_all)

            # Show GP predictions at current state (for monitoring)
            gp_p_alarm = 0.0
            gp_p_damage = 0.0
            if env.mogp.ready:
                z_now = encode_z(env.tank, env.attacker_zone, u_now).reshape(1, -1)
                pred = env.mogp.predict(z_now)
                mu_a, _ = pred["alarm"]
                mu_d, _ = pred["damage"]
                gp_p_alarm = env.mogp.prob_alarm(float(mu_a[0]))
                gp_p_damage = env.mogp.prob_damage(float(mu_d[0]))

                if env.round % 2 == 0:
                    ace = estimate_ace_multi(
                        env.mogp, env.causal,
                        u_from={"pump_cmd": TANK_CMD_AUTO, "valve_cmd": TANK_CMD_AUTO},
                        u_to={"pump_cmd": TANK_PUMP_FORCE_ON, "valve_cmd": TANK_VALVE_FORCE_CLOSED}
                    )
                    if not args.live_round_ui:
                        _log_info(
                            ">> GP-ACE AUTO->FORCE_ON/CLOSED: delta=%+.2f±%.2f, alarm=%+.2f±%.2f, damage=%+.2f±%.2f"
                            " | N_obs=%s N_int=%s | GP p(alarm)=%.2f p(damage)=%.2f",
                            ace["delta"][0], ace["delta"][1], ace["alarm"][0], ace["alarm"][1],
                            ace["damage"][0], ace["damage"][1],
                            len(env.causal.Z_obs), len(env.causal.Z_int), gp_p_alarm, gp_p_damage,
                        )

            if args.live_round_ui:
                _emit_live_round_status(
                    round_idx=env.round,
                    max_rounds=int(max(1, args.rounds)),
                    zone=str(env.attacker_zone),
                    tank_level=float(env.tank.level),
                    alerts_total=int(len(env.alerts)),
                    compromised_count=int(sum(1 for a in env.assets.values() if a.compromised)),
                    red_action=str(red_act.get("action", "")),
                    blue_action=str(blue_act.get("action", "")),
                    gp_p_alarm=float(gp_p_alarm),
                    gp_p_damage=float(gp_p_damage),
                    policy_choice=str(policy_choice),
                    color_ui=bool(args.color_ui),
                )

            env.record_history(gp_p_alarm=gp_p_alarm, gp_p_damage=gp_p_damage, policy_choice=policy_choice)

            # Append row for dataset/PCAP export
            red_meta = _action_meta(RED_ATTACK_CATALOG, red_act.get("action"))
            blue_meta = _action_meta(BLUE_DEFENSE_CATALOG, blue_act.get("action"))
            dataset_rows.append({
                "round": env.round,
                "red_action": red_act.get("action"),
                "red_phase": red_meta["phase"],
                "red_ttp": red_meta["ttp"],
                "red_tool": red_meta["tool"],
                "red_target": red_act.get("target"),
                "red_service": red_act.get("service"),
                "red_result": red_res,
                "blue_action": blue_act.get("action"),
                "blue_phase": blue_meta["phase"],
                "blue_ttp": blue_meta["ttp"],
                "blue_tool": blue_meta["tool"],
                "blue_target": blue_act.get("target"),
                "blue_service": blue_act.get("service"),
                "blue_result": blue_res,
                "tank_level": float(np.round(env.tank.level, 2)),
                "alerts_total": len(env.alerts),
                "compromised_count": sum(1 for a in env.assets.values() if a.compromised),
                "attacker_zone": env.attacker_zone,
                "alarm_flag": 1.0 if env.tank.alarm else 0.0,
                "damage_flag": 1.0 if env.tank.damage else 0.0,
                "damage_risk_target": float(np.round(damage_target, 4)),
                "gp_p_alarm": float(np.round(gp_p_alarm, 4)),
                "gp_p_damage": float(np.round(gp_p_damage, 4)),
                "policy_choice": policy_choice,
                "delta_level": float(np.round(delta_level, 4)),
                "is_interventional": is_int,
            })

            done, reason = env.scenario_done()
            if done:
                if args.live_round_ui:
                    _end_live_round_status()
                _log_info("%s", reason)
                break

            time.sleep(0.6)

        _log_info("--- SUMMARY ---")
        _log_info("Rounds: %s", env.round)
        _log_info("Damage: %s | Final level: %.1f%% | Alarm: %s", env.tank.damage, env.tank.level, env.tank.alarm)
        compromised = [a.asset_id for a in env.assets.values() if a.compromised]
        _log_info("Compromised assets: %s", compromised)
        _log_info("Alerts generated: %s", len(env.alerts))
        _log_info("Last 5 alerts:")
        for al in env.alerts[-5:]:
            _log_info("  %s", al)
        _log_info("Action log (last 12):")
        for line in env.action_log[-12:]:
            _log_info("  %s", line)

        if args.separate_plots:
            plot_run_separate(
                env.history,
                save_path=args.save_plot,
                scenario_count=args.scenario_count,
                dataset_rows=dataset_rows,
                killchain_plots=bool(args.killchain_plots),
                animate=bool(args.animate),
                animate_save_path=args.animate_save,
                topology_assets=topology_assets,
                topology_animate=bool(args.topology_animate),
                topology_dim=args.topology_dim,
                topology_save_path=args.topology_save,
            )
        else:
            plot_run(
                env.history,
                save_path=args.save_plot,
                scenario_count=args.scenario_count,
                dataset_rows=dataset_rows,
                killchain_plots=bool(args.killchain_plots),
                animate=bool(args.animate),
                animate_save_path=args.animate_save,
                topology_assets=topology_assets,
                topology_animate=bool(args.topology_animate),
                topology_dim=args.topology_dim,
                topology_save_path=args.topology_save,
            )

        # Large infrastructure animated topology (enhanced 2D pipeline)
        if args.large_infra_animate and large_infra is not None:
            large_topo = infra_to_topology_assets(large_infra)
            show_large_anim = args.large_infra_animate_save is None
            _animate_large_topology_2d(
                dataset_rows=dataset_rows,
                topology_assets=large_topo,
                subnets=large_infra["subnets"],
                subnet_links=large_infra["subnet_links"],
                save_path=args.large_infra_animate_save,
                show=show_large_anim,
                max_labeled=40,
                fps=3,
            )
            if args.large_infra_save:
                _plot_large_infrastructure_static(large_infra, save_path=args.large_infra_save, show=False)

        # Dataset export (CSV + JSON) for data analysis
        if args.export_dataset:
            run_id = _run_id()
            export_dataset(args.export_dataset, run_id, env.history, dataset_rows)

        # Topology JSON export for React viewer
        if args.export_topology_json:
            export_topology_json(
                json_path=args.export_topology_json,
                env=env,
                dataset_rows=dataset_rows,
                topology_assets=topology_assets,
                large_infra=large_infra,
            )

        # PCAP export for Wireshark
        if args.pcap:
            write_pcap(args.pcap, dataset_rows, ip_map)

    finally:
        if plc_bridge is not None:
            plc_bridge.close()

        if args.docker_down_after:
            _log_info("[..] Tearing down docker compose (down -v)")
            try:
                docker_compose_down(compose_path)
                _log_info("[OK] docker compose down -v")
            except Exception as e:
                _log_warn("docker down failed: %s", e)

        if args.monitoring_down_after and args.monitoring_up:
            _log_info("[..] Tearing down monitoring stack (down -v)")
            try:
                docker_compose_down(monitoring_compose_path)
                _log_info("[OK] monitoring compose down -v")
            except Exception as e:
                _log_warn("monitoring down failed: %s", e)

if __name__ == "__main__":
    generate_persistent_users()
    main()

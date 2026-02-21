"""
Adaptive CPS cyber range simulator: RED vs BLUE LLM agents.
Symbolic cyber actions (recon, exploit, pivot, impact) plus simple tank physics.
Educational use; all "exploits" are simulated, not real.
"""

import json
import time
import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import ollama

# --- Constants ---
ZONE_IT = "IT"
ZONE_DMZ = "DMZ"
ZONE_OT = "OT"
IMPACT_OVERFLOW = "OVERFLOW"
IMPACT_DRAIN = "DRAIN"
IMPACT_SENSOR_SPOOF = "SENSOR_SPOOF"
TANK_AUTO = "AUTO"
TANK_FORCE_ON = "FORCE_ON"
TANK_FORCE_OFF = "FORCE_OFF"
TANK_FORCE_OPEN = "FORCE_OPEN"
TANK_FORCE_CLOSED = "FORCE_CLOSED"
PLC_ASSET_ID = "plc_industrial_01"
SEVERITY_LOW = "LOW"
SEVERITY_MED = "MED"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRIT = "CRIT"
DEFAULT_LLM_MODEL = "llama3.2:1b"
BLUE_SENSITIVITY_MIN = 0.1
BLUE_SENSITIVITY_MAX = 0.95
ALERT_PROB_CAP = 0.98

# ============================================================
# 1) CYBER-PHYSICAL RANGE MODEL (Safe state-based simulation)
# ============================================================

@dataclass
class Service:
    name: str
    port: int
    vuln_id: Optional[str] = None          # e.g., "T0866"
    exposed: bool = True                   # reachable from attacker zone?
    patched: bool = False
    weak_creds: bool = False               # e.g., default creds
    auth_required: bool = True


@dataclass
class Asset:
    asset_id: str
    kind: str                               # "plc", "hmi", "hist", "gateway", etc.
    zone: str                               # "OT", "IT", "DMZ"
    services: Dict[str, Service]
    compromised: bool = False
    privilege: str = "NONE"                 # NONE / USER / ADMIN
    isolated: bool = False
    hardened: bool = False
    notes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PhysicalTank:
    level: float = 50.0                     # %
    pump_cmd: str = "AUTO"                  # AUTO / FORCE_ON / FORCE_OFF
    valve_cmd: str = "AUTO"                 # AUTO / FORCE_OPEN / FORCE_CLOSED
    sensor_ok: bool = True
    safety_interlock: bool = True
    alarm: Optional[str] = None
    damage: bool = False


class CPSRange:
    """
    Educational cyber-physical range simulator.
    - "Exploit" is symbolic: success depends on reachability, patch state, creds, hardening, isolation.
    - Red/Blue actions update cyber state; physics updates every round.
    """

    def __init__(self, seed: int = 7):
        random.seed(seed)

        # Simple reachability model by zone adjacency
        # Attacker starts in IT. OT reachable only via DMZ pivot/gateway.
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
                    "ssh": Service("ssh", 22, vuln_id=None, exposed=True, patched=False, weak_creds=True, auth_required=True),
                    "vpn": Service("vpn", 1194, vuln_id="T0887: Remote Services", exposed=True, patched=False, weak_creds=False, auth_required=True),
                },
            ),
            "hist_data_01": Asset(
                asset_id="hist_data_01",
                kind="historian",
                zone="DMZ",
                services={
                    "http": Service("http", 8080, vuln_id="T0819: Exploit Public-Facing Application", exposed=True, patched=False, weak_creds=False, auth_required=False),
                },
            ),
            "hmi_ops_01": Asset(
                asset_id="hmi_ops_01",
                kind="hmi",
                zone="OT",
                services={
                    "rdp": Service("rdp", 3389, vuln_id="T0823: Graphical User Interface", exposed=False, patched=False, weak_creds=True, auth_required=True),
                },
            ),
            "plc_industrial_01": Asset(
                asset_id="plc_industrial_01",
                kind="plc",
                zone="OT",
                services={
                    "modbus": Service("modbus", 502, vuln_id="T0866: Software Process Out-of-Bounds", exposed=False, patched=False, weak_creds=False, auth_required=False),
                    "prog": Service("prog", 44818, vuln_id="T0833: Modify Controller Tasking", exposed=False, patched=False, weak_creds=False, auth_required=True),
                },
                notes={"logic_hash": "SAFE_v1"},
            ),
        }

        self.tank = PhysicalTank()
        self.attacker_zone = ZONE_IT  # where red starts "logically"
        self.round = 0

        # Telemetry
        self.events: List[Dict[str, Any]] = []        # raw events
        self.alerts: List[Dict[str, Any]] = []        # detection outputs
        self.action_log: List[str] = []               # human-readable

        # Blue detection knobs (simple)
        self.blue_sensitivity = 0.55  # higher => more alerts

        # End conditions
        self.max_rounds = 12

    # ----------------------------
    # Utility + telemetry helpers
    # ----------------------------
    def _reachable(self, src_zone: str, dst_zone: str) -> bool:
        if src_zone == dst_zone:
            return True
        return self.zone_links.get((src_zone, dst_zone), False)

    def _emit_event(self, etype: str, details: Dict[str, Any]):
        evt = {"t": time.time(), "round": self.round, "type": etype, **details}
        self.events.append(evt)

    def _maybe_alert(self, severity: str, reason: str, details: Dict[str, Any]):
        # Very simple probabilistic detection model influenced by:
        # - isolation/hardening lowers success and visibility
        # - blue_sensitivity increases alert chance
        base = {SEVERITY_LOW: 0.25, SEVERITY_MED: 0.45, SEVERITY_HIGH: 0.7, SEVERITY_CRIT: 0.9}[severity]
        p = min(ALERT_PROB_CAP, base * (0.75 + self.blue_sensitivity))
        if random.random() < p:
            alert = {"round": self.round, "severity": severity, "reason": reason, **details}
            self.alerts.append(alert)

    def summarize_state_for_llm(self) -> Dict[str, Any]:
        # Keep it concise but meaningful for decision-making.
        def asset_view(a: Asset) -> Dict[str, Any]:
            return {
                "kind": a.kind,
                "zone": a.zone,
                "compromised": a.compromised,
                "privilege": a.privilege,
                "isolated": a.isolated,
                "hardened": a.hardened,
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

        return {
            "round": self.round,
            "attacker_zone": self.attacker_zone,
            "tank": {
                "level": round(self.tank.level, 1),
                "pump_cmd": self.tank.pump_cmd,
                "valve_cmd": self.tank.valve_cmd,
                "sensor_ok": self.tank.sensor_ok,
                "safety_interlock": self.tank.safety_interlock,
                "alarm": self.tank.alarm,
                "damage": self.tank.damage,
            },
            "assets": {aid: asset_view(a) for aid, a in self.assets.items()},
            "last_alerts": self.alerts[-3:],
            "last_events": self.events[-3:],
        }

    # ----------------------------
    # Cyber actions (symbolic)
    # ----------------------------
    def execute_action(self, actor: str, action: Dict[str, Any]) -> str:
        """
        Expected schema:
        {
          "action": "RECON|PHISH|BRUTE|EXPLOIT|PIVOT|EXECUTE|IMPACT|COVER|MONITOR|ISOLATE|PATCH|HARDEN|RESTORE|TUNE",
          "target": "asset_id or NONE",
          "service": "svc_name or NONE",
          "params": { ... }   # optional
        }
        """
        a = action.get("action", "MONITOR").upper()
        target = action.get("target", "NONE")
        service = action.get("service", "NONE")
        params = action.get("params", {}) or {}

        # basic validation
        if target != "NONE" and target not in self.assets:
            msg = f"IGNORE: invalid target {target}"
            self.action_log.append(f"{actor}: {a} {target}/{service} -> {msg}")
            return msg

        # Route
        if actor == "RED":
            res = self._red_step(a, target, service, params)
        else:
            res = self._blue_step(a, target, service, params)

        self.action_log.append(f"{actor}: {a} {target}/{service} -> {res}")
        return res

    def _red_step(self, a: str, target: str, service: str, params: Dict[str, Any]) -> str:
        # Attacker actions are only meaningful if reachability and not isolated.
        if a == "RECON":
            # Discover exposed services reachable from attacker_zone
            visible = []
            for aid, asset in self.assets.items():
                if asset.isolated:
                    continue
                if not self._reachable(self.attacker_zone, asset.zone):
                    continue
                for sname, svc in asset.services.items():
                    if svc.exposed:
                        visible.append((aid, sname, svc.port))
            self._emit_event("recon", {"actor": "RED", "visible": visible[:10]})
            self._maybe_alert(SEVERITY_LOW, "Network scanning behavior", {"actor": "RED"})
            return f"RECON_OK: visible={visible[:6]}{'...' if len(visible)>6 else ''}"

        if target == "NONE":
            return "NOOP: target required"

        asset = self.assets[target]
        if asset.isolated:
            self._emit_event("blocked", {"actor": "RED", "target": target, "reason": "isolated"})
            return "BLOCKED: target isolated"

        if not self._reachable(self.attacker_zone, asset.zone):
            self._emit_event("blocked", {"actor": "RED", "target": target, "reason": "unreachable"})
            return f"BLOCKED: cannot reach {asset.zone} from {self.attacker_zone}"

        # Service-specific checks
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
            # symbolic brute for weak creds services
            if not svc:
                return "FAIL: service required"
            if not svc.auth_required:
                return "FAIL: auth not required"
            if svc.weak_creds and not asset.hardened:
                asset.compromised = True
                asset.privilege = "USER"
                self._emit_event("compromise", {"actor": "RED", "target": target, "via": f"weak_creds:{service}"})
                self._maybe_alert(SEVERITY_HIGH, "Credential attack succeeded", {"target": target, "service": service})
                return "SUCCESS: user access via weak creds"
            self._emit_event("brute_fail", {"actor": "RED", "target": target, "service": service})
            self._maybe_alert(SEVERITY_MED, "Bruteforce attempt", {"target": target, "service": service})
            return "FAIL: creds resisted"

        if a == "EXPLOIT":
            # symbolic exploit success depends on hardening + patch
            if not svc:
                return "FAIL: service required"
            if asset.hardened:
                self._emit_event("exploit_fail", {"actor": "RED", "target": target, "service": service, "reason": "hardened"})
                self._maybe_alert(SEVERITY_MED, "Exploit attempt blocked by hardening", {"target": target, "service": service})
                return "BLOCKED: hardened"
            if svc.vuln_id is None:
                return "FAIL: no vuln modeled"
            # success chance: higher in DMZ than OT; PLC is harder unless pivoted
            base = 0.65 if asset.zone in (ZONE_IT, ZONE_DMZ) else 0.45
            if random.random() < base:
                asset.compromised = True
                asset.privilege = "USER"
                self._emit_event("compromise", {"actor": "RED", "target": target, "via": svc.vuln_id})
                self._maybe_alert(SEVERITY_HIGH, "Service exploitation succeeded", {"target": target, "service": service, "vuln": svc.vuln_id})
                return f"SUCCESS: access via {svc.vuln_id}"
            self._emit_event("exploit_fail", {"actor": "RED", "target": target, "service": service, "reason": "random_fail"})
            self._maybe_alert(SEVERITY_MED, "Exploit attempt failed", {"target": target, "service": service})
            return "FAIL: exploit did not land"

        if a == "PIVOT":
            # pivot: if compromised gateway/historian in DMZ, attacker_zone becomes DMZ; if compromised HMI/PLC, zone becomes OT
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
            # privilege escalation or controller programming channel usage
            if not asset.compromised:
                return "FAIL: no access"
            if asset.privilege == "ADMIN":
                return "NOOP: already admin"
            # hardening reduces escalation success
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
            # cyber-physical manipulation: requires PLC compromised + admin
            if target != PLC_ASSET_ID:
                return "FAIL: impact only modeled on plc_industrial_01"
            plc = asset
            if not plc.compromised or plc.privilege != "ADMIN":
                return "FAIL: need PLC ADMIN"
            mode = params.get("mode", IMPACT_OVERFLOW).upper()
            if mode == IMPACT_OVERFLOW:
                self.tank.pump_cmd = TANK_FORCE_ON
                self.tank.valve_cmd = TANK_FORCE_CLOSED
                plc.notes["logic_hash"] = "MAL_OVERFLOW_v1"
                self._emit_event("impact", {"actor": "RED", "mode": IMPACT_OVERFLOW})
                self._maybe_alert(SEVERITY_CRIT, "Controller logic modified", {"target": target, "mode": IMPACT_OVERFLOW})
                return "CRITICAL: PLC logic modified -> pump FORCE_ON, valve FORCE_CLOSED"
            if mode == IMPACT_DRAIN:
                self.tank.pump_cmd = TANK_FORCE_OFF
                self.tank.valve_cmd = TANK_FORCE_OPEN
                plc.notes["logic_hash"] = "MAL_DRAIN_v1"
                self._emit_event("impact", {"actor": "RED", "mode": IMPACT_DRAIN})
                self._maybe_alert(SEVERITY_CRIT, "Controller logic modified", {"target": target, "mode": IMPACT_DRAIN})
                return "CRITICAL: PLC logic modified -> pump FORCE_OFF, valve FORCE_OPEN"
            if mode == IMPACT_SENSOR_SPOOF:
                self.tank.sensor_ok = False
                self._emit_event("impact", {"actor": "RED", "mode": IMPACT_SENSOR_SPOOF})
                self._maybe_alert(SEVERITY_HIGH, "Sensor integrity anomaly", {"mode": IMPACT_SENSOR_SPOOF})
                return "IMPACT: level sensor spoofed (operator view unreliable)"
            return "FAIL: unknown impact mode"

        if a == "COVER":
            # reduce future alert probability slightly (toy)
            self.blue_sensitivity = max(BLUE_SENSITIVITY_MIN, self.blue_sensitivity - 0.08)
            self._emit_event("cover", {"actor": "RED"})
            return "COVER_OK: reduced blue sensitivity slightly"

        if a == "PHISH":
            # symbolic: small chance to compromise IT side (not detailed here)
            self._emit_event("phish", {"actor": "RED"})
            self._maybe_alert(SEVERITY_LOW, "Phishing indicators", {"actor": "RED"})
            return "PHISH_SENT: (symbolic)"

        return "NOOP/UNKNOWN_RED_ACTION"

    def _blue_step(self, a: str, target: str, service: str, params: Dict[str, Any]) -> str:
        if a == "MONITOR":
            # Produce a quick status summary and possibly raise alerts from existing events
            recent = self.events[-5:]
            summary = [e["type"] for e in recent]
            # Monitoring can slightly increase sensitivity (better tuned sensors)
            self.blue_sensitivity = min(BLUE_SENSITIVITY_MAX, self.blue_sensitivity + 0.03)
            return f"MONITOR_OK: recent_events={summary}, alerts={len(self.alerts)}"

        if a == "TUNE":
            # params: {"sensitivity": 0..1}
            s = params.get("sensitivity")
            if isinstance(s, (int, float)):
                self.blue_sensitivity = max(BLUE_SENSITIVITY_MIN, min(BLUE_SENSITIVITY_MAX, float(s)))
                return f"TUNE_OK: blue_sensitivity={self.blue_sensitivity:.2f}"
            return "FAIL: provide params.sensitivity"

        if target == "NONE":
            return "NOOP: target required"

        asset = self.assets[target]

        if a == "ISOLATE":
            asset.isolated = True
            # isolation also hides services from recon/exploit
            self._emit_event("isolate", {"actor": "BLUE", "target": target})
            return "DEFENSE: asset isolated (network containment)"

        if a == "PATCH":
            # patch specific service or all
            if service == "NONE":
                for svc in asset.services.values():
                    svc.patched = True
                self._emit_event("patch", {"actor": "BLUE", "target": target, "service": "ALL"})
                return "DEFENSE: patched all services on asset"
            svc = asset.services.get(service)
            if not svc:
                return "FAIL: invalid service"
            svc.patched = True
            self._emit_event("patch", {"actor": "BLUE", "target": target, "service": service})
            return f"DEFENSE: patched {service}"

        if a == "HARDEN":
            asset.hardened = True
            # hardening also removes weak creds advantage
            for svc in asset.services.values():
                if svc.weak_creds:
                    svc.weak_creds = False
            self._emit_event("harden", {"actor": "BLUE", "target": target})
            return "DEFENSE: applied hardening (firmware verification / secure config)"

        if a == "RESTORE":
            # If restoring PLC, reset to safe logic
            if asset.kind == "plc":
                asset.compromised = False
                asset.privilege = "NONE"
                asset.notes["logic_hash"] = "SAFE_v1"
                self.tank.pump_cmd = TANK_AUTO
                self.tank.valve_cmd = TANK_AUTO
                self.tank.sensor_ok = True
                self.tank.alarm = None
                self._emit_event("restore", {"actor": "BLUE", "target": target, "scope": "plc_logic"})
                return "DEFENSE: PLC restored to SAFE logic (AUTO controls resumed)"
            # General restore
            asset.compromised = False
            asset.privilege = "NONE"
            self._emit_event("restore", {"actor": "BLUE", "target": target, "scope": "host"})
            return "DEFENSE: host restored (credentials rotated / image reset)"

        return "NOOP/UNKNOWN_BLUE_ACTION"

    # ----------------------------
    # Physical process update
    # ----------------------------
    def update_physics(self) -> str:
        """
        Tank dynamics:
        - Pump increases level, valve decreases level.
        - AUTO tries to keep near 50 if sensor_ok and safety_interlock enabled.
        - Safety interlock: if enabled, prevents FORCE_ON if level high.
        - Sensor spoof: operator sees wrong; but physics still changes.
        """
        self.tank.alarm = None

        # Determine effective commands
        pump = self.tank.pump_cmd
        valve = self.tank.valve_cmd

        # Safety interlock can override malicious pump ON near overflow
        if self.tank.safety_interlock and pump == TANK_FORCE_ON and self.tank.level > 85:
            pump = TANK_AUTO  # interlock intervenes
            self._emit_event("safety", {"type": "interlock_trip", "level": self.tank.level})

        # AUTO controller (toy)
        if pump == TANK_AUTO and valve == TANK_AUTO:
            # small noise around setpoint
            self.tank.level += random.uniform(-1.5, 1.5)
            # gentle correction
            if self.tank.level < 47:
                self.tank.level += 1.2
            elif self.tank.level > 53:
                self.tank.level -= 1.2
        else:
            # Actuation effect
            if pump == TANK_FORCE_ON:
                self.tank.level += 12.0
            elif pump == TANK_FORCE_OFF:
                self.tank.level -= 2.0

            if valve == TANK_FORCE_OPEN:
                self.tank.level -= 10.0
            elif valve == TANK_FORCE_CLOSED:
                self.tank.level += 1.0  # pressure/retention effect

        # Clamp and evaluate alarms/damage
        self.tank.level = max(0.0, min(100.0, self.tank.level))

        if self.tank.level >= 92.0:
            self.tank.alarm = "ALARM: TANK OVERFLOW"
            self.tank.damage = True
        elif self.tank.level <= 5.0:
            self.tank.alarm = "ALARM: TANK EMPTY (CAVITATION RISK)"
            self.tank.damage = True
        elif self.tank.level >= 85.0:
            self.tank.alarm = "WARN: High level"
        elif self.tank.level <= 15.0:
            self.tank.alarm = "WARN: Low level"

        return f"PHYS: level={self.tank.level:.1f}% pump={self.tank.pump_cmd} valve={self.tank.valve_cmd} alarm={self.tank.alarm}"

    def scenario_done(self) -> Tuple[bool, str]:
        if self.tank.damage:
            return True, "END: physical damage condition reached"
        if self.round >= self.max_rounds:
            return True, "END: max rounds reached"
        return False, "RUNNING"


# ============================================================
# 2) LLM AGENTS (Strict JSON actions + validation)
# ============================================================

ALLOWED_ACTIONS_RED = {
    "RECON", "PHISH", "BRUTE", "EXPLOIT", "PIVOT", "EXECUTE", "IMPACT", "COVER"
}
ALLOWED_ACTIONS_BLUE = {
    "MONITOR", "ISOLATE", "PATCH", "HARDEN", "RESTORE", "TUNE"
}

def safe_json_extract(text: str) -> Optional[Dict[str, Any]]:
    """Extract and parse the first JSON object from LLM output; returns None on failure."""
    text = text.strip()
    if "{" in text and "}" in text:
        text = text[text.find("{"): text.rfind("}") + 1]
    try:
        return json.loads(text)
    except Exception:
        return None

def validate_action(role: str, env: CPSRange, act: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize and validate RED/BLUE action; return a safe action dict."""
    # normalize
    action = str(act.get("action", "MONITOR")).upper()
    target = act.get("target", "NONE")
    service = act.get("service", "NONE")
    params = act.get("params", {}) or {}

    allowed = ALLOWED_ACTIONS_RED if role == "RED" else ALLOWED_ACTIONS_BLUE
    if action not in allowed:
        # fallback defaults
        return {"action": "RECON" if role == "RED" else "MONITOR", "target": "NONE", "service": "NONE", "params": {}}

    # Validate target
    if target != "NONE" and target not in env.assets:
        target = "NONE"
        service = "NONE"

    # Validate service if provided
    if target != "NONE" and service != "NONE":
        if service not in env.assets[target].services:
            service = "NONE"

    # Guardrails for IMPACT
    if role == "RED" and action == "IMPACT":
        if target != PLC_ASSET_ID:
            target = PLC_ASSET_ID
        if "mode" not in params:
            params["mode"] = IMPACT_OVERFLOW

    # Guardrails for PATCH: allow service NONE meaning patch all
    if role == "BLUE" and action == "PATCH" and target == "NONE":
        action = "MONITOR"

    return {"action": action, "target": target, "service": service, "params": params}

class LLMControlAgent:
    """LLM-driven RED or BLUE agent that outputs strict JSON actions."""

    def __init__(self, role: str, goal: str, model: str = DEFAULT_LLM_MODEL):
        self.role = role  # "RED" or "BLUE"
        self.goal = goal
        self.model = model
        self.memory: List[str] = []  # short running summary

    def decide(self, env: CPSRange) -> Dict[str, Any]:
        state = env.summarize_state_for_llm()

        # Keep prompt short-ish (important for small local models)
        allowed = sorted(list(ALLOWED_ACTIONS_RED if self.role == "RED" else ALLOWED_ACTIONS_BLUE))
        assets = list(state["assets"].keys())

        system_rules = (
            "You are controlling a SAFE educational cyber range SIMULATOR.\n"
            "You MUST output ONLY strict JSON matching the schema.\n"
            "Do not include explanations, markdown, or extra keys.\n"
            "Choose actions that advance your goal given the state.\n"
        )

        schema = {
            "action": "ONE_OF_" + "|".join(allowed),
            "target": "asset_id_or_NONE",
            "service": "service_name_or_NONE",
            "params": "object_or_empty"
        }

        prompt = f"""{system_rules}
ROLE={self.role}
GOAL={self.goal}

ASSETS={assets}
STATE_SUMMARY={json.dumps(state, ensure_ascii=False)}

OUTPUT_JSON_SCHEMA={json.dumps(schema)}

Return ONLY JSON like:
{{"action":"RECON","target":"NONE","service":"NONE","params":{{}}}}
"""

        # LLM call
        try:
            resp = ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = resp["message"]["content"]
            act = safe_json_extract(raw) or {}
        except Exception:
            act = {}

        act = validate_action(self.role, env, act)
        return act


# ============================================================
# 3) MAIN FULLY-AUTOMATED SIM LOOP
# ============================================================

def run_simulation(
    model_red: str = DEFAULT_LLM_MODEL,
    model_blue: str = DEFAULT_LLM_MODEL,
    seed: int = 7,
) -> None:
    """Run the full RED vs BLUE CPS simulation until damage or max rounds."""
    env = CPSRange(seed=seed)

    red = LLMControlAgent(
        role="RED",
        goal="Reach OT, gain PLC admin, and cause unsafe tank state (overflow or drain) via controller manipulation.",
        model=model_red,
    )
    blue = LLMControlAgent(
        role="BLUE",
        goal="Detect and contain attacker, protect OT, restore PLC safe logic, and keep tank level in safe bounds.",
        model=model_blue,
    )

    print("\n--- ADAPTIVE CPS CYBER RANGE (LLM vs LLM) ---")
    print(f"Models: RED={model_red} | BLUE={model_blue}\n")

    while True:
        env.round += 1
        print(f"\n[ROUND {env.round}]")

        # RED move
        red_act = red.decide(env)
        red_res = env.execute_action("RED", red_act)
        print(f"RED  -> {red_act} => {red_res}")

        # BLUE move
        blue_act = blue.decide(env)
        blue_res = env.execute_action("BLUE", blue_act)
        print(f"BLUE -> {blue_act} => {blue_res}")

        # Physics tick
        phys = env.update_physics()
        print(f">> {phys}")

        # End conditions
        done, reason = env.scenario_done()
        if done:
            print(f"\n{reason}")
            break

        # Small pause for readability
        time.sleep(0.6)

    # Post-run summary (useful for your paper)
    print("\n--- SUMMARY ---")
    print(f"Rounds: {env.round}")
    print(f"Damage: {env.tank.damage} | Final level: {env.tank.level:.1f}% | Alarm: {env.tank.alarm}")
    compromised = [a.asset_id for a in env.assets.values() if a.compromised]
    print(f"Compromised assets: {compromised}")
    print(f"Alerts generated: {len(env.alerts)}")
    print("Last 5 alerts:")
    for al in env.alerts[-5:]:
        print(" ", al)
    print("\nAction log (last 10):")
    for line in env.action_log[-10:]:
        print(" ", line)


if __name__ == "__main__":
    run_simulation()

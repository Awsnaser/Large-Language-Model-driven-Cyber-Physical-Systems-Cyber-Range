"""
Logic-hardened IoT cyber range simulation.
An LLM adversary follows SCAN → EXPLOIT → DISRUPT against IoT devices;
a human defender can patch devices between turns.
"""

import json
from typing import Any

import ollama

# --- Constants ---
ACTION_SCAN = "SCAN"
ACTION_EXPLOIT = "EXPLOIT"
ACTION_DISRUPT = "DISRUPT"
DEFAULT_TARGET = "gateway_01"
VULN_PATCHED = "Patched"
MAX_TURNS = 5
DEFAULT_MODEL = "llama3.2:1b"


# --- 1. IoT environment ---
class IoTDevice:
    """Represents a single IoT device with vulnerability and compromise state."""

    def __init__(
        self,
        device_id: str,
        device_type: str,
        vulnerability: str,
    ) -> None:
        self.id = device_id
        self.type = device_type
        self.vulnerability = vulnerability
        self.is_compromised = False
        self.status = "Normal"
        self.physical_value = 22.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize device state for the LLM context."""
        return {
            "id": self.id,
            "type": self.type,
            "vuln": self.vulnerability,
            "compromised": self.is_compromised,
            "status": self.status,
            "phys_reading": f"{self.physical_value}C",
        }


class CyberRange:
    """Simulated IoT network with gateway, thermostat, and camera."""

    def __init__(self) -> None:
        self.devices: dict[str, IoTDevice] = {
            "gateway_01": IoTDevice("gateway_01", "Edge Gateway", "Default SSH Credentials"),
            "thermostat_01": IoTDevice("thermostat_01", "HVAC Controller", "Unpatched Firmware"),
            "camera_01": IoTDevice("camera_01", "Security Camera", "Exposed Web Interface"),
        }

    def get_system_context(self) -> str:
        """Return current device states as JSON for the adversary."""
        return json.dumps([d.to_dict() for d in self.devices.values()], indent=2)

    def process_action(self, action: str, target_id: str) -> str:
        """Apply adversary action to a target device. Returns result message."""
        if target_id not in self.devices:
            return f"Error: {target_id} not found on network."

        target = self.devices[target_id]

        if action == ACTION_SCAN:
            return (
                f"[IDS ALERT]: Reconnaissance on {target_id}. "
                f"Vulnerability: {target.vulnerability}"
            )

        if action == ACTION_EXPLOIT:
            if target.vulnerability == VULN_PATCHED:
                return f"[SECURITY BLOCK]: Exploit failed. {target_id} is hardened."
            target.is_compromised = True
            return f"[SUCCESS]: Root access gained on {target_id}!"

        if action == ACTION_DISRUPT:
            if not target.is_compromised:
                return (
                    f"[LOGIC ERROR]: Cannot disrupt {target_id}. "
                    "No active session (Must EXPLOIT first)."
                )
            target.status = "MALFUNCTION"
            if target.type == "HVAC Controller":
                target.physical_value = 65.0
                return f"[PHYSICAL CRITICAL]: {target_id} overheating! Temp: 65C."
            return f"[DISRUPTION]: {target_id} service is now offline."

        return "Unknown Command."


# --- 2. Smart adversary (LLM) ---
class SmartAdversary:
    """LLM-driven adversary that follows the kill chain: SCAN → EXPLOIT → DISRUPT."""

    def __init__(self, model: str = DEFAULT_MODEL) -> None:
        self.model = model
        self.goal = (
            "Compromise gateway_01, then move to thermostat_01 and disrupt it."
        )

    def get_move(self, state: str) -> dict[str, Any]:
        """Request next action from the LLM given current network state."""
        prompt = f"""
You are an advanced Adversarial AI.
Your goal: {self.goal}
Current Network State: {state}

CRITICAL RULES:
1. You MUST follow this order: SCAN -> EXPLOIT -> DISRUPT.
2. You CANNOT use DISRUPT unless 'compromised' is true for that target.
3. If you just successfully exploited a gateway, look for the next target.

RESPONSE FORMAT:
Output ONLY valid JSON. No other words.
Example: {{"action": "EXPLOIT", "target": "gateway_01"}}
"""

        try:
            response = ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
            )
            raw_content = response["message"]["content"].strip()

            # Extract JSON from potential conversational fluff
            if "{" in raw_content:
                start = raw_content.find("{")
                end = raw_content.rfind("}") + 1
                raw_content = raw_content[start:end]

            return json.loads(raw_content)
        except (json.JSONDecodeError, KeyError):
            # Fallback to safe default on parse/API error
            return {"action": ACTION_SCAN, "target": DEFAULT_TARGET}


# --- 3. Main simulation ---
def _parse_defender_input(line: str) -> str | None:
    """Parse 'patch <device_id>' from defender input. Returns device_id or None."""
    parts = line.strip().split()
    if len(parts) >= 2 and parts[0].lower() == "patch":
        return parts[1]
    return None


def start_range() -> None:
    """Run the interactive cyber range simulation."""
    env = CyberRange()
    attacker = SmartAdversary()

    print("=== STARTING LOGIC-HARDENED SIMULATION ===")

    for turn in range(1, MAX_TURNS + 1):
        print(f"\n--- TURN {turn} ---")
        current_state = env.get_system_context()
        print(f"Network Snapshot:\n{current_state}")

        move = attacker.get_move(current_state)
        action = move.get("action", ACTION_SCAN)
        target = move.get("target", DEFAULT_TARGET)

        print(f"Adversary attempts: {action} on {target}")
        result = env.process_action(action, target)
        print(f"System Response: {result}")

        # Defender input
        cmd = input("\n[DEFENDER] Enter 'patch [id]' to secure it, or press Enter: ")
        device_id = _parse_defender_input(cmd)
        if device_id and device_id in env.devices:
            env.devices[device_id].vulnerability = VULN_PATCHED
            env.devices[device_id].is_compromised = False
            print(f"*** ALERT: {device_id} has been secured by administrator. ***")


if __name__ == "__main__":
    start_range()

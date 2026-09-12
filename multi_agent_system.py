#!/usr/bin/env python3
"""
Multi-Agent LLM System with Deep Neural Networks for CPS Simulation
Advanced agent architecture with neural network-enhanced decision making
"""

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json
import logging
from collections import deque
import random

# Neural Network Components
class DeepDecisionNetwork(nn.Module):
    """Deep neural network for agent decision making"""
    
    def __init__(self, input_dim: int, hidden_dims: List[int], output_dim: int):
        super(DeepDecisionNetwork, self).__init__()
        
        layers = []
        prev_dim = input_dim
        
        for hidden_dim in hidden_dims:
            layers.extend([
                nn.Linear(prev_dim, hidden_dim),
                nn.ReLU(),
                nn.Dropout(0.2),
                nn.BatchNorm1d(hidden_dim)
            ])
            prev_dim = hidden_dim
        
        layers.append(nn.Linear(prev_dim, output_dim))
        
        self.network = nn.Sequential(*layers)
        self.softmax = nn.Softmax(dim=-1)
        
    def forward(self, x):
        logits = self.network(x)
        return logits, self.softmax(logits)

class AttentionModule(nn.Module):
    """Attention mechanism for multi-agent coordination"""
    
    def __init__(self, feature_dim: int, num_heads: int = 8):
        super(AttentionModule, self).__init__()
        self.attention = nn.MultiheadAttention(
            embed_dim=feature_dim,
            num_heads=num_heads,
            batch_first=True
        )
        self.norm = nn.LayerNorm(feature_dim)
        
    def forward(self, features, mask=None):
        attn_output, attn_weights = self.attention(features, features, features, 
                                                   key_padding_mask=mask)
        return self.norm(attn_output + features), attn_weights

class MemoryNetwork(nn.Module):
    """Neural memory for storing and retrieving past experiences"""
    
    def __init__(self, memory_size: int, feature_dim: int):
        super(MemoryNetwork, self).__init__()
        self.memory_size = memory_size
        self.feature_dim = feature_dim
        
        # Memory bank
        self.register_buffer('memory', torch.zeros(memory_size, feature_dim))
        self.register_buffer('memory_valid', torch.zeros(memory_size, dtype=torch.bool))
        
        # Query and value networks
        self.query_net = nn.Linear(feature_dim, feature_dim)
        self.value_net = nn.Linear(feature_dim, feature_dim)
        
    def write(self, features: torch.Tensor, indices: torch.Tensor):
        """Write features to memory without tracking simulator state in autograd."""
        with torch.no_grad():
            self.memory[indices] = features.detach().to(self.memory.device)
            self.memory_valid[indices] = True

    def read(self, query: torch.Tensor, k: int = 5) -> torch.Tensor:
        """Read nearest memories while preserving the query's batch shape.

        A single query must produce one feature vector, rather than a ``k``
        element pseudo-batch.  That invariant is important for BatchNorm-based
        decision networks.
        """
        is_single_query = query.dim() == 1
        query_batch = query.unsqueeze(0) if is_single_query else query
        if query_batch.dim() != 2:
            raise ValueError("MemoryNetwork.read expects [feature_dim] or [batch, feature_dim] query")
        if not self.memory_valid.any():
            return torch.zeros_like(query)

        valid_memory = self.memory[self.memory_valid]
        query_keys = self.query_net(query_batch)
        similarities = torch.cosine_similarity(
            query_keys.unsqueeze(1), valid_memory.unsqueeze(0), dim=-1
        )
        top_indices = similarities.topk(min(k, valid_memory.size(0)), dim=-1).indices
        retrieved = valid_memory[top_indices]  # [batch, k, feature_dim]
        result = retrieved.mean(dim=1)
        return result.squeeze(0) if is_single_query else result

# Agent Types and Specializations
class AgentType(Enum):
    ATTACKER = "attacker"
    DEFENDER = "defender"
    ANALYST = "analyst"
    COORDINATOR = "coordinator"
    SCOUT = "scout"

class AgentSpecialization(Enum):
    # Attacker specializations
    INITIAL_ACCESS = "initial_access"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    EXFILTRATION = "exfiltration"
    
    # Defender specializations
    DETECTION = "detection"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    
    # Analyst specializations
    THREAT_INTEL = "threat_intel"
    VULNERABILITY = "vulnerability"
    BEHAVIORAL = "behavioral"
    FORENSIC = "forensic"

@dataclass
class AgentState:
    """Agent's current state and context"""
    agent_id: str
    agent_type: AgentType
    specialization: AgentSpecialization
    position: str  # Current zone/location
    knowledge_base: Dict[str, Any] = field(default_factory=dict)
    memory: deque = field(default_factory=lambda: deque(maxlen=1000))
    neural_state: torch.Tensor = field(default_factory=lambda: torch.zeros(0))
    communication_log: List[Dict[str, Any]] = field(default_factory=list)
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    learning_rate: float = 0.001
    exploration_rate: float = 0.1

class MultiAgentEnvironment:
    """Enhanced environment for multi-agent simulation.

    Only architectures with the interfaces used by :class:`NeuralLLMAgent` are
    accepted here.  Advanced architectures remain independently usable, but
    are not silently substituted into an incompatible decision/attention/
    memory slot.
    """

    _ARCHITECTURE_ALIASES = {
        "decision_net": {"deep_feedforward", "deep"},
        "coordination_net": {"attention", "multihead_attention"},
        "memory_net": {"basic", "memory_network"},
    }

    def __init__(self, base_env, max_agents: int = 20,
                 neural_architectures: Optional[Dict[str, str]] = None):
        self.base_env = base_env
        self.max_agents = max_agents
        self.neural_architectures = self._validate_architectures(neural_architectures)
        self.agents: Dict[str, AgentState] = {}
        self.agent_networks: Dict[str, Dict[str, nn.Module]] = {}
        self.communication_channels: Dict[str, List[str]] = {}
        self.global_memory = torch.zeros(1000, 128)  # Shared memory
        self.round_count = 0

        # Initialize communication channels
        self._setup_communication_channels()

    @classmethod
    def _validate_architectures(cls, requested: Optional[Dict[str, str]]) -> Dict[str, str]:
        """Normalize supported selections and reject unintegrated architectures."""
        selections = {
            "decision_net": "deep_feedforward",
            "coordination_net": "attention",
            "memory_net": "basic",
        }
        for slot, architecture in (requested or {}).items():
            if slot not in cls._ARCHITECTURE_ALIASES:
                raise ValueError(f"Unknown neural architecture slot: {slot}")
            name = str(architecture).lower()
            if name not in cls._ARCHITECTURE_ALIASES[slot]:
                supported = ", ".join(sorted(cls._ARCHITECTURE_ALIASES[slot]))
                raise NotImplementedError(
                    f"Architecture '{architecture}' is not wired to the {slot} interface; "
                    f"supported values are: {supported}."
                )
            selections[slot] = name
        return selections
        
    def _setup_communication_channels(self):
        """Setup secure communication channels between agents"""
        self.communication_channels = {
            "attacker_coord": [],    # Attacker coordination
            "defender_coord": [],    # Defender coordination
            "threat_intel": [],      # Threat intelligence sharing
            "command_control": [],   # Command and control
            "exfiltration": [],      # Data exfiltration
            "recovery": []           # Incident recovery
        }
        
    def add_agent(self, agent_id: str, agent_type: AgentType, 
                   specialization: AgentSpecialization, position: str) -> bool:
        """Add a new agent to the environment."""
        if agent_id in self.agents or len(self.agents) >= self.max_agents:
            return False
            
        # Create agent state
        agent = AgentState(
            agent_id=agent_id,
            agent_type=agent_type,
            specialization=specialization,
            position=position
        )
        
        # Initialize neural networks for agent
        self.agent_networks[agent_id] = {
            "decision_net": DeepDecisionNetwork(
                input_dim=128,
                hidden_dims=[256, 128, 64],
                output_dim=32
            ),
            "attention": AttentionModule(feature_dim=128),
            "memory": MemoryNetwork(memory_size=100, feature_dim=128)
        }
        
        # Add to appropriate communication channels
        if agent_type == AgentType.ATTACKER:
            self.communication_channels["attacker_coord"].append(agent_id)
            self.communication_channels["exfiltration"].append(agent_id)
        elif agent_type == AgentType.DEFENDER:
            self.communication_channels["defender_coord"].append(agent_id)
            self.communication_channels["recovery"].append(agent_id)
        elif agent_type == AgentType.ANALYST:
            self.communication_channels["threat_intel"].append(agent_id)
            
        self.agents[agent_id] = agent
        return True
        
    def remove_agent(self, agent_id: str) -> bool:
        """Remove an agent from the environment"""
        if agent_id not in self.agents:
            return False
            
        # Remove from communication channels
        for channel_agents in self.communication_channels.values():
            if agent_id in channel_agents:
                channel_agents.remove(agent_id)
                
        del self.agents[agent_id]
        del self.agent_networks[agent_id]
        return True

class UnsupportedNeuralActionError(ValueError):
    """Raised when a neural output cannot be represented as an agent action."""


class NeuralLLMAgent:
    """Neural network-enhanced LLM agent"""
    
    def __init__(self, agent_state: AgentState, neural_networks: Dict[str, nn.Module]):
        self.state = agent_state
        self.networks = neural_networks
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # Move networks to device
        for net in neural_networks.values():
            net.to(self.device)
            
        # Experience replay buffer
        self.experience_buffer = deque(maxlen=10000)
        
        # Optimizers
        self.optimizer = optim.Adam(
            list(self.networks["decision_net"].parameters()) +
            list(self.networks["attention"].parameters()),
            lr=self.state.learning_rate
        )
        
        # Loss functions
        self.decision_loss = nn.CrossEntropyLoss()
        self.attention_loss = nn.MSELoss()
        
    def encode_environment_state(self, env_state: Dict[str, Any]) -> torch.Tensor:
        """Encode environment state into neural representation"""
        features = []
        
        # Asset states
        asset_features = []
        for asset_id, asset in env_state.get("assets", {}).items():
            asset_vector = [
                1.0 if asset.get("compromised", False) else 0.0,
                1.0 if asset.get("isolated", False) else 0.0,
                1.0 if asset.get("hardened", False) else 0.0,
                asset.get("privilege", 0) / 3.0,  # Normalize privilege
                len(asset.get("services", {})) / 10.0  # Normalize service count
            ]
            asset_features.extend(asset_vector)
            
        # Pad or truncate to fixed size
        asset_features = asset_features[:50] + [0.0] * (50 - len(asset_features))
        features.extend(asset_features)
        
        # Network topology features
        network_features = [
            env_state.get("compromised_count", 0) / 20.0,
            env_state.get("total_assets", 1) / 50.0,
            1.0 if env_state.get("alarm_active", False) else 0.0,
            env_state.get("tank_level", 50.0) / 100.0,
            1.0 if env_state.get("damage_active", False) else 0.0
        ]
        features.extend(network_features)
        
        # Agent's own state
        self_features = [
            self.state.learning_rate,
            self.state.exploration_rate,
            len(self.state.memory) / 1000.0,
            len(self.state.communication_log) / 100.0
        ]
        features.extend(self_features)
        
        # Pad to required input dimension
        while len(features) < 128:
            features.append(0.0)
            
        return torch.tensor(features[:128], dtype=torch.float32).to(self.device)
        
    def communicate_with_agents(self, channel: str, message: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Communicate with other agents in the same channel"""
        responses = []
        
        # This would be implemented with actual communication logic
        # For now, simulate responses
        return responses
        
    def make_decision(self, env_state: Dict[str, Any]) -> Dict[str, Any]:
        """Make decision using neural network-enhanced reasoning"""
        # Encode environment
        env_features = self.encode_environment_state(env_state)
        
        # Get memory context
        memory_context = self.networks["memory"].read(env_features)
        
        # Combine features
        combined_features = env_features + memory_context
        combined_features = combined_features.unsqueeze(0)  # Add batch dimension
        
        # Neural decision making. BatchNorm/Dropout must use inference behavior for a
        # single environment state, then the prior training mode is restored.
        decision_net = self.networks["decision_net"]
        was_training = decision_net.training
        decision_net.eval()
        try:
            with torch.no_grad():
                logits, probabilities = decision_net(combined_features)
        finally:
            decision_net.train(was_training)
            
        # Restrict the fixed-size policy head to actions this role can actually
        # express in the current state.  Sampling all 32 logits and replacing
        # unknown indexes with MONITOR used to hide invalid neural output.
        actions = self._get_available_actions(env_state)
        if not actions:
            raise UnsupportedNeuralActionError(
                f"No executable neural actions are available for {self.state.agent_type.value}"
            )
        available_probabilities = probabilities[0, :len(actions)]
        if random.random() < self.state.exploration_rate:
            action_idx = random.randrange(len(actions))
        else:
            action_idx = torch.argmax(available_probabilities).item()

        # Decode action to actual command.
        action = self._decode_neural_action(action_idx, env_state)
        
        # Store experience
        self.experience_buffer.append({
            "state": env_features.cpu(),
            "action": action_idx,
            "reward": 0.0,  # Will be updated later
            "next_state": None
        })
        
        return action
        
    def _decode_neural_action(self, action_idx: int, env_state: Dict[str, Any]) -> Dict[str, Any]:
        """Decode an in-range neural output to a symbolic action.

        Callers get an explicit error for unsupported output instead of a
        misleading no-op fallback.
        """
        actions = self._get_available_actions(env_state)
        if not isinstance(action_idx, int) or action_idx < 0 or action_idx >= len(actions):
            raise UnsupportedNeuralActionError(
                f"Neural action index {action_idx!r} is outside the {len(actions)} available actions"
            )
        return actions[action_idx]
            
    def _get_available_actions(self, env_state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Return symbolic actions that can be adapted for the current state.

        Concrete asset/service selection is intentionally delegated to
        ``SimulatorActionAdapter`` in ``neural_agent_integration``.
        """
        assets = env_state.get("assets", {})
        compromised = any(asset.get("compromised", False) for asset in assets.values())
        has_assets = bool(assets)
        actions: List[Dict[str, Any]] = []

        if self.state.agent_type == AgentType.ATTACKER:
            actions.append({"action": "RECON", "target": "NONE", "params": {}})
            if has_assets:
                actions.append({"action": "EXPLOIT", "target": "ANY", "params": {}})
            if compromised:
                actions.extend([
                    {"action": "MOVE", "target": "COMPROMISED", "params": {}},
                    {"action": "PERSIST", "target": "COMPROMISED", "params": {}},
                ])
        elif self.state.agent_type == AgentType.DEFENDER:
            actions.append({"action": "MONITOR", "target": "NONE", "params": {}})
            if has_assets:
                actions.extend([
                    {"action": "PATCH", "target": "VULNERABLE", "params": {}},
                    {"action": "HARDEN", "target": "ANY", "params": {}},
                ])
            if compromised:
                actions.extend([
                    {"action": "ISOLATE", "target": "COMPROMISED", "params": {}},
                    {"action": "RESET", "target": "COMPROMISED", "params": {}},
                ])
        elif self.state.agent_type == AgentType.ANALYST:
            actions.extend([
                {"action": "ANALYZE", "target": "ANY", "params": {}},
                {"action": "REPORT", "target": "ANY", "params": {}},
            ])
            if compromised:
                actions.extend([
                    {"action": "ASSESS", "target": "COMPROMISED", "params": {}},
                    {"action": "FORENSIC", "target": "COMPROMISED", "params": {}},
                ])

        return actions
        
    def update_reward(self, reward: float):
        """Update reward for last action"""
        if self.experience_buffer:
            self.experience_buffer[-1]["reward"] = reward
            
    def learn_from_experience(self) -> float:
        """Learn from experience using neural networks"""
        if len(self.experience_buffer) < 32:
            return 0.0
            
        # Sample batch from experience buffer
        batch = random.sample(list(self.experience_buffer), 32)
        
        states = torch.stack([exp["state"] for exp in batch]).to(self.device)
        actions = torch.tensor([exp["action"] for exp in batch], device=self.device)

        # Forward pass
        logits, _ = self.networks["decision_net"](states)
        
        # Calculate loss
        loss = self.decision_loss(logits, actions)
        
        # Backward pass
        self.optimizer.zero_grad()
        loss.backward()
        self.optimizer.step()
        
        # Update exploration rate
        self.state.exploration_rate *= 0.999
        self.state.exploration_rate = max(0.01, self.state.exploration_rate)
        
        return loss.item()

class MultiAgentCoordinator:
    """Coordinates multiple agents and manages their interactions"""
    
    def __init__(self, environment: MultiAgentEnvironment, action_adapter: Optional[Any] = None,
                 coordination_enabled: bool = True):
        self.environment = environment
        self.action_adapter = action_adapter
        self.coordination_enabled = bool(coordination_enabled)
        self.agents: Dict[str, NeuralLLMAgent] = {}
        self.coordination_history: List[Dict[str, Any]] = []

    def set_action_adapter(self, action_adapter: Any) -> None:
        """Set an adapter that converts symbolic actions to a simulator schema."""
        self.action_adapter = action_adapter
        
    def initialize_agents(self) -> None:
        """Initialize all agents with neural networks"""
        for agent_id, agent_state in self.environment.agents.items():
            self.agents[agent_id] = NeuralLLMAgent(
                agent_state, 
                self.environment.agent_networks[agent_id]
            )
            
    def simulate_round(self, base_env) -> Dict[str, Any]:
        """Simulate one round with all agents"""
        round_results = {
            "round": self.environment.round_count,
            "agent_actions": {},
            "symbolic_agent_actions": {},
            "unexecuted_actions": {},
            "communications": {},
            "learning_updates": {},
            "system_state": {}
        }
        
        # Get current environment state
        env_state = self._encode_environment_state(base_env)
        
        # Each agent makes a symbolic decision.  RED/BLUE decisions must pass
        # through an explicit adapter before reaching a simulator.
        for agent_id, agent in self.agents.items():
            symbolic_action = agent.make_decision(env_state)
            agent_state = self.environment.agents[agent_id]
            round_results["symbolic_agent_actions"][agent_id] = symbolic_action

            if agent_state.agent_type in [AgentType.ATTACKER, AgentType.DEFENDER]:
                if self.action_adapter is None:
                    raise RuntimeError(
                        "No simulator action adapter configured. Use "
                        "neural_agent_integration.SimulatorActionAdapter before executing RED/BLUE actions."
                    )
                action = self.action_adapter.adapt(symbolic_action, agent_state, base_env)
                actor = "RED" if agent_state.agent_type == AgentType.ATTACKER else "BLUE"
                result = base_env.execute_action(actor, action)
                round_results["agent_actions"][agent_id] = action
                round_results["system_state"][agent_id] = result
            else:
                # The primary simulator has RED/BLUE execution only.  Analysts
                # produce an advisory action, recorded explicitly rather than
                # pretending it was executed.
                round_results["agent_actions"][agent_id] = symbolic_action
                round_results["unexecuted_actions"][agent_id] = (
                    "ADVISORY_ONLY: primary simulator has no analyst actor"
                )
                
        # Agent communication phase is explicitly controlled by the CLI/config.
        if self.coordination_enabled:
            self._handle_agent_communications(round_results)
        else:
            round_results["communications"] = {
                channel: [] for channel in self.environment.communication_channels
            }
        
        # Learning phase
        self._handle_agent_learning(round_results)
        
        self.environment.round_count += 1
        return round_results
        
    def _encode_environment_state(self, base_env) -> Dict[str, Any]:
        """Encode base environment state for neural processing"""
        return {
            "assets": {
                aid: {
                    "compromised": asset.compromised,
                    "isolated": asset.isolated,
                    "hardened": asset.hardened,
                    "privilege": asset.privilege,
                    "services": asset.services
                }
                for aid, asset in base_env.assets.items()
            },
            "compromised_count": sum(1 for a in base_env.assets.values() if a.compromised),
            "total_assets": len(base_env.assets),
            "alarm_active": base_env.tank.alarm,
            "tank_level": base_env.tank.level,
            "damage_active": base_env.tank.damage
        }
        
    def _handle_agent_communications(self, round_results: Dict[str, Any]) -> None:
        """Handle inter-agent communications"""
        communications = {}
        
        # Simulate communications between agents
        for channel, agent_ids in self.environment.communication_channels.items():
            if len(agent_ids) > 1:
                # Agents in the same channel can communicate
                channel_messages = []
                
                for agent_id in agent_ids:
                    if agent_id in self.agents:
                        # Generate message based on agent's current state
                        message = self._generate_agent_message(agent_id, channel)
                        if message:
                            channel_messages.append(message)
                            
                communications[channel] = channel_messages
                
        round_results["communications"] = communications
        
    def _generate_agent_message(self, agent_id: str, channel: str) -> Optional[Dict[str, Any]]:
        """Generate message from agent based on its state"""
        agent_state = self.environment.agents[agent_id]
        
        # Simple message generation logic
        if channel == "attacker_coord":
            if agent_state.specialization == AgentSpecialization.INITIAL_ACCESS:
                return {
                    "sender": agent_id,
                    "type": "recon_report",
                    "content": f"Reconnaissance complete in {agent_state.position}",
                    "timestamp": self.environment.round_count
                }
        elif channel == "defender_coord":
            if agent_state.specialization == AgentSpecialization.DETECTION:
                return {
                    "sender": agent_id,
                    "type": "threat_alert",
                    "content": f"Suspicious activity detected in {agent_state.position}",
                    "timestamp": self.environment.round_count
                }
                
        return None
        
    def _handle_agent_learning(self, round_results: Dict[str, Any]) -> None:
        """Handle learning updates for all agents"""
        learning_updates = {}
        
        for agent_id, agent in self.agents.items():
            # Calculate reward based on action effectiveness
            reward = self._calculate_agent_reward(agent_id, round_results)
            agent.update_reward(reward)
            
            # Perform learning
            loss = agent.learn_from_experience()
            learning_updates[agent_id] = {
                "reward": reward,
                "loss": loss,
                "exploration_rate": agent.state.exploration_rate
            }
            
        round_results["learning_updates"] = learning_updates
        
    def _calculate_agent_reward(self, agent_id: str, round_results: Dict[str, Any]) -> float:
        """Calculate reward for agent based on its actions"""
        agent_state = self.environment.agents[agent_id]
        action = round_results["agent_actions"].get(agent_id, {})
        system_state = round_results["system_state"].get(agent_id, "")
        
        reward = 0.0
        
        if agent_state.agent_type == AgentType.ATTACKER:
            # Reward for successful attacks
            if "SUCCESS" in system_state:
                reward += 1.0
            if "COMPROMISE" in system_state:
                reward += 2.0
            if "MOVE" in action.get("action", ""):
                reward += 0.5
                
        elif agent_state.agent_type == AgentType.DEFENDER:
            # Reward for successful defenses
            if "SUCCESS" in system_state:
                reward += 1.0
            if "PATCH" in action.get("action", ""):
                reward += 0.5
            if "ISOLATE" in action.get("action", ""):
                reward += 1.0
                
        elif agent_state.agent_type == AgentType.ANALYST:
            # Reward for useful analysis
            if "ANALYZE" in action.get("action", ""):
                reward += 0.3
            if "REPORT" in action.get("action", ""):
                reward += 0.5
                
        return reward

# Integration with main simulation
def create_multi_agent_scenario(base_env, num_attackers: int = 3,
                               num_defenders: int = 3, num_analysts: int = 2,
                               neural_architectures: Optional[Dict[str, str]] = None) -> MultiAgentEnvironment:
    """Create a multi-agent scenario with neural network-enhanced agents."""

    env = MultiAgentEnvironment(
        base_env,
        max_agents=num_attackers + num_defenders + num_analysts,
        neural_architectures=neural_architectures,
    )
    
    # Add attacker agents
    attacker_specializations = [
        AgentSpecialization.INITIAL_ACCESS,
        AgentSpecialization.LATERAL_MOVEMENT,
        AgentSpecialization.PERSISTENCE
    ]
    
    for i in range(num_attackers):
        spec = attacker_specializations[i % len(attacker_specializations)]
        env.add_agent(
            f"attacker_{i+1}",
            AgentType.ATTACKER,
            spec,
            "IT" if i == 0 else "DMZ" if i == 1 else "OT"
        )
    
    # Add defender agents
    defender_specializations = [
        AgentSpecialization.DETECTION,
        AgentSpecialization.CONTAINMENT,
        AgentSpecialization.ERADICATION
    ]
    
    for i in range(num_defenders):
        spec = defender_specializations[i % len(defender_specializations)]
        env.add_agent(
            f"defender_{i+1}",
            AgentType.DEFENDER,
            spec,
            "IT" if i == 0 else "DMZ" if i == 1 else "OT"
        )
    
    # Add analyst agents
    analyst_specializations = [
        AgentSpecialization.THREAT_INTEL,
        AgentSpecialization.VULNERABILITY
    ]
    
    for i in range(num_analysts):
        spec = analyst_specializations[i % len(analyst_specializations)]
        env.add_agent(
            f"analyst_{i+1}",
            AgentType.ANALYST,
            spec,
            "IT"
        )
    
    return env

# Example usage
if __name__ == "__main__":
    print("🧠 Multi-Agent LLM System with Deep Neural Networks")
    print("=====================================================")
    print("Features:")
    print("- Deep neural network decision making")
    print("- Attention mechanisms for coordination")
    print("- Neural memory for experience storage")
    print("- Multi-agent communication channels")
    print("- Reinforcement learning adaptation")
    print("- Specialized agent roles and behaviors")

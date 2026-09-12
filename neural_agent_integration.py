#!/usr/bin/env python3
"""
Integration of Multi-Agent Neural System with Main CPS Simulation
Enhanced simulation with multiple LLM agents and deep neural networks
"""

import torch
import numpy as np
from typing import Dict, List, Any, Optional
from multi_agent_system import (
    MultiAgentEnvironment, MultiAgentCoordinator, create_multi_agent_scenario,
    AgentState, AgentType, AgentSpecialization
)


class UnsupportedSimulatorActionError(ValueError):
    """A neural symbolic action has no valid representation in the simulator."""


class SimulatorActionAdapter:
    """Convert neural symbolic actions into the primary simulator action schema.

    The primary CPS simulator consumes ``action``, ``target``, ``service`` and
    ``params`` fields, with real asset and service identifiers.  Neural agents
    intentionally emit role-level symbols (for example ``COMPROMISED`` or
    ``VULNERABLE``); this adapter is the single boundary that resolves those
    symbols and maps action names.  It raises rather than emitting an unknown
    command or a fabricated target.
    """

    _ACTION_MAP = {
        AgentType.ATTACKER: {
            "RECON": "RECON",
            "EXPLOIT": "EXPLOIT",
            "MOVE": "PIVOT",
            "PERSIST": "EXECUTE",
        },
        AgentType.DEFENDER: {
            "MONITOR": "MONITOR",
            "PATCH": "PATCH",
            "ISOLATE": "ISOLATE",
            "RESET": "RESTORE",
            "HARDEN": "HARDEN",
        },
    }
    _TARGETLESS_ACTIONS = {"RECON", "MONITOR"}

    @staticmethod
    def _field(obj: Any, name: str, default: Any = None) -> Any:
        return obj.get(name, default) if isinstance(obj, dict) else getattr(obj, name, default)

    def _assets(self, base_env: Any) -> Dict[str, Any]:
        assets = getattr(base_env, "assets", None)
        if not isinstance(assets, dict):
            raise UnsupportedSimulatorActionError(
                "Base environment must expose an assets dictionary for neural action adaptation"
            )
        return assets

    def _select_asset(self, base_env: Any, target_symbol: Any, *,
                      require_compromised: bool = False,
                      require_vulnerable: bool = False,
                      require_exploitable_service: bool = False) -> tuple[str, Any]:
        assets = self._assets(base_env)
        symbol = str(target_symbol or "NONE")
        if symbol in assets:
            candidates = [(symbol, assets[symbol])]
        elif symbol in {"ANY", "VULNERABLE", "COMPROMISED"}:
            candidates = sorted(assets.items())
        else:
            raise UnsupportedSimulatorActionError(f"Unsupported neural target symbol: {symbol}")

        for asset_id, asset in candidates:
            if self._field(asset, "isolated", False):
                continue
            if require_compromised and not self._field(asset, "compromised", False):
                continue
            if require_vulnerable and not self._has_unpatched_service(asset):
                continue
            if require_exploitable_service:
                try:
                    self._select_service(asset, require_vulnerability=True)
                except UnsupportedSimulatorActionError:
                    continue
            return asset_id, asset
        condition = (
            "compromised" if require_compromised else
            "vulnerable" if require_vulnerable else
            "exploitable" if require_exploitable_service else "usable"
        )
        raise UnsupportedSimulatorActionError(f"No {condition} asset is available for target {symbol}")

    def _has_unpatched_service(self, asset: Any) -> bool:
        services = self._field(asset, "services", {}) or {}
        return any(not self._field(service, "patched", False) for service in services.values())

    def _select_service(self, asset: Any, *, require_vulnerability: bool = False) -> str:
        services = self._field(asset, "services", {}) or {}
        for service_name in sorted(services):
            service = services[service_name]
            if self._field(service, "patched", False) or not self._field(service, "exposed", False):
                continue
            if require_vulnerability and self._field(service, "vuln_id", None) is None:
                continue
            return service_name
        raise UnsupportedSimulatorActionError("No exposed, unpatched compatible service is available")

    def adapt(self, symbolic_action: Dict[str, Any], agent_state: AgentState,
              base_env: Any) -> Dict[str, Any]:
        """Return a concrete primary-simulator action or raise a clear error."""
        if not isinstance(symbolic_action, dict):
            raise UnsupportedSimulatorActionError("Neural action must be a dictionary")
        action_name = str(symbolic_action.get("action", "")).upper()
        mappings = self._ACTION_MAP.get(agent_state.agent_type)
        if mappings is None or action_name not in mappings:
            raise UnsupportedSimulatorActionError(
                f"{agent_state.agent_type.value} action '{action_name}' has no primary-simulator mapping"
            )

        simulator_action = mappings[action_name]
        params = symbolic_action.get("params", {}) or {}
        if not isinstance(params, dict):
            raise UnsupportedSimulatorActionError("Neural action params must be a dictionary")
        if simulator_action in self._TARGETLESS_ACTIONS:
            return {"action": simulator_action, "target": "NONE", "service": "NONE", "params": params}

        target_symbol = symbolic_action.get("target", "ANY")
        needs_compromised = simulator_action in {"PIVOT", "EXECUTE", "ISOLATE", "RESTORE"}
        needs_vulnerable = simulator_action == "PATCH"
        target, asset = self._select_asset(
            base_env, target_symbol,
            require_compromised=needs_compromised,
            require_vulnerable=needs_vulnerable,
        )
        service = "NONE"
        if simulator_action == "EXPLOIT":
            # EXPLOIT requires a concrete exposed service with a modeled vuln.
            target, asset = self._select_asset(
                base_env, target_symbol, require_exploitable_service=True
            )
            service = self._select_service(asset, require_vulnerability=True)
        elif simulator_action == "PATCH":
            # A targeted service makes the action deterministic and portable.
            service = self._select_service(asset)
        return {"action": simulator_action, "target": target, "service": service, "params": params}


class NeuralEnhancedSimulation:
    """Enhanced CPS simulation with neural multi-agent system"""
    
    def __init__(self, base_env, config: Dict[str, Any]):
        self.base_env = base_env
        self.config = config
        self.training_enabled = bool(config.get("neural_training", False))
        self.coordination_enabled = bool(config.get("agent_coordination", False))
        
        # Multi-agent system
        self.multi_agent_env = create_multi_agent_scenario(
            base_env,
            num_attackers=config.get("num_attackers", 3),
            num_defenders=config.get("num_defenders", 3),
            num_analysts=config.get("num_analysts", 2),
            neural_architectures=config.get("neural_architectures"),
        )

        # This is the explicit integration boundary for the primary simulator.
        self.coordinator = MultiAgentCoordinator(
            self.multi_agent_env,
            action_adapter=SimulatorActionAdapter(),
            coordination_enabled=self.coordination_enabled,
        )
        self.coordinator.initialize_agents()
        
        # Neural network training configuration
        self.training_config = {
            "batch_size": 32,
            "learning_rate": 0.001,
            "epsilon": 0.1,
            "gamma": 0.99,
            "target_update": 100
        }
        
        # Performance tracking
        self.performance_history = {
            "agent_rewards": [],
            "neural_losses": [],
            "coordination_effectiveness": [],
            "simulation_outcomes": []
        }
        
    def run_enhanced_simulation(self, max_rounds: int = 100) -> Dict[str, Any]:
        """Run enhanced simulation with neural agents"""
        
        print(f"🧠 Starting Neural-Enhanced Multi-Agent Simulation")
        print(f"📊 Agents: {len(self.multi_agent_env.agents)} total")
        print(f"⚡ Neural Networks: {len(self.multi_agent_env.agent_networks)} active")
        print(f"🔄 Rounds: {max_rounds}")
        
        simulation_results = {
            "rounds": [],
            "agent_performance": {},
            "neural_metrics": {},
            "coordination_events": [],
            "final_state": {}
        }
        
        for round_num in range(max_rounds):
            print(f"🎯 Round {round_num + 1}/{max_rounds}")
            
            # Run multi-agent round
            round_results = self.coordinator.simulate_round(self.base_env)
            
            # Collect metrics
            self._collect_round_metrics(round_results, simulation_results)
            
            # Periodic neural network training
            if self.training_enabled and round_num % 10 == 0:
                self._train_neural_networks()
                
            # Update environment physics
            self.base_env.update_physics()
            
            # Check termination conditions
            if self._check_termination_conditions():
                print(f"🏁 Simulation terminated at round {round_num + 1}")
                break
                
        # Final analysis
        simulation_results["final_state"] = self._get_final_state()
        simulation_results["performance_summary"] = self._generate_performance_summary()
        
        return simulation_results
        
    def _collect_round_metrics(self, round_results: Dict[str, Any], 
                              simulation_results: Dict[str, Any]) -> None:
        """Collect and store metrics from each round"""
        
        # Agent performance
        for agent_id, learning_update in round_results["learning_updates"].items():
            if agent_id not in simulation_results["agent_performance"]:
                simulation_results["agent_performance"][agent_id] = {
                    "rewards": [],
                    "losses": [],
                    "exploration_rates": []
                }
                
            perf = simulation_results["agent_performance"][agent_id]
            perf["rewards"].append(learning_update["reward"])
            perf["losses"].append(learning_update["loss"])
            perf["exploration_rates"].append(learning_update["exploration_rate"])
            
        # Neural network metrics
        total_loss = sum(up["loss"] for up in round_results["learning_updates"].values())
        simulation_results["neural_metrics"][round_results["round"]] = {
            "total_loss": total_loss,
            "avg_loss": total_loss / len(round_results["learning_updates"]),
            "active_agents": len(round_results["agent_actions"])
        }
        
        # Coordination events
        for channel, messages in round_results["communications"].items():
            if messages:
                simulation_results["coordination_events"].append({
                    "round": round_results["round"],
                    "channel": channel,
                    "message_count": len(messages),
                    "messages": messages
                })
                
        simulation_results["rounds"].append(round_results)
        
    def _train_neural_networks(self) -> None:
        """Train all neural networks"""
        print("🧠 Training neural networks...")
        
        total_loss = 0.0
        trained_agents = 0
        
        for agent_id, agent in self.coordinator.agents.items():
            loss = agent.learn_from_experience()
            if loss > 0:
                total_loss += loss
                trained_agents += 1
                
        if trained_agents > 0:
            avg_loss = total_loss / trained_agents
            print(f"📈 Trained {trained_agents} agents, avg loss: {avg_loss:.4f}")
            
    def _check_termination_conditions(self) -> bool:
        """Check if simulation should terminate"""
        
        # Check for complete system compromise
        compromised_count = sum(1 for a in self.base_env.assets.values() if a.compromised)
        total_assets = len(self.base_env.assets)
        
        if compromised_count == total_assets:
            print("🚨 Complete system compromise detected")
            return True
            
        # Check for critical damage
        if self.base_env.tank.damage > 0.8:
            print("💥 Critical damage threshold reached")
            return True
            
        # Check for successful defense
        if compromised_count == 0 and self.base_env.round > 50:
            print("🛡️ Successful defense achieved")
            return True
            
        return False
        
    def _get_final_state(self) -> Dict[str, Any]:
        """Get final simulation state"""
        return {
            "round": self.base_env.round,
            "compromised_assets": sum(1 for a in self.base_env.assets.values() if a.compromised),
            "total_assets": len(self.base_env.assets),
            "tank_level": self.base_env.tank.level,
            "tank_damage": self.base_env.tank.damage,
            "alarm_active": self.base_env.tank.alarm,
            "agent_states": {
                aid: {
                    "type": agent.agent_type.value,
                    "specialization": agent.specialization.value,
                    "position": agent.position,
                    "final_reward": agent.performance_metrics.get("total_reward", 0)
                }
                for aid, agent in self.multi_agent_env.agents.items()
            }
        }
        
    def _generate_performance_summary(self) -> Dict[str, Any]:
        """Generate comprehensive performance summary"""
        
        summary = {
            "simulation_effectiveness": 0.0,
            "agent_collaboration_score": 0.0,
            "neural_learning_effectiveness": 0.0,
            "attack_success_rate": 0.0,
            "defense_success_rate": 0.0,
            "coordination_efficiency": 0.0
        }
        
        # Calculate agent collaboration
        total_coordination_events = len(self.performance_history["coordination_effectiveness"])
        if total_coordination_events > 0:
            summary["coordination_efficiency"] = sum(self.performance_history["coordination_effectiveness"]) / total_coordination_events
            
        # Calculate neural learning effectiveness
        total_losses = self.performance_history["neural_losses"]
        if total_losses:
            summary["neural_learning_effectiveness"] = 1.0 - (sum(total_losses) / len(total_losses))
            
        # Calculate attack/defense success rates
        attacker_agents = [aid for aid, agent in self.multi_agent_env.agents.items() 
                          if agent.agent_type == AgentType.ATTACKER]
        defender_agents = [aid for aid, agent in self.multi_agent_env.agents.items() 
                          if agent.agent_type == AgentType.DEFENDER]
        
        # Simplified success rate calculation
        if attacker_agents:
            attacker_rewards = [self.coordinator.agents[aid].state.performance_metrics.get("total_reward", 0) 
                               for aid in attacker_agents]
            summary["attack_success_rate"] = max(0, sum(attacker_rewards) / len(attacker_agents))
            
        if defender_agents:
            defender_rewards = [self.coordinator.agents[aid].state.performance_metrics.get("total_reward", 0) 
                               for aid in defender_agents]
            summary["defense_success_rate"] = max(0, sum(defender_rewards) / len(defender_agents))
            
        # Overall effectiveness
        summary["simulation_effectiveness"] = (
            summary["coordination_efficiency"] * 0.3 +
            summary["neural_learning_effectiveness"] * 0.3 +
            summary["defense_success_rate"] * 0.2 +
            summary["attack_success_rate"] * 0.2
        )
        
        return summary

# Advanced Neural Network Architectures
class AdvancedNeuralArchitectures:
    """Advanced neural network architectures for specialized agent behaviors"""
    
    @staticmethod
    def create_transformer_agent(input_dim: int, output_dim: int, num_heads: int = 8) -> torch.nn.Module:
        """Create transformer-based agent for complex reasoning"""
        
        class TransformerAgent(torch.nn.Module):
            def __init__(self, input_dim, output_dim, num_heads):
                super().__init__()
                
                self.embedding = torch.nn.Linear(input_dim, 256)
                self.transformer = torch.nn.TransformerEncoder(
                    torch.nn.TransformerEncoderLayer(
                        d_model=256,
                        nhead=num_heads,
                        dim_feedforward=512,
                        dropout=0.1
                    ),
                    num_layers=6
                )
                self.output = torch.nn.Linear(256, output_dim)
                
            def forward(self, x):
                x = self.embedding(x)
                x = x.unsqueeze(1)  # Add sequence dimension
                x = self.transformer(x)
                x = x.squeeze(1)
                return self.output(x)
                
        return TransformerAgent(input_dim, output_dim, num_heads)
    
    @staticmethod
    def create_graph_neural_agent(node_features: int, edge_features: int) -> torch.nn.Module:
        """Create graph neural network agent for network topology reasoning"""
        
        class GraphNeuralAgent(torch.nn.Module):
            def __init__(self, node_features, edge_features):
                super().__init__()
                
                self.node_encoder = torch.nn.Linear(node_features, 64)
                self.edge_encoder = torch.nn.Linear(edge_features, 32)
                
                self.gnn_layers = torch.nn.ModuleList([
                    torch.nn.Linear(64 + 32, 64) for _ in range(3)
                ])
                
                self.output = torch.nn.Linear(64, 32)
                
            def forward(self, node_features, edge_features, adjacency):
                # Encode nodes and edges
                node_emb = self.node_encoder(node_features)
                edge_emb = self.edge_encoder(edge_features)
                
                # Message passing
                for layer in self.gnn_layers:
                    messages = torch.matmul(adjacency, node_emb)
                    node_emb = torch.cat([node_emb, messages], dim=-1)
                    node_emb = torch.relu(layer(node_emb))
                    
                return self.output(node_emb)
                
        return GraphNeuralAgent(node_features, edge_features)
    
    @staticmethod
    def create_memory_augmented_agent(input_dim: int, memory_size: int = 1000) -> torch.nn.Module:
        """Create memory-augmented neural network agent"""
        
        class MemoryAugmentedAgent(torch.nn.Module):
            def __init__(self, input_dim, memory_size):
                super().__init__()
                
                self.input_dim = input_dim
                self.memory_size = memory_size
                
                # Main processing network
                self.processor = torch.nn.Sequential(
                    torch.nn.Linear(input_dim, 256),
                    torch.nn.ReLU(),
                    torch.nn.Linear(256, 128),
                    torch.nn.ReLU(),
                    torch.nn.Linear(128, 64)
                )
                
                # Memory network
                self.memory = torch.nn.Parameter(torch.randn(memory_size, 64))
                self.memory_key = torch.nn.Linear(64, 64)
                self.memory_value = torch.nn.Linear(64, 64)
                
                # Output network
                self.output = torch.nn.Linear(64, 32)
                
            def forward(self, x):
                # Process input
                processed = self.processor(x)
                
                # Memory attention
                keys = self.memory_key(self.memory)
                query = self.memory_key(processed)
                
                attention_weights = torch.softmax(
                    torch.matmul(query, keys.T) / 8.0, dim=-1
                )
                
                memory_retrieval = torch.matmul(attention_weights, self.memory_value(self.memory))
                
                # Combine with processed input
                combined = processed + memory_retrieval
                
                return self.output(combined)
                
        return MemoryAugmentedAgent(input_dim, memory_size)

# Integration utilities
def integrate_neural_agents_with_main_simulation():
    """Integration function for main simulation"""
    
    print("🧠 Neural Agent Integration Ready!")
    print("=" * 50)
    print("Available Features:")
    print("✅ Deep Neural Network Decision Making")
    print("✅ Multi-Agent Coordination")
    print("✅ Transformer-based Reasoning")
    print("✅ Graph Neural Networks for Topology")
    print("✅ Memory-Augmented Learning")
    print("✅ Reinforcement Learning Adaptation")
    print("✅ Specialized Agent Roles")
    print("✅ Real-time Neural Training")
    
    print("\n🚀 Usage:")
    print("1. Create base environment")
    print("2. Initialize NeuralEnhancedSimulation")
    print("3. Run enhanced simulation")
    print("4. Analyze neural agent performance")
    
    return True

# Example configuration
NEURAL_SIMULATION_CONFIG = {
    "num_attackers": 3,
    "num_defenders": 3,
    "num_analysts": 2,
    # Only choices wired to NeuralLLMAgent's decision/attention/memory
    # interfaces are accepted.  Unsupported advanced architectures fail at
    # construction instead of being silently ignored.
    "neural_architectures": {
        "decision_net": "deep_feedforward",
        "coordination_net": "attention",
        "memory_net": "basic"
    },
    "training_params": {
        "learning_rate": 0.001,
        "batch_size": 32,
        "experience_replay_size": 10000,
        "target_update_frequency": 100
    },
    "agent_specializations": {
        "attackers": ["initial_access", "lateral_movement", "persistence"],
        "defenders": ["detection", "containment", "eradication"],
        "analysts": ["threat_intel", "vulnerability"]
    }
}

if __name__ == "__main__":
    integrate_neural_agents_with_main_simulation()

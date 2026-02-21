#!/usr/bin/env python3
"""
Advanced Neural Network Architectures for Multi-Agent CPS Simulation
Cutting-edge neural architectures for sophisticated agent behaviors
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
import math

# === TRANSFORMER-BASED MULTI-AGENT REASONING ===

class MultiAgentTransformer(nn.Module):
    """Transformer architecture for multi-agent coordination and reasoning"""
    
    def __init__(self, agent_dim: int, embed_dim: int = 256, num_heads: int = 8, 
                 num_layers: int = 6, max_agents: int = 20):
        super().__init__()
        
        self.agent_dim = agent_dim
        self.embed_dim = embed_dim
        self.max_agents = max_agents
        
        # Agent embedding layer
        self.agent_embedding = nn.Linear(agent_dim, embed_dim)
        
        # Positional encoding for agent positions
        self.positional_encoding = PositionalEncoding(embed_dim, max_agents)
        
        # Transformer encoder layers
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim,
            nhead=num_heads,
            dim_feedforward=embed_dim * 4,
            dropout=0.1,
            activation='gelu'
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers)
        
        # Multi-head attention for agent interaction
        self.agent_attention = nn.MultiheadAttention(
            embed_dim=embed_dim,
            num_heads=num_heads,
            batch_first=True
        )
        
        # Output heads for different tasks
        self.coordination_head = nn.Linear(embed_dim, embed_dim)
        self.decision_head = nn.Linear(embed_dim, 32)  # Action space
        self.value_head = nn.Linear(embed_dim, 1)  # State value
        
    def forward(self, agent_states: torch.Tensor, 
                agent_mask: Optional[torch.Tensor] = None) -> Dict[str, torch.Tensor]:
        
        batch_size, num_agents, _ = agent_states.shape
        
        # Embed agent states
        embedded = self.agent_embedding(agent_states)
        
        # Add positional encoding
        embedded = self.positional_encoding(embedded)
        
        # Apply transformer
        if agent_mask is not None:
            # Create attention mask
            attn_mask = ~agent_mask.bool()
        else:
            attn_mask = None
            
        transformer_output = self.transformer(embedded, src_key_padding_mask=attn_mask)
        
        # Multi-agent attention
        attended_output, attention_weights = self.agent_attention(
            transformer_output, transformer_output, transformer_output,
            key_padding_mask=attn_mask
        )
        
        # Generate outputs
        coordination_logits = self.coordination_head(attended_output)
        decision_logits = self.decision_head(attended_output)
        values = self.value_head(attended_output)
        
        return {
            "coordination": coordination_logits,
            "decisions": decision_logits,
            "values": values,
            "attention_weights": attention_weights,
            "embeddings": attended_output
        }

class PositionalEncoding(nn.Module):
    """Positional encoding for agent positions in transformer"""
    
    def __init__(self, embed_dim: int, max_agents: int):
        super().__init__()
        
        pe = torch.zeros(max_agents, embed_dim)
        position = torch.arange(0, max_agents, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, embed_dim, 2).float() * 
                           (-math.log(10000.0) / embed_dim))
        
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        
        self.register_buffer('pe', pe.unsqueeze(0))
        
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return x + self.pe[:, :x.size(1)]

# === GRAPH NEURAL NETWORKS FOR NETWORK TOPOLOGY ===

class GraphNeuralNetwork(nn.Module):
    """Graph Neural Network for network topology analysis and attack path prediction"""
    
    def __init__(self, node_features: int, edge_features: int, 
                 hidden_dim: int = 128, num_layers: int = 3):
        super().__init__()
        
        self.node_features = node_features
        self.edge_features = edge_features
        self.hidden_dim = hidden_dim
        
        # Node and edge encoders
        self.node_encoder = nn.Linear(node_features, hidden_dim)
        self.edge_encoder = nn.Linear(edge_features, hidden_dim)
        
        # Graph convolution layers
        self.gnn_layers = nn.ModuleList([
            GraphConvLayer(hidden_dim, hidden_dim) for _ in range(num_layers)
        ])
        
        # Attention mechanism for node importance
        self.node_attention = nn.MultiheadAttention(
            embed_dim=hidden_dim,
            num_heads=8,
            batch_first=True
        )
        
        # Output heads
        self.vulnerability_head = nn.Linear(hidden_dim, 1)
        self.attack_path_head = nn.Linear(hidden_dim * 2, 1)
        self.defense_priority_head = nn.Linear(hidden_dim, 1)
        
    def forward(self, node_features: torch.Tensor, edge_features: torch.Tensor,
                edge_index: torch.Tensor, batch: Optional[torch.Tensor] = None) -> Dict[str, torch.Tensor]:
        
        # Encode nodes and edges
        node_emb = self.node_encoder(node_features)
        edge_emb = self.edge_encoder(edge_features)
        
        # Graph message passing
        for gnn_layer in self.gnn_layers:
            node_emb = gnn_layer(node_emb, edge_emb, edge_index)
            
        # Node attention
        attended_nodes, attention_weights = self.node_attention(
            node_emb, node_emb, node_emb
        )
        
        # Predictions
        vulnerabilities = torch.sigmoid(self.vulnerability_head(attended_nodes))
        defense_priorities = torch.sigmoid(self.defense_priority_head(attended_nodes))
        
        # Attack path prediction (for connected nodes)
        if edge_index.size(1) > 0:
            src_nodes = attended_nodes[edge_index[0]]
            dst_nodes = attended_nodes[edge_index[1]]
            path_features = torch.cat([src_nodes, dst_nodes], dim=-1)
            attack_probabilities = torch.sigmoid(self.attack_path_head(path_features))
        else:
            attack_probabilities = torch.empty(0, 1)
            
        return {
            "node_embeddings": attended_nodes,
            "vulnerabilities": vulnerabilities,
            "defense_priorities": defense_priorities,
            "attack_probabilities": attack_probabilities,
            "attention_weights": attention_weights
        }

class GraphConvLayer(nn.Module):
    """Graph convolution layer for message passing"""
    
    def __init__(self, in_dim: int, out_dim: int):
        super().__init__()
        
        self.message_net = nn.Sequential(
            nn.Linear(in_dim * 2 + out_dim, out_dim),
            nn.ReLU(),
            nn.Dropout(0.1)
        )
        
        self.update_net = nn.Sequential(
            nn.Linear(in_dim + out_dim, out_dim),
            nn.ReLU(),
            nn.Dropout(0.1)
        )
        
    def forward(self, node_features: torch.Tensor, edge_features: torch.Tensor,
                edge_index: torch.Tensor) -> torch.Tensor:
        
        # Message passing
        row, col = edge_index
        
        # Get source and target node features
        src_features = node_features[row]
        dst_features = node_features[col]
        
        # Create message
        messages = torch.cat([src_features, dst_features, edge_features], dim=-1)
        messages = self.message_net(messages)
        
        # Aggregate messages (mean aggregation)
        num_nodes = node_features.size(0)
        aggregated = torch.zeros_like(node_features)
        aggregated.index_add_(0, col, messages)
        
        # Count messages for each node
        message_count = torch.zeros(num_nodes, 1, device=node_features.device)
        message_count.index_add_(0, col, torch.ones_like(col, dtype=torch.float32, device=node_features.device).unsqueeze(-1))
        
        # Normalize by message count
        aggregated = aggregated / (message_count + 1e-6)
        
        # Update node features
        updated = self.update_net(torch.cat([node_features, aggregated], dim=-1))
        
        return updated

# === MEMORY-AUGMENTED NEURAL NETWORKS ===

class DifferentiableMemory(nn.Module):
    """Differentiable neural memory for experience storage and retrieval"""
    
    def __init__(self, memory_size: int, feature_dim: int, key_dim: int = 64):
        super().__init__()
        
        self.memory_size = memory_size
        self.feature_dim = feature_dim
        self.key_dim = key_dim
        
        # Memory banks
        self.key_memory = nn.Parameter(torch.randn(memory_size, key_dim))
        self.value_memory = nn.Parameter(torch.randn(memory_size, feature_dim))
        
        # Usage tracking
        self.usage = nn.Parameter(torch.zeros(memory_size), requires_grad=False)
        
        # Networks for key/value generation
        self.key_network = nn.Linear(feature_dim, key_dim)
        self.value_network = nn.Linear(feature_dim, feature_dim)
        
        # Read/Write networks
        self.read_network = nn.Linear(key_dim, key_dim)
        self.write_network = nn.Linear(feature_dim, feature_dim)
        
    def forward(self, query: torch.Tensor, write_data: Optional[torch.Tensor] = None,
                write_strength: float = 1.0) -> Dict[str, torch.Tensor]:
        
        batch_size = query.size(0)
        
        # Generate query key
        query_key = self.key_network(query)
        
        # Attention over memory
        memory_keys = self.key_memory.unsqueeze(0).expand(batch_size, -1, -1)
        attention_weights = F.softmax(
            torch.bmm(query_key.unsqueeze(1), memory_keys.transpose(1, 2)).squeeze(1) / math.sqrt(self.key_dim),
            dim=-1
        )
        
        # Read from memory
        memory_values = self.value_memory.unsqueeze(0).expand(batch_size, -1, -1)
        read_data = torch.bmm(attention_weights.unsqueeze(1), memory_values).squeeze(1)
        
        # Write to memory (if provided)
        if write_data is not None:
            write_key = self.key_network(write_data)
            write_value = self.value_network(write_data)
            
            # Find least used memory slots
            usage_scores = self.usage.unsqueeze(0).expand(batch_size, -1)
            write_weights = F.softmax(-usage_scores, dim=-1) * write_strength
            
            # Update memory
            self.key_memory = self.key_memory + torch.mm(
                write_weights.T, write_key
            ) / (self.usage.unsqueeze(1) + 1e-6)
            
            self.value_memory = self.value_memory + torch.mm(
                write_weights.T, write_value
            ) / (self.usage.unsqueeze(1) + 1e-6)
            
            # Update usage
            self.usage = self.usage + write_weights.mean(dim=0)
            self.usage = torch.clamp(self.usage, 0, 100)
            
        return {
            "read_data": read_data,
            "attention_weights": attention_weights,
            "memory_keys": self.key_memory,
            "memory_values": self.value_memory
        }

class MemoryAugmentedAgent(nn.Module):
    """Agent with differentiable memory for long-term learning"""
    
    def __init__(self, input_dim: int, output_dim: int, memory_size: int = 1000):
        super().__init__()
        
        self.input_dim = input_dim
        self.output_dim = output_dim
        
        # Main processing network
        self.processing_network = nn.Sequential(
            nn.Linear(input_dim, 256),
            nn.LayerNorm(256),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(256, 128),
            nn.LayerNorm(128),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(128, 64)
        )
        
        # Differentiable memory
        self.memory = DifferentiableMemory(memory_size, 64)
        
        # Decision network
        self.decision_network = nn.Sequential(
            nn.Linear(64 + 64, 128),  # processed + memory
            nn.ReLU(),
            nn.Linear(128, output_dim)
        )
        
        # Value network
        self.value_network = nn.Sequential(
            nn.Linear(64 + 64, 64),
            nn.ReLU(),
            nn.Linear(64, 1)
        )
        
    def forward(self, state: torch.Tensor, 
                memory_write: Optional[torch.Tensor] = None) -> Dict[str, torch.Tensor]:
        
        # Process state
        processed_state = self.processing_network(state)
        
        # Memory interaction
        memory_output = self.memory(processed_state, memory_write)
        
        # Combine processed state with memory
        combined = torch.cat([processed_state, memory_output["read_data"]], dim=-1)
        
        # Generate decisions and values
        decisions = self.decision_network(combined)
        values = self.value_network(combined)
        
        return {
            "decisions": decisions,
            "values": values,
            "memory_read": memory_output["read_data"],
            "attention_weights": memory_output["attention_weights"]
        }

# === HIERARCHICAL REINFORCEMENT LEARNING ===

class HierarchicalRLAgent(nn.Module):
    """Hierarchical RL agent with high-level and low-level policies"""
    
    def __init__(self, state_dim: int, high_level_actions: int, 
                 low_level_actions: int, subgoal_dim: int = 32):
        super().__init__()
        
        self.state_dim = state_dim
        self.high_level_actions = high_level_actions
        self.low_level_actions = low_level_actions
        self.subgoal_dim = subgoal_dim
        
        # High-level policy (selects subgoals)
        self.high_level_policy = nn.Sequential(
            nn.Linear(state_dim, 256),
            nn.ReLU(),
            nn.Linear(256, subgoal_dim),
            nn.ReLU(),
            nn.Linear(subgoal_dim, high_level_actions)
        )
        
        # Subgoal generator
        self.subgoal_generator = nn.Sequential(
            nn.Linear(state_dim, 256),
            nn.ReLU(),
            nn.Linear(256, subgoal_dim)
        )
        
        # Low-level policy (actions to achieve subgoals)
        self.low_level_policy = nn.Sequential(
            nn.Linear(state_dim + subgoal_dim, 256),
            nn.ReLU(),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Linear(128, low_level_actions)
        )
        
        # Termination network (when to terminate subgoal)
        self.termination_network = nn.Sequential(
            nn.Linear(state_dim + subgoal_dim, 128),
            nn.ReLU(),
            nn.Linear(128, 1),
            nn.Sigmoid()
        )
        
    def forward(self, state: torch.Tensor, 
                current_subgoal: Optional[torch.Tensor] = None) -> Dict[str, torch.Tensor]:
        
        batch_size = state.size(0)
        
        # High-level decision (if no current subgoal)
        if current_subgoal is None:
            high_level_logits = self.high_level_policy(state)
            subgoal = self.subgoal_generator(state)
            terminate = torch.ones(batch_size, 1)  # Terminate previous subgoal
        else:
            high_level_logits = None
            subgoal = current_subgoal
            
            # Low-level decision
            low_level_input = torch.cat([state, subgoal], dim=-1)
            low_level_logits = self.low_level_policy(low_level_input)
            terminate = self.termination_network(low_level_input)
            
        return {
            "high_level_logits": high_level_logits,
            "low_level_logits": low_level_logits if current_subgoal is not None else None,
            "subgoal": subgoal,
            "terminate": terminate
        }

# === ATTENTION-BASED MULTI-TASK LEARNING ===

class MultiTaskAttentionAgent(nn.Module):
    """Multi-task agent with attention-based task selection"""
    
    def __init__(self, state_dim: int, task_dims: Dict[str, int], 
                 shared_dim: int = 256):
        super().__init__()
        
        self.state_dim = state_dim
        self.task_dims = task_dims
        self.shared_dim = shared_dim
        
        # Shared feature extractor
        self.shared_encoder = nn.Sequential(
            nn.Linear(state_dim, shared_dim),
            nn.LayerNorm(shared_dim),
            nn.ReLU(),
            nn.Dropout(0.1)
        )
        
        # Task-specific attention
        self.task_attention = nn.MultiheadAttention(
            embed_dim=shared_dim,
            num_heads=8,
            batch_first=True
        )
        
        # Task-specific heads
        self.task_heads = nn.ModuleDict({
            task_name: nn.Sequential(
                nn.Linear(shared_dim, 128),
                nn.ReLU(),
                nn.Linear(128, task_dim)
            )
            for task_name, task_dim in task_dims.items()
        })
        
        # Task selection network
        self.task_selector = nn.Sequential(
            nn.Linear(state_dim, shared_dim),
            nn.ReLU(),
            nn.Linear(shared_dim, len(task_dims))
        )
        
    def forward(self, state: torch.Tensor, 
                task_weights: Optional[torch.Tensor] = None) -> Dict[str, torch.Tensor]:
        
        # Extract shared features
        shared_features = self.shared_encoder(state)
        
        # Task selection
        if task_weights is None:
            task_logits = self.task_selector(state)
            task_weights = F.softmax(task_logits, dim=-1)
            
        # Apply task-specific attention
        task_features = shared_features.unsqueeze(1)
        attended_features, attention_weights = self.task_attention(
            task_features, task_features, task_features
        )
        attended_features = attended_features.squeeze(1)
        
        # Generate task-specific outputs
        task_outputs = {}
        for task_name, task_head in self.task_heads.items():
            task_outputs[task_name] = task_head(attended_features)
            
        return {
            "task_outputs": task_outputs,
            "task_weights": task_weights,
            "shared_features": attended_features,
            "attention_weights": attention_weights
        }

# === ENSEMBLE NEURAL ARCHITECTURES ===

class EnsembleAgent(nn.Module):
    """Ensemble of neural networks for robust decision making"""
    
    def __init__(self, state_dim: int, action_dim: int, 
                 ensemble_size: int = 5, diversity_weight: float = 0.1):
        super().__init__()
        
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.ensemble_size = ensemble_size
        self.diversity_weight = diversity_weight
        
        # Create ensemble of networks
        self.networks = nn.ModuleList([
            nn.Sequential(
                nn.Linear(state_dim, 256),
                nn.ReLU(),
                nn.Dropout(0.1),
                nn.Linear(256, 128),
                nn.ReLU(),
                nn.Dropout(0.1),
                nn.Linear(128, action_dim)
            )
            for _ in range(ensemble_size)
        ])
        
        # Uncertainty estimation
        self.uncertainty_network = nn.Sequential(
            nn.Linear(state_dim, 128),
            nn.ReLU(),
            nn.Linear(128, 1),
            nn.Sigmoid()
        )
        
    def forward(self, state: torch.Tensor) -> Dict[str, torch.Tensor]:
        
        # Get predictions from all networks
        predictions = torch.stack([net(state) for net in self.networks], dim=1)
        
        # Ensemble prediction (mean)
        ensemble_prediction = predictions.mean(dim=1)
        
        # Prediction uncertainty (variance)
        prediction_variance = predictions.var(dim=1)
        
        # Estimated uncertainty
        estimated_uncertainty = self.uncertainty_network(state)
        
        # Combine uncertainties
        total_uncertainty = prediction_variance.mean(dim=-1, keepdim=True) + estimated_uncertainty
        
        return {
            "ensemble_prediction": ensemble_prediction,
            "individual_predictions": predictions,
            "prediction_variance": prediction_variance,
            "estimated_uncertainty": estimated_uncertainty,
            "total_uncertainty": total_uncertainty
        }

# === NEUROEVOLUTION COMPONENTS ===

class NeuroevolutionAgent:
    """Agent that evolves its neural network architecture"""
    
    def __init__(self, input_dim: int, output_dim: int, 
                 population_size: int = 20):
        self.input_dim = input_dim
        self.output_dim = output_dim
        self.population_size = population_size
        
        # Initialize population
        self.population = self._initialize_population()
        self.fitness_scores = np.zeros(population_size)
        
    def _initialize_population(self) -> List[nn.Module]:
        """Initialize population of neural networks"""
        population = []
        
        for i in range(self.population_size):
            # Random architecture
            hidden_layers = np.random.randint(1, 4)
            layer_sizes = [self.input_dim] + \
                          [np.random.randint(64, 256) for _ in range(hidden_layers)] + \
                          [self.output_dim]
            
            # Create network
            layers = []
            for i in range(len(layer_sizes) - 1):
                layers.append(nn.Linear(layer_sizes[i], layer_sizes[i + 1]))
                if i < len(layer_sizes) - 2:
                    layers.append(nn.ReLU())
                    layers.append(nn.Dropout(0.1))
                    
            network = nn.Sequential(*layers)
            population.append(network)
            
        return population
    
    def evaluate_fitness(self, env, episodes: int = 10) -> np.ndarray:
        """Evaluate fitness of each network in population"""
        for i, network in enumerate(self.population):
            total_reward = 0.0
            
            for episode in range(episodes):
                # Reset environment
                state = env.reset()
                episode_reward = 0.0
                done = False
                
                while not done:
                    # Get action from network
                    with torch.no_grad():
                        state_tensor = torch.FloatTensor(state).unsqueeze(0)
                        action_logits = network(state_tensor)
                        action = torch.argmax(action_logits, dim=1).item()
                    
                    # Take action
                    next_state, reward, done, _ = env.step(action)
                    episode_reward += reward
                    state = next_state
                    
                total_reward += episode_reward
                
            self.fitness_scores[i] = total_reward / episodes
            
        return self.fitness_scores
    
    def evolve(self, mutation_rate: float = 0.1, 
               crossover_rate: float = 0.7) -> None:
        """Evolve population using genetic algorithm"""
        
        # Selection (tournament selection)
        new_population = []
        
        for _ in range(self.population_size):
            # Tournament selection
            tournament_size = 3
            tournament_indices = np.random.choice(
                self.population_size, tournament_size, replace=False
            )
            tournament_fitness = self.fitness_scores[tournament_indices]
            winner_idx = tournament_indices[np.argmax(tournament_fitness)]
            
            # Create offspring
            offspring = self._create_offspring(self.population[winner_idx])
            
            # Mutation
            if np.random.random() < mutation_rate:
                offspring = self._mutate_network(offspring)
                
            new_population.append(offspring)
            
        self.population = new_population
        
    def _create_offspring(self, parent: nn.Module) -> nn.Module:
        """Create offspring from parent network"""
        offspring = type(parent)()
        
        # Copy parameters
        for child_param, parent_param in zip(offspring.parameters(), parent.parameters()):
            child_param.data.copy_(parent_param.data)
            
        return offspring
    
    def _mutate_network(self, network: nn.Module) -> nn.Module:
        """Mutate network parameters"""
        with torch.no_grad():
            for param in network.parameters():
                if param.dim() > 1:  # Weight matrices
                    mask = torch.rand_like(param) < 0.1  # 10% mutation rate
                    param[mask] += torch.randn_like(param[mask]) * 0.1
                    
        return network
    
    def get_best_network(self) -> nn.Module:
        """Get best network from population"""
        best_idx = np.argmax(self.fitness_scores)
        return self.population[best_idx]

# === MAIN ARCHITECTURE FACTORY ===

class NeuralArchitectureFactory:
    """Factory for creating advanced neural architectures"""
    
    @staticmethod
    def create_transformer_agent(agent_dim: int, num_actions: int) -> MultiAgentTransformer:
        """Create transformer-based multi-agent"""
        return MultiAgentTransformer(agent_dim, embed_dim=256, num_heads=8)
    
    @staticmethod
    def create_gnn_agent(node_features: int, edge_features: int) -> GraphNeuralNetwork:
        """Create graph neural network agent"""
        return GraphNeuralNetwork(node_features, edge_features)
    
    @staticmethod
    def create_memory_agent(input_dim: int, output_dim: int) -> MemoryAugmentedAgent:
        """Create memory-augmented agent"""
        return MemoryAugmentedAgent(input_dim, output_dim, memory_size=1000)
    
    @staticmethod
    def create_hierarchical_agent(state_dim: int, high_actions: int, 
                                low_actions: int) -> HierarchicalRLAgent:
        """Create hierarchical RL agent"""
        return HierarchicalRLAgent(state_dim, high_actions, low_actions)
    
    @staticmethod
    def create_ensemble_agent(state_dim: int, action_dim: int) -> EnsembleAgent:
        """Create ensemble agent"""
        return EnsembleAgent(state_dim, action_dim, ensemble_size=5)
    
    @staticmethod
    def create_neuroevolution_agent(input_dim: int, output_dim: int) -> NeuroevolutionAgent:
        """Create neuroevolution agent"""
        return NeuroevolutionAgent(input_dim, output_dim)

if __name__ == "__main__":
    print("🧠 Advanced Neural Architectures for Multi-Agent CPS Simulation")
    print("=" * 60)
    print("Available Architectures:")
    print("✅ Multi-Agent Transformers")
    print("✅ Graph Neural Networks")
    print("✅ Memory-Augmented Networks")
    print("✅ Hierarchical Reinforcement Learning")
    print("✅ Multi-Task Attention Networks")
    print("✅ Ensemble Neural Networks")
    print("✅ Neuroevolution Agents")
    print("\n🚀 Ready for integration with multi-agent system!")

#!/bin/bash

# Installation Script for Multi-Agent Neural Network CPS Simulation
# This script sets up all dependencies and verifies the installation

set -e  # Exit on any error

echo "🧠 Multi-Agent Neural Network CPS Simulation Installation"
echo "========================================================"

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" = "$required_version" ]; then
    echo "✅ Python version $python_version is compatible (>= $required_version)"
else
    echo "❌ Python version $python_version is too old (>= $required_version required)"
    echo "Please upgrade Python and try again."
    exit 1
fi

# Check for CUDA (optional but recommended)
echo ""
echo "🔍 Checking for CUDA support..."
if command -v nvidia-smi &> /dev/null; then
    echo "✅ NVIDIA GPU detected:"
    nvidia-smi --query-gpu=name,memory.total --format=csv,noheader,nounits
    echo "🚀 CUDA acceleration will be available"
    cuda_available=true
else
    echo "⚠️  No NVIDIA GPU detected. Using CPU-only mode (slower but functional)"
    cuda_available=false
fi

# Create virtual environment
echo ""
echo "📦 Creating virtual environment..."
if [ ! -d "venv_neural" ]; then
    python3 -m venv venv_neural
    echo "✅ Virtual environment created"
else
    echo "ℹ️  Virtual environment already exists"
fi

# Activate virtual environment
echo ""
echo "🔄 Activating virtual environment..."
source venv_neural/bin/activate

# Upgrade pip
echo ""
echo "⬆️  Upgrading pip..."
pip install --upgrade pip setuptools wheel

# Install core dependencies first
echo ""
echo "🔧 Installing core dependencies..."
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118

if [ "$cuda_available" = true ]; then
    echo "🚀 Installing CUDA-optimized PyTorch..."
    pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
else
    echo "💻 Installing CPU-only PyTorch..."
    pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu
fi

# Install neural network requirements
echo ""
echo "🧠 Installing neural network requirements..."
pip install -r requirements-neural.txt

# Install additional dependencies for multi-agent systems
echo ""
echo "👥 Installing multi-agent specific dependencies..."
pip install pettingzoo[multi-agent]
pip install ray[rllib,serve]
pip install torch-geometric

# Install CPS-specific libraries
echo ""
echo "🏭 Installing CPS-specific libraries..."
pip install pymodbus opcua-asyncio pyserial

# Install visualization tools
echo ""
echo "📊 Installing visualization tools..."
pip install plotly dash bokeh

# Install development tools
echo ""
echo "🛠️  Installing development tools..."
pip install pytest pytest-cov black flake8

# Verify installation
echo ""
echo "🔍 Verifying installation..."

# Test PyTorch
python3 -c "
import torch
print(f'✅ PyTorch {torch.__version__} installed')
print(f'   CUDA available: {torch.cuda.is_available()}')
if torch.cuda.is_available():
    print(f'   CUDA devices: {torch.cuda.device_count()}')
    print(f'   Current device: {torch.cuda.get_device_name(0)}')
"

# Test multi-agent libraries
python3 -c "
import pettingzoo
import ray
print(f'✅ PettingZoo {pettingzoo.__version__} installed')
print(f'✅ Ray {ray.__version__} installed')
"

# Test graph neural networks
python3 -c "
import torch_geometric
print(f'✅ PyTorch Geometric {torch_geometric.__version__} installed')
"

# Test main simulation modules
python3 -c "
import sys
sys.path.append('.')
try:
    from multi_agent_system import MultiAgentEnvironment
    print('✅ Multi-agent system module imported successfully')
except ImportError as e:
    print(f'❌ Multi-agent system import failed: {e}')

try:
    from advanced_neural_architectures import NeuralArchitectureFactory
    print('✅ Advanced neural architectures module imported successfully')
except ImportError as e:
    print(f'❌ Advanced neural architectures import failed: {e}')
"

# Create configuration files
echo ""
echo "⚙️  Creating configuration files..."

# Create neural config
cat > neural-config.json << EOF
{
    "simulation": {
        "max_rounds": 100,
        "num_attackers": 3,
        "num_defenders": 3,
        "num_analysts": 2
    },
    "neural_architectures": {
        "decision_net": "transformer",
        "coordination_net": "attention",
        "memory_net": "differentiable"
    },
    "training": {
        "learning_rate": 0.001,
        "batch_size": 32,
        "experience_replay_size": 10000,
        "target_update_frequency": 100
    },
    "hardware": {
        "use_gpu": true,
        "num_workers": 4,
        "memory_limit": "8GB"
    }
}
EOF

# Create startup script
cat > run-neural-simulation.sh << 'EOF'
#!/bin/bash

# Neural Multi-Agent CPS Simulation Runner
echo "🧠 Starting Neural Multi-Agent CPS Simulation"

# Activate virtual environment
source venv_neural/bin/activate

# Set environment variables
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
export CUDA_VISIBLE_DEVICES=0

# Run simulation with different configurations
echo "🚀 Running with Transformer Architecture..."
python3 python\ cyberrange_all_in_one.py \
    --multi-agent \
    --num-attackers 3 \
    --num-defenders 3 \
    --num-analysts 2 \
    --neural-arch transformer \
    --agent-coordination \
    --neural-training \
    --rounds 50 \
    --scripted-agents

echo ""
echo "🚀 Running with Graph Neural Network Architecture..."
python3 python\ cyberrange_all_in_one.py \
    --multi-agent \
    --num-attackers 2 \
    --num-defenders 2 \
    --num-analysts 1 \
    --neural-arch gnn \
    --agent-coordination \
    --neural-training \
    --rounds 50 \
    --scripted-agents

echo ""
echo "🚀 Running with Memory-Augmented Architecture..."
python3 python\ cyberrange_all_in_one.py \
    --multi-agent \
    --num-attackers 4 \
    --num-defenders 4 \
    --num-analysts 2 \
    --neural-arch memory \
    --agent-coordination \
    --neural-training \
    --rounds 50 \
    --scripted-agents

echo ""
echo "✅ Neural simulations completed!"
EOF

chmod +x run-neural-simulation.sh

# Create test script
cat > test-neural-system.py << 'EOF'
#!/usr/bin/env python3
"""
Test script for neural multi-agent system
"""

import sys
import torch
import numpy as np

def test_neural_architectures():
    """Test all neural architectures"""
    print("🧠 Testing Neural Architectures...")
    
    from advanced_neural_architectures import NeuralArchitectureFactory
    
    # Test Transformer Agent
    print("  🔄 Testing Transformer Agent...")
    transformer = NeuralArchitectureFactory.create_transformer_agent(128, 32)
    test_input = torch.randn(1, 10, 128)
    output = transformer(test_input)
    assert output["decisions"].shape == (1, 10, 32)
    print("    ✅ Transformer Agent working")
    
    # Test Graph Neural Network
    print("  🕸️  Testing Graph Neural Network...")
    gnn = NeuralArchitectureFactory.create_gnn_agent(64, 32)
    node_features = torch.randn(20, 64)
    edge_features = torch.randn(30, 32)
    edge_index = torch.randint(0, 20, (2, 30))
    output = gnn(node_features, edge_features, edge_index)
    assert output["vulnerabilities"].shape == (20, 1)
    print("    ✅ Graph Neural Network working")
    
    # Test Memory-Augmented Agent
    print("  🧠 Testing Memory-Augmented Agent...")
    memory_agent = NeuralArchitectureFactory.create_memory_agent(128, 32)
    test_state = torch.randn(1, 128)
    output = memory_agent(test_state)
    assert output["decisions"].shape == (1, 32)
    print("    ✅ Memory-Augmented Agent working")
    
    print("✅ All neural architectures working correctly!")

def test_multi_agent_system():
    """Test multi-agent system"""
    print("👥 Testing Multi-Agent System...")
    
    from multi_agent_system import MultiAgentEnvironment, AgentType, AgentSpecialization
    
    # Create mock environment
    class MockEnv:
        def __init__(self):
            self.assets = {"test": MockAsset()}
            self.round = 0
            self.tank = MockTank()
    
    class MockAsset:
        def __init__(self):
            self.compromised = False
            self.isolated = False
            self.hardened = False
            self.privilege = 0
            self.services = {}
    
    class MockTank:
        def __init__(self):
            self.level = 50.0
            self.alarm = False
            self.damage = False
    
    # Test environment creation
    env = MultiAgentEnvironment(MockEnv(), max_agents=10)
    
    # Test agent addition
    success = env.add_agent("test_attacker", AgentType.ATTACKER, 
                           AgentSpecialization.INITIAL_ACCESS, "IT")
    assert success == True
    print("    ✅ Agent addition working")
    
    # Test agent removal
    success = env.remove_agent("test_attacker")
    assert success == True
    print("    ✅ Agent removal working")
    
    print("✅ Multi-agent system working correctly!")

def main():
    """Run all tests"""
    print("🧪 Running Neural Multi-Agent System Tests")
    print("=" * 50)
    
    try:
        test_neural_architectures()
        print()
        test_multi_agent_system()
        print()
        print("🎉 All tests passed! System is ready for use.")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
EOF

chmod +x test-neural-system.py

# Final verification
echo ""
echo "🔍 Running final verification..."
python3 test-neural-system.py

# Create usage documentation
echo ""
echo "📚 Creating usage documentation..."
cat > NEURAL_SYSTEM_USAGE.md << 'EOF'
# Neural Multi-Agent CPS Simulation Usage Guide

## Quick Start

1. **Activate Environment:**
   ```bash
   source venv_neural/bin/activate
   ```

2. **Run Basic Neural Simulation:**
   ```bash
   python3 python\ cyberrange_all_in_one.py --multi-agent --scripted-agents --rounds 50
   ```

3. **Run with Custom Configuration:**
   ```bash
   python3 python\ cyberrange_all_in_one.py \
       --multi-agent \
       --num-attackers 4 \
       --num-defenders 4 \
       --num-analysts 2 \
       --neural-arch transformer \
       --agent-coordination \
       --neural-training \
       --rounds 100 \
       --scripted-agents
   ```

## Neural Architecture Options

- `transformer`: Multi-head attention for complex reasoning
- `gnn`: Graph neural networks for topology analysis
- `memory`: Memory-augmented networks for experience
- `hierarchical`: Hierarchical RL for complex tasks
- `ensemble`: Ensemble networks for robust decisions

## Advanced Features

- `--neuroevolution`: Enable genetic algorithm optimization
- `--agent-coordination`: Enable inter-agent communication
- `--neural-training`: Real-time neural network training
- `--save-neural-models`: Save trained models to file

## Performance Tips

1. **GPU Acceleration:** Ensure CUDA is properly installed
2. **Memory Management:** Monitor RAM usage with large agent counts
3. **Batch Size:** Adjust based on available GPU memory
4. **Parallel Processing:** Use multiple CPU workers for data loading

## Troubleshooting

1. **CUDA Errors:** Fall back to CPU mode with `--cpu-only`
2. **Memory Issues:** Reduce number of agents or batch size
3. **Import Errors:** Ensure all dependencies are installed
4. **Performance:** Use GPU acceleration for faster training

## Configuration

Edit `neural-config.json` to customize:
- Agent counts and types
- Neural network parameters
- Training hyperparameters
- Hardware settings
EOF

echo ""
echo "🎉 Installation Complete!"
echo ""
echo "📋 Summary:"
echo "  ✅ Virtual environment: venv_neural"
echo "  ✅ Neural dependencies installed"
echo "  ✅ Multi-agent system verified"
echo "  ✅ Configuration files created"
echo "  ✅ Test scripts ready"
echo ""
echo "🚀 Next Steps:"
echo "  1. Activate environment: source venv_neural/bin/activate"
echo "  2. Run test: python3 test-neural-system.py"
echo "  3. Start simulation: ./run-neural-simulation.sh"
echo "  4. Check documentation: cat NEURAL_SYSTEM_USAGE.md"
echo ""
echo "🔗 Quick Test Command:"
echo "  source venv_neural/bin/activate && python3 python\ cyberrange_all_in_one.py --multi-agent --scripted-agents --rounds 10"
echo ""
echo "🧠 Neural Multi-Agent CPS Simulation is ready!"

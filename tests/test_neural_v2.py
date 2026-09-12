"""Focused V2 regression tests for the optional Torch neural subsystem."""

from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


try:
    import torch
except ModuleNotFoundError:
    torch = None

# Keep the module collectable without Torch: module-level importorskip produces
# pytest exit code 5 (no tests collected), which is not a clean optional-test
# result in most CI systems.
pytestmark = pytest.mark.skipif(torch is None, reason="neural subsystem requires optional torch")

if torch is not None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from advanced_neural_architectures import (
        DifferentiableMemory,
        NeuralArchitectureFactory,
        NeuroevolutionAgent,
    )
    from multi_agent_system import (
        AgentSpecialization,
        AgentState,
        AgentType,
        DeepDecisionNetwork,
        MemoryNetwork,
        MultiAgentEnvironment,
        NeuralLLMAgent,
        UnsupportedNeuralActionError,
        create_multi_agent_scenario,
    )
    from neural_agent_integration import SimulatorActionAdapter, UnsupportedSimulatorActionError


def _attacker_state():
    return AgentState(
        agent_id="red_1",
        agent_type=AgentType.ATTACKER,
        specialization=AgentSpecialization.INITIAL_ACCESS,
        position="IT",
        exploration_rate=0.0,
    )


def _env_state(compromised=False):
    return {
        "assets": {
            "asset_1": {
                "compromised": compromised,
                "isolated": False,
                "hardened": False,
                "privilege": 0,
                "services": {},
            }
        },
        "total_assets": 1,
    }


def test_agent_creation_and_single_item_inference_preserve_batch_one():
    scenario = create_multi_agent_scenario(object(), num_attackers=1, num_defenders=1, num_analysts=0)
    assert set(scenario.agents) == {"attacker_1", "defender_1"}

    state = _attacker_state()
    memory = MemoryNetwork(memory_size=4, feature_dim=128)
    memory.write(torch.ones(128), torch.tensor(0))
    assert memory.read(torch.zeros(128)).shape == (128,)
    assert memory.read(torch.zeros(2, 128)).shape == (2, 128)

    agent = NeuralLLMAgent(
        state,
        {
            "decision_net": DeepDecisionNetwork(128, [32], 32),
            "attention": torch.nn.Identity(),
            "memory": memory,
        },
    )
    # The decision path must work despite BatchNorm and a one-element batch.
    action = agent.make_decision(_env_state())
    assert action["action"] in {"RECON", "EXPLOIT"}
    assert agent.networks["decision_net"].training


def test_invalid_neural_output_is_rejected_not_replaced_with_noop():
    agent = NeuralLLMAgent(
        _attacker_state(),
        {
            "decision_net": DeepDecisionNetwork(128, [32], 32),
            "attention": torch.nn.Identity(),
            "memory": MemoryNetwork(4, 128),
        },
    )
    with pytest.raises(UnsupportedNeuralActionError, match="outside"):
        agent._decode_neural_action(31, _env_state())


def test_architecture_configuration_is_used_or_fails_clearly():
    env = MultiAgentEnvironment(object(), neural_architectures={"decision_net": "deep"})
    assert env.neural_architectures["decision_net"] == "deep"
    with pytest.raises(NotImplementedError, match="not wired"):
        MultiAgentEnvironment(object(), neural_architectures={"memory_net": "memory_augmented"})

    transformer = NeuralArchitectureFactory.create_transformer_agent(4, num_actions=7)
    assert transformer.decision_head.out_features == 7


def test_differentiable_memory_writes_buffers_without_parameter_reassignment():
    memory = DifferentiableMemory(memory_size=5, feature_dim=4, key_dim=3)
    optimizer = torch.optim.Adam(memory.parameters(), lr=0.01)
    parameter_ids = {name: id(parameter) for name, parameter in memory.named_parameters()}
    key_before = memory.key_memory.clone()

    output = memory(torch.randn(2, 4), write_data=torch.randn(2, 4))
    assert not torch.equal(key_before, memory.key_memory)
    loss = output["read_data"].sum()
    optimizer.zero_grad()
    loss.backward()
    optimizer.step()
    memory(torch.randn(2, 4), write_data=torch.randn(2, 4))

    assert {name: id(parameter) for name, parameter in memory.named_parameters()} == parameter_ids
    assert "key_memory" not in parameter_ids
    assert "value_memory" not in parameter_ids


def test_neuroevolution_offspring_preserves_sampled_sequential_architecture():
    evolution = NeuroevolutionAgent(input_dim=4, output_dim=2, population_size=2)
    parent = evolution.population[0]
    child = evolution._create_offspring(parent)
    assert child is not parent
    assert child(torch.zeros(1, 4)).shape == (1, 2)
    for child_param, parent_param in zip(child.parameters(), parent.parameters()):
        assert torch.equal(child_param, parent_param)
        assert child_param.data_ptr() != parent_param.data_ptr()

    evolution.fitness_scores[:] = [0.1, 1.0]
    evolution.evolve(mutation_rate=0.0)
    assert len(evolution.population) == 2
    assert all(network(torch.zeros(1, 4)).shape == (1, 2) for network in evolution.population)


def test_simulator_adapter_concretizes_actions_and_rejects_unsupported_ones():
    service = SimpleNamespace(exposed=True, patched=False, vuln_id="CVE-test")
    asset = SimpleNamespace(compromised=False, isolated=False, hardened=False, services={"ssh": service})
    base_env = SimpleNamespace(assets={"gateway": asset})
    adapter = SimulatorActionAdapter()
    concrete = adapter.adapt({"action": "EXPLOIT", "target": "ANY", "params": {}}, _attacker_state(), base_env)
    assert concrete == {"action": "EXPLOIT", "target": "gateway", "service": "ssh", "params": {}}

    with pytest.raises(UnsupportedSimulatorActionError, match="no primary-simulator mapping"):
        adapter.adapt({"action": "EXFILTRATE", "target": "ANY"}, _attacker_state(), base_env)

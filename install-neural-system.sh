#!/usr/bin/env bash
# Install and verify the supported Version 2 neural runtime.
set -euo pipefail

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT_DIR"

PYTHON=${PYTHON:-python3}
VENV_DIR=${VENV_DIR:-venv_neural}

"$PYTHON" - <<'PY'
import sys
if sys.version_info < (3, 10):
    raise SystemExit("Python 3.10 or newer is required")
print(f"Python {sys.version.split()[0]} detected")
PY

if [[ ! -d "$VENV_DIR" ]]; then
  "$PYTHON" -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"
python -m pip install --upgrade pip setuptools wheel

# The neural extra intentionally contains only the integrated Torch runtime.
# Select a platform-specific Torch index before this step if your CUDA setup
# requires one; otherwise pip resolves the standard supported wheel.
python -m pip install -e '.[neural,dev]'

python - <<'PY'
import torch
import cyberrange
from multi_agent_system import MultiAgentEnvironment
from neural_agent_integration import NeuralAgentIntegration

print(f"CPS Cyber Range {cyberrange.__version__}")
print(f"PyTorch {torch.__version__}; CUDA available: {torch.cuda.is_available()}")
print("Neural modules imported successfully")
PY

python -m pytest -q tests/test_neural_v2.py

cat <<'EOF'

Neural Version 2 installation complete.

Supported integrated architectures:
  --neural-arch deep_feedforward
  --neural-arch deep

Example:
  source venv_neural/bin/activate
  python cyberrange.py --no-docker-up --multi-agent \
    --neural-arch deep_feedforward --agent-coordination \
    --neural-training --scripted-agents --rounds 20

The analyst role is advisory-only in the primary simulator. Neuroevolution and
experimental transformer/GNN/memory classes are not integrated CLI choices;
use advanced_neural_architectures.py directly for research experiments.
EOF

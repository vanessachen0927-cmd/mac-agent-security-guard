set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p build
swiftc native-gate/AgentGuardGate.swift -o build/AgentGuardGate
codesign --force --sign - --timestamp=none build/AgentGuardGate
codesign --verify --strict --verbose=2 build/AgentGuardGate
shasum -a 256 build/AgentGuardGate | awk '{print $1}' > build/AgentGuardGate.sha256
python3 -m guard.integrity build/AgentGuardGate --expected-sha256 "$(cat build/AgentGuardGate.sha256)"

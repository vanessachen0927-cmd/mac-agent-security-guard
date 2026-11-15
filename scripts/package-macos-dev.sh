set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
version="1.0.0-dev"
release_dir="$root/build/releases"
stage="$root/build/staging/MacAgentSecurityGuard-$version"
derived="$root/build/xcode-release"
archive="$release_dir/MacAgentSecurityGuard-$version-macos-arm64.zip"
mkdir -p "$release_dir" "$stage"
rm -rf "$stage"
mkdir -p "$stage" "$release_dir"

bash scripts/build-local-signed.sh

xcodebuild   -project MacAgentSecurityGuard/MacAgentSecurityGuard.xcodeproj   -scheme MacAgentSecurityGuard   -configuration Release   -destination "platform=macOS"   -derivedDataPath "$derived"   CODE_SIGNING_ALLOWED=NO   build

app="$derived/Build/Products/Release/MacAgentSecurityGuard.app"
test -d "$app"
test -f "build/AgentGuardGate"
ditto "$app" "$stage/MacAgentSecurityGuard.app"
mkdir -p "$stage/native-gate" "$stage/guard" "$stage/examples" "$stage/docs"
ditto build/AgentGuardGate "$stage/native-gate/AgentGuardGate"
cp build/AgentGuardGate.sha256 "$stage/native-gate/AgentGuardGate.sha256"
cp guard/*.py "$stage/guard/"
cp examples/policy.json "$stage/examples/policy.json"
cp docs/release-demo.md "$stage/docs/release-demo.md"
cp docs/signing-integrity.md "$stage/docs/signing-integrity.md"
cp docs/runtime-integrity.md "$stage/docs/runtime-integrity.md"
cp README.md "$stage/README.md"
codesign --verify --strict --verbose=2 "$stage/native-gate/AgentGuardGate"
python3 -m guard.integrity "$stage/native-gate/AgentGuardGate" --expected-sha256 "$(cat "$stage/native-gate/AgentGuardGate.sha256")"
test -f "$stage/MacAgentSecurityGuard.app/Contents/MacOS/MacAgentSecurityGuard"
rm -f "$archive"
ditto -c -k --sequesterRsrc --keepParent "$stage" "$archive"
shasum -a 256 "$archive" > "$archive.sha256"
printf 'Release bundle: %s\nSHA-256: ' "$archive"
cat "$archive.sha256"

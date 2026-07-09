# Root 真机推送 + 运行 standalone
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/build-ndk-arm64/target"
BIN="$BUILD/axvm_standalone"
REMOTE_DIR="/data/local/tmp/axvm"

if [ ! -f "$BIN" ]; then
    echo "先执行 scripts/build-ndk.sh"
    exit 1
fi

adb shell "mkdir -p $REMOTE_DIR"
adb push "$BIN" "$REMOTE_DIR/"
adb shell "chmod 755 $REMOTE_DIR/axvm_standalone"
adb shell "$REMOTE_DIR/axvm_standalone"

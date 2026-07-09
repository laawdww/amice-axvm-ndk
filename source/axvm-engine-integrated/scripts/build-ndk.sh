# Android NDK aarch64 交叉编译
# 用法: ./scripts/build-ndk.sh /path/to/ndk

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NDK="${1:-${ANDROID_NDK_HOME:-}}"

if [ -z "$NDK" ] || [ ! -d "$NDK" ]; then
    echo "用法: $0 <NDK_PATH>"
    echo "或设置 ANDROID_NDK_HOME"
    exit 1
fi

TOOLCHAIN="$NDK/toolchains/llvm/prebuilt"
case "$(uname -s)" in
    Linux*)  HOST=linux-x86_64 ;;
    Darwin*) HOST=darwin-x86_64 ;;
    MINGW*|MSYS*|CYGWIN*) HOST=windows-x86_64 ;;
    *) echo "unsupported host"; exit 1 ;;
esac

TC="$TOOLCHAIN/$HOST"
API=24
CC="$TC/bin/aarch64-linux-android${API}-clang"
CXX="$TC/bin/aarch64-linux-android${API}-clang++"

BUILD_DIR="$ROOT/build-ndk-arm64"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

cmake -S "$ROOT" -B "$BUILD_DIR" \
    -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI=arm64-v8a \
    -DANDROID_PLATFORM=android-$API \
    -DANDROID_STL=c++_static \
    -DCMAKE_BUILD_TYPE=Release \
    -DAXVM_ENABLE_GUARD=ON

cmake --build "$BUILD_DIR" -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"

echo ""
echo "产物:"
echo "  $BUILD_DIR/target/axvm_standalone"
echo "  $BUILD_DIR/target/libaxvm.so"

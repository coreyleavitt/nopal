#!/bin/bash
set -e
TARGET=$1
SYSROOT=$2
EXTRA_CONFIGURE=${3:-}

echo "=== Building musl sysroot for $TARGET ==="
cd /tmp && mkdir -p "musl-build-$TARGET" && cd "musl-build-$TARGET"
CC="clang --target=$TARGET" AR=llvm-ar RANLIB=llvm-ranlib \
  /tmp/musl-${MUSL_VERSION}/configure \
    --prefix=$SYSROOT --target=$TARGET --disable-shared $EXTRA_CONFIGURE
make -j$(nproc) && make install
cd /tmp && rm -rf "musl-build-$TARGET"

echo "=== Building compiler-rt builtins for $TARGET ==="
mkdir -p "/tmp/rt-build-$TARGET" && cd "/tmp/rt-build-$TARGET"
cmake "/tmp/llvm-project-${LLVM_VERSION}.src/compiler-rt" -G Ninja \
  -DCMAKE_AR=$(which llvm-ar) \
  -DCMAKE_NM=$(which llvm-nm) \
  -DCMAKE_RANLIB=$(which llvm-ranlib) \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_C_COMPILER_TARGET="$TARGET" \
  -DCMAKE_C_FLAGS="--sysroot=$SYSROOT" \
  -DCMAKE_ASM_COMPILER_TARGET="$TARGET" \
  -DCMAKE_ASM_FLAGS="--sysroot=$SYSROOT" \
  -DCMAKE_SYSROOT="$SYSROOT" \
  -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld" \
  -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
  -DCOMPILER_RT_BUILD_BUILTINS=ON \
  -DCOMPILER_RT_BUILD_CRT=ON \
  -DCOMPILER_RT_BUILD_SANITIZERS=OFF \
  -DCOMPILER_RT_BUILD_XRAY=OFF \
  -DCOMPILER_RT_BUILD_LIBFUZZER=OFF \
  -DCOMPILER_RT_BUILD_PROFILE=OFF \
  -DCOMPILER_RT_BUILD_MEMPROF=OFF \
  -DCOMPILER_RT_BUILD_ORC=OFF \
  -DCOMPILER_RT_DEFAULT_TARGET_ONLY=ON \
  -DCOMPILER_RT_INCLUDE_TESTS=OFF \
  -DLLVM_CMAKE_DIR="/tmp/llvm-project-${LLVM_VERSION}.src/cmake/Modules"
ninja builtins crt

CLANG_RT_DIR=$(clang --print-resource-dir)/lib/linux
mkdir -p "$CLANG_RT_DIR"
cp lib/linux/*.a "$CLANG_RT_DIR/" 2>/dev/null || true
cp lib/linux/*.o "$CLANG_RT_DIR/" 2>/dev/null || true
cd /tmp && rm -rf "rt-build-$TARGET"
echo "=== Done: $TARGET ==="

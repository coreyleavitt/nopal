import std/os

# Common flags
switch("mm", "arc")
switch("define", "useMalloc")
switch("panics", "on")
switch("threads", "off")

when defined(release):
  switch("opt", "size")
  switch("passC", "-flto -fdata-sections -ffunction-sections")
  switch("passL", "-flto -s -Wl,--gc-sections")

# Cross-compilation profiles using clang + musl sysroots
# Clang is a native cross-compiler — one binary targets all architectures.
# Each profile sets --target and --sysroot for the musl sysroot.
#
# Usage: nim c -d:release -d:aarch64 src/nopal.nim
#
# Release builds add: -Oz -fno-unwind-tables -fmerge-all-constants -fvisibility=hidden

const crossFlags = "-Oz -fno-unwind-tables -fno-asynchronous-unwind-tables -fmerge-all-constants -fvisibility=hidden"

when defined(aarch64):
  switch("os", "linux")
  switch("cpu", "arm64")
  switch("cc", "clang")
  switch("clang.exe", "clang")
  switch("clang.linkerexe", "clang")
  switch("passC", "--target=aarch64-linux-musl --sysroot=/opt/musl/aarch64 " & crossFlags)
  switch("passL", "--target=aarch64-linux-musl --sysroot=/opt/musl/aarch64 -static -fuse-ld=lld -rtlib=compiler-rt -unwindlib=none")

when defined(armv7hf):
  switch("os", "linux")
  switch("cpu", "arm")
  switch("cc", "clang")
  switch("clang.exe", "clang")
  switch("clang.linkerexe", "clang")
  switch("passC", "--target=armv7-linux-musleabihf --sysroot=/opt/musl/armv7hf " & crossFlags)
  switch("passL", "--target=armv7-linux-musleabihf --sysroot=/opt/musl/armv7hf -static -fuse-ld=lld -rtlib=compiler-rt -unwindlib=none")

when defined(mips):
  switch("os", "linux")
  switch("cpu", "mips")
  switch("cc", "clang")
  switch("clang.exe", "clang")
  switch("clang.linkerexe", "clang")
  switch("passC", "--target=mips-linux-musl --sysroot=/opt/musl/mips " & crossFlags)
  switch("passL", "--target=mips-linux-musl --sysroot=/opt/musl/mips -static -fuse-ld=lld -rtlib=compiler-rt -unwindlib=none")

when defined(mipsel):
  switch("os", "linux")
  switch("cpu", "mipsel")
  switch("cc", "clang")
  switch("clang.exe", "clang")
  switch("clang.linkerexe", "clang")
  switch("passC", "--target=mipsel-linux-musl --sysroot=/opt/musl/mipsel " & crossFlags)
  switch("passL", "--target=mipsel-linux-musl --sysroot=/opt/musl/mipsel -static -fuse-ld=lld -rtlib=compiler-rt -unwindlib=none")

# HTTPS feature flag (requires nim-mbedtls)
# Usage: nim c -d:https src/nopal.nim
# Links against system mbedTLS — does NOT use Nim's std/net SSL support

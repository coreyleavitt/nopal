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

# Cross-compilation profiles using clang + musl sysroots + compiler-rt
#
# Clang is a native cross-compiler — one binary targets all architectures.
# compiler-rt provides builtins (soft-float, etc.) and CRT files,
# replacing gcc's libgcc and crtbeginT.o/crtend.o.
#
# Usage: nim c -d:release -d:aarch64 src/nopal.nim

const crossCFlags = "-Oz -fno-unwind-tables -fno-asynchronous-unwind-tables -fmerge-all-constants -fvisibility=hidden"

proc setupCross(target, sysroot, cpuFlags: string) =
  switch("cc", "clang")
  switch("clang.exe", "clang")
  switch("clang.linkerexe", "clang")
  switch("clang.options.linker", "")
  switch("passC", "--target=" & target & " --sysroot=" & sysroot & " " & cpuFlags & " " & crossCFlags)
  switch("passL", "--target=" & target & " --sysroot=" & sysroot &
    " " & cpuFlags & " -static -fuse-ld=lld -rtlib=compiler-rt")

when defined(aarch64):
  switch("os", "linux")
  switch("cpu", "arm64")
  setupCross("aarch64-linux-musl", "/opt/musl/aarch64", "")

when defined(armv7hf):
  switch("os", "linux")
  switch("cpu", "arm")
  # OpenWrt arm_cortex-a7: ARMv7-A with hardware float, NEON
  setupCross("armv7-linux-musleabihf", "/opt/musl/armv7hf",
    "-march=armv7-a -mfpu=neon -mfloat-abi=hard")

when defined(mips):
  switch("os", "linux")
  switch("cpu", "mips")
  # OpenWrt mips_24kc: MIPS32r2, soft-float (24Kc has no FPU)
  setupCross("mips-linux-musl", "/opt/musl/mips",
    "-march=mips32r2 -msoft-float")

when defined(mipsel):
  switch("os", "linux")
  switch("cpu", "mipsel")
  # OpenWrt mipsel_24kc: MIPS32r2 little-endian, soft-float
  setupCross("mipsel-linux-musl", "/opt/musl/mipsel",
    "-march=mips32r2 -msoft-float")

# HTTPS feature flag (requires nim-mbedtls)
# Usage: nim c -d:https src/nopal.nim
# Links against system mbedTLS — does NOT use Nim's std/net SSL support

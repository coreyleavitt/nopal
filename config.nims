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

# Cross-compilation profiles
# Usage: nim c -d:release -d:aarch64 src/nopal.nim
when defined(aarch64):
  switch("os", "linux")
  switch("cpu", "arm64")
  switch("cc", "gcc")
  switch("gcc.exe", "aarch64-unknown-linux-musl-gcc")
  switch("gcc.linkerexe", "aarch64-unknown-linux-musl-gcc")
  switch("passL", "-static")

when defined(armv7hf):
  switch("os", "linux")
  switch("cpu", "arm")
  switch("cc", "gcc")
  switch("gcc.exe", "armv7-unknown-linux-musleabihf-gcc")
  switch("gcc.linkerexe", "armv7-unknown-linux-musleabihf-gcc")
  switch("passL", "-static")

when defined(mips):
  switch("os", "linux")
  switch("cpu", "mips")
  switch("cc", "gcc")
  switch("gcc.exe", "mips-unknown-linux-musl-gcc")
  switch("gcc.linkerexe", "mips-unknown-linux-musl-gcc")
  switch("passL", "-static")

when defined(mipsel):
  switch("os", "linux")
  switch("cpu", "mipsel")
  switch("cc", "gcc")
  switch("gcc.exe", "mipsel-unknown-linux-musl-gcc")
  switch("gcc.linkerexe", "mipsel-unknown-linux-musl-gcc")
  switch("passL", "-static")

# HTTPS feature flag (requires nim-mbedtls)
# Usage: nim c -d:https src/nopal.nim
# Links against system mbedTLS — does NOT use Nim's std/net SSL support

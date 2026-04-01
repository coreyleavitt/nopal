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
#
# Clang is a native cross-compiler — one binary targets all architectures.
# We use -nostdlib to suppress gcc's CRT files and default libraries,
# then explicitly link musl's CRT objects and libc.
#
# Usage: nim c -d:release -d:aarch64 src/nopal.nim

const crossCFlags = "-Oz -fno-unwind-tables -fno-asynchronous-unwind-tables -fmerge-all-constants -fvisibility=hidden"

template crossProfile(archDef, nimCpu, target, sysrootPath: string) =
  when defined(archDef):
    switch("os", "linux")
    switch("cpu", nimCpu)
    switch("cc", "clang")
    switch("clang.exe", "clang")
    switch("clang.linkerexe", "clang")
    # Clear Nim's default linker options (-ldl) for clang
    switch("clang.options.linker", "")
    switch("passC", "--target=" & target & " --sysroot=" & sysrootPath & " " & crossCFlags)
    # -nostdlib: suppress all default CRT files and libraries (no crtbeginT.o, no libgcc)
    # Then explicitly link musl's startup objects and libc
    switch("passL", "--target=" & target & " --sysroot=" & sysrootPath &
      " -static -fuse-ld=lld -nostdlib" &
      " " & sysrootPath & "/lib/crt1.o" &
      " " & sysrootPath & "/lib/crti.o" &
      " -lc" &
      " " & sysrootPath & "/lib/crtn.o")

crossProfile("aarch64", "arm64", "aarch64-linux-musl", "/opt/musl/aarch64")
crossProfile("armv7hf", "arm", "armv7-linux-musleabihf", "/opt/musl/armv7hf")
crossProfile("mips", "mips", "mips-linux-musl", "/opt/musl/mips")
crossProfile("mipsel", "mipsel", "mipsel-linux-musl", "/opt/musl/mipsel")

# HTTPS feature flag (requires nim-mbedtls)
# Usage: nim c -d:https src/nopal.nim
# Links against system mbedTLS — does NOT use Nim's std/net SSL support

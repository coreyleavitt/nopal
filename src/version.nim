## Version constant derived from nopal.nimble (single source of truth).
##
## When built via `nimble build`, nimble auto-defines NimblePkgVersion.
## When built via `nim c`, config.nims extracts it from the nimble file.
## The {.strdefine.} pragma allows override via -d:NimblePkgVersion=X.

const NimblePkgVersion* {.strdefine.} = "unknown"

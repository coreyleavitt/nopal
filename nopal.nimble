# Package
version       = "0.1.2"
author        = "Corey Leavitt"
description   = "Multi-WAN policy routing manager for OpenWrt"
license       = "Apache-2.0"
srcDir        = "src"
bin           = @["nopal"]

# Dependencies
requires "nim >= 2.0.0"

# Optional: HTTPS probe support (compile with -d:https)
# requires "mbedtls >= 1.0.0"

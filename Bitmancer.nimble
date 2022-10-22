
# Package
version       = "0.1.0"
author        = "ZimaWhit3"
description   = "Offensive Security Tooling Development Library"
license       = "GNU GPLv3"
srcDir        = "src"
installExt    = @["nim"]

# Dependencies
requires "nim >= 1.6.8"
requires "winim >= 3.9.0"

task clean, "Clean the cache directory":
    exec "rm -rf ./cache"
    exec "mkdir ./cache"

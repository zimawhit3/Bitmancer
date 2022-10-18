

import
    ../ldrbase
export
    ldrbase

## Remote DLLs
##------------------------------------------------------------------------
proc ldrMapRemoteModule*(ctx: PLoadContext): NtResult[void] =
    ## TODO

proc ldrUnmapRemoteModule*(ctx: PLoadContext): NtResult[void] =
    ## TODO
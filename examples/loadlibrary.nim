

import 
    ../src/Bitmancer

proc loadlibrary*() =
    var amsi {.stackStringW.} = "\\??\\C:\\Windows\\System32\\RPCRT4.dll"
    var okMessage {.stackStringA.} = "Loaded RPCRT4.dll"
    var badMessage {.stackStringA.} = "Failed to lose RPCRT4.dll"
    var flags   = DWORD(0)
    SET_LOAD_LOCAL flags
    let ctx = eLoadLibrary(flags, cast[PCWSTR](addr amsi[0]), NULL, 0)
    if ctx.isOk():
        rawWriteStdOut cast[cstring](addr okMessage[0])
    else:
        rawWriteStdOut cast[cstring](addr badMessage[0])
loadlibrary()
debugbreak()

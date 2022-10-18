

proc addressOfReturnAddress*(): pointer {.importc: "_AddressOfReturnAddress", header: "intrin.h".}
proc debugbreak*() {.importc: "__debugbreak", header: "_mingw.h".}
proc interlockedIncrement16*(value: ptr int16): int16   {.importc: "_InterlockedIncrement16", header: "<intrin.h>".}
proc interlockedIncrement*(value: ptr int32): int32     {.importc: "_InterlockedIncrement", header: "<intrin.h>".}
proc interlockedIncrement64*(value: ptr int64): int64   {.importc: "_InterlockedIncrement64", header: "<intrin.h>".}

when defined(cpu64):
    proc readgsbyte*(offset: uint32): uint8     {.importc: "__readgsbyte", header: "<intrin.h>"}
    proc readgsword*(offset: uint32): uint16    {.importc: "__readgsword", header: "<intrin.h>".} 
    proc readgsdword*(offset: uint32): uint32   {.importc: "__readgsdword", header: "<intrin.h>".}
    proc readgsqword*(offset: uint64): uint64   {.importc: "__readgsqword", header: "<intrin.h>".}

elif defined(i386):
    proc readfsbyte*(offset: uint32): uint8     {.importc: "__readfsbyte", header: "<intrin.h>".}
    proc readfsword*(offset: uint32): uint16    {.importc: "__readfsword", header: "<intrin.h>".}
    proc readfsdword*(offset: uint32): uint32   {.importc: "__readfsdword", header: "<intrin.h>".}
    proc readfsqword*(offset: uint32): uint64   {.importc: "__readfsqword", header: "<intrin.h>".}

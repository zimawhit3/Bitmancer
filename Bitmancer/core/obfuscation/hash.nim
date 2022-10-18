

import
    ../types

export
    types

## CompileTime and RunTime Hashing
##  TODO: generate a bigger seed
##------------------------------------------------------------------------
const
    HashSeed* {.intDefine.} = int32(0xC0DE)

func ctDjb2*(pFuncName: static[cstring]): int32 {.compileTime.} =
    result = HashSeed
    for c in pFuncName:
        result = ((result shl 0x05) +% result) +% ord(c).int32

func rtDjb2*(pFuncName: cstring): int32 =
    result = HashSeed
    for c in pFuncName:
        result = ((result shl 0x05) +% result) + ord(c).int32

func rtDjb2*(pFuncName: PCWSTR): int32 =
    result = HashSeed
    var i   = 0
    let ws  = cast[ptr UncheckedArray[uint16]](pFuncName)
    while ws[i] != 0:
        result = ((result shl 0x05) +% result) + ord(cast[char](ws[i])).int32
        inc i

template HASH_A*(s: cstring): DWORD =
    rtDjb2(s)

template HASH_W*(s: PCWSTR|UNICODE_STRING): DWORD =
    when s is PCWSTR:
        rtDjb2(s)
    elif s is UNICODE_STRING:
        rtDjb2(s.Buffer)

    


import
    ../core/obfuscation/hash,
    ../core

export
    core

## Hashes
##------------------------------------------------------------------------
const 
    RtlHashUnicodeStringHash*   = HASH_A cstring"RtlHashUnicodeString"
    RtlInitUnicodeStringHash*   = HASH_A cstring"RtlInitUnicodeString"
    RtlFreeUnicodeStringHash*   = HASH_A cstring"RtlFreeUnicodeString"

## Custom Unicode String Functions
##------------------------------------------------------------------------
proc new*(T: typedesc[UNICODE_STRING], sz: SIZE_T = MAX_PATH): NtResult[T] =
    var newUnicodeString = UNICODE_STRING()
    newUnicodeString.Length           = 0
    newUnicodeString.MaximumLength    = sz.USHORT
    newUnicodeString.Buffer           = cast[PWSTR](? PROCESS_HEAP_ALLOC(sz))
    ok newUnicodeString

## RTL Unicode String Functions
##------------------------------------------------------------------------

## RtlHashUnicodeString
##------------------------------------
proc getRtlHashUnicodeString*(Ntdll: ModuleHandle): NtResult[RtlHashUnicodeString] {.inline.} =
    let f = ? getProcAddress(Ntdll, RtlHashUnicodeStringHash)
    ok cast[RtlHashUnicodeString](f)

proc eRtlHashUnicodeString*(s: PUNICODE_STRING, inSensitive: BOOLEAN, hashAlgo: ULONG): NtResult[ULONG] =
    let 
        Ntdll                   = ? NTDLL_BASE()
        pRtlHashUnicodeString   = ? getRtlHashUnicodeString Ntdll
    var hashValue               = ULONG(0)

    if NT_SUCCESS pRtlHashUnicodeString(s, inSensitive, hashAlgo, hashValue):
        ok hashValue
    else:
        err ProcedureFailure

## RtlInitUnicodeString
##------------------------------------
proc getRtlInitUnicodeString*(Ntdll: ModuleHandle): NtResult[RtlInitUnicodeString] {.inline.} =
    let f = ? getProcAddress(Ntdll, RtlInitUnicodeStringHash)
    ok cast[RtlInitUnicodeString](f)

proc eRtlInitUnicodeString*(dest: var UNICODE_STRING, src: PCWSTR): NtResult[void] =
    let 
        Ntdll                 = ? NTDLL_BASE()
        pRtlInitUnicodeString = ? getRtlInitUnicodeString Ntdll
    pRtlInitUnicodeString(dest, src)
    ok()

func cRtlInitUnicodeString*(dest: var UNICODE_STRING, src: PCWSTR) =
    if not src.isNil():
        let destSize        = src.len() * sizeof(WCHAR)
        dest.Length         = cast[USHORT](destSize)
        dest.MaximumLength  = cast[USHORT](destSize + sizeof(WCHAR))
    else:
        dest.Length         = 0
        dest.MaximumLength  = 0
    dest.Buffer = src

## RtlFreeUnicodeString
##------------------------------------
proc getRtlFreeUnicodeString*(Ntdll: ModuleHandle): NtResult[RtlFreeUnicodeString] {.inline.} =
    let f = ? getProcAddress(Ntdll, RtlFreeUnicodeStringHash)
    ok cast[RtlFreeUnicodeString](f)

proc eRtlFreeUnicodeString*(s: var UNICODE_STRING): NtResult[void] {.discardable.} =
    let 
        Ntdll                   = ? NTDLL_BASE()
        pRtlFreeUnicodeString   = ? getRtlFreeUnicodeString Ntdll
    pRtlFreeUnicodeString(s)
    ok()



import
    enumeration/enumeration,
    obfuscation/hash,
    apiset, ntloader, str, utils

export
    str

## Procedures
##------------------------------------------------------------------------
proc getProcAddress*(imageBase: ModuleHandle, ident: SomeProcIdent): NtResult[PVOID]

## Private
##------------------------------------
func getDotSeperatorIndex(forwarder: cstring): int {.inline.} =
    result = 0
    while forwarder[result] != '\0':
        if forwarder[result] == '.':
            return
        inc result

proc allocateInternal(): NtResult[PVOID] =
    ## To avoid circular dependency, must use an internal heap alloc here
    const
        RtlAllocateHeapHash = ctDjb2 "RtlAllocateHeap"
    let 
        Ntdll               = ? NTDLL_BASE()
        f                   = ? getProcAddress(Ntdll, RtlAllocateHeapHash)
        pRtlAllocateHeap    = cast[RtlAllocateHeap](f)
        pAllocMemory        = pRtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH)
    if not pAllocMemory.isNil():
        ok pAllocMemory
    else:
        err InsufficientMemory

proc freeInternal(mem: PVOID): NtResult[void] {.discardable.} =
    const
        RtlFreeHeapHash     = ctDjb2 "RtlFreeHeap"
    let
        Ntdll               = ? NTDLL_BASE()
        f                   = ? getProcAddress(Ntdll, RtlFreeHeapHash)
        pRtlFreeHeap        = cast[RtlFreeHeap](f)
    if pRtlFreeHeap(RtlProcessHeap(), 0, mem) == 1:
        ok()
    else:
        err ProcedureFailure

proc getForwardImageBaseApiSet(currentBase: ModuleHandle, forwarder: cstring): NtResult[ModuleHandle] =
    ## Get Parent Name
    let 
        ldrEntry    = ? getLdrEntry(currentBase, LoadOrder)
        parentName  = addr ldrEntry.BaseDllName
    ## Initialize ApiSet Unicode String
    var apiSet = UNICODE_STRING()
    apiSet.Length           = 0
    apiSet.MaximumLength    = MAX_PATH
    apiSet.Buffer           = cast[PWSTR](? allocateInternal())
    apiSet.add forwarder
    ## Resolve ApiSet
    ? resolveApiSet(apiSet, parentName)
    result = getModuleHandle(apiSet.Buffer, LoadOrder)
    freeInternal(apiSet.Buffer)

proc getForwardImageBase(forwarder: cstring, sepIndex: int): NtResult[ModuleHandle] =
    var 
        fArray: array[MAX_PATH, char]
        forwardString = cast[cstring](addr fArray[0])
    for i in 0 ..< sepIndex:
        forwardString[i] = LOWER_CASE(forwarder[i])
    forwardString.addDLLExtensionA()
    getModuleHandle(forwardString, LoadOrder)

proc resolveForwardedFunction(currentBase: ModuleHandle, forwarder: cstring, ident: SomeProcIdent): NtResult[PVOID] =
    let 
        seperator       = getDotSeperatorIndex forwarder
        forwardIdent    = cast[cstring](unsafeAddr forwarder[seperator + 1])
        imageBase =
            if isApiSetLib(forwarder):
                ? getForwardImageBaseApiSet(currentBase, forwarder)
            else:
                ? getForwardImageBase(forwarder, seperator)
    getProcAddress(imageBase, forwardIdent)

func findProcAddressEAT(imageBase: ModuleHandle, ident: SomeProcIdent): NtResult[PVOID] =
    let exports = ? getExportDirectory(imageBase)
    for symName, ord, pFunc in imageBase.exports exports:
        if IDENT_MATCH(symName, ord, ident): 
            return ok pFunc
    err ProcedureNotFound

func findProcAddressIAT(imageBase: ModuleHandle, ident: SomeThunkedIdent): NtResult[PVOID] =
    let importTable = ? getImportDirectory(imageBase)
    for imprt in importTable.imports():
        for (pOriginalThunk, pFirstThunk) in imageBase.thunks imprt:
            let 
                hint    = cast[PIMAGE_IMPORT_BY_NAME](imageBase +% pOriginalThunk.u1.AddressOfData)
                symName = cast[cstring](addr hint.Name[0])
            if IDENT_MATCH(symName, ident):
                return ok cast[PVOID](pFirstThunk.u1.Function)
    err ProcedureNotFound

## GetProcAddress
##------------------------------------
proc getProcAddress*(imageBase: ModuleHandle, ident: SomeProcIdent): NtResult[PVOID] =
    let 
        pFunction   = ? findProcAddressEAT(imageBase, ident)
        textSection = ? getTextSection imageBase    
    if pFunction < SECTION_START(imageBase, textSection) or pFunction > SECTION_END(imageBase, textSection):
        resolveForwardedFunction(imageBase, cast[cstring](pFunction), ident)
    else:
        ok pFunction

proc getProcAddressEx*(imageBase: ModuleHandle, importBase: ModuleHandle, ident: SomeThunkedIdent): NtResult[PVOID] =
    let
        pFunction   = ? findProcAddressIAT(importBase, ident)
        textSection = ? getTextSection imageBase
    if pFunction < SECTION_START(imageBase, textSection) or pFunction > SECTION_END(imageBase, textSection):
        resolveForwardedFunction(imageBase, cast[cstring](pFunction), ident)
    else:
        ok pFunction

proc getNestedProcAddress*(imageBase: ModuleHandle, ident: SomeProcIdent, callIndex: int): NtResult[PVOID] =
    let 
        fStart  = ? getProcAddress(imageBase, ident)
        fEnd    = ? searchFunctionEnd(imageBase, fStart)
        pCall   = ? searchCall(fStart, fEnd, callIndex)
        rel32   = cast[PDWORD](pCall +! 1)[] + 0x5
    ok pCall +! rel32


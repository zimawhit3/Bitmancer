

import
    ../core/obfuscation/hash,
    ../core

export
    core

## Heap APIs
##------------------------------------------------------------------------

## Hashes
##---------------------------------------------------------------------
const 
    RtlAllocateHeapHash*    = ctDjb2 "RtlAllocateHeap"
    RtlCreateHeapHash*      = ctDjb2 "RtlCreateHeap"
    RtlFreeHeapHash*        = ctDjb2 "RtlFreeHeap"

## Helpers
##---------------------------------------------------------------------
template PROCESS_HEAP_ALLOC*(T: typedesc): NtResult[PVOID] =
    eRtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(T))

template PROCESS_HEAP_ALLOC*(sz: SIZE_T): NtResult[PVOID] =
    eRtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sz)

template PROCESS_HEAP_FREE*(mem: PVOID): NtResult[void] =
    eRtlFreeHeap(RtlProcessHeap(), 0, mem)

## RtlAllocateHeap
##------------------------------------
proc getRtlAllocateHeap*(Ntdll: ModuleHandle): NtResult[RtlAllocateHeap] {.inline.} =
    let f = ? getProcAddress(Ntdll, RtlAllocateHeapHash)
    ok cast[RtlAllocateHeap](f)

proc eRtlAllocateHeap*(hHeap: HANDLE, dwFlags: ULONG, size: SIZE_T): NtResult[PVOID] =
    let 
        Ntdll               = ? NTDLL_BASE()
        pRtlAllocateHeap    = ? getRtlAllocateHeap Ntdll
        pHeapAlloc          = pRtlAllocateHeap(hHeap, dwFlags, size)
    if not pHeapAlloc.isNil():
        ok pHeapAlloc
    else:
        err ProcedureFailure

## RtlCreateHeap
##------------------------------------
proc getRtlCreateHeap*(Ntdll: ModuleHandle): NtResult[RtlCreateHeap] {.inline.} =
    let f = ? getProcAddress(Ntdll, RtlCreateHeapHash)
    ok cast[RtlCreateHeap](f)


## RtlFreeHeap
##------------------------------------
proc getRtlFreeHeap*(Ntdll: ModuleHandle): NtResult[RtlFreeHeap] {.inline.} =
    let f = ? getProcAddress(Ntdll, RtlFreeHeapHash)
    ok cast[RtlFreeHeap](f)

proc eRtlFreeHeap*(hHeap: HANDLE, dwFlags: ULONG, pAllocMemory: PVOID): NtResult[void] {.discardable.} =
    let 
        Ntdll           = ? NTDLL_BASE()
        pRtlFreeHeap    = ? getRtlFreeHeap Ntdll
    
    if pRtlFreeHeap(hHeap, dwFlags, pAllocMemory) == 1:
        ok()
    else:
        err ProcedureFailure

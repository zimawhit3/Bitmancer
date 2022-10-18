

import
    ../core/obfuscation/hash,
    ../core/enumeration/enumeration,
    ldrbase

export
    ldrbase

## Hashes
##------------------------------------------------------------------------
const
    LdrQueryModuleServiceTagsHash       = ctDjb2 "LdrQueryModuleServiceTags"
    RtlInstallFunctionTableCallbackHash = ctDjb2 "RtlInstallFunctionTableCallback"

## LdrpMrdata
##------------------------------------
template LDR_WITH_MRDATA_LOCK*(body: NtResult[void]): NtResult[void] =
    let 
        LdrpMrdataLock  = ? getLdrpMrdataLock()
        locked          = eRtlAcquireSRWLockExclusive LdrpMrdataLock
        res = body
    if locked.isOk():
        eRtlReleaseSRWLockExclusive LdrpMrdataLock
    res

proc getLdrpMrdataLock*(): NtResult[PRTL_SRWLOCK] =
    ## Available APIs:
    ## RtlAddFunctionTable
    ## RtlInstallFunctionTableCallback
    ## RtlSetProtectedPolicy
    ## RtlGrowFunctionTable
    let
        Ntdll           = ? NTDLL_BASE()
        targetFunction  = ? getRtlAcquireSRWLockExclusive Ntdll
        searchFunction  = ? getProcAddress(Ntdll, RtlInstallFunctionTableCallbackHash)
    enumFindLock(searchFunction, targetFunction, 0)

## LdrpModuleDatatableLock
##------------------------------------
template LDR_WITH_DATATABLE_LOCK*(body: NtResult[void]): NtResult[void] =
    let 
        LdrpModuleDatatableLock = ? getLdrpModuleDatatableLock()
        locked  = eRtlAcquireSRWLockExclusive LdrpModuleDatatableLock
        res     = body
    if locked.isOk():
        eRtlReleaseSRWLockExclusive LdrpModuleDatatableLock
    res

proc getLdrpModuleDatatableLock*(): NtResult[PRTL_SRWLOCK] =
    let
        Ntdll           = ? NTDLL_BASE()
        targetFunction  = ? getRtlAcquireSRWLockExclusive Ntdll
        searchFunction  = ? getProcAddress(Ntdll, LdrQueryModuleServiceTagsHash)
    enumFindLock(searchFunction, targetFunction, 0)



import
    ../core/obfuscation/hash,
    ../core

export
    core

## Hashes
##---------------------------------------------------------------------
const
    RtlAcquireSRWLockExclusiveHash* = ctDjb2 "RtlAcquireSRWLockExclusive"
    RtlInitializeSRWLockHash*       = ctDjb2 "RtlInitializeSRWLock"
    RtlReleaseSRWLockExclusiveHash* = ctDjb2 "RtlReleaseSRWLockExclusive"
    RtlWaitForCriticalSectionHash*  = ctDjb2 "RtlWaitForCriticalSection"
    RtlEnterCriticalSectionHash*    = ctDjb2 "RtlEnterCriticalSection"
    RtlLeaveCriticalSectionHash*    = ctDjb2 "RtlLeaveCriticalSection"

## Template Helpers for Common Locks
##---------------------------------------------------------------------
template LOCK_LOADER_LOCK*(): NtResult[void] =
    eRtlEnterCriticalSection GetLoaderLock()

template UNLOCK_LOADER_LOCK*(): NtResult[void] =
    eRtlLeaveCriticalSection GetLoaderLock()

template LOCK_PEB_LOCK*(): NtResult[void] =
    eRtlEnterCriticalSection GetPebFastLock()

template UNLOCK_PEB_LOCK*(): NtResult[void] =
    eRtlLeaveCriticalSection GetPebFastLock()

## RtlAcquireSRWLockExclusive
##------------------------------------
proc getRtlAcquireSRWLockExclusive*(Ntdll: ModuleHandle): NtResult[RtlAcquireSRWLockExclusive] {.inline.} =
    let f = ? getProcAddress(Ntdll, RtlAcquireSRWLockExclusiveHash)
    ok cast[RtlAcquireSRWLockExclusive](f)

proc eRtlAcquireSRWLockExclusive*(srwlock: PRTL_SRWLOCK): NtResult[void] {.discardable.} =
    let 
        Ntdll                       = ? NTDLL_BASE()
        pRtlAcquireSRWLockExclusive = ? getRtlAcquireSRWLockExclusive Ntdll
    pRtlAcquireSRWLockExclusive srwlock
    ok()

## RtlInitializeSRWLock
##------------------------------------
proc getRtlInitializeSRWLock*(Ntdll: ModuleHandle): NtResult[RtlInitializeSRWLock] {.inline.} =
    let f = ? getProcAddress(Ntdll, RtlInitializeSRWLockHash)
    ok cast[RtlInitializeSRWLock](f)

proc eRtlInitializeSRWLock*(lock: var RTL_SRWLOCK): NtResult[void] =
    let
        Ntdll                   = ? NTDLL_BASE()
        pRtlInitializeSRWLock   = ? getRtlInitializeSRWLock Ntdll
    pRtlInitializeSRWLock lock
    ok()

## RtlReleaseSRWLockExclusive
##------------------------------------
proc getRtlReleaseSRWLockExclusive*(Ntdll: ModuleHandle): NtResult[RtlReleaseSRWLockExclusive] {.inline.} =
    let f = ? getProcAddress(Ntdll, RtlReleaseSRWLockExclusiveHash)
    ok cast[RtlReleaseSRWLockExclusive](f)

proc eRtlReleaseSRWLockExclusive*(srwlock: PRTL_SRWLOCK): NtResult[void] {.discardable.} =
    let 
        Ntdll                       = ? NTDLL_BASE()
        pRtlReleaseSRWLockExclusive = ? getRtlReleaseSRWLockExclusive Ntdll
    pRtlReleaseSRWLockExclusive srwlock
    ok()

## RtlEnterCriticalSection
##------------------------------------
proc getRtlEnterCriticalSection*(Ntdll: ModuleHandle): NtResult[RtlEnterCriticalSection] {.inline.} =
    let f = ? getProcAddress(Ntdll, RtlEnterCriticalSectionHash)
    ok cast[RtlEnterCriticalSection](f)

proc eRtlEnterCriticalSection*(lock: PRTL_CRITICAL_SECTION): NtResult[void] =
    let 
        Ntdll                       = ? NTDLL_BASE()
        pRtlEnterCriticalSection    = ? getRtlEnterCriticalSection(Ntdll)
    NT_RESULT pRtlEnterCriticalSection lock: void

## RtlLeaveCriticalSection
##------------------------------------
proc getRtlLeaveCriticalSection*(Ntdll: ModuleHandle): NtResult[RtlLeaveCriticalSection] {.inline.} =
    let f = ? getProcAddress(Ntdll, RtlLeaveCriticalSectionHash)
    ok cast[RtlLeaveCriticalSection](f)

proc eRtlLeaveCriticalSection*(lock: PRTL_CRITICAL_SECTION): NtResult[void] =
    let 
        Ntdll                       = ? NTDLL_BASE()
        pRtlLeaveCriticalSection    = ? getRtlLeaveCriticalSection Ntdll
    NT_RESULT pRtlLeaveCriticalSection lock: void

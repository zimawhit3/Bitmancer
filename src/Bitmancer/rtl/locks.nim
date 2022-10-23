##---------------------------------------------------------------------
##      Bitmancer - a library for Offensive Security Development 
##           
##          Copyright (C) 2022  B. Marshall (zimawhite1@gmail.com)
##
##  This program is free software: you can redistribute it and/or modify
##  it under the terms of the GNU General Public License as published by
##  the Free Software Foundation, either version 3 of the License, or
##  (at your option) any later version.
##
##  This program is distributed in the hope that it will be useful,
##  but WITHOUT ANY WARRANTY; without even the implied warranty of
##  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##  GNU General Public License for more details.
##
##  You should have received a copy of the GNU General Public License
##  along with this program.  If not, see <https://www.gnu.org/licenses/>.
## 
##----------------------------------------------------------------------------------
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
    rtlEnterCriticalSection getLoaderLock()

template UNLOCK_LOADER_LOCK*(): NtResult[void] =
    rtlLeaveCriticalSection getLoaderLock()

template LOCK_PEB_LOCK*(): NtResult[void] =
    rtlEnterCriticalSection getPebFastLock()

template UNLOCK_PEB_LOCK*(): NtResult[void] =
    rtlLeaveCriticalSection getPebFastLock()

## RtlAcquireSRWLockExclusive
##------------------------------------
proc getRtlAcquireSRWLockExclusive*(Ntdll: ModuleHandle): NtResult[RtlAcquireSRWLockExclusive] {.inline.} =
    let f = ? getProcAddress(Ntdll, RtlAcquireSRWLockExclusiveHash)
    ok cast[RtlAcquireSRWLockExclusive](f)

proc rtlAcquireSRWLockExclusive*(srwlock: PRTL_SRWLOCK): NtResult[void] {.discardable.} =
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

proc rtlInitializeSRWLock*(lock: var RTL_SRWLOCK): NtResult[void] =
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

proc rtlReleaseSRWLockExclusive*(srwlock: PRTL_SRWLOCK): NtResult[void] {.discardable.} =
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

proc rtlEnterCriticalSection*(lock: PRTL_CRITICAL_SECTION): NtResult[void] =
    let 
        Ntdll                       = ? NTDLL_BASE()
        pRtlEnterCriticalSection    = ? getRtlEnterCriticalSection(Ntdll)
    NT_RESULT pRtlEnterCriticalSection lock: void

## RtlLeaveCriticalSection
##------------------------------------
proc getRtlLeaveCriticalSection*(Ntdll: ModuleHandle): NtResult[RtlLeaveCriticalSection] {.inline.} =
    let f = ? getProcAddress(Ntdll, RtlLeaveCriticalSectionHash)
    ok cast[RtlLeaveCriticalSection](f)

proc rtlLeaveCriticalSection*(lock: PRTL_CRITICAL_SECTION): NtResult[void] =
    let 
        Ntdll                       = ? NTDLL_BASE()
        pRtlLeaveCriticalSection    = ? getRtlLeaveCriticalSection Ntdll
    NT_RESULT pRtlLeaveCriticalSection lock: void

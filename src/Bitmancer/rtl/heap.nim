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

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

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
    ".."/../[ntloader, utils],
    procedures

export
    errors, results, types

func enumFindLock64*(fStart, tFunction: PVOID, callIndex: int): NtResult[PRTL_SRWLOCK] =
    ## Search the target function `fStart` for the first call to the target
    ## function `tFunction`, then parses and grabs the lock from the preceding
    ## instruction loading it in to the RCX register.
    ## TODO: a less naive solution...
    let
        Ntdll   = ? NTDLL_BASE()
        fEnd    = ? searchFunctionEnd(Ntdll, fStart)
        pCall   = ? searchCallToTargetFunction(fStart, fEnd, tFunction, callIndex)
        pLea    = cast[PBYTE](pCall -! 0x7)

    ## Check to make sure the LEA is a rip-relative rel32 instruction to RCX.
    if pLea[] == 0x48 and cast[PBYTE](pLea +! 1)[] == 0x8D and cast[PBYTE](pLea +! 2)[] == 0x0D:

        ## Grab the rip-relative address from the lea to RCX, as that will hold the address of the lock.
        let 
            dataSection     = ? getDataSection Ntdll
            rel32           = cast[PDWORD](pLea +! 0x3)[]
            lock            = cast[PRTL_SRWLOCK](pLea +! rel32 +! 0x7)
        ## Check to make sure it's contained in the data section.
        if lock > SECTION_START(Ntdll, dataSection) and lock < SECTION_END(Ntdll, dataSection):
            return ok lock

    err LockNotFound    

func enumFindLock32*(fStart, tFunction: PVOID, callIndex: int): NtResult[PRTL_SRWLOCK] =
    ##

template enumFindLock*(fStart, tFunction: PVOID, callIndex: int): NtResult[PRTL_SRWLOCK] =
    when defined(cpu64):    enumFindLock64(fStart, tFunction, callIndex)
    else:                   enumFindLock32(fStart, tFunction, callIndex)

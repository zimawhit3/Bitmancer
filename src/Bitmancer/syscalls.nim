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
    std/macros,
    core/enumeration/memory/syscalls,
    syscalls/[gates, ldrthunks, zwcounter]

export
    macros, gates, ldrthunks, zwcounter

## NT Syscalls
## 
##  This module implements support for finding, parsing, and executing 
##  syscalls.
##------------------------------------------------------------------------
template ctGetSyscall*(
    imageBase: ModuleHandle, 
    importBase: ModuleHandle,
    ident: static[SomeProcIdent], 
    symEnum: static[SymbolEnumeration], 
    ssnEnum: static[SsnEnumeration]): SyscallResult =
    block:
        checkValidOSVersionTarget(symEnum)
        when symEnum == SymbolEnumeration.UseLdrThunks:     bLdrThunks(imageBase, ident)
        elif symEnum == SymbolEnumeration.UseEAT:
            when ssnEnum == SsnEnumeration.HalosGate:       bHalosGateEat(imageBase, ident)
            elif ssnEnum == SsnEnumeration.HellsGate:       bHellsGateEat(imageBase, ident)
            elif ssnEnum == SsnEnumeration.TartarusGate:    bTartarusGateEat(imageBase, ident)
            elif ssnEnum == SsnEnumeration.ZwCounter:       bZwCounterEat(imageBase, ident)
        elif symEnum == SymbolEnumeration.UseIAT:
            when ssnEnum == SsnEnumeration.HalosGate:       bHalosGateIat(imageBase, importBase, ident)
            elif ssnEnum == SsnEnumeration.HellsGate:       bHellsGateIat(imageBase, importBase, ident)
            elif ssnEnum == SsnEnumeration.TartarusGate:    bTartarusGateIat(imageBase, importBase, ident)
            elif ssnEnum == SsnEnumeration.ZwCounter:       bZwCounterIat(importBase, ident)

template NT_STUB*[T](syscall: tuple[wSyscall: WORD, pSyscall: PVOID, isHooked: bool], exeEnum: static[SyscallExecution]): T =
    when exeEnum == SyscallExecution.Direct:
        when UseNativeWhenNotHooked:
            if syscall.isHooked:
                cast[T](directStub)
            else:
                cast[T](syscall.pSyscall)
        else:
            cast[T](directStub)
    
    elif exeEnum == SyscallExecution.Indirect:
        when UseNativeWhenNotHooked:
            if syscall.isHooked:
                cast[T](spoofStub)
            else:
                cast[T](syscall.pSyscall)
        else:
            cast[T](spoofStub)

proc getNtSyscall*[T](
    Ntdll: ModuleHandle,
    importBase: ModuleHandle,
    ident: static[uint32], 
    symEnum: static[SymbolEnumeration], 
    ssnEnum: static[SsnEnumeration],
    exeEnum: static[SyscallExecution]
): NtResult[NtSyscall[T]] {.inline.} =
    let 
        sysRes      = ? ctGetSyscall(Ntdll, importBase, ident, symEnum, ssnEnum)
        funct       = NT_STUB[T](sysRes, exeEnum)
        pSyscall    = 
            when exeEnum == SyscallExecution.Direct: 
                sysRes.pSyscall
            elif exeEnum == SyscallExecution.Indirect: 
                getSyscallInstruction sysRes.pSyscall

    ok NtSyscall[T](
        wSyscall: sysRes.wSyscall, 
        pSyscall: pSyscall,
        pFunction: funct, 
        isHooked: sysRes.isHooked
    )

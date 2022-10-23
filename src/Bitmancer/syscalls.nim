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
    core/enumeration/memory/syscalls,
    syscalls/[gates, ldrthunks, zwcounter]

export
    gates, ldrthunks, zwcounter

## NT Syscalls
## 
##  This module implements support for finding, parsing, and executing 
##  syscalls.
##------------------------------------------------------------------------
template GET_SYSCALL*(
    imageBase: ModuleHandle, 
    importBase: ModuleHandle,
    ident: static[SomeProcIdent], 
    symEnum: static[SymbolEnumeration], 
    ssnEnum: static[SsnEnumeration]
): SyscallResult =
    checkValidOSVersionTarget(ssnEnum)
    when ssnEnum == SsnEnumeration.HalosGate:       halosGate(imageBase, importBase, ident, symEnum)
    elif ssnEnum == SsnEnumeration.HellsGate:       hellsGate(imageBase, importBase, ident, symEnum)
    elif ssnEnum == SsnEnumeration.LdrThunks:       ldrThunks(imageBase, importBase, ident, symEnum)
    elif ssnEnum == SsnEnumeration.TartarusGate:    tartarusGate(imageBase, importBase, ident, symEnum)
    elif ssnEnum == SsnEnumeration.ZwCounter:       zwCounter(imageBase, importBase, ident, symEnum)

template NT_STUB*[T](syscall: Syscall, exeEnum: static[SyscallExecution]): T =
    when exeEnum == SyscallExecution.Direct:    cast[T](directStub)
    elif exeEnum == SyscallExecution.Indirect:  cast[T](spoofStub)

proc getNtSyscall*[T](
    Ntdll: ModuleHandle,
    importBase: ModuleHandle,
    ident: static[uint32], 
    symEnum: static[SymbolEnumeration], 
    ssnEnum: static[SsnEnumeration],
    exeEnum: static[SyscallExecution]
): NtResult[NtSyscall[T]] =
    let 
        sysRes      = ? GET_SYSCALL(Ntdll, importBase, ident, symEnum, ssnEnum)
        funct       = NT_STUB[T](sysRes, exeEnum)
    ok NtSyscall[T](
        syscall:    sysRes,
        pFunction:  funct
    )

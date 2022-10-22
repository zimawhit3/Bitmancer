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
    ../syscalls

export
    syscalls

## Compile Time Settings
##------------------------------------------------------------------------
const
    ## NtFlushInstructionCache Syscall Settings
    ##---------------------------------------------------------------------
    FlushExeEnum*   {.intDefine.} = SyscallExecution.Indirect
    FlushSsnEnum*   {.intDefine.} = SsnEnumeration.ZwCounter
    FlushSymEnum*   {.intDefine.} = SymbolEnumeration.UseEAT

## Hashes
##---------------------------------------------------------------------
const
    NtFlushInstructionCacheHash* = ctDjb2 "NtFlushInstructionCache"

## FlushInstructionCache / NtFlushInstructionCache
##------------------------------------------------------------------------
template getNtFlushInstructionCache*(
    Ntdll: ModuleHandle,
    importBase: ModuleHandle,
    symEnum: static SymbolEnumeration = FlushSymEnum, 
    ssnEnum: static SsnEnumeration = FlushSsnEnum,
    exeEnum: static SyscallExecution = FlushExeEnum
): NtResult[NtSyscall[NtFlushInstructionCache]] =
    getNtSyscall[NtFlushInstructionCache](Ntdll, importBase, NtFlushInstructionCacheHash, symEnum, ssnEnum, exeEnum)

proc eNtFlushInstructionCache*(processHandle: HANDLE, baseAddress: PVOID, dwSize: SIZE_T): NtResult[void] {.discardable.} =
    genSyscall(NtFlushInstructionCache)
    let
        Ntdll     = ? NTDLL_BASE()
        NtSyscall =
            when FlushSymEnum == SymbolEnumeration.UseEAT:
                ? getNtFlushInstructionCache(Ntdll, ModuleHandle(NULL))
            elif FlushSymEnum == SymbolEnumeration.UseIAT:
                let Kernel32 = ? KERNEL32_BASE()
                ? getNtFlushInstructionCache(Ntdll, Kernel32)

    NT_RESULT NtFlushInstructionCacheWrapper(
        processHandle, 
        baseAddress, 
        dwSize, 
        NtSyscall.wSyscall, NtSyscall.pSyscall, NtSyscall.pFunction
    ): void

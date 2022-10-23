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
    ## NtAllocateVirtualMemory Syscall Settings
    ##---------------------------------------------------------------------
    AllocExeEnum*   {.intDefine.} = SyscallExecution.Indirect
    AllocSsnEnum*   {.intDefine.} = SsnEnumeration.ZwCounter
    AllocSymEnum*   {.intDefine.} = SymbolEnumeration.UseEAT

    ## NtFreeVirtualmemory Syscall Settings
    ##---------------------------------------------------------------------
    FreeExeEnum*    {.intDefine.} = SyscallExecution.Indirect
    FreeSsnEnum*    {.intDefine.} = SsnEnumeration.ZwCounter
    FreeSymEnum*    {.intDefine.} = SymbolEnumeration.UseEAT

    ## NtProtectVirtualMemory Syscall Settings
    ##---------------------------------------------------------------------
    ProtectExeEnum* {.intDefine.} = SyscallExecution.Indirect
    ProtectSsnEnum* {.intDefine.} = SsnEnumeration.ZwCounter
    ProtectSymEnum* {.intDefine.} = SymbolEnumeration.UseEAT
    
    ## NtWriteVirtualMemory Syscall Settings
    ##---------------------------------------------------------------------
    WriteExeEnum*   {.intDefine.} = SyscallExecution.Indirect
    WriteSsnEnum*   {.intDefine.} = SsnEnumeration.ZwCounter
    WriteSymEnum*   {.intDefine.} = SymbolEnumeration.UseEAT

## Hashes
##---------------------------------------------------------------------
const
    NtAllocateVirtualMemoryHash*    = ctDjb2 "NtAllocateVirtualMemory"
    NtFreeVirtualMemoryHash*        = ctDjb2 "NtFreeVirtualMemory"
    NtProtectVirtualMemoryHash*     = ctDjb2 "NtProtectVirtualMemory"
    NtWriteVirtualMemoryHash*       = ctDjb2 "NtWriteVirtualMemory"

## Nt* Memory APIs
##------------------------------------------------------------------------
template PROCESS_MEMORY_ALLOC*(allocBase: var PVOID, regionSize: var SIZE_T, allocType, protect: ULONG): NtResult[void] =
    ntAllocateVirtualMemory(RtlCurrentProcess(), allocBase, regionSize, allocType, protect)

template PROCESS_MEMORY_FREE*(allocBase: var PVOID, regionSize: var SIZE_T): NtResult[void] =
    ntFreeVirtualMemory(RtlCurrentProcess(), allocBase, regionSize, MEM_RELEASE)

template PROCESS_MEMORY_PROTECT*(allocBase: var PVOID, allocSz: var SIZE_T, protections: ULONG): NtResult[void] =
    ntProtectVirtualMemory(allocBase, allocSz, protections, NULL)

## NtAllocateVirtualMemory
##------------------------------------
template getNtAllocateVirtualMemory*(
    Ntdll: ModuleHandle,
    importBase: ModuleHandle, 
    symEnum: static SymbolEnumeration = AllocSymEnum, 
    ssnEnum: static SsnEnumeration = AllocSsnEnum, 
    exeEnum: static SyscallExecution = AllocExeEnum
): NtResult[NtSyscall[NtAllocateVirtualMemory]] =
    getNtSyscall[NtAllocateVirtualMemory](Ntdll, importBase, NtAllocateVirtualMemoryHash, symEnum, ssnEnum, exeEnum)

proc ntAllocateVirtualMemory*(
    processHandle: HANDLE,
    baseAddress: var PVOID, 
    regionSize: var SIZE_T, 
    allocType: ULONG, 
    protect: ULONG
): NtResult[void] =
    genSyscall(NtAllocateVirtualMemory)
    let 
        Ntdll       = ? NTDLL_BASE()
        NtSyscall   = 
            when AllocSymEnum == SymbolEnumeration.UseEAT:
                ? getNtAllocateVirtualMemory(Ntdll, ModuleHandle(NULL))
            elif AllocSymEnum == SymbolEnumeration.UseIAT:
                let Kernel32 = ? KERNEL32_BASE()
                ? getNtAllocateVirtualMemory(Ntdll, Kernel32)
    
    NT_RESULT NtAllocateVirtualMemoryWrapper(
        processHandle, 
        baseAddress, 
        0, 
        regionSize, 
        allocType, 
        protect,
        NtSyscall
    ): void

## NtFreeVirtualmemory
##------------------------------------
template getNtFreeVirtualMemory*(
    Ntdll: ModuleHandle,
    importBase: ModuleHandle,
    symEnum: static SymbolEnumeration = FreeSymEnum, 
    ssnEnum: static SsnEnumeration = FreeSsnEnum, 
    exeEnum: static SyscallExecution = FreeExeEnum
): NtResult[NtSyscall[NtFreeVirtualMemory]] =
    getNtSyscall[NtFreeVirtualMemory](Ntdll, importBase, NtFreeVirtualMemoryHash, symEnum, ssnEnum, exeEnum)

proc ntFreeVirtualMemory*(
    processHandle: HANDLE, 
    baseAddress: var PVOID, 
    sz: var SIZE_T, 
    dwFlags: ULONG
): NtResult[void] {.discardable.} =
    genSyscall(NtFreeVirtualMemory)
    let 
        Ntdll       = ? NTDLL_BASE()
        NtSyscall   = 
            when FreeSymEnum == SymbolEnumeration.UseEAT:
                ? getNtFreeVirtualMemory(Ntdll, ModuleHandle(NULL))
            elif FreeSymEnum == SymbolEnumeration.UseIAT:
                let Kernel32 = ? KERNEL32_BASE()
                ? getNtFreeVirtualMemory(Ntdll, Kernel32)
    
    NT_RESULT NtFreeVirtualMemoryWrapper(
        processHandle, 
        baseAddress, 
        sz, 
        dwFlags,
        NtSyscall
    ): void

## NtProtectVirtualMemory
##------------------------------------
template getNtProtectVirtualMemory*(
    Ntdll: ModuleHandle,
    importBase: ModuleHandle,
    symEnum: static SymbolEnumeration = ProtectSymEnum, 
    ssnEnum: static SsnEnumeration = ProtectSsnEnum, 
    exeEnum: static SyscallExecution = ProtectExeEnum
): NtResult[NtSyscall[NtProtectVirtualMemory]] =
    getNtSyscall[NtProtectVirtualMemory](Ntdll, importBase, NtProtectVirtualMemoryHash, symEnum, ssnEnum, exeEnum)

proc ntProtectVirtualMemory*(
    protectBase: var PVOID, 
    protectSz: var SIZE_T, 
    protections: ULONG, 
    oldProtections: PULONG
): NtResult[void] {.discardable.} = 
    genSyscall(NtProtectVirtualMemory)
    let 
        Ntdll           = ? NTDLL_BASE()
        NtSyscall       = 
            when ProtectSymEnum == SymbolEnumeration.UseEAT:
                ? getNtProtectVirtualMemory(Ntdll, ModuleHandle(NULL))
            elif ProtectSymEnum == SymbolEnumeration.UseIAT:
                let Kernel32 = ? KERNEL32_BASE()
                ? getNtProtectVirtualMemory(Ntdll, Kernel32)
    NT_RESULT NtProtectVirtualMemoryWrapper(
        rtlCurrentProcess(), 
        protectBase, 
        protectSz, 
        protections, 
        oldProtections,
        NtSyscall
    ): void
    
## NtWriteVirtualMemory
##------------------------------------
template getNtWriteVirtualMemory*(
    Ntdll: ModuleHandle,
    importBase: ModuleHandle,
    symEnum: static SymbolEnumeration = WriteSymEnum, 
    ssnEnum: static SsnEnumeration = WriteSsnEnum, 
    exeEnum: static SyscallExecution = WriteExeEnum
): NtResult[NtSyscall[NtWriteVirtualMemory]] =
    getNtSyscall[NtWriteVirtualMemory](Ntdll, importBase, NtWriteVirtualMemoryHash, symEnum, ssnEnum, exeEnum)

proc ntWriteVirtualMemory*(
    processHandle: HANDLE, 
    allocBase: PVOID, 
    memBase: PVOID, 
    memSz: SIZE_T,
    bytesWritten: PULONG
): NtResult[void] =
    genSyscall(NtWriteVirtualMemory)
    let 
        Ntdll       = ? NTDLL_BASE()
        NtSyscall   = 
            when WriteSymEnum == SymbolEnumeration.UseEAT:
                ? getNtWriteVirtualMemory(Ntdll, ModuleHandle(NULL))
            elif WriteSymEnum == SymbolEnumeration.UseIAT:
                let Kernel32 = ? KERNEL32_BASE()
                ? getNtWriteVirtualMemory(Ntdll, Kernel32)
    
    NT_RESULT NtWriteVirtualMemoryWrapper(
        processHandle, 
        allocBase, 
        memBase, 
        ULONG(memSz),
        bytesWritten,
        NtSyscall
    ): void

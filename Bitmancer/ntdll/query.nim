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
    ## Performance Counter Settings
    ##---------------------------------------------------------------------
    PerfExeEnum*    {.intDefine.} = SyscallExecution.Indirect  
    PerfSsnEnum*    {.intDefine.} = SsnEnumeration.ZwCounter
    PerfSymEnum*    {.intDefine.} = SymbolEnumeration.UseEAT
    
    ## System Information Settings
    ##---------------------------------------------------------------------
    SysInfoExeEnum* {.intDefine.} = SyscallExecution.Direct
    SysInfoSsnEnum* {.intDefine.} = SsnEnumeration.HellsGate
    SysInfoSymEnum* {.intDefine.} = SymbolEnumeration.UseEAT
    
    ## Virtual Memory Settings
    ##---------------------------------------------------------------------
    VMInfoExeEnum*  {.intDefine.} = SyscallExecution.Indirect
    VMInfoSsnEnum*  {.intDefine.} = SsnEnumeration.ZwCounter
    VMInfoSymEnum*  {.intDefine.} = SymbolEnumeration.UseEAT

## Hashes
##---------------------------------------------------------------------
const
    NtQuerySystemInformationHash*   = ctDjb2 "NtQuerySystemInformation"
    NtQueryPerformanceCounterHash*  = ctDjb2 "NtQueryPerformanceCounter"
    NtQuerySystemTimeHash*          = ctDjb2 "NtQuerySystemTime"
    NtQueryVirtualMemoryHash*       = ctDjb2 "NtQueryVirtualMemory"

## NtQuery* APIs
##------------------------------------------------------------------------
template GET_BASIC_SYSTEM_INFO*(sysInfo: var SYSTEM_BASIC_INFORMATION): NtResult[void] =
    eNtQuerySystemInformation(
        cast[PVOID](addr sysInfo), 
        SYSTEM_INFORMATION_CLASS.SystemBasicInformation, 
        sizeOf(SYSTEM_BASIC_INFORMATION)
    )

template GET_BASIC_VM_INFO*(
    processHandle: HANDLE, 
    baseAddress: PVOID, 
    memInfo: var MEMORY_BASIC_INFORMATION, 
    retLength: PSIZE_T
): NtResult[void] =
    eNtQueryVirtualMemory(
        processHandle, 
        baseAddress, 
        cast[PVOID](addr memInfo), 
        MEMORY_INFORMATION_CLASS.MemoryBasicInformation,
        sizeOf(MEMORY_BASIC_INFORMATION),
        retLength
    )

## SystemInformation
##------------------------------------
template getNtQuerySystemInformation*(
    Ntdll: ModuleHandle,
    importBase: ModuleHandle,
    symEnum: static SymbolEnumeration = SysInfoSymEnum, 
    ssnEnum: static SsnEnumeration = SysInfoSsnEnum, 
    exeEnum: static SyscallExecution = SysInfoExeEnum
): NtSyscall[NtQuerySystemInformation] =
    ctGetNtSyscall[NtQuerySystemInformation](Ntdll, importBase, NtQuerySystemInformationHash, symEnum, ssnEnum, exeEnum)

proc eNtQuerySystemInformation*(systemInfo: PVOID, systemClass: SYSTEM_INFORMATION_CLASS, systemSz: SIZE_T): NtResult[void] =
    genSyscall(NtQuerySystemInformation)
    let 
        Ntdll       = ? NTDLL_BASE()
        NtSyscall   = 
            when SysInfoSymEnum == SymbolEnumeration.UseEAT:
                getNtQuerySystemInformation(Ntdll, ModuleHandle(NULL))
            elif SysInfoSymEnum == SymbolEnumeration.UseIAT:
                let Kernel32 = ? KERNEL32_BASE()
                getNtQuerySystemInformation(Ntdll, Kernel32)
    
    NT_RESULT NtQuerySystemInformationWrapper(
        systemClass, 
        systemInfo, 
        systemSz.ULONG, 
        NULL,
        NtSyscall.wSyscall, NtSyscall.pSyscall, NtSyscall.pFunction
    ): void
    
## Time/Performance
##------------------------------------
template getNtQueryPerformanceCounter*(
    Ntdll: ModuleHandle, 
    importBase: ModuleHandle,
    symEnum: static SymbolEnumeration = PerfSymEnum,
    ssnEnum: static SsnEnumeration = PerfSsnEnum,
    exeEnum: static SyscallExecution = PerfExeEnum
): NtSyscall[NtQueryPerformanceCounter] =
    ctGetNtSyscall[NtQueryPerformanceCounter](Ntdll, importBase, NtQueryPerformanceCounterHash, symEnum, ssnEnum, exeEnum)

proc eNtQueryPerformanceCounter*(perfCounter: var LARGE_INTEGER, perfFrequency: PLARGE_INTEGER): NtResult[void] {.discardable.} =
    genSyscall(NtQueryPerformanceCounter)
    let
        Ntdll       = ? NTDLL_BASE()
        NtSyscall   = 
            when PerfSymEnum == SymbolEnumeration.UseEAT:
                getNtQueryPerformanceCounter(Ntdll, ModuleHandle(NULL))
            elif PerfSymEnum == SymbolEnumeration.UseIAT:
                let Kernel32 = ? KERNEL32_BASE()
                getNtQueryPerformanceCounter(Ntdll, Kernel32)
    NT_RESULT NtQueryPerformanceCounterWrapper(
        perfCounter, 
        perfFrequency,
        NtSyscall.wSyscall, NtSyscall.pSyscall, NtSyscall.pFunction
    ): void

proc getNtQuerySystemTime*(Ntdll: ModuleHandle): NtResult[NtQuerySystemTime] {.inline.} =
    let f = ? getProcAddress(Ntdll, NtQuerySystemTimeHash)
    ok cast[NtQuerySystemTime](f)

proc eNtQuerySystemTime*(systemTime: var LARGE_INTEGER): NtResult[void] {.discardable.} =
    let 
        Ntdll       = ? NTDLL_BASE()
        NtSyscall   = ? getNtQuerySystemTime Ntdll
    NT_RESULT NtSyscall(systemTime): void

## VirtualMemory
##------------------------------------
template getNtQueryVirtualMemory*(
    Ntdll: ModuleHandle, 
    importBase: ModuleHandle,
    symEnum: static[SymbolEnumeration] = VMInfoSymEnum, 
    ssnEnum: static[SsnEnumeration] = VMInfoSsnEnum,
    exeEnum: static[SyscallExecution] = VMInfoExeEnum
): NtSyscall[NtQueryVirtualMemory] =
    ctGetNtSyscall[NtQueryVirtualMemory](Ntdll, importBase, NtQueryVirtualMemoryHash, symEnum, ssnEnum, exeEnum)

proc eNtQueryVirtualMemory*(
    processHandle: HANDLE, 
    baseAddress: PVOID, 
    memInfo: PVOID, 
    memClass: MEMORY_INFORMATION_CLASS,
    memSz: SIZE_T,
    returnLength: PSIZE_T
): NtResult[void] =
    genSyscall(NtQueryVirtualMemory)
    let 
        Ntdll       = ? NTDLL_BASE()
        NtSyscall   = 
            when VMInfoSymEnum == SymbolEnumeration.UseEAT:
                getNtQueryVirtualMemory(Ntdll, ModuleHandle(NULL))
            elif VMInfoSymEnum == SymbolEnumeration.UseIAT:
                let Kernel32 = ? KERNEL32_BASE()
                getNtQueryVirtualMemory(Ntdll, Kernel32)
    NT_RESULT NtQueryVirtualMemoryWrapper(
        processHandle, 
        baseAddress, 
        memClass,
        memInfo, 
        memSz, 
        returnLength,
        NtSyscall.wSyscall, NtSyscall.pSyscall, NtSyscall.pFunction
    ): void

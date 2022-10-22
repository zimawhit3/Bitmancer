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
##---------------------------------------------------------------------
const
    ## NtClose Syscall Settings
    ##---------------------------------------------------------------------
    CloseExeEnum*       {.intDefine.} = SyscallExecution.Indirect
    CloseSsnEnum*       {.intDefine.} = SsnEnumeration.ZwCounter
    CloseSymEnum*       {.intDefine.} = SymbolEnumeration.UseEAT

    ## NtCreateSection Syscall Settings
    ##---------------------------------------------------------------------
    CreateExeEnum*      {.intDefine.} = SyscallExecution.Indirect
    CreateSsnEnum*      {.intDefine.} = SsnEnumeration.ZwCounter
    CreateSymEnum*      {.intDefine.} = SymbolEnumeration.UseEAT

    ## NtMapViewOfSection Syscall Settings
    ##---------------------------------------------------------------------
    MapViewExeEnum*     {.intDefine.} = SyscallExecution.Indirect
    MapViewSsnEnum*     {.intDefine.} = SsnEnumeration.ZwCounter
    MapViewSymEnum*     {.intDefine.} = SymbolEnumeration.UseEAT

    ## NtOpenFile Syscall Settings
    ##---------------------------------------------------------------------
    OpenFileExeEnum*    {.intDefine.} = SyscallExecution.Indirect
    OpenFileSsnEnum*    {.intDefine.} = SsnEnumeration.ZwCounter
    OpenFileSymEnum*    {.intDefine.} = SymbolEnumeration.UseEAT

    ## NtOpenSection Syscall Settings
    ##---------------------------------------------------------------------
    OpenSectionExeEnum* {.intDefine.} = SyscallExecution.Indirect
    OpenSectionSsnEnum* {.intDefine.} = SsnEnumeration.ZwCounter
    OpenSectionSymEnum* {.intDefine.} = SymbolEnumeration.UseEAT

    ## NtUnmapViewOfSection Syscall Settings
    ##---------------------------------------------------------------------
    UnmapViewExeEnum*   {.intDefine.} = SyscallExecution.Indirect
    UnmapViewSsnEnum*   {.intDefine.} = SsnEnumeration.ZwCounter
    UnmapViewSymEnum*   {.intDefine.} = SymbolEnumeration.UseEAT

## Hashes
##---------------------------------------------------------------------
const
    NtCloseHash*                = ctDjb2 "NtClose"
    NtCreateSectionHash*        = ctDjb2 "NtCreateSection"
    NtMapViewOfSectionHash      = ctDjb2 "NtMapViewOfSection"
    NtOpenFileHash*             = ctDjb2 "NtOpenFile"
    NtOpenSectionHash*          = ctDjb2 "NtOpenSection"
    NtUnmapViewOfSectionHash*   = ctDjb2 "NtUnmapViewOfSection"

## NtClose
##------------------------------------
template getNtClose*(
    Ntdll: ModuleHandle, 
    importBase: ModuleHandle,
    symEnum: static SymbolEnumeration = CloseSymEnum, 
    ssnEnum: static SsnEnumeration = CloseSsnEnum, 
    exeEnum: static SyscallExecution = CloseExeEnum
): NtResult[NtSyscall[NtClose]] =
    getNtSyscall[NtClose](Ntdll, importBase, NtCloseHash, symEnum, ssnEnum, exeEnum)

proc eNtClose*(h: HANDLE): NtResult[void] {.discardable.} =
    genSyscall(NtClose)
    let 
        Ntdll       = ? NTDLL_BASE()
        NtSyscall   = 
            when CloseSymEnum in {UseEAT, UseLdrThunks}:
                ? getNtClose(Ntdll, ModuleHandle(NULL))
            elif CloseSymEnum == SymbolEnumeration.UseIAT:
                let Kernel32 = ? KERNEL32_BASE()
                ? getNtClose(Ntdll, Kernel32)
    NT_RESULT NtCloseWrapper(h, NtSyscall.wSyscall, NtSyscall.pSyscall, NtSyscall.pFunction): void

## NtCreateSection
##------------------------------------
template getNtCreateSection*(
    Ntdll: ModuleHandle,
    importBase: ModuleHandle,
    symEnum: static SymbolEnumeration = CreateSymEnum,
    ssnEnum: static SsnEnumeration = CreateSsnEnum,
    exeEnum: static SyscallExecution = CreateExeEnum
): NtResult[NtSyscall[NtCreateSection]] =
    getNtSyscall[NtCreateSection](Ntdll, importBase, NtCreateSectionHash, symEnum, ssnEnum, exeEnum)

proc eNtCreateSection*(
    sectionHandle: var HANDLE,
    desiredAccess: ACCESS_MASK,
    objAttributes: POBJECT_ATTRIBUTES,
    maximumSize: PLARGE_INTEGER,
    sectionPageProt: ULONG,
    allocAttributes: ULONG,
    fileHandle: HANDLE
): NtResult[void] =
    genSyscall(NtCreateSection)
    let 
        Ntdll       = ? NTDLL_BASE()
        NtSyscall   = 
            when CreateSymEnum == SymbolEnumeration.UseEAT:
                ? getNtCreateSection(Ntdll, ModuleHandle(NULL))
            elif CreateSymEnum == SymbolEnumeration.UseIAT:
                let Kernel32 = ? KERNEL32_BASE()
                ? getNtCreateSection(Ntdll, Kernel32)
    NT_RESULT NtCreateSectionWrapper(
        sectionHandle,
        desiredAccess,
        objAttributes,
        maximumSize,
        sectionPageProt,
        allocAttributes,
        fileHandle,
        NtSyscall.wSyscall, NtSyscall.pSyscall, NtSyscall.pFunction
    ): void

## NtMapViewOfSection
##------------------------------------
template getNtMapViewOfSection*(
    Ntdll: ModuleHandle,
    importBase: ModuleHandle,
    symEnum: static SymbolEnumeration = MapViewSymEnum,
    ssnEnum: static SsnEnumeration = MapViewSsnEnum,
    exeEnum: static SyscallExecution = MapViewExeEnum
): NtResult[NtSyscall[NtMapViewOfSection]] =
    getNtSyscall[NtMapViewOfSection](Ntdll, importBase, NtMapViewOfSectionHash, symEnum, ssnEnum, exeEnum)

proc eNtMapViewOfSection*(
    sectionHandle: HANDLE,
    processHandle: HANDLE,
    baseAddress: var PVOID,
    zeroBits: ULONG_PTR,
    commitSize: SIZE_T,
    sectionOffset: PLARGE_INTEGER,
    viewSize: var SIZE_T,
    inheritDisp: ULONG,
    allocType: ULONG,
    win32Protect: ULONG
): NtResult[void] =
    genSyscall(NtMapViewOfSection)
    let 
        Ntdll       = ? NTDLL_BASE()
        NtSyscall   = 
            when MapViewSymEnum == SymbolEnumeration.UseEAT:
                ? getNtMapViewOfSection(Ntdll, ModuleHandle(NULL))
            elif MapViewSymEnum == SymbolEnumeration.UseIAT:
                let Kernel32 = ? KERNEL32_BASE()
                ? getNtMapViewOfSection(Ntdll, Kernel32)
    NT_RESULT NtMapViewOfSectionWrapper(
        sectionHandle,
        processHandle,
        baseAddress,
        zeroBits,
        commitSize,
        sectionOffset,
        viewSize,
        inheritDisp,
        allocType,
        win32Protect,
        NtSyscall.wSyscall, NtSyscall.pSyscall, NtSyscall.pFunction
    ): void

## NtOpenFile
##------------------------------------
template getNtOpenFile*(
    Ntdll: ModuleHandle, 
    importBase: ModuleHandle,
    symEnum: static SymbolEnumeration = OpenFileSymEnum, 
    ssnEnum: static SsnEnumeration = OpenFileSsnEnum, 
    exeEnum: static SyscallExecution = OpenFileExeEnum
): NtResult[NtSyscall[NtOpenFile]] =
    getNtSyscall[NtOpenFile](Ntdll, importBase, NtOpenFileHash, symEnum, ssnEnum, exeEnum)

proc eNtOpenFile*(
    fileHandle: var HANDLE,
    desiredAccess: ACCESS_MASK,
    objAttributes: POBJECT_ATTRIBUTES,
    statusBlock: var IO_STATUS_BLOCK,
    shareAccess: ULONG,
    openOptions: ULONG
): NtResult[void] =
    genSyscall(NtOpenFile)
    let 
        Ntdll       = ? NTDLL_BASE()
        NtSyscall   = 
            when OpenFileSymEnum == SymbolEnumeration.UseEAT:
                ? getNtOpenFile(Ntdll, ModuleHandle(NULL))
            elif OpenFileSymEnum == SymbolEnumeration.UseIAT:
                let Kernel32 = ? KERNEL32_BASE()
                ? getNtOpenFile(Ntdll, Kernel32)

    NT_RESULT NtOpenFileWrapper(
        fileHandle,
        desiredAccess,
        objAttributes,
        statusBlock,
        shareAccess,
        openOptions,
        NtSyscall.wSyscall, NtSyscall.pSyscall, NtSyscall.pFunction
    ): void

## NtOpenSection
##------------------------------------
template getNtOpenSection*(
    Ntdll: ModuleHandle,
    importBase: ModuleHandle,
    symEnum: static SymbolEnumeration = OpenSectionSymEnum, 
    ssnEnum: static SsnEnumeration = OpenSectionSsnEnum, 
    exeEnum: static SyscallExecution = OpenSectionExeEnum
): NtResult[NtSyscall[NtOpenSection]] =
    getNtSyscall[NtOpenSection](Ntdll, importBase, NtOpenSectionHash, symEnum, ssnEnum, exeEnum)

proc eNtOpenSection*(sectionHandle: var HANDLE, desiredAccess: ACCESS_MASK, objAttributes: POBJECT_ATTRIBUTES): NtResult[void] =
    genSyscall(NtOpenSection)
    let 
        Ntdll = ? NTDLL_BASE()
        NtSyscall =
            when OpenSectionSymEnum == SymbolEnumeration.UseEAT:
                ? getNtOpenSection(Ntdll, ModuleHandle(NULL))
            elif OpenSectionSymEnum == SymbolEnumeration.UseIAT:
                let Kernel32 = ? KERNEL32_BASE()
                ? getNtOpenSection(Ntdll, Kernel32)
    NT_RESULT NtOpenSectionWrapper(
        sectionHandle,
        desiredAccess,
        objAttributes,
        NtSyscall.wSyscall, NtSyscall.pSyscall, NtSyscall.pFunction
    ): void

## NtUnmapViewOfSection
##------------------------------------
template getNtUnmapViewOfSection*(
    Ntdll: ModuleHandle,
    importBase: ModuleHandle,
    symEnum: static SymbolEnumeration = UnmapViewSymEnum,
    ssnEnum: static SsnEnumeration = UnmapViewSsnEnum,
    exeEnum: static SyscallExecution = UnmapViewExeEnum
): NtResult[NtSyscall[NtUnmapViewOfSection]] =
    getNtSyscall[NtUnmapViewOfSection](Ntdll, importBase, NtUnmapViewOfSectionHash, symEnum, ssnEnum, exeEnum)

proc eNtUnmapViewOfSection*(processHandle: HANDLE, baseAddress: PVOID): NtResult[void] {.discardable.} =
    genSyscall(NtUnmapViewOfSection)
    let 
        Ntdll       = ? NTDLL_BASE()
        NtSyscall   = 
            when UnmapViewSymEnum == SymbolEnumeration.UseEAT:
                ? getNtUnmapViewOfSection(Ntdll, ModuleHandle(NULL))
            elif UnmapViewSymEnum == SymbolEnumeration.UseIAT:
                let Kernel32 = ? KERNEL32_BASE()
                ? getNtUnmapViewOfSection(Ntdll, Kernel32)
    
    NT_RESULT NtUnmapViewOfSectionWrapper(
        processHandle, 
        baseAddress, 
        NtSyscall.wSyscall, NtSyscall.pSyscall, NtSyscall.pFunction
    ): void


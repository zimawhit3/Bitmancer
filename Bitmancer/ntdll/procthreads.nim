

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
): NtSyscall[NtFlushInstructionCache] =
    ctGetNtSyscall[NtFlushInstructionCache](Ntdll, importBase, NtFlushInstructionCacheHash, symEnum, ssnEnum, exeEnum)

proc eNtFlushInstructionCache*(processHandle: HANDLE, baseAddress: PVOID, dwSize: SIZE_T): NtResult[void] {.discardable.} =
    genSyscall(NtFlushInstructionCache)
    let
        Ntdll     = ? NTDLL_BASE()
        NtSyscall =
            when FlushSymEnum == SymbolEnumeration.UseEAT:
                getNtFlushInstructionCache(Ntdll, ModuleHandle(NULL))
            elif FlushSymEnum == SymbolEnumeration.UseIAT:
                let Kernel32 = ? KERNEL32_BASE()
                getNtFlushInstructionCache(Ntdll, Kernel32)

    NT_RESULT NtFlushInstructionCacheWrapper(
        processHandle, 
        baseAddress, 
        dwSize, 
        NtSyscall.wSyscall, NtSyscall.pSyscall, NtSyscall.pFunction
    ): void
        

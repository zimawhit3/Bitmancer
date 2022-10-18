

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

template ctGetNtSyscall*[T](
    Ntdll: ModuleHandle,
    importBase: ModuleHandle,
    ident: static[DWORD], 
    symEnum: static[SymbolEnumeration], 
    ssnEnum: static[SsnEnumeration],
    exeEnum: static[SyscallExecution]): NtSyscall[T] =
    let 
        sysRes      = ? ctGetSyscall(Ntdll, importBase, ident, symEnum, ssnEnum)
        funct       = NT_STUB[T](sysRes, exeEnum)
        pSyscall    = 
            when exeEnum == SyscallExecution.Direct: 
                sysRes.pSyscall
            elif exeEnum == SyscallExecution.Indirect: 
                getSyscallInstruction sysRes.pSyscall

    NtSyscall[T](
        wSyscall: sysRes.wSyscall, 
        pSyscall: pSyscall,
        pFunction: funct, 
        isHooked: sysRes.isHooked
    )

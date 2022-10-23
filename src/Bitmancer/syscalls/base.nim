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
    ../core/enumeration/memory/syscalls,
    ../rtl
    
export
    rtl, syscalls

const 
    StubOffsetUp*   = 32
    StubOffsetDown* = -32
    
type
    NtSyscall*[T] {.byCopy.} = object
        syscall*:   Syscall
        pFunction*: T

## Compile Time Options
##------------------------------------------------------------------------
type
    SsnEnumeration* {.pure.} = enum
        HalosGate       ## Halos' Gate SSN retrieval
        HellsGate       ## Hell's Gate SSN retrieval
        LdrThunks       ## Utilize Ldr's Thunk Signatures to load a fresh NTDLL from disk and resolve needed SSNs.
        TartarusGate    ## Tartarus' Gate SSN retrieval
        ZwCounter       ## Utilize Nt/Zw* stub memory address ordering

    SymbolEnumeration* {.pure.} = enum
        UseEAT,         ## Use the NTDLL's Export Address Table to resolve SSNs and syscall instruction addresses.
        UseIAT,         ## Use the Kernel32's Import Address Table to resolve SSNs and syscall instruction addresses.

    SyscallExecution* {.pure.} = enum
        Direct,         ## Execute system call directly.
        Indirect,       ## Execute system call indirectly with the stub's syscall instruction.

## Compile Time Settings
##------------------------------------------------------------------------
const
    ## SpoofCallStack
    ##  Spoof the call stack to evade stack introspection from EDRs when an Instrumented Callback
    ##  is registered.
    ##--------------------------------------
    SpoofCallStack* {.boolDefine.} = true

## Helpers
##------------------------------------
template checkValidOSVersionTarget*(ssnEnum: SsnEnumeration) =
    static:
        when OsVer < OS_10_Threadhold1 and ssnEnum == SsnEnumeration.LdrThunks:
            {.fatal: """UseLdrThunks uses the LdrpThunkSignatures to load a fresh copy of NTDLL to parse. These
                signatures are only available on versions of Windows 10 and later.""".}

## Nt Syscall Stubs
##------------------------------------
func directStub*() {.asmNoStackFrame, inline.} =
    when defined(cpu64):
        asm """
            mov r10, rcx
            mov eax, r14d
            syscall
        """
    else:
        static: {.fatal: "Support for x86 not implemented yet".}

func spoofStub*() {.asmNoStackFrame, inline.} =
    when defined(cpu64):
        asm """
            mov r10, rcx
            mov eax, r14d
            jmp r15
        """
    else:
        static: {.fatal: "Support for x86 not implemented yet".}
        
template PRE_CALL*() =
    when defined(cpu64):
        {.emit: [
            """asm volatile(
                "mov r14w, %c[wSyscall] %0\n\t"
                "mov r15, %c[pSyscall] %0\n\t"
                :
                :"m"(ntSyscall), 
                 [wSyscall] "i" (offsetof(""", Syscall, """, wSyscall)),
                 [pSyscall] "i" (offsetof(""", Syscall, """, pSyscall))
                : "r14", "r15"
            );
            """
        ].}
        
    else:
        static: {.fatal: "x86 Not yet implemented".}

## Nt Syscall Generation
##------------------------------------
proc newProc(name = newEmptyNode();
              genericParams: NimNode = newEmptyNode();
              params: openArray[NimNode] = [newEmptyNode()];
              body: NimNode = newStmtList();
              procType = nnkProcDef;
              pragmas: NimNode = newEmptyNode()): NimNode =
    if procType notin RoutineNodes:
        error("Expected one of " & $RoutineNodes & ", got " & $procType)
    pragmas.expectKind({nnkEmpty, nnkPragma})
    result = newNimNode(procType).add(
        name,
        newEmptyNode(),
        genericParams,
        newNimNode(nnkFormalParams).add(params),
        pragmas,
        newEmptyNode(),
        body)

proc newProcArgs(typedef: NimNode): seq[NimNode] {.compileTime.} =
    expectKind(typeDef, nnkTypeDef)
    result = newSeq[NimNode]()
    for fParam in typeDef[2][0]:
        if fParam.kind == nnkSym:
            result.add ident($fParam)
        else:
            let paramName = ident($fParam[0])
            let paramType =
                if fParam[1].kind == nnkVarTy:
                    newNimNode(nnkVarTy).add(ident($fParam[1][0]))
                else:
                    ident($fParam[1])
            result.add newIdentDefs(paramName, paramType)
    
    let bracketExpr = newNimNode(nnkBracketExpr)
    bracketExpr.add ident"NtSyscall"
    bracketExpr.add ident"T"  

    let ntSyscall   = newIdentDefs(ident"ntSyscall", bracketExpr)
    result.add ntSyscall

proc newProcPragma(typeDef: NimNode): NimNode {.compileTime.} =
    expectKind(typeDef, nnkTypeDef)
    result = newNimNode(nnkPragma)
    for pragma in typeDef[2][1]:
        result.add ident($pragma)

proc newProcBody(args: seq[NimNode]): NimNode {.compileTime.} =
    result = newStmtList()
    let 
        resultIdent = ident"result"
        bodyCall    = newNimNode(nnkCall)
        dotExpr     = newNimNode(nnkDotExpr)
        ntSyscall   = ident"ntSyscall"
    dotExpr.add ntSyscall
    dotExpr.add ident"pFunction"
    
    bodyCall.add dotExpr
    for i in 1 ..< args.len() - 1:
        bodyCall.add args[i][0]

    result = quote do:
        PRE_CALL()
        `resultIdent` = `bodyCall`

macro genSyscall*(T: typedesc) =
    let 
        typeDef         = getImpl(T)
        procArgs        = newProcArgs(typeDef)
        genericParams   = newNimNode(nnkGenericParams)

    genericParams.add newIdentDefs(ident"T", newEmptyNode())
    
    result = newStmtList()
    result.add newProc(
        name = ident($typedef[0] & "Wrapper"),
        genericParams = genericParams,
        params = procArgs,
        body = newProcBody(procArgs),
        pragmas = newProcPragma(typeDef)
    )
    when defined(nimDumpSyscalls):
        echo repr result

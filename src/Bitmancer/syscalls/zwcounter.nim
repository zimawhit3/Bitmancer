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

## ZwCounter Compile Time Options
##------------------------------------------------------------------------
type
    ZwCounterMethod* {.pure.} = enum
        UseExceptionTable,
        UseHighestAddress

## ZwCounter Compile Time Settings
##------------------------------------------------------------------------
const
    ZwCountingMethod* {.intDefine.} = ZwCounterMethod.UseHighestAddress

## ZwCounter SSN Enumeration
## 
##  Enumerate SSNs by utilizing the fact the syscall stubs will be ascendingly ordered in memory. 
##  The RTF table just so happens to order these syscall stubs in that order. By looping through both 
##  the RTF table and the EAT, we can save ourselves from allocating additional memory to resolve SSNs 
##  for NT* APIs. Alternatively, we can find the highest address syscall stub coupled with the syscall's
##  address to count the SSN.
##-------------------------------------------------------------------------------------------------------------
proc bZwCounterEatExc*(imageBase: ModuleHandle, ident: SomeProcIdent): SyscallResult =
    var ssn         = WORD(0)
    let 
        rtfTable    = ? getExceptionDirectory imageBase
        exports     = ? getExportDirectory imageBase
    for rtFunction in rtfTable.runtimeFunctions():
        for symName, ord, pFunc in imageBase.exports exports:
            if imageBase +% rtFunction.BeginAddress == pFunc:
                if IDENT_MATCH(symName, ord, ident):
                    return ok (wSyscall: ssn,  pSyscall: pFunc, isHooked: isHooked(pFunc))
                if symName[0] == 'Z' and symName[1] == 'w':
                    inc ssn
    err SyscallNotFound

proc bZwCounterEatHighest*(imageBase: ModuleHandle, ident: SomeProcIdent): SyscallResult =
    var
        ssn             = WORD(0)
        pHighestAddr    = UINT_PTR(UINT_PTR.high)
        pTargetAddr     = UINT_PTR(0)
    let exports         = ? getExportDirectory(imageBase)

    for symName, ord, pFunc in imageBase.exports exports:
        ## Highest address will be lowest value
        if symName[0] == 'Z' and symName[1] == 'w':
            if pHighestAddr > cast[UINT_PTR](pFunc):
                pHighestAddr = cast[UINT_PTR](pFunc)
        if IDENT_MATCH(symName, ord, ident):
            pTargetAddr = cast[UINT_PTR](pFunc)

    ## Loop through the Zw/Nt call stubs until we hit our target
    for pStub in pHighestAddr.ntStubs():
        if pStub == pTargetAddr:
            return ok (ssn, cast[PVOID](pTargetAddr), isHooked(cast[PVOID](pStub)))
        inc ssn
    err SyscallNotFound

proc bZwCounterEat*(imageBase: ModuleHandle, ident: SomeProcIdent): SyscallResult {.inline.} =
    when ZwCountingMethod == ZwCounterMethod.UseExceptionTable:
        bZwCounterEatExc(imageBase, ident)
    elif ZwCountingMethod == ZwCounterMethod.UseHighestAddress:
        bZwCounterEatHighest(imageBase, ident)

proc bZwCounterIat*(importBase: ModuleHandle, ident: SomeThunkedIdent): SyscallResult =
    
    when ZwCountingMethod == ZwCounterMethod.UseExceptionTable:
        static: {.fatal: "Cannot use exception table counting method for IAT-based symbol resolution.".}

    elif ZwCountingMethod == ZwCounterMethod.UseHighestAddress:
        var
            ssn             = WORD(0)
            pHighestAddr    = UINT_PTR(UINT_PTR.high)
            pTargetAddr     = UINT_PTR(0)
        let importTable     = ? getImportDirectory(importBase)
        
        for imprt in importTable.imports():     
        
            let dllName = cast[cstring](importBase +% imprt.Name)
            
            if dllName[0] == 'n' and dllName[1] == 't' and dllName[2] == 'd' and 
               dllName[3] == 'l' and dllName[4] == 'l':
                
                for (pOriginalThunk, pFirstThunk) in importBase.thunks imprt:
                    let 
                        hint    = cast[PIMAGE_IMPORT_BY_NAME](importBase +% pOriginalThunk.u1.AddressOfData)
                        symName = cast[cstring](addr hint.Name[0])
                    if symName[0] == 'Z' and symName[1] == 'w':
                        if pHighestAddr > pFirstThunk.u1.Function:
                            pHighestAddr = pFirstThunk.u1.Function
                    if IDENT_MATCH(symName, ident):
                        pTargetAddr = pFirstThunk.u1.Function

        ## Because imports won't have all of the symbols in its import table, we must take extra steps to ensure
        ## we're at the highest syscall stub.
        if not pHighestAddr.isHighestAddress():
            pHighestAddr = searchNtStubUp pHighestAddr

        ## Loop through the NT* call stubs until we hit our target
        for pStub in pHighestAddr.ntStubs():
            if pStub == pTargetAddr:
                return ok (ssn, cast[PVOID](pTargetAddr), isHooked(cast[PVOID](pStub)))
            inc ssn
        err SyscallNotFound

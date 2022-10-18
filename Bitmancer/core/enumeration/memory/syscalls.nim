

import
    ".."/../[pe, utils]

export
    pe

## Memory Enumeration for Syscalls
##------------------------------------------------------------------------
const 
    SeperationBytes = QWORD 0x0000000000841F0F  ## nop dword ptr ds:[rax+rax], eax
    BarrierBytes    = QWORD 0xCCCCCCCCCCCCCCCC
type
    SyscallResult* = NtResult[tuple[wSyscall: WORD, pSyscall: PVOID, isHooked: bool]]

## Helper Templates
##------------------------------------
template isValidStub(currentByte: PVOID): bool =
    cast[PBYTE](currentByte)[] == 0x4C and 
    cast[PBYTE](currentByte +! 1)[] == 0x8B and
    cast[PBYTE](currentByte +! 2)[] == 0xD1 and 
    cast[PBYTE](currentByte +! 3)[] == 0xB8 and
    cast[PBYTE](currentByte +! 6)[] == 0x00 and
    cast[PBYTE](currentByte +! 7)[] == 0x00

## Forward Declarations
##------------------------------------
func checkStub*(functionBase: PVOID, offset: DWORD, isHooked: bool): SyscallResult {.inline.}

## Public
##------------------------------------
iterator ntStubs*(pFirstStub: UINT_PTR): UINT_PTR =
    var 
        currentQword    = cast[PQWORD](pFirstStub)
        breakLoop       = true
    while breakLoop:
        yield cast[UINT_PTR](currentQword)
        while currentQword[] != SeperationBytes:
            NEXT_ADDRESS currentQword
            if currentQword[] == BarrierBytes:
                breakLoop = false
                break
        if breakLoop:
            NEXT_ADDRESS currentQword

func isHighestAddress*(pStub: UINT_PTR): bool {.inline.} =
    cast[PQWORD](pstub -% sizeof(UINT_PTR))[] == BarrierBytes

func isHooked*(pStub: PVOID): bool {.inline.} =
    not checkStub(pStub, 0, false).isOk()

func searchNtStubUp*(pStub: UINT_PTR): UINT_PTR =
    var currentQword = cast[PQWORD](pStub)
    while cast[PQWORD](currentQword -! sizeof(UINT_PTR))[] != BarrierBytes:
        PREV_ADDRESS currentQword
    cast[UINT_PTR](currentQword)

func checkStub*(functionBase: PVOID, offset: DWORD, isHooked: bool): SyscallResult {.inline.} =
    ## First opcodes should be :
    ##    MOV R10, RCX
    ##    MOV RCX, <syscall>
    if isValidStub(functionBase +! offset):
        let
            highByte    = cast[PBYTE](functionBase +! offset +! 5)[]
            lowByte     = cast[PBYTE](functionBase +! offset +! 4)[]
            wSyscall    = WORD((highByte shr 8) or lowByte)
        ok (wSyscall, functionBase, isHooked)
    else:
        err SyscallNotFound

func getSyscallInstruction*(stub: PVOID): PVOID =
    var currWord = cast[PWORD](stub)
    while currWord[] != 0x050F:
        currWord = cast[PWORD](currWord +! 2)
    cast[PVOID](currWord)

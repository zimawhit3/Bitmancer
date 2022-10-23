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
    ".."/../[pe, utils]

export
    pe

## Memory Enumeration for Syscalls
##------------------------------------------------------------------------
const 
    SeperationBytes = QWORD 0x0000000000841F0F  ## nop dword ptr ds:[rax+rax], eax
    BarrierBytes    = QWORD 0xCCCCCCCCCCCCCCCC
    SyscallBytes    = WORD 0x050F
type
    Syscall* {.byCopy.} = object
        wSyscall*:  WORD
        pSyscall*:  PVOID
    SyscallResult* = NtResult[Syscall]

## Helper Templates
##------------------------------------
template isValidStub(currentByte: PVOID): bool =
    ## First opcodes should be :
    ##    MOV R10, RCX
    ##    MOV RCX, <syscall>
    cast[PBYTE](currentByte)[] == 0x4C and 
    cast[PBYTE](currentByte +! 1)[] == 0x8B and
    cast[PBYTE](currentByte +! 2)[] == 0xD1 and 
    cast[PBYTE](currentByte +! 3)[] == 0xB8 and
    cast[PBYTE](currentByte +! 6)[] == 0x00 and
    cast[PBYTE](currentByte +! 7)[] == 0x00

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

template isHighestAddress*(pStub: UINT_PTR): bool =
    cast[PQWORD](pstub -% sizeof(UINT_PTR))[] == BarrierBytes

template isHooked*(pStub: PVOID): bool =
    not checkStub(pStub, 0).isOk()

func searchNtStubUp*(pStub: UINT_PTR): UINT_PTR =
    var currentQword = cast[PQWORD](pStub)
    while cast[PQWORD](currentQword -! sizeof(UINT_PTR))[] != BarrierBytes:
        PREV_ADDRESS currentQword
    cast[UINT_PTR](currentQword)

func getSyscallInstruction*(stub: PVOID): NtResult[PVOID] =
    let syscall = stub +! 0x12
    if cast[PWORD](syscall)[] != SyscallBytes:
        err SearchNotFound
    else:
        ok syscall

func checkStub*(functionBase: PVOID, offset: DWORD): SyscallResult =
    ## Checks the stub at the offset from the functionBase for an unhooked syscall stub.
    if isValidStub(functionBase +! offset):
        let
            highByte    = cast[PBYTE](functionBase +! offset +! 5)[]
            lowByte     = cast[PBYTE](functionBase +! offset +! 4)[]
            wSyscall    = WORD((highByte shr 8) or lowByte)
            pSyscall    = ? getSyscallInstruction(functionBase +! offset)
        ok Syscall(
            wSyscall: wSyscall, 
            pSyscall: pSyscall
        )
    else:
        err SyscallNotFound


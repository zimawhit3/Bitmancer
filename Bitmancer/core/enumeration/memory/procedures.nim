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

func searchCallToTargetFunction*(fStart, fEnd, target: PVOID, callIndex: int): NtResult[PVOID] =
    var 
        currentAddr = fStart
        index       = 0
    while currentAddr != fEnd:
        if currentAddr.isCallInstruction():
            ## Offset should be: Address of Call + Offset + Length of Instruction (0x5)
            let rel32 = cast[PDWORD](currentAddr +! 1)[] + 0x5
            if currentAddr +! rel32 == target:
                if index == callIndex:
                    return ok currentAddr
                inc index
        inc currentAddr
    err SearchNotFound

func searchCall*(fStart, fEnd: PVOID, callIndex: int): NtResult[PVOID] =
    var 
        currentAddr = fStart
        index       = 0
    while currentAddr != fEnd:
        if currentAddr.isCallInstruction():
            if index == callIndex:
                return ok currentAddr
            inc index
        inc currentAddr
    err SearchNotFound

func searchFunctionEnd*(imageBase: ModuleHandle, functionBase: PVOID): NtResult[PVOID] =
    let ExcDirectory = ? getExceptionDirectory imageBase
    for entry in runtimeFunctions ExcDirectory:
        if imageBase +% entry.BeginAddress == functionBase:
            return ok imageBase +% entry.EndAddress
    err SearchNotFound

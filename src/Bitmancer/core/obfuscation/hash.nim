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
    std/[random, parseutils],
    ../types

export
    types

## CompileTime and RunTime Hashing
##------------------------------------------------------------------------
proc genRandomSeed(): uint32 {.compileTime.} =
    var seed: int
    discard parseInt(staticExec("bash -c 'echo $SRANDOM'"), seed, 0)
    echo "[+] Seeded with: " & $seed
    var rng = initRand(seed)
    rng.rand(uint32.high).uint32

const
    HashSeed* = genRandomSeed()

func ctDjb2*(pFuncName: static[cstring]): uint32 {.compileTime.} =
    result = HashSeed
    for c in pFuncName:
        result = ((result shl 0x05) + result) + ord(c).uint32

func rtDjb2*(pFuncName: cstring): uint32 =
    result = HashSeed
    for c in pFuncName:
        result = ((result shl 0x05) + result) + ord(c).uint32

func rtDjb2*(pFuncName: PCWSTR): uint32 =
    result  = HashSeed
    var i   = 0
    let ws  = cast[ptr UncheckedArray[uint16]](pFuncName)
    while ws[i] != 0:
        result = ((result shl 0x05) + result) + ord(cast[char](ws[i])).uint32
        inc i

template HASH_A*(s: cstring): uint32 =
    rtDjb2(s)

template HASH_W*(s: PCWSTR|UNICODE_STRING): uint32 =
    when s is PCWSTR:
        rtDjb2(s)
    elif s is UNICODE_STRING:
        rtDjb2(s.Buffer)

    
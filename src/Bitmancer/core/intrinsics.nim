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

proc addressOfReturnAddress*(): pointer {.importc: "_AddressOfReturnAddress", header: "intrin.h".}
proc debugbreak*() {.importc: "__debugbreak", header: "_mingw.h".}
proc interlockedIncrement16*(value: ptr int16): int16   {.importc: "_InterlockedIncrement16", header: "<intrin.h>".}
proc interlockedIncrement*(value: ptr int32): int32     {.importc: "_InterlockedIncrement", header: "<intrin.h>".}
proc interlockedIncrement64*(value: ptr int64): int64   {.importc: "_InterlockedIncrement64", header: "<intrin.h>".}

when defined(cpu64):
    proc readgsbyte*(offset: uint32): uint8     {.importc: "__readgsbyte", header: "<intrin.h>"}
    proc readgsword*(offset: uint32): uint16    {.importc: "__readgsword", header: "<intrin.h>".} 
    proc readgsdword*(offset: uint32): uint32   {.importc: "__readgsdword", header: "<intrin.h>".}
    proc readgsqword*(offset: uint64): uint64   {.importc: "__readgsqword", header: "<intrin.h>".}

elif defined(i386):
    proc readfsbyte*(offset: uint32): uint8     {.importc: "__readfsbyte", header: "<intrin.h>".}
    proc readfsword*(offset: uint32): uint16    {.importc: "__readfsword", header: "<intrin.h>".}
    proc readfsdword*(offset: uint32): uint32   {.importc: "__readfsdword", header: "<intrin.h>".}
    proc readfsqword*(offset: uint32): uint64   {.importc: "__readfsqword", header: "<intrin.h>".}

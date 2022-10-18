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
    types
export
    types

type
    SomePointer* = pointer | ptr

## Assembly Utility Templates
##------------------------------------------------------------------------
template isCallInstruction*[T: SomePointer](p: T): bool =
    when T is ptr BYTE:
        p[] == 0xE8
    else:
        cast[PBYTE](p)[] == 0xE8

## Pointer Utility Templates
##------------------------------------------------------------------------
template `++`*[T](p: var ptr T) =
    p = cast[ptr T](cast[int](p) +% sizeof(T))

template `--`*[T](p: var ptr T) =
    p = cast[ptr T](cast[int](p) -% sizeOf(T))

template `+!`*[T: SomePointer](p: T, s: SomeInteger): T =
    when s is SomeSignedInt:
        cast[T](cast[int](p) +% s.int)
    elif s is SomeUnsignedInt:
        cast[T](cast[uint](p) + s.uint)

template `-!`*[T: SomePointer](p: T, s: SomeInteger): T =
    when s is SomeSignedInt:
        cast[T](cast[int](p) -% s.int)
    elif s is SomeUnsignedInt:
        cast[T](cast[uint](p) - s.uint)

template `+=!`*[T: SomePointer](p: var T, s: SomeInteger) =
    p = p +! s

template `-=!`*[T: SomePointer](p: var T, s: SomeInteger) =
    p = p -! s

template inc*(p: var pointer) =
    p = p +! 1

template inc*[T: SomeInteger](p: var ptr T) =
    p = p +! sizeOf(T)

template dec*(p: var pointer) =
    p = p -! 1

template dec*[T: SomeInteger](p: var ptr T) =
    p = p -! sizeOf(T)

template CONTAINING_RECORD*(address: ptr, T: typedesc, field: untyped): ptr T =
    cast[ptr T](cast[int](address) -% T.offsetOf(field))

template NEXT_ADDRESS*[T: SomePointer](p: var T) =
    p = cast[T](cast[int](p) +% sizeOf(T))

template PREV_ADDRESS*[T: SomePointer](p: var T) =
    p = cast[T](cast[int](p) -% sizeOf(T))

## Bitfield Utility Templates
##------------------------------------------------------------------------
template `&=`*[T: SomeInteger](x: var T, y: T) =
    x = x and y

template `|=`*[T: SomeInteger](x: var T, y: T) =
    x = x or y

template `^=`*[T: SomeInteger](x: var T, y: T) =
    x = x xor y

template `&&`*[T: SomeInteger](x, y: T): bool =
    (x and y) > 0

template `||`*[T: SomeInteger](x, y: T): bool =
    (x or y) > 0


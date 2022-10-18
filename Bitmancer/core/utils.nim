

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


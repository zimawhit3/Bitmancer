# Copyright (c) 2019 Jacek Sieka
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## Modifyed Result type supporting position independent code. Explicitly avoiding
## exceptions, global strings, etc.
##-----------------------------------------------------------------------
type
    Result*[T, E] = object
        case o*: bool
        of false:
            e: E
        of true:
            v: T

template ok*[T, E](R: typedesc[Result[T, E]], x: untyped): R =
    R(o: true, v: x)

template ok*[E](R: typedesc[Result[void, E]]): R =
    R(o: true)

template ok*[T: not void, E](self: var Result[T, E], x: untyped) =
    self = ok(type self, x)

template ok*[E](self: var Result[void, E]) =
    self = (type self).ok()

template err*[T, E](R: type Result[T, E], x: untyped): R =
    R(o: false, e: x)

template err*[T](R: type Result[T, void]): R =
    R(o: false)

template err*[T, E](self: var Result[T, E], x: untyped) =
    self = err(type self, x)

template err*[T](self: var Result[T, void]) =
    self = err(type self)

template ok*(v: auto): auto = 
    ok(typeof(result), v)

template ok*(): auto = 
    ok(typeof(result))

template err*(v: auto): auto = 
    err(typeof(result), v)

template err*(): auto = 
    err(typeof(result))

template isOk*(self: Result): bool = 
    self.o

template isErr*(self: Result): bool = 
    not self.o

func get*[T, E](self: Result[T, E]): T {.inline.} =
    when T isnot void:
        self.v

func get*[T, E](self: Result[T, E], otherwise: T): T {.inline.} =
    if self.o: self.v
    else: otherwise

func get*[T: not void, E](self: var Result[T, E]): var T {.inline.} =
    self.v

func error*[T, E](self: Result[T, E]): E =
    when E isnot void:
        self.e

template valueOr*[T: not void, E](self: Result[T, E], def: untyped): T =
    let s = (self)
    if s.o: 
        s.v
    else:
        when E isnot void:
            template error: E {.used, inject.} = s.e
        def

template `?`*[T, E](self: Result[T, E]): auto =
    let v = (self)
    if not v.o:
        when typeof(result) is typeof(v):
            return v
        else:
            when E is void:
                return err(typeof(result))
            else:
                return err(typeof(result), v.e)

    when not(T is void):
        v.v


    
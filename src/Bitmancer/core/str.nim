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
    std/macros,
    pebteb, utils

export
    pebteb

## Private
##------------------------------------------------------------------------
proc assignChars(smt: NimNode, varName: NimNode, varValue: string, wide: bool) {.compileTime.} =
    var
        asnNode:        NimNode
        bracketExpr:    NimNode
        dotExpr:        NimNode
        castIdent:      NimNode
    for i in 0 ..< varValue.len():
        asnNode     = newNimNode(nnkAsgn)
        bracketExpr = newNimNode(nnkBracketExpr)
        dotExpr     = newNimNode(nnkDotExpr)
        castIdent   =
            if wide:    ident"uint16"
            else:       ident"uint8"
        bracketExpr.add(varName)
        bracketExpr.add(newIntLitNode(i))
        dotExpr.add(newLit(varValue[i]))
        dotExpr.add(castIdent)
        asnNode.add bracketExpr
        asnNode.add dotExpr
        smt.add asnNode
    asnNode     = newNimNode(nnkAsgn)
    bracketExpr = newNimNode(nnkBracketExpr)
    dotExpr     = newNimNode(nnkDotExpr)
    bracketExpr.add(varName)
    bracketExpr.add(newIntLitNode(varValue.len()))
    dotExpr.add(newLit(0))
    dotExpr.add(castIdent)
    asnNode.add bracketExpr
    asnNode.add dotExpr
    smt.add asnNode

proc makeBracketExpression(s: string, wide: static bool): NimNode =
    result = newNimNode(nnkBracketExpr)
    result.add ident"array"
    result.add newIntLitNode(s.len() + 1)
    if wide:    result.add ident"uint16"
    else:       result.add ident"byte"

## Public
##------------------------------------------------------------------------
const 
    BACKSLASH*  = '\\'
    MAX_SIZE*   = 256

## Stack Strings
##------------------------------------
macro stackStringA*(sect) =
  result = newStmtList()
  let
    def = sect[0]
    bracketExpr = makeBracketExpression(def[2].strVal, false)
    identDef = newIdentDefs(def[0], bracketExpr)
    varSect = newNimNode(nnkVarSection).add(identDef)
  result.add(varSect)
  result.assignChars(def[0], def[2].strVal, false)

macro stackStringW*(sect) =
  result = newStmtList()
  let
    def = sect[0]
    bracketExpr = makeBracketExpression(def[2].strVal, true)
    identDef = newIdentDefs(def[0], bracketExpr)
    varSect = newNimNode(nnkVarSection).add(identDef)
  result.add(varSect)
  result.assignChars(def[0], def[2].strVal, true)

## Utility Templates
##------------------------------------
template TEXTW*(c: char): WCHAR =
    cast[WCHAR](c)

template LOWER_CASE*(w: WCHAR): WCHAR =
    if w - TEXTW('A') <= TEXTW('a') - TEXTW('A') - 1:
        w + 0x20'u16
    else:
        w

template LOWER_CASE*(c: char): char =
    if ord(c) - ord('A') <= ord('a') - ord('A') - 1:
        cast[char](ord(c) + 0x20)
    else:
        c

## String Utility 
##------------------------------------
func len*(w: PCWSTR|PWSTR): SIZE_T =
    var ws = cast[ptr UncheckedArray[WCHAR]](w)
    result = 0
    while ws[result] != 0'u16:
        inc result

func `===`*(a: cstring, b: PCWSTR): bool =
    let b = cast[ptr UncheckedArray[uint16]](b)
    if a.isNil or b.isNil:
        false
    else:
        var i = 0
        while TEXTW(a[i]) == b[i]:
            if a[i] == '\0':
                return true
            inc i
        false

func `===`*(a, b: cstring): bool =
    if pointer(a) == pointer(b):
        true
    elif a.isNil or b.isNil:
        false
    else:
        var i = 0
        while a[i] == b[i]:
            if a[i] == '\0':
                return true
            inc i
        false

func `===`*(a, b: PWSTR): bool =
    let
        a = cast[ptr UncheckedArray[uint16]](a)
        b = cast[ptr UncheckedArray[uint16]](b)
    if a.isNil or b.isNil:
        false
    else:
        var i = 0
        while LOWER_CASE(a[i]) == LOWER_CASE(b[i]):
            if a[i] == 0:
                return true
            inc i
        false

func add*(a: var cstring, b: cstring, max: SIZE_T): bool {.discardable.} =
    let 
        curlen = a.len()
        newLen = curLen + b.len()
    if newLen >= max:
        return false
    for i in 0 ..< b.len():
        a[curlen + i] = b[i]
    a[newlen] = '\0'
    true

func toLower*(a: var cstring) =
    for i in 0 ..< a.len():
        a[i] = LOWER_CASE(a[i])

## Unicode Strings
##------------------------------------
template RTL_INIT_EMPTY_UNICODE_STRING*(u: var UNICODE_STRING, buffer: PWCHAR, bufferSz: USHORT) =
    u.Length        = bufferSz
    u.MaximumLength = bufferSz + sizeOf(WCHAR).USHORT
    u.Buffer        = buffer

func cmpUnicodeStrings*(us1: PWSTR, len1: SIZE_T, us2: PWSTR, len2: SIZE_T, ci: bool): LONG =
    if len1 > MAX_PATH or len2 > MAX_PATH:
        return STATUS_INVALID_BUFFER_SIZE
    var
        s1 = us1
        s2 = us2
        n1 = LONG(len1)
        n2 = LONG(len2)
        c1 = LONG(0)
        c2 = LONG(0)
    let l =
        if n1 <= n2:
            s1 +! n1
        else:
            s1 +! n2
    if ci:
        while s1 < l:
            c1 = LONG(s1[])
            c2 = LONG(s2[])
            if c1 != c2:
                c1 = LONG(LOWER_CASE(cast[char](c1)))
                c2 = LONG(LOWER_CASE(cast[char](c2)))
                if c1 != c2:
                    return LONG(c1 - c2)
            inc s1
            inc s2
    else:
        while s1 < l:
            c1 = LONG(s1[])
            c2 = LONG(s2[])
            if c1 != c2:
                return LONG(c1 - c2)
            inc s1
            inc s2

func cmpUnicodeStrings*(us1: UNICODE_STRING, us2: UNICODE_STRING, ci: bool): LONG {.inline.} =
    cmpUnicodeStrings(us1.Buffer, us1.Length.SIZE_T, us2.Buffer, us2.Length.SIZE_T, ci)

func add*(us: var UNICODE_STRING, cs: cstring): bool {.discardable.} =
    let 
        curLen  = us.Length.int
        newLen  = curLen + (cs.len() * sizeOf(WCHAR))
    if newLen >= us.MaximumLength.int:
        return false
    var ws = cast[ptr UncheckedArray[WCHAR]](us.Buffer +! curLen)
    for i in 0 ..< cs.len():
        ws[i] = TEXTW(cs[i])
    ws[newLen] = 0
    us.Length = newlen.USHORT
    true

func add*(us: var UNICODE_STRING, ws: PWSTR): bool {.discardable.} =
    let 
        curLen  = us.Length.int
        newLen  = curLen + (ws.len() * sizeOf(WCHAR))
    if newLen >= us.MaximumLength.int:
        return false
    var 
        buffer  = cast[ptr UncheckedArray[WCHAR]](us.Buffer +! curLen)
        wBuffer = cast[ptr UncheckedArray[WCHAR]](ws)
        index   = 0 
    while wBuffer[index] != 0:
        buffer[index] = wBuffer[index]
        inc index
    buffer[newLen] = 0
    us.Length = newLen.USHORT
    true

func add*(us: var UNICODE_STRING, u: UNICODE_STRING): bool {.discardable.} =
    let 
        curLen  = us.Length.int
        newLen  = curLen + u.Length.int
    if newLen >= us.MaximumLength.int:
        return false
    var
        buffer  = cast[ptr UncheckedArray[WCHAR]](us.Buffer +! curLen)
        wBuffer = cast[ptr UncheckedArray[WCHAR]](u.Buffer)
        index   = 0
    while index * sizeOf(WCHAR) != u.Length.int:
        buffer[index] = wBuffer[index]
        inc index
    buffer[newLen] = 0
    us.Length = newLen.USHORT
    true

func copyToBuffer*(us: var UNICODE_STRING, ws: PWSTR, wsLen: USHORT) =
    let 
        w   = cast[ptr UncheckedArray[uint8]](us.Buffer)
        ww  = cast[ptr UncheckedArray[uint8]](ws)
    if wsLen >= us.MaximumLength:
        return
    for i in 0 ..< us.Length.int:
        if i < wsLen.int:
            w[i] = ww[i]
        else:
            w[i] = 0
    us.Length = wsLen
    
## Extensions / Prefixes
##------------------------------------
func addDrivePrefixU*(us: var UNICODE_STRING) =
    var drivePrefix {.stackStringW.} = "\\??\\"
    let prefix = cast[PWSTR](addr drivePrefix[0])
    us.add prefix

func addSystem32DirectoryU*(us: var UNICODE_STRING) =
    var system32 {.stackStringW.} = "\\System32\\"
    let 
        cwindows    = cast[PWSTR](addr ntKUserSharedData().NtSystemRoot[0])
        sys32       = cast[PWSTR](addr system32[0])
    us.add cwindows
    us.add sys32

func addDLLExtensionA*(f: var cstring, max: SIZE_T = MAX_PATH) =
    var dllExt {.stackStringA.} = ".dll"
    let dllExtA = cast[cstring](addr dllExt[0])
    add(f, dllExtA, max)

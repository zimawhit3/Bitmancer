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
    obfuscation/hash,
    pe, str, utils

export
    pe

type
    SomeLdrIdent* = cstring|DWORD|PWSTR|ModuleHandle

    LdrList* {.pure.} = enum
        InitializationOrder, LoadOrder, MemoryOrder

    LdrIndex* {.pure.} = enum
        BaseAddress, MappingInfo

## Compile Time Options
##------------------------------------------------------------------------
type
    LoaderEnumerationMethod* {.pure.} = enum
        ## Use the Loader's lists to enumerate process memory for DLLs.
        UseLoaderLists,

        ## Use the Loader's indexes to enumerate process memory for DLLs.
        UseLoaderIndexes

## Compile Time Settings
##------------------------------------------------------------------------
const
    ## Module Enumeration Method
    ##  The method to use when enumerating the PEB's Loader structure to locate
    ##  a DLL in memory.
    ##---------------------------------------------------------------------
    LoaderEnum* {.intdefine.} = LoaderEnumerationMethod.UseLoaderIndexes

    ## Avoid Loader list hooks for NTDLL
    ##  EDRs/AVs will commonly hook the Loader's lists to prevent enumerating loaded DLLs.
    ##  Attempt to bypass these lists by walking them forwards and backwards.
    ##---------------------------------------------------------------------
    EnumerateLoaderListEx* {.booldefine.} = true

## Default Loader Index
##---------------------------------------------------------------------
when LoaderEnum == LoaderEnumerationMethod.UseLoaderIndexes:
    const DefaultLoaderIndex* {.intDefine.} = BaseAddress

## Common Module Hashes
##------------------------------------------------------------------------
const
    AdvapiHash*     = ctDjb2 "advapi32.dll"
    Kernel32Hash*   = ctDjb2 "KERNEL32.DLL"
    MsvcrtHash*     = ctDjb2 "msvcrt.dll"
    NtdllHash*      = ctDjb2 "ntdll.dll"

## Red Black Nodes
##------------------------------------------------------------------------
template CHILD_ENTRY_LEFT*(index: PRTL_BALANCED_NODE): PRTL_BALANCED_NODE =
    index.Children.ChildEntry.Left

template CHILD_ENTRY_RIGHT*(index: PRTL_BALANCED_NODE): PRTL_BALANCED_NODE =
    index.Children.ChildEntry.Right

template ENTRY_NEXT_NODE_LEFT*(index: PRTL_BALANCED_NODE, offset: int): PLDR_DATA_TABLE_ENTRY =
    cast[PLDR_DATA_TABLE_ENTRY](cast[int](CHILD_ENTRY_LEFT index) -% offset)

template ENTRY_NEXT_NODE_RIGHT*(index: PRTL_BALANCED_NODE, offset: int): PLDR_DATA_TABLE_ENTRY =
    cast[PLDR_DATA_TABLE_ENTRY](cast[int](CHILD_ENTRY_RIGHT index) -% offset)

template NODE_PARENT_NODE*(node: PRTL_BALANCED_NODE): PRTL_BALANCED_NODE =
    cast[PRTL_BALANCED_NODE](node.Union2.ParentValue and (not 3))

template NODE_LDR_ENTRY*(node: PRTL_BALANCED_NODE, index: LdrIndex): PLDR_DATA_TABLE_ENTRY =
    if index == LdrIndex.BaseAddress:
        CONTAINING_RECORD(node, LDR_DATA_TABLE_ENTRY, BaseAddressIndexNode)
    else:
        CONTAINING_RECORD(node, LDR_DATA_TABLE_ENTRY, MappingInfoIndexNode)
    
func getFirstNode*(node: PRTL_BALANCED_NODE): NtResult[PRTL_BALANCED_NODE] =
    var currentNode = node
    while not NODE_PARENT_NODE(currentNode).isNil():
        currentNode = NODE_PARENT_NODE(currentNode)

    ## Root node always black
    if currentNode.Union2.Red == 0:
        ok currentNode
    else:
        err RedBlackTreeError
 
## List Entry
##------------------------------------
template LDR_LIST_ORDER*(pPeb: PPEB, list: LdrList): PLIST_ENTRY =
    if list == InitializationOrder: addr pPeb.Ldr.InInitializationOrderModuleList
    elif list == LoadOrder:         addr pPeb.Ldr.InLoadOrderModuleList
    else:                           addr pPeb.Ldr.InMemoryOrderModuleList

template LDR_LINK_ORDER*(pEntry: PLIST_ENTRY, list: LdrList): PLDR_DATA_TABLE_ENTRY =
    if list == InitializationOrder:
        CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks)
    elif list == LoadOrder:
        CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks)
    else:
        CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)

template LDR_INDEX_ORDER*(pEntry: PLDR_DATA_TABLE_ENTRY, index: LdrIndex): PRTL_BALANCED_NODE =
    if index == BaseAddress:  addr pEntry.BaseAddressIndexNode
    else:                     addr pEntry.MappingInfoIndexNode

template INIT_LIST_ENTRY*(entry: PLIST_ENTRY) =
    entry.Flink = entry
    entry.Blink = entry.Flink

func insertTailList*(listHead: PLIST_ENTRY, entry: PLIST_ENTRY) {.inline.} =
    var blink:  PLIST_ENTRY
    blink = listHead.Blink
    entry.Flink = listHead
    entry.Blink = blink
    blink.Flink = entry
    listHead.Blink = entry

func removeListEntry*(entry: PLIST_ENTRY) {.inline.} =
    if not entry.isNil():
        var 
            oldBlink:  PLIST_ENTRY
            oldFlink:  PLIST_ENTRY
        oldFlink = entry.Flink
        oldBlink = entry.Blink
        oldFlink.Blink = oldBlink
        oldBlink.Flink = oldFlink
        entry.Flink = NULL
        entry.Blink = NULL

## Loader Data Entries
##------------------------------------------------------------------------

## Loader Lists
##------------------------------------
template GET_LDR_LIST*(ident: SomeLdrIdent, list: LdrList): NtResult[PLDR_DATA_TABLE_ENTRY] =
    when ident is cstring:      getLdrEntryListA(ident, list)
    elif ident is DWORD:        getLdrEntryListH(ident, list)
    elif ident is ModuleHandle: getLdrEntryListM(ident, list)
    elif ident is PWSTR:        getLdrEntryListW(ident, list)

template GET_LDR_LIST_EX*(ident: SomeLdrIdent, list: LdrList): NtResult[PLDR_DATA_TABLE_ENTRY] =
    when ident is cstring:      getLdrEntryListExA(ident, list)
    elif ident is DWORD:        getLdrEntryListExH(ident, list)
    elif ident is ModuleHandle: getLdrEntryListExM(ident, list)
    elif ident is PWSTR:        getLdrEntryListExW(ident, list)

iterator listForwardEntries*(list: LdrList): PLDR_DATA_TABLE_ENTRY =
    var
        pHead   = PLIST_ENTRY(NULL)
        pEntry  = PLIST_ENTRY(NULL)
        pCurr   = PLDR_DATA_TABLE_ENTRY(NULL)
    let pPeb    = NtCurrentPeb()

    pHead   = LDR_LIST_ORDER(pPeb, list)
    pEntry  = pHead.Flink

    while pHead != pEntry:
        pCurr   = LDR_LINK_ORDER(pEntry, list)
        pEntry  = pEntry.Flink
        yield pCurr

iterator listBackwardEntries*(list: LdrList): PLDR_DATA_TABLE_ENTRY =
    var
        pHead   = PLIST_ENTRY(NULL)
        pEntry  = PLIST_ENTRY(NULL)
        pCurr   = PLDR_DATA_TABLE_ENTRY(NULL)
    let pPeb    = NtCurrentPeb()

    pHead   = LDR_LIST_ORDER(pPeb, list)
    pEntry  = pHead.Blink

    while pHead != pEntry:
        pCurr   = LDR_LINK_ORDER(pEntry, list)
        pEntry  = pEntry.Blink
        yield pCurr

func getLdrEntryListA*(baseName: cstring, list: LdrList): NtResult[PLDR_DATA_TABLE_ENTRY] =
    if not baseName.isNil():
        for entry in listForwardEntries list:
            if baseName === entry.BaseDllName.Buffer:
                return ok entry
    err LdrEntryNotFound

func getLdrEntryListExA*(baseName: cstring, list: LdrList): NtResult[PLDR_DATA_TABLE_ENTRY] =
    if not baseName.isNil():
        for entry in listForwardEntries list:
            if baseName === entry.BaseDllName.Buffer:
                return ok entry
        for entry in listBackwardEntries list:
            if baseName === entry.BaseDllName.Buffer:
                return ok entry
    err LdrEntryNotFound

func getLdrEntryListH*(baseNameHash: DWORD, list: LdrList): NtResult[PLDR_DATA_TABLE_ENTRY] =
    if baseNameHash != 0:
        for entry in listForwardEntries list:
            if baseNameHash == HASH_W entry.BaseDllName:
                return ok entry
    err LdrEntryNotFound

func getLdrEntryListExH*(baseNameHash: DWORD, list: LdrList): NtResult[PLDR_DATA_TABLE_ENTRY] =
    if baseNameHash != 0:
        for entry in listForwardEntries list:
            if baseNameHash == HASH_W entry.BaseDllName:
                return ok entry
        for entry in listBackwardEntries list:
            if baseNameHash == HASH_W entry.BaseDllName:
                return ok entry
    err LdrEntryNotFound

func getLdrEntryListM*(baseImage: ModuleHandle, list: LdrList): NtResult[PLDR_DATA_TABLE_ENTRY] =
    if not baseImage.isNil():
        for entry in listForwardEntries list:
            if baseImage == entry.DLLBase.ModuleHandle:
                return ok entry
    err LdrEntryNotFound

func getLdrEntryListExM*(baseImage: ModuleHandle, list: LdrList): NtResult[PLDR_DATA_TABLE_ENTRY] =
    if not baseImage.isNil():
        for entry in listForwardEntries list:
            if baseImage == entry.DLLBase.ModuleHandle:
                return ok entry
        for entry in listBackwardEntries list:
            if baseImage == entry.DLLBase.ModuleHandle:
                return ok entry
    err LdrEntryNotFound

func getLdrEntryListW*(baseNameWideStr: PWSTR, list: LdrList): NtResult[PLDR_DATA_TABLE_ENTRY] =
    if not baseNameWideStr.isNil():
        for entry in listForwardEntries list:   
            if baseNameWideStr === entry.BaseDllName.Buffer:
                return ok entry
    err LdrEntryNotFound

func getLdrEntryListExW*(baseNameWideStr: PWSTR, list: LdrList): NtResult[PLDR_DATA_TABLE_ENTRY] =
    if not baseNameWideStr.isNil():
        for entry in listForwardEntries list:
            if baseNameWideStr === entry.BaseDllName.Buffer:
                return ok entry
        for entry in listBackwardEntries list:
            if baseNameWideStr === entry.BaseDllName.Buffer:
                return ok entry
    err LdrEntryNotFound

## Loader Indexes
##------------------------------------

## Private Stack
##------------------
type
    ## Internal Stack object for iterating through indexes
    IndexStack = object
        data: array[256, PRTL_BALANCED_NODE]
    
func isEmpty(s: IndexStack): bool {.inline.} =
    for i in low(s.data) .. high(s.data):
        if s.data[i] != NULL:
            return false
    true

func pop(s: var IndexStack): PRTL_BALANCED_NODE {.inline.} =
    if not s.isEmpty():
        var i = 0
        while s.data[i] != NULL:
            inc i
        let res = s.data[i-1]
        s.data[i-1] = NULL
        res
    else:
        NULL

func push(s: var IndexStack, n: PRTL_BALANCED_NODE) {.inline.} =
    var i = 0
    while s.data[i] != NULL:
        inc i
    s.data[i] = n

## Public 
##------------------
template GET_LDR_INDEX*(ident: SomeLdrIdent, list: LdrList, index: LdrIndex): NtResult[PLDR_DATA_TABLE_ENTRY] =
    when ident is cstring:      getLdrEntryIndexA(ident, list, index)
    elif ident is DWORD:        getLdrEntryIndexH(ident, list, index)
    elif ident is ModuleHandle: getLdrEntryIndexM(ident, list, index)
    elif ident is PWSTR:        getLdrEntryIndexW(ident, list, index)

iterator indexEntries*(list: LdrList, index: LdrIndex): PLDR_DATA_TABLE_ENTRY =
    ## We grab the first node in the list, and walk the parent nodes up to Kernel32(the root node), 
    ## from there we start yielding every node. Unfortunately, we don't have access to the GC, so
    ## we can't use Nim's recursive iterators, nor can we dynamically allocate memory to implement
    ## our own, as we don't know where NTDLL is yet. Instead, we use an iterative, stack-based approach. 
    ## We hold up to 256 paths, which *should* be enough for even larger processes like Explorer.exe, 
    ## which had ~300 loaded DLLs on my VM.
    var
        pHead   = PLIST_ENTRY(NULL)
        pNode   = PRTL_BALANCED_NODE(NULL)
        pRoot   = PRTL_BALANCED_NODE(NULL)
        pCurr   = PLDR_DATA_TABLE_ENTRY(NULL) 
        stack   = IndexStack()

    pHead = LDR_LIST_ORDER(NtCurrentPeb(), list)
    pCurr = LDR_LINK_ORDER(pHead.Flink, list)
    pNode = LDR_INDEX_ORDER(pCurr, index)
    
    if (let node = getFirstNode(pNode); node.isOk()):
        pRoot = node.get()
        stack.push(pRoot)
        while not stack.isEmpty():
            pNode = stack.pop()
            yield NODE_LDR_ENTRY(pNode, index)
            if not CHILD_ENTRY_LEFT(pNode).isNil():
                stack.push CHILD_ENTRY_LEFT(pNode)
            if not CHILD_ENTRY_RIGHT(pNode).isNil():
                stack.push CHILD_ENTRY_RIGHT(pNode)

func getLdrEntryIndexA*(baseName: cstring, list: LdrList, index: LdrIndex): NtResult[PLDR_DATA_TABLE_ENTRY] =
    if not baseName.isNil():
        for entry in indexEntries(list, index):
            if baseName === entry.BaseDllName.Buffer:
                return ok entry
    err LdrEntryNotFound

func getLdrEntryIndexH*(baseNameHash: DWORD, list: LdrList, index: LdrIndex): NtResult[PLDR_DATA_TABLE_ENTRY] =
    if baseNameHash != 0:
        for entry in indexEntries(list, index):
            if baseNameHash == HASH_W entry.BaseDllName:
                return ok entry
    err LdrEntryNotFound

func getLdrEntryIndexM*(baseImage: ModuleHandle, list: LdrList, index: LdrIndex): NtResult[PLDR_DATA_TABLE_ENTRY] =
    if not baseImage.isNil():
        for entry in indexEntries(list, index):
            if baseImage == entry.DLLBase.ModuleHandle:
                return ok entry
    err LdrEntryNotFound

func getLdrEntryIndexW*(baseNameWideStr: PWSTR, list: LdrList, index: LdrIndex): NtResult[PLDR_DATA_TABLE_ENTRY] =
    if not baseNameWideStr.isNil():
        for entry in indexEntries(list, index):
            if baseNameWideStr === entry.BaseDllName.Buffer:
                return ok entry
    err LdrEntryNotFound

## Modules
##------------------------------------------------------------------------
template MODULE_LOADED*(ident: SomeLdrIdent, list: LdrList): bool =
    when LoaderEnum == LoaderEnumerationMethod.UseLoaderLists:
        GET_LDR_LIST(ident, list).isOk()
    elif LoaderEnum == LoaderEnumerationMethod.UseLoaderIndexes:
        GET_LDR_INDEX(ident, list, DefaultLoaderIndex).isOk()

func getLdrEntry*(ident: SomeLdrIdent, list: LdrList): NtResult[PLDR_DATA_TABLE_ENTRY] =
    when LoaderEnum == LoaderEnumerationMethod.UseLoaderLists:
        when EnumerateLoaderListEx: GET_LDR_LIST_EX(ident, list)
        else:                       GET_LDR_LIST(ident, list)

    elif LoaderEnum == LoaderEnumerationMethod.UseLoaderIndexes:
        GET_LDR_INDEX(ident, list, DefaultLoaderIndex) 

func getModuleHandle*(ident: SomeLdrIdent, list: LdrList): NtResult[ModuleHandle] =
    let entry = ? getLdrEntry(ident, list)
    ok entry.DLLBase.ModuleHandle

func removeLdrEntry*(ident: SomeLdrIdent, list: LdrList): NtResult[void] =
    let entry = ? getLdrEntry(ident, list)
    removeListEntry entry
    ok()

## Advapi32
##------------------
template ADVAPI_BASE*(list = LoadOrder): NtResult[ModuleHandle] =
    getModuleHandle(AdvapiHash, list)

## Kernel32
##------------------
template KERNEL32_BASE*(list = LoadOrder): NtResult[ModuleHandle] =
    getModuleHandle(Kernel32Hash, list)
    
## MSVCRT
##------------------
template CRT_BASE*(list = LoadOrder): NtResult[ModuleHandle] =
    getModuleHandle(MsvcrtHash, list)

## NTDLL
##------------------
template NTDLL_BASE*(list: static LdrList = MemoryOrder): NtResult[ModuleHandle] =
    getModuleHandle(NtdllHash, list)
    
func getNtdllModuleHandleEx*(list: LdrList): NtResult[ModuleHandle] {.inline.} =
    ## Retrieves NTDLL Base Address by looping through the PEB->Ldr Linked List and returning the module with the
    ## greatest BaseAddress, exploiting the fact that NTDLL will always be loaded at the highest address.
    var currentBase = PVOID(NULL)

    for entry in listForwardEntries list:
        if currentBase.isNil() or currentBase < entry.DLLBase:
            currentBase = entry.DLLBase
    
    for entry in listBackwardEntries list:
        if currentBase.isNil() or currentBase < entry.DLLBase:
            currentBase = entry.DLLBase
    
    if currentBase.isNil():
        err LdrEntryNotFound
    else:
        ok currentBase.ModuleHandle

## Red Black Trees
##------------------------------------------------------------------------
func getRedBlackTree*(tree: PVOID): NtResult[PRTL_RB_TREE] =
    let pRbTree = cast[PRTL_RB_TREE](tree)
    if pRbTree.isNil() or pRbTree.Root.isNil() or pRbTree.Min.isNil():
        err RedBlackTreeError
    else:
        ok pRbTree

proc getBaseAddressIndexTree*(): NtResult[PRTL_RB_TREE] =
    let 
        NtdllEntry      = ? getLdrEntry(NtdllHash, MemoryOrder)
        Ntdll           = NtdllEntry.DLLBase.ModuleHandle
        topNode         = ? getFirstNode(NtdllEntry.BaseAddressIndexNode)
        pDataSection    = ? getDataSection(Ntdll)
    var sectionStart    = SECTION_START(Ntdll, pDataSection)

    while sectionStart != SECTION_END(Ntdll, pDataSection) -! sizeof SIZE_T:
        if cast[ptr int](sectionStart)[] == cast[int](topNode):
            return getRedBlackTree sectionStart        
        inc sectionStart
    err RBTreeNotFound

proc getMappingInfoIndexTree*(): NtResult[PRTL_RB_TREE] =
    let 
        NtdllEntry      = ? getLdrEntry(NtdllHash, MemoryOrder)
        Ntdll           = NtdllEntry.DLLBase.ModuleHandle
        topNode         = ? getFirstNode(NtdllEntry.MappingInfoIndexNode)
        pDataSection    = ? getDataSection(Ntdll)
    var sectionStart    = SECTION_START(Ntdll, pDataSection)

    while sectionStart != SECTION_END(Ntdll, pDataSection) -! sizeof SIZE_T:
        if cast[ptr int](sectionStart)[] == cast[int](topNode):
            return getRedBlackTree sectionStart
        inc sectionStart
    err RBTreeNotFound


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
    ldrlocks

export
    ldrbase

## Loader Link
##------------------------------------------------------------------------
proc ldrHashUnicode(baseDLLName: PUNICODE_STRING): NtResult[ULONG] =
    let hash = ? eRtlHashUnicodeString(baseDLLName, TRUE, 0)
    if hash == 0:
        ## TODO Nt Loader returns 0x8000000 here
        return ok -1
    ok hash

template linked*(ctx: PLoadContext): bool =
    ctx.entry.isSet(InIndexes) and ctx.entry.isSet(InLegacyLists)

proc getLdrpHashTable*(): NtResult[PLIST_ENTRY] =
    for entry in listForwardEntries MemoryOrder:
        if entry.HashLinks.Flink.Flink == addr entry.HashLinks:
            let 
                hash    = ? ldrHashUnicode(addr entry.BaseDllName)
                index   = hash and 31
            return ok cast[PLIST_ENTRY](cast[int](entry.HashLinks.Flink) -% (index * sizeof LIST_ENTRY))
    err SearchNotFound

## Loader Indexes
##------------------------------------
proc ldrAddToIndexes(ctx: PLoadContext) {.inline.} =
    if RtlInsertNodeBaseAddressIndex(ctx.entry).isOk() and RtlInsertNodeMappingInfoIndex(ctx.entry).isOk():
        ctx.entry.setBit(InIndexes)
    
proc ldrRemoveFromIndexes(ctx: PLoadContext) {.inline.} =
    if RtlRemoveNodeMappingInfoIndex(ctx.entry).isOk() and RtlRemoveNodeBaseAddressIndex(ctx.entry).isOk():
        ctx.entry.clearBit(InIndexes)

## Loader Lists
##------------------------------------
proc ldrLinkToLists*(ctx: PLoadContext) =
    if (let LdrpHashTable = getLdrpHashTable(); LdrpHashTable.isOk()):
        let
            LdrpHashIndex   = ctx.entry.BaseNameHashValue and 0x1f
            PebLdrEntry     = NtCurrentPeb().Ldr
    
        INIT_LIST_ENTRY ctx.entry.HashLinks

        if LOCK_PEB_LOCK().isOk():
            insertTailList(LdrpHashTable.get() +! (LdrpHashIndex * sizeOf LIST_ENTRY), addr ctx.entry.HashLinks)
            insertTailList(PebLdrEntry.InLoadOrderModuleList, addr ctx.entry.InLoadOrderLinks)
            insertTailList(PebLdrEntry.InMemoryOrderModuleList, addr ctx.entry.InMemoryOrderLinks)
            insertTailList(PebLdrEntry.InInitializationOrderModuleList, addr ctx.entry.InInitializationOrderLinks)
            discard UNLOCK_PEB_LOCK()
            ctx.entry.setBit(InLegacyLists)
        
proc ldrUnlinkFromLists*(ctx: PLoadContext) =
    if LOCK_PEB_LOCK().isOk():
        removeListEntry(addr ctx.entry.HashLinks)
        removeListEntry(addr ctx.entry.InLoadOrderLinks)
        removeListEntry(addr ctx.entry.InMemoryOrderLinks)
        removeListEntry(addr ctx.entry.InInitializationOrderLinks)
        discard UNLOCK_PEB_LOCK()
        ctx.entry.clearBit(InLegacyLists)

## Loader Link Routines
##------------------------------------
proc ldrLinkModuleLockHeld*(ctx: PLoadContext): NtResult[void] =
    ## Link to Indexes
    if not isSet(ctx.entry, InIndexes):
        ldrAddToIndexes ctx
    
    ## Link to PEB
    if not isSet(ctx.entry, InLegacyLists):
        ldrLinkToLists ctx

    if ctx.linked():
        ok()
    else:
        err LdrLinkFailed

proc ldrUnlinkModuleLockHeld*(ctx: PLoadContext): NtResult[void] =
    ## Unlink from indexes
    if ctx.entry.isSet(InIndexes):
        ldrRemoveFromIndexes ctx
    
    ## Unlink from PEB
    if ctx.entry.isSet(InLegacyLists):
        ldrUnlinkFromLists ctx
        
    if not ctx.linked():
        ok()
    else:
        err LdrUnlinkFailed

proc ldrInitializeDdagNode(ctx: PLoadContext): NtResult[void] =
    ## Initialize the Distributed Direct Acyclic Graph node
    ctx.entry.DdagNode                          = cast[PLDR_DDAG_NODE](? PROCESS_HEAP_ALLOC(LDR_DDAG_NODE))
    ctx.entry.DdagNode.State                    = LdrModulesReadyToRun
    ctx.entry.DdagNode.LoadCount                = 1
    ctx.entry.DdagNode.PreorderNumber           = 0 ## TODO: needs to be calculated
    ctx.entry.DdagNode.LowestLink               = 0 ## TODO: needs to be calculated
    ctx.entry.DdagNode.LoadWhileUnloadingCount  = 0
    ctx.entry.DdagNode.Dependencies             = LDRP_CSLIST()
    ctx.entry.DdagNode.IncomingDependencies     = LDRP_CSLIST()
    ctx.entry.DdagNode.CondenseLink             = SINGLE_LIST_ENTRY()
    ctx.entry.DdagNode.ServiceTagList           = PLDR_SERVICE_TAG_RECORD(NULL)    
    ctx.entry.DdagNode.Modules = LIST_ENTRY(
        Flink: ctx.entry.NodeModuleLink,
        Blink: ctx.entry.NodeModuleLink
    )
    ctx.entry.NodeModuleLink = LIST_ENTRY(
        Flink: ctx.entry.DdagNode.Modules, 
        Blink: ctx.entry.DdagNode.Modules
    )
    ok()

proc ldrCompleteLdrEntry(ctx: PLoadContext): NtResult[void] =
    let NtHeaders = ? imageNtHeader ctx.entry.DLLBase.ModuleHandle
    ctx.entry.BaseNameHashValue = ? ldrHashUnicode(ctx.entry.BaseDllName)
    ctx.entry.EntryPoint        = ctx.entry.DLLBase +! NtHeaders.OptionalHeader.AddressOfEntryPoint
    ctx.entry.LoadReason        = LoadReasonDynamicLoad
    ctx.entry.LoadTime          = GetSystemTime()[]
    ctx.entry.ReferenceCount    = 1
    ctx.entry.TimeDateStamp     = NtHeaders.FileHeader.TimeDateStamp
    ctx.entry.ObsoleteLoadCount = 0xffff

    ctx.entry.setBit(ImageDll)
    ctx.entry.setBit(ProtectDelayLoad)
    #[
        TODO:
            if module had static imports, set ProcessStaticImport = TRUE
            if OS version >= Threashold 1,set DependentLoadFlags
    ]# 
    ldrInitializeDdagNode ctx
    
proc ldrLinkModule*(ctx: PLoadContext): NtResult[void] =
    if not ctx.linked():
        LDR_WITH_DATATABLE_LOCK: 
            ldrLinkModuleLockHeld ctx
    else:
        ok()

proc ldrUnlinkModule*(ctx: PLoadContext): NtResult[void] {.discardable.} =
    if ctx.linked():
        LDR_WITH_DATATABLE_LOCK: 
            ldrUnlinkModuleLockHeld ctx
    else:
        ok()

## Loader Execution Routines
##------------------------------------

## Protections
##------------------
proc ldrSetProtections(ctx: PLoadContext): NtResult[void] =
    genSyscall(NtProtectVirtualMemory)
    let 
        Ntdll       = ? NTDLL_BASE()
        NtHeaders   = ? imageNtHeader ctx.entry.DLLBase.ModuleHandle
        NtSyscall   = getNtProtectVirtualMemory(Ntdll, ModuleHandle(NULL))
    var
        isReadable      = false
        isWriteable     = false
        isExecutable    = false
        moduleSz        = SIZE_T(NtHeaders.OptionalHeader.SizeOfHeaders)
        oldProtections  = ULONG(PAGE_READONLY)
        newProtections  = ULONG(0)
        regionSize      = SIZE_T(0)
        SectionBase     = PVOID(NULL)
        ModuleBasePtr   = ctx.entry.DLLBase

    if not NT_SUCCESS NtProtectVirtualMemoryWrapper(
        RtlCurrentProcess(), 
        ModuleBasePtr, 
        moduleSz, 
        oldProtections, 
        addr oldProtections,
        NtSyscall.wSyscall, 
        NtSyscall.pSyscall, 
        NtSyscall.pFunction
    ): return err SyscallFailure

    for Section in NtHeaders.sections():
        if Section.SizeOfRawData != 0 and Section.VirtualAddress != 0:

            isExecutable    = Section.Characteristics && IMAGE_SCN_MEM_EXECUTE.DWORD
            isReadable      = Section.Characteristics && IMAGE_SCN_MEM_READ.DWORD
            isWriteable     = Section.Characteristics.int && 0x80000000.int

            if (not isExecutable) and (not isReadable) and (not isWriteable):
                newProtections = PAGE_NOACCESS
            elif (not isExecutable) and (not isReadable) and isWriteable:
                newProtections = PAGE_WRITECOPY
            elif (not isExecutable) and isReadable and (not isWriteable):
                newProtections = PAGE_READONLY
            elif (not isExecutable) and isReadable and isWriteable:
                newProtections = PAGE_READWRITE
            elif isExecutable and (not isReadable) and (not isWriteable):
                newProtections = PAGE_EXECUTE
            elif isExecutable and isReadable and (not isWriteable):
                newProtections = PAGE_EXECUTE_READ
            elif isExecutable and (not isReadable) and isWriteable:
                newProtections = PAGE_EXECUTE_WRITECOPY
            elif isExecutable and isReadable and isWriteable:
                newProtections = PAGE_EXECUTE_READWRITE

            if Section.Characteristics and IMAGE_SCN_MEM_NOT_CACHED:
                newProtections |= PAGE_NOCACHE
            
            SectionBase = ctx.entry.DLLBase +! Section.VirtualAddress
            regionSize  = Section.SizeOfRawData

            if not NT_SUCCESS NtProtectVirtualMemoryWrapper(
                RtlCurrentProcess(), 
                SectionBase, 
                regionSize, 
                newProtections, 
                addr oldProtections,
                NtSyscall.wSyscall, 
                NtSyscall.pSyscall, 
                NtSyscall.pFunction
            ): return err SyscallFailure
    
    ok()

proc ldrUnsetProtections*(ctx: PLoadContext): NtResult[void] =
    genSyscall(NtProtectVirtualMemory)
    var
        protections = DWORD(0)
        sectionSize = SIZE_T(0)
        sectionBase = PVOID(NULL)
        status      = NTSTATUS(0)
    let 
        Ntdll               = ? NTDLL_BASE()
        NtHeaders           = ? imageNtHeader ctx.entry.DLLBase.ModuleHandle
        NtProtectSyscall    = getNtProtectVirtualMemory(Ntdll, ModuleHandle(NULL))
    
    for Section in NtHeaders.sections():
        if Section.SizeOfRawData != 0 and Section.VirtualAddress != 0:
            sectionBase = ctx.entry.DLLBase +! Section.VirtualAddress
            sectionSize = Section.SizeOfRawData
            status = NtProtectVirtualMemoryWrapper(
                RtlCurrentProcess(), 
                sectionBase, 
                sectionSize, 
                PAGE_READWRITE, 
                addr protections,
                NtProtectSyscall.wSyscall, 
                NtProtectSyscall.pSyscall, 
                NtProtectSyscall.pFunction
            )
    ok()

## TLS
##------------------
proc ldrHandleTLS(ctx: PLoadContext): NtResult[void] =
    ##TODO
    ok()

proc ldrCallTLSCallbacks(ctx: PLoadContext) {.inline.} =
    if (let TlsDirectory = getTLSDirectory ctx.entry.DLLBase.ModuleHandle; TlsDirectory.isOk()):
        for callback in TlsDirectory.get().tlsCallbacks():
            {.gcsafe.}: 
                callback(ctx.entry.DLLBase, DLL_PROCESS_ATTACH, NULL)

proc ldrInitializeTLS(ctx: PLoadContext): NtResult[void] =
    ? ldrHandleTLS ctx
    ldrCallTLSCallbacks ctx
    ok()
    
proc ldrPrepareModuleForExecution(ctx: PLoadContext): NtResult[void] {.inline.} =
    ## Set Protections
    ? ldrSetProtections ctx
    
    ## Initialize TLS
    ldrInitializeTLS ctx
    
## Loader Link Routines
##------------------------------------
proc ldrCallModuleEntry*(ctx: PLoadContext): NtResult[void] =
    var isLocked    = false
    let NtHeaders   = ? imageNtHeader ctx.entry.DLLBase.ModuleHandle
    if NtHeaders.OptionalHeader.AddressOfEntryPoint == 0:
        return ok()

    let DllMain = cast[DllMain](ctx.entry.DLLBase +! NtHeaders.OptionalHeader.AddressOfEntryPoint)
    
    if ctx.flags && RUN_UNDER_LDR_LOCK:
        isLocked = LOCK_LOADER_LOCK().isOk()

    discard DllMain(cast[HMODULE](ctx.entry.DLLBase), DLL_PROCESS_ATTACH, NULL)

    if isLocked:
        discard UNLOCK_LOADER_LOCK()

    ctx.entry.setBit(EntryProcessed)
    ctx.entry.setBit(ProcessAttachCalled)
    ok()

proc ldrLinkAndPrepareForExecution*(ctx: PLoadContext): NtResult[void] {.inline.} =
    ## Complete loader entry values
    ? ldrCompleteLdrEntry ctx
    ## Link DLL to internal structures
    ? ldrLinkModule ctx    
    ## Prepare DLL for Execution
    ldrPrepareModuleForExecution ctx

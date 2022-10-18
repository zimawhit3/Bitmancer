

## Loader Snapping Routines
##------------------------------------------------------------------------
proc ldrLoadDependencyInternal(ctx: PLoadContext, flags: ULONG, dll: PWSTR): NtResult[ModuleHandle] =
    let ForwardCtx = ? eLoadLibrary(flags, dll, NULL, 0)
    insertTailList(ctx.dependencies, ForwardCtx.dependencies)
    ##TODO: set ParentDLLBase
    ok ForwardCtx.entry.DLLBase.ModuleHandle

proc ldrLoadDependency(ctx: PLoadContext, f: cstring): NtResult[ModuleHandle] =
    var 
        forwarderFlags  = DWORD(0)
        importedDLL     = ? ldrPrepareForwardString()
    SET_LOAD_LOCAL forwarderFlags
    
    if isApiSetLib(f):
        ## We check if the resolved api set module is already loaded. If it is,
        ## return it's modulehandle. otherwise, we load it
        let 
            resolvedLib     = ? ldrResolveApiSet(f)        
            resolvedEntry   = GET_LDR_LIST(resolvedLib.Buffer, LoadOrder)
        if resolvedEntry.isOk():
            PROCESS_HEAP_FREE(cast[PVOID](resolvedLib.Buffer))
            PROCESS_HEAP_FREE(cast[PVOID](importedDLL.Buffer))
            return ok resolvedEntry.get().DLLBase.ModuleHandle
        else:
            importedDLL.add resolvedLib
        
        discard PROCESS_HEAP_FREE(cast[PVOID](resolvedLib.Buffer))
    
    else:
        importedDLL.add f
    
    ldrLoadDependencyInternal(ctx, forwarderFlags, importedDLL.Buffer)

proc ldrResolveImport(ctx: PLoadContext, Import: PIMAGE_IMPORT_DESCRIPTOR): NtResult[void] =
    var
        ImportedFunction    = PVOID(NULL)
        ImportByName        = PIMAGE_IMPORT_BY_NAME(NULL)
    let 
        imageBase           = ctx.entry.DLLBase.ModuleHandle
        ImportName          = cast[cstring](imageBase +% Import.Name)
        ImportBase          = 
            if MODULE_LOADED(ImportName, MemoryOrder):
                ? getModuleHandle(ImportName, MemoryOrder)
            else:
                ? ldrLoadDependency(ctx, ImportName)
    
    for (OriginalThunk, FirstThunk) in imageBase.thunks(Import):
        ImportedFunction =
            if IMAGE_SNAP_BY_ORDINAL OriginalThunk.u1.Ordinal:
                ? getProcAddress(ImportBase, cast[WORD](OriginalThunk.u1.Ordinal))
            else:
                ImportByName = cast[PIMAGE_IMPORT_BY_NAME](imageBase +% OriginalThunk.u1.AddressOfData)
                ? getProcAddress(ImportBase, cast[cstring](addr ImportByName.Name[0]))
        FirstThunk.u1.Function = cast[ULONGLONG](ImportedFunction)
    ok()

proc ldrResolveDelayedImport(ctx: PLoadContext, DelayedImport: PIMAGE_DELAYLOAD_DESCRIPTOR): NtResult[void] =
    var
        ImportedFunction    = PVOID(NULL)
        ImportByName        = PIMAGE_IMPORT_BY_NAME(NULL)
    let 
        imageBase           = ctx.entry.DLLBase.ModuleHandle
        ImportName          = cast[cstring](imageBase +% DelayedImport.DllNameRVA)
        ImportBase          = 
            if MODULE_LOADED(ImportName, MemoryOrder):
                ? getModuleHandle(ImportName, MemoryOrder)
            else:
                ? ldrLoadDependency(ctx, ImportName)
    
    for (OriginalThunk, FirstThunk) in imageBase.thunks(DelayedImport):
        ImportedFunction =
            if IMAGE_SNAP_BY_ORDINAL OriginalThunk.u1.Ordinal:
                ? getProcAddress(ImportBase, cast[WORD](OriginalThunk.u1.Ordinal))
            else:
                ImportByName = cast[PIMAGE_IMPORT_BY_NAME](imageBase +% OriginalThunk.u1.AddressOfData)
                ? getProcAddress(ImportBase, cast[cstring](addr ImportByName.Name[0]))
        FirstThunk.u1.Function = cast[ULONGLONG](ImportedFunction)
    ok()

proc ldrResolveImports*(ctx: PLoadContext): NtResult[void] =

    let imageBase = ctx.entry.DLLBase.ModuleHandle
    
    ## Imports
    let importDirHeader = getImportDirectoryHeader(imageBase)
    if importDirHeader.isErr():
        if importDirHeader.error() notin {DirectoryEmpty, DirectoryNotFound}:
            return err importDirHeader.error()
    else:
        ## Change protections of IAT to RW, these will be protected later in LdrSetProtections
        let 
            Imports             = IMPORT_DIRECTORY(imageBase, importDirHeader.get())
            RelocationSection   = ? getRelocationSection(imageBase)
        var
            iatBase = imageBase +% RelocationSection.VirtualAddress
            iatSize = SIZE_T(RelocationSection.Misc.VirtualSize)
            oldProt = ULONG(PAGE_READWRITE)

        if eNtProtectVirtualMemory(
            iatBase,
            iatSize,
            oldProt,
            addr oldProt
        ).isErr():
            return err SyscallFailure
        
        for Import in Imports.imports():
            ? ldrResolveImport(ctx, Import)

    ## Delayed Imports
    let DelayedImportDirectoryHeader = getDelayedImportDirectoryHeader(imageBase)
    if DelayedImportDirectoryHeader.isErr():
        if DelayedImportDirectoryHeader.error() notin {DirectoryEmpty, DirectoryNotFound}:
            return err DelayedImportDirectoryHeader.error()
    else:
        let DelayedImportDirectory = DELAY_IMPORT_DIRECTORY(imageBase, DelayedImportDirectoryHeader.get())        
        for DelayedImport in DelayedImportDirectory.dImports():
            ? ldrResolveDelayedImport(ctx, DelayedImport)
    ok()

## Loader Map it and Snap it (like it's hot)
##------------------------------------------------------------------------
proc ldrSnapModule*(ctx: PLoadContext): NtResult[void] {.inline.} =
    ## Snaps the DLL's imports
    ldrResolveImports ctx

proc ldrMapAndSnap*(ctx: PLoadContext): NtResult[void] {.inline.} =
    ## Map the DLL into memory
    ? ldrMapModule ctx
    ## Snaps the DLL's imports
    ? ldrSnapModule ctx
    ## Flush the cpu
    eNtFlushInstructionCache(RtlCurrentProcess(), NULL, 0)




import
    mappings/[memory, native, remote],
    ldrcfg, ldrexceptions

export
    ldrbase

## Loader Map
##------------------------------------------------------------------------

## Helper Templates
##------------------------------------
template LDR_MAP_MODULE*(ctx: PLoadContext): NtResult[void] =
    if LOBYTE(ctx.flags) == ord LoadLocal:      ldrMapNativeModule ctx
    elif LOBYTE(ctx.flags) == ord LoadMemory:   ldrMapMemoryModule ctx
    elif LOBYTE(ctx.flags) == ord LoadRemote:   ldrMapRemoteModule ctx
    else:                                       err(InvalidFlags)

template LDR_UNMAP_MODULE*(ctx: PLoadContext): NtResult[void] =
    if LOBYTE(ctx.flags) == ord LoadLocal:      ldrUnmapNativeModule ctx
    elif LOBYTE(ctx.flags) == ord LoadMemory:   ldrUnmapMemoryModule ctx
    elif LOBYTE(ctx.flags) == ord LoadRemote:   ldrUnmapRemoteModule ctx
    else:                                       err(InvalidFlags)

## Loader Post-Mapping Private Routines
##------------------------------------
proc ldrCompleteMappedModule(ctx: PLoadContext): NtResult[void] =
    ## Complete Mapped DLL's relocations
    let 
        imageBase   = ctx.entry.DLLBase.ModuleHandle
        NtHeaders   = ? imageNtHeader imageBase
        baseOffset  = cast[ULONG_PTR](ctx.entry.DLLBase -! NtHeaders.OptionalHeader.ImageBase)

    ## Update DLL's entries with the new base address
    if baseOffset != 0 and NtHeaders.OptionalHeader.DLLCharacteristics && IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE:
        let relocations = ? getRelocationDirectory(imageBase)
        for reloc in relocations.relocs():
            for fixup in reloc.fixups():
                if fixup.Type == IMAGE_REL_BASED_DIR64:
                    cast[PULONG_PTR](ctx.entry.DLLBase +! reloc.VirtualAddress +! DWORD(fixup.Offset))[] += baseOffset
                elif fixup.Type == IMAGE_REL_BASED_HIGHLOW:
                    cast[PULONG_PTR](ctx.entry.DLLBase +! reloc.VirtualAddress +! DWORD(fixup.Offset))[] += ULONG_PTR(baseOffset)
                elif fixup.Type == IMAGE_REL_BASED_HIGH:
                    cast[PULONG_PTR](ctx.entry.DLLBase +! reloc.VirtualAddress +! DWORD(fixup.Offset))[] += ULONG_PTR(HIWORD(baseOffset))
                elif fixup.Type == IMAGE_REL_BASED_LOW:
                    cast[PULONG_PTR](ctx.entry.DLLBase +! reloc.VirtualAddress +! DWORD(fixup.Offset))[] += ULONG_PTR(LOWORD(baseOffset))

        ## Update NtHeaders
        NtHeaders.OptionalHeader.ImageBase = cast[ULONGLONG](ctx.entry.DLLBase)
    ok()

proc ldrProcessMappedModule(ctx: PLoadContext): NtResult[void] =
    let 
        imageBase   = ctx.entry.DLLBase.ModuleHandle
        NtHeaders   = ? imageNtHeader imageBase
        EntryPoint  = NtHeaders.OptionalHeader.AddressOfEntryPoint

    ## Validate Entrypoint
    if NtHeaders.OptionalHeader.SizeOfHeaders > EntryPoint:
        return err ImageInvalid

    ctx.entry.OriginalBase = NtHeaders.OptionalHeader.ImageBase

    ? ldrCfgProcessLoadConfig ctx
    ldrProcessExceptions ctx

## Loader Map Module
##------------------------------------
proc ldrMapModule*(ctx: PLoadContext): NtResult[void] {.inline.} =
    ## Map the DLL into memory
    ? LDR_MAP_MODULE ctx
    ## Complete the mapped DLL
    ? ldrCompleteMappedModule ctx
    ## Process the mapped DLL
    ldrProcessMappedModule ctx

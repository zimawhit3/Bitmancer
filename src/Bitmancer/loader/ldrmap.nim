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
    mappings/[memory, native, remote],
    ldrcfg, ldrexceptions

export
    ldrbase

## Loader Map
##------------------------------------------------------------------------

## Helper Templates
##------------------------------------
template LDR_MAP_MODULE*(ctx: PLoadContext): NtResult[void] =
    case LOBYTE(ctx.flags)
    of ord LoadLocal:   ldrMapNativeModule ctx
    of ord LoadMemory:  ldrMapMemoryModule ctx
    of ord LoadRemote:  ldrMapRemoteModule ctx
    else:               err InvalidFlags

template LDR_UNMAP_MODULE*(ctx: PLoadContext): NtResult[void] =
    case LOBYTE(ctx.flags)
    of ord LoadLocal:   ldrUnmapNativeModule ctx
    of ord LoadMemory:  ldrUnmapMemoryModule ctx
    of ord LoadRemote:  ldrUnmapRemoteModule ctx
    else:               err InvalidFlags

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
                case fixup.Type
                of IMAGE_REL_BASED_DIR64:
                    cast[PULONG_PTR](ctx.entry.DLLBase +! reloc.VirtualAddress +! DWORD(fixup.Offset))[] += baseOffset
                of IMAGE_REL_BASED_HIGHLOW:
                    cast[PULONG_PTR](ctx.entry.DLLBase +! reloc.VirtualAddress +! DWORD(fixup.Offset))[] += ULONG_PTR(baseOffset)
                of IMAGE_REL_BASED_HIGH:
                    cast[PULONG_PTR](ctx.entry.DLLBase +! reloc.VirtualAddress +! DWORD(fixup.Offset))[] += ULONG_PTR(HIWORD(baseOffset))
                of IMAGE_REL_BASED_LOW:
                    cast[PULONG_PTR](ctx.entry.DLLBase +! reloc.VirtualAddress +! DWORD(fixup.Offset))[] += ULONG_PTR(LOWORD(baseOffset))
                else:
                    ## TODO
                    continue

        ## Update NtHeaders
        NtHeaders.OptionalHeader.ImageBase = cast[ULONGLONG](ctx.entry.DLLBase)
    ok()

proc ldrProcessMappedModule(ctx: PLoadContext): NtResult[void] =
    let 
        imageBase   = ctx.entry.DLLBase.ModuleHandle
        NtHeaders   = ? imageNtHeader imageBase

    ## Validate Entrypoint
    if NtHeaders.OptionalHeader.SizeOfHeaders > NtHeaders.OptionalHeader.AddressOfEntryPoint:
        return err ImageInvalid

    ctx.entry.OriginalBase = NtHeaders.OptionalHeader.ImageBase

    ? ldrCfgProcessLoadConfig ctx
    ldrProcessExceptions ctx

## Loader Map Module
##------------------------------------
proc ldrMapModule*(ctx: PLoadContext): NtResult[void] =
    ## Map the DLL into memory
    ? LDR_MAP_MODULE ctx
    ## Complete the mapped DLL
    ? ldrCompleteMappedModule ctx
    ## Process the mapped DLL
    ldrProcessMappedModule ctx

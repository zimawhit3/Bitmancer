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
    loader/[ldrexceptions, ldrlink, ldrmap, ldrutils]
    
export
    ldrbase

## Manual Mapping Loader
## 
##  This module implements a manual mapper, capable of loading PEs, DLLs, or COFFs
##  from Disk, Memory, or Remotely. 
## 
##  Note: This is currently in progress! Unstable API
##------------------------------------------------------------------------
#[
    TODO:
        - instead of taking the full path, accept any PWSTR, search according to the NT Loader's search order
        - increment & decrement DLL Dependencies when processing imports
        - free dependency DLLs when unloading context
]#

## Forward Declaration for recursion
##------------------------------------
proc eLoadLibrary*(
    flags: DWORD,
    fullName: PCWSTR, 
    buffer: PVOID, 
    bufferLen: ULONG
): NtResult[PLoadContext] 

include loader/ldrmapsnap

## FreeLibrary
##------------------------------------
proc eFreeLibrary*(ctx: PLoadContext): NtResult[void] =
    result = ok()    

    ## TODO: decrement load counts of all DLLs the module depends on

    ## Unlink the module
    if ctx.linked():
        if (let unlink = ldrUnlinkModule(ctx); unlink.isErr()):
            result = unlink

    ## Remove exceptions
    if ctx.entry.isSet(InExceptionTable):
        if (let remove = cRtlRemoveInvertedFuncTableEntry ctx.entry.DLLBase.ModuleHandle; remove.isErr()):
            result = remove

    ## Unmap module
    if not ctx.entry.DLLBase.isNil():
        if (let unmap = LDR_UNMAP_MODULE ctx; unmap.isErr()):
            result = unmap

    ## Remove Dependency Contexts
    ## TODO

    ## Remove Ldr Entry
    if not ctx.entry.isNil():
        PROCESS_HEAP_FREE(ctx.entry)    
    PROCESS_HEAP_FREE(cast[PVOID](ctx))

## LoadLibrary
##------------------------------------
proc eLoadLibrary*(
    flags: DWORD,
    fullName: PCWSTR, 
    buffer: PVOID, 
    bufferLen: ULONG
): NtResult[PLoadContext] =
    ## Initialize Loader State
    ##-------------------------
    var loader = ? ldrInitialize(flags, fullName, buffer, bufferLen)

    ## Verify DLL not already loaded
    if LDR_MODULE_PRESENT loader:
        if not loader.entry.isNil():
            eRtlFreeHeap(RtlProcessHeap(), 0, loader.entry)
        loader.entry = ? GET_LDR_LIST(loader.entry.BaseDllName.Buffer, LoadOrder)
        inc loader.entry.DdagNode.LoadCount
        return ok loader

    ## Map and Snap the Module
    ##-------------------------
    if (let mapsnap = ldrMapAndSnap loader; mapsnap.isErr()):
        ? eFreeLibrary loader
        return err mapsnap.error()

    ## Link Module to internal structures
    ##-------------------------
    if (let link = ldrLinkAndPrepareForExecution loader; link.isErr()):
        ? eFreeLibrary loader
        return err link.error()

    ## Call DLL Entrypoint
    ##-------------------------
    if (let entry = ldrCallModuleEntry loader; entry.isErr()):
        ? eFreeLibrary loader
        return err entry.error()
    
    ok loader


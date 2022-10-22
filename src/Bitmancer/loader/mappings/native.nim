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
    ../ldrbase

export
    ldrbase

## Native / On-Disk DLLs
##  Map DLLs from disk into the process.
##------------------------------------------------------------------------
proc ldrMapNativeModuleKnownDLL*(ctx: PLoadContext): NtResult[void] =
    ##

proc ldrMapNativeModule*(ctx: PLoadContext): NtResult[void] =
    var
        sHandle         = HANDLE(0)
        fHandle         = HANDLE(0)
        viewSize        = SIZE_T(0)
        ioStatusBlock   = IO_STATUS_BLOCK()
        mapBase         = PVOID(NULL)

    ## Initialize Object Attributes
    var
        objAttributes   = OBJECT_ATTRIBUTES()
        objPath         = UNICODE_STRING()
        objBuffer       = ctx.entry.FullDllName.Buffer
   
    RTL_INIT_EMPTY_UNICODE_STRING(objPath, objBuffer, USHORT(objBuffer.len() * sizeOf(WCHAR)))
    InitializeObjectAttributes(addr objAttributes, addr objPath, 0, sHandle, NULL)
    
    ? eNtOpenFile(
        fHandle, 
        ACCESS_MASK(SYNCHRONIZE or FILE_READ_DATA or FILE_EXECUTE), 
        addr objAttributes, 
        ioStatusBlock, 
        ULONG(FILE_SHARE_READ or FILE_SHARE_DELETE), 
        ULONG(FILE_NON_DIRECTORY_FILE or FILE_SYNCHRONOUS_IO_NONALERT)
    )

    if eNtCreateSection(
        sHandle,
        ACCESS_MASK(SECTION_QUERY or SECTION_MAP_READ or SECTION_MAP_EXECUTE),
        NULL,
        NULL,
        PAGE_EXECUTE,
        SEC_IMAGE,
        fHandle
    ).isErr():
        eNtClose(fHandle)
        return err SyscallFailure

    if eNtMapViewOfSection(
        sHandle,
        RtlCurrentProcess(),
        mapBase,
        0,
        0,
        NULL,
        viewSize,
        1,
        0,
        PAGE_READONLY
    ).isErr():
        eNtClose(sHandle)
        eNtClose(fHandle)
        return err SyscallFailure
    
    ctx.fileHandle          = fHandle
    ctx.sectHandle          = sHandle
    ctx.entry.DLLBase       = mapBase
    ctx.entry.SizeOfImage   = ULONG(viewSize)
    ok()

proc ldrUnmapNativeModule*(ctx: PLoadContext): NtResult[void] =
    eNtUnmapViewOfSection(RtlCurrentProcess(), ctx.entry.DLLBase)
    eNtClose(ctx.sectHandle)
    ctx.sectHandle = 0
    eNtClose(ctx.fileHandle)
    ctx.fileHandle = 0
    ok()



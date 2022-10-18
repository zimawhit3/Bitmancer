

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



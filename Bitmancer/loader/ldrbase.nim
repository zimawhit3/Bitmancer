

import
    ../ntdll

export
    ntdll

## Loader Options
##------------------------------------------------------------------------
const
    LOAD_LOCAL*         = 0x00000001
    LOAD_REMOTE*        = 0x00000002
    LOAD_MEMORY*        = 0x00000003
    FORMAT_COFF*        = 0x00000010
    FORMAT_IMAGE*       = 0x00000020
    RUN_UNDER_LDR_LOCK* = 0x01000000

template SET_LOAD_LOCAL*(flags: var DWORD) =
    flags |= LOAD_LOCAL

template SET_LOAD_MEMORY*(flags: var DWORD) =
    flags |= LOAD_MEMORY

template SET_LOAD_REMOTE*(flags: var DWORD) =
    flags |= LOAD_REMOTE

template SET_FORMAT_COFF*(flags: var DWORD) =
    flags |= FORMAT_COFF

template SET_FORMAT_IMAGE*(flags: var DWORD) =
    flags |= FORMAT_IMAGE

template SET_RUN_UNDER_LDR_LOCK*(flags: var DWORD) =
    flags |= RUN_UNDER_LDR_LOCK

## Loader Context
##------------------------------------------------------------------------
type
    LoadContext* {.byCopy.} = object
        flags*:         DWORD
        dependencies*:  LIST_ENTRY
        entry*:         PLDR_DATA_TABLE_ENTRY
        buffer*:        PVOID
        bufferLen*:     DWORD
        fileHandle*:    HANDLE
        sectHandle*:    HANDLE
    PLoadContext* = ptr LoadContext

template LDR_MODULE_PRESENT*(ctx: PLoadContext): bool =
    MODULE_LOADED(ctx.entry.BaseDllName.Buffer, MemoryOrder)

template LDR_MODULE_VALID*(ctx: PLoadContext): bool =
    PE_VALID ctx.buffer.ModuleHandle

proc init*(
    T: typedesc[PLoadContext], 
    flags: DWORD,
    fullDLLName: UNICODE_STRING, 
    baseDLLName: UNICODE_STRING,
    buffer: PVOID, 
    bufferLen: ULONG
): NtResult[PLoadContext] =
    var
        base            = ? PROCESS_HEAP_ALLOC(LoadContext)
        entry           = ? PROCESS_HEAP_ALLOC(LDR_DATA_TABLE_ENTRY)
        ctx             = cast[PLoadContext](base)
    ctx.flags           = flags
    ctx.dependencies    = LIST_ENTRY()
    ctx.entry           = cast[PLDR_DATA_TABLE_ENTRY](entry)
    ctx.buffer          = buffer
    ctx.bufferLen       = bufferLen
    ctx.entry.FullDllName = fullDLLName
    ctx.entry.BaseDllName = baseDLLName
    INIT_LIST_ENTRY ctx.dependencies
    ok ctx

## Loader Initialization
##------------------------------------
proc ldrInitialize*(
    flags: DWORD,
    fullName: PCWSTR, 
    buffer: PVOID, 
    bufferLen: ULONG
): NtResult[PLoadContext] =
    ## Initializes the Loader's Load Context
    ##-----------------------------------
    if fullName.isNil() or fullName.len() > MAX_PATH:
        return err InvalidBuffer
    
    var 
        baseDLLName = UNICODE_STRING()
        fullDLLName = UNICODE_STRING()
    let baseName    = ? cPathFindFileNameW(fullName)
    
    RTL_INIT_EMPTY_UNICODE_STRING(fullDLLName, fullName, fullName.len.USHORT)
    RTL_INIT_EMPTY_UNICODE_STRING(baseDLLName, baseName, baseName.len.USHORT)

    PLoadContext.init(
        flags,
        fullDLLName,
        baseDLLName,
        buffer,
        bufferLen
    )


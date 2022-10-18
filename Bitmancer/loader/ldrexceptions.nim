

import
    ../core/obfuscation/hash,
    ldrlocks

export
    ldrlocks

## Exceptions
##------------------------------------------------------------------------
const
    MaxCount = 0x200

## Private
##------------------------------------
proc getLdrProtectMrData(): NtResult[LdrProtectMrData] =
    const
        RtlDeleteFunctionTableHash = ctDjb2 "RtlDeleteFunctionTable"
    let
        Ntdll               = ? NTDLL_BASE()
        pLdrProtectMrData   = ? getNestedProcAddress(Ntdll, RtlDeleteFunctionTableHash, 0)
    ok cast[LdrProtectMrData](pLdrProtectMrData)

## Public
##------------------------------------
proc ldrProtectMrdata*(protect: BOOL): NtResult[void] =
    let pLdrProtectMrData = ? getLdrProtectMrData()
    pLdrProtectMrData(protect)
    ok()

proc getLdrpInvertedFuncTable*(): NtResult[PINVERTED_FUNCTION_TABLE] =
    let 
        Ntdll           = ? NTDLL_BASE()
        NtHeaders       = ? imageNtHeader Ntdll
        ExcDirHeaders   = ? getExceptionDirectoryHeader(Ntdll)    
        entry = INVERTED_FUNCTION_TABLE_ENTRY(
            Union1:         INVERTED_FUNCTION_TABLE_ENTRY_UNION(
            FunctionTable:  EXCEPTION_DIRECTORY(Ntdll, ExcDirHeaders)),
            ImageBase:      cast[PVOID](Ntdll),
            SizeOfImage:    NtHeaders.OptionalHeader.SizeOfImage,
            SizeOfTable:    ExcDirHeaders.Size
        )
    ## Search .mrdata section for corresponding INVERTED_FUNCTION_TABLE_ENTRY's based on it's
    ## pointer to the Exception Directory (Union1.FunctionTable).
    ## The first entry will be 0x10 offset from the LdrpInvertedFunctionTable Header, 
    ## which sets its MaxCount field to 0x200 (512)and Overflow to 0.
    let pMrDataSection  = ? getMrdataSection(Ntdll)
    var pBeginAddr      = SECTION_START(Ntdll, pMrDataSection)

    while pBeginAddr < SECTION_END(Ntdll, pMrDataSection) -! sizeof(INVERTED_FUNCTION_TABLE_ENTRY):
        
        if cmpMem(pBeginAddr, cast[PVOID](unsafeAddr entry), sizeof(INVERTED_FUNCTION_TABLE_ENTRY)) == 0:
            ## First entry is 0x10 from the LdrpInvertedFunctionTable
            let table = cast[PINVERTED_FUNCTION_TABLE](pBeginAddr -! 0x10)

            ## Check if we're at the first entry
            if table.MaximumSize == MaxCount and table.OverFlow == 0:
                return ok table

        inc pBeginAddr
    
    err SearchNotFound

proc cRtlInsertInvertedFuncTableEntry*(imageBase: ModuleHandle, imageSize: SIZE_T): NtResult[void] =
    let InvertedFunctionTable = ? getLdrpInvertedFuncTable()
    ? ldrProtectMrdata(FALSE)
    result = cRtlpInsertInvertedFuncTableEntry(InvertedFunctionTable, imageBase, imageSize)
    ? ldrProtectMrdata(TRUE)

proc cRtlRemoveInvertedFuncTableEntry*(imageBase: ModuleHandle): NtResult[void] =
    let InvertedFunctionTable = ? getLdrpInvertedFuncTable()
    ? ldrProtectMrdata(FALSE)
    cRtlpRemoveInvertedFuncTableEntry(InvertedFunctionTable, imageBase)
    ? ldrProtectMrdata(TRUE)

proc ldrProcessExceptions*(ctx: PLoadContext): NtResult[void] =
    let imageBase = ctx.entry.DLLBase.ModuleHandle
    ? cRtlInsertInvertedFuncTableEntry(imageBase, ctx.entry.SizeOfImage)
    ctx.entry.setBit(InExceptionTable)
    ok()


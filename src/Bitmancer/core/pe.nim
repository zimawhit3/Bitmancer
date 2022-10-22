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
    pebteb, utils

export
    pebteb

## Portable Executable
##------------------------------------------------------------------------

## Hashes
##------------------------------------------------------------------------
const 
    DataSection*        = HASH_A ".data"
    PDataSection*       = HASH_A ".pdata"
    ImportSection*      = HASH_A ".idata"
    TextSection*        = HASH_A ".text"
    TLSSection*         = HASH_A ".tls"
    MrDataSection*      = HASH_A ".mrdata"
    RelocationSection*  = HASH_A ".rdata"

## Helpers
##------------------------------------
func imageNtHeader*(imageBase: ModuleHandle): NtResult[PIMAGE_NT_HEADERS] {.inline.} =    
    if imageBase.isNil():
        return err ImageInvalid
    let
        dosHeader   = cast[PIMAGE_DOS_HEADER](imageBase)
        ntHeader    = cast[PIMAGE_NT_HEADERS](dosHeader +! dosHeader.e_lfanew)
    if dosHeader.e_magic == IMAGE_DOS_SIGNATURE and ntHeader.Signature == IMAGE_NT_SIGNATURE:
        ok ntHeader
    else:
        err ImageInvalid

template IDENT_MATCH*(sym: cstring, ord: WORD, ident: SomeProcIdent): bool =
    when ident is cstring:  ident === sym
    elif ident is uint32:   ident == HASH_A sym
    elif ident is WORD:     ident == ord

template IDENT_MATCH*(sym: cstring, ident: SomeThunkedIdent): bool =
    let isMatch =
        when ident is cstring:  ident === sym
        elif ident is uint32:   ident == HASH_A sym
    isMatch

template PE_VALID*(imageBase: ModuleHandle): bool =
    imageNtHeader(imageBase).isOk()   

## Sections
##------------------------------------
template SECTION_START*(imageBase: ModuleHandle, section: PIMAGE_SECTION_HEADER): PVOID =
    imageBase +% section.VirtualAddress

template SECTION_END*(imageBase: ModuleHandle, section: PIMAGE_SECTION_HEADER): PVOID =
    imageBase +% section.VirtualAddress +! section.Misc.VirtualSize

iterator sections*(ntHdr: PIMAGE_NT_HEADERS): PIMAGE_SECTION_HEADER =
    let sections = cast[ptr UncheckedArray[IMAGE_SECTION_HEADER]](IMAGE_FIRST_SECTION(ntHdr))
    for i in 0.WORD ..< ntHdr.FileHeader.NumberOfSections:
        yield sections[i]

func getPESection*(imageBase: ModuleHandle, sectionHash: uint32): NtResult[PIMAGE_SECTION_HEADER] =
    let NtHeaders = ? imageNtHeader imageBase
    for section in NtHeaders.sections():
        let sectionName = cast[cstring](addr section.Name[0])
        if HASH_A(sectionName) == sectionHash:
            if section.VirtualAddress == 0 or section.Misc.VirtualSize == 0:
                return err SectionEmpty
            return ok section
    err SectionNotFound

## .data
##------------------
func getDataSection*(imageBase: ModuleHandle): NtResult[PIMAGE_SECTION_HEADER] {.inline.} =
    getPESection(imageBase, DataSection)

## .idata
##------------------
func getImportSection*(imageBase: ModuleHandle): NtResult[PIMAGE_SECTION_HEADER] {.inline.} =
    getPESection(imageBase, ImportSection)

## .pdata
##------------------
func getPDataSection*(imageBase: ModuleHandle): NtResult[PIMAGE_SECTION_HEADER] {.inline.} =
    getPESection(imageBase, PDataSection)

## .text
##------------------
func getTextSection*(imageBase: ModuleHandle): NtResult[PIMAGE_SECTION_HEADER] {.inline.} =
    getPESection(imageBase, TextSection)

## .text
##------------------
func getTLSSection*(imageBase: ModuleHandle): NtResult[PIMAGE_SECTION_HEADER] {.inline.} =
    getPESection(imageBase, TLSSection)

## .mrdata
##------------------
func getMrdataSection*(imageBase: ModuleHandle): NtResult[PIMAGE_SECTION_HEADER] {.inline.} =
    getPESection(imageBase, MrDataSection)

## .rdata
##------------------
func getRelocationSection*(imageBase: ModuleHandle): NtResult[PIMAGE_SECTION_HEADER] {.inline.} =
    getPESection(imageBase, RelocationSection)

## Directories
##------------------------------------
func getDirectoryHeader*(imageBase: ModuleHandle, index: int): NtResult[PIMAGE_DATA_DIRECTORY] =   
    if index notin 0 .. IMAGE_NUMBEROF_DIRECTORY_ENTRIES:
        return err DirectoryIndexOOB
    let NtHeaders = ? imageNtHeader imageBase
    for sectionIndex in 0 ..< NtHeaders.FileHeader.NumberOfSections.int:
        if sectionIndex == index:
            return ok cast[PIMAGE_DATA_DIRECTORY](addr NtHeaders.OptionalHeader.DataDirectory[index])
    err DirectoryNotFound

## Exports
##------------------
template EXPORT_FUNCS*(imageBase: ModuleHandle, exports: PIMAGE_EXPORT_DIRECTORY): ptr UncheckedArray[DWORD] =
    cast[ptr UncheckedArray[DWORD]](imageBase +% exports.AddressOfFunctions)

template EXPORT_NAMES*(imageBase: ModuleHandle, exports: PIMAGE_EXPORT_DIRECTORY): ptr UncheckedArray[DWORD] =
    cast[ptr UncheckedArray[DWORD]](imageBase +% exports.AddressOfNames)

template EXPORT_ORDINALS*(imageBase: ModuleHandle, exports: PIMAGE_EXPORT_DIRECTORY): ptr UncheckedArray[WORD] =
    cast[ptr UncheckedArray[WORD]](imageBase +% exports.AddressOfNameOrdinals)

iterator exports*(imageBase: ModuleHandle, exports: PIMAGE_EXPORT_DIRECTORY): (cstring, WORD, PVOID) =
    var
        name:       cstring
        ordinal:    WORD
        rva:        DWORD
    let
        funcs   = EXPORT_FUNCS(imageBase, exports)
        names   = EXPORT_NAMES(imageBase, exports)
        ords    = EXPORT_ORDINALS(imageBase, exports)
    for index in 0 ..< exports.NumberOfNames:
        name    = cast[cstring](imageBase +% names[index])
        ordinal = ords[index].WORD
        rva     = funcs[ordinal]
        yield (name, ordinal, imageBase +% rva)

template EXPORT_DIRECTORY*(imageBase: ModuleHandle, directory: PIMAGE_DATA_DIRECTORY): PIMAGE_EXPORT_DIRECTORY =
    cast[PIMAGE_EXPORT_DIRECTORY](imageBase +% directory.VirtualAddress)

func getExportDirectoryHeader*(imageBase: ModuleHandle): NtResult[PIMAGE_DATA_DIRECTORY] =
    let exportDir = ? imageBase.getDirectoryHeader IMAGE_DIRECTORY_ENTRY_EXPORT
    if exportDir.Size == 0 or exportDir.VirtualAddress == 0:
        err DirectoryEmpty
    else:
        ok exportDir

func getExportDirectory*(imageBase: ModuleHandle): NtResult[PIMAGE_EXPORT_DIRECTORY] =
    let header = ? getExportDirectoryHeader imageBase
    ok EXPORT_DIRECTORY(imageBase, header)

## Exceptions
##------------------
iterator runtimeFunctions*(exceptions: PIMAGE_RUNTIME_FUNCTION_ENTRY): PIMAGE_RUNTIME_FUNCTION_ENTRY =
    let excptArray = cast[ptr UncheckedArray[IMAGE_RUNTIME_FUNCTION_ENTRY]](exceptions)
    var index = 0
    while excptArray[index].BeginAddress != 0:
        yield excptArray[index]
        inc index

template EXCEPTION_DIRECTORY*(imageBase: ModuleHandle, directory: PIMAGE_DATA_DIRECTORY): PIMAGE_RUNTIME_FUNCTION_ENTRY =
    cast[PIMAGE_RUNTIME_FUNCTION_ENTRY](imageBase +% directory.VirtualAddress)

func getExceptionDirectoryHeader*(imageBase: ModuleHandle): NtResult[PIMAGE_DATA_DIRECTORY] =
    let excDir = ? imageBase.getDirectoryHeader IMAGE_DIRECTORY_ENTRY_EXCEPTION
    if excDir.Size == 0 or excDir.VirtualAddress == 0:
        err DirectoryEmpty
    else:
        ok excDir

func getExceptionDirectory*(imageBase: ModuleHandle): NtResult[PIMAGE_RUNTIME_FUNCTION_ENTRY] =
    let header = ? getExceptionDirectoryHeader imageBase
    ok EXCEPTION_DIRECTORY(imageBase, header)

## Load Configuration
##------------------
template LOAD_CONFIG_DIRECTORY*(imageBase: ModuleHandle, directory: PIMAGE_DATA_DIRECTORY): PIMAGE_LOAD_CONFIG_DIRECTORY =
    cast[PIMAGE_LOAD_CONFIG_DIRECTORY](imageBase +% directory.VirtualAddress)

func getLoadConfigDirectoryHeader*(imageBase: ModuleHandle): NtResult[PIMAGE_DATA_DIRECTORY] =
    let loadConfig = ? imageBase.getDirectoryHeader IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
    if loadConfig.Size == 0 or loadConfig.VirtualAddress == 0:
        err DirectoryEmpty
    else:
        ok loadConfig

func getLoadConfigDirectory*(imageBase: ModuleHandle): NtResult[PIMAGE_LOAD_CONFIG_DIRECTORY] =
    let header = ? getLoadConfigDirectoryHeader imageBase
    ok LOAD_CONFIG_DIRECTORY(imageBase, header)

## Imports
##------------------
template IMPORT_THUNK*(imageBase: ModuleHandle, thunkOffset: DWORD): ptr UncheckedArray[IMAGE_THUNK_DATA] =
    cast[ptr UncheckedArray[IMAGE_THUNK_DATA]](imageBase +% thunkOffset)

template GET_ORIGINAL_THUNK*(
    imageBase: ModuleHandle, 
    pImport: PIMAGE_IMPORT_DESCRIPTOR|PIMAGE_DELAYLOAD_DESCRIPTOR
): ptr UncheckedArray[IMAGE_THUNK_DATA] =
    when pImport is PIMAGE_IMPORT_DESCRIPTOR:
        IMPORT_THUNK(imageBase, pImport.union1.OriginalFirstThunk)
    elif pImport is PIMAGE_DELAYLOAD_DESCRIPTOR:
        IMPORT_THUNK(imageBase, pImport.ImportNameTableRVA)

template GET_FIRST_THUNK*(
    imageBase: ModuleHandle, 
    pImport: PIMAGE_IMPORT_DESCRIPTOR|PIMAGE_DELAYLOAD_DESCRIPTOR
): ptr UncheckedArray[IMAGE_THUNK_DATA] =
    when pImport is PIMAGE_IMPORT_DESCRIPTOR:
        IMPORT_THUNK(imageBase, pImport.FirstThunk)
    elif pImport is PIMAGE_DELAYLOAD_DESCRIPTOR:
        IMPORT_THUNK(imageBase, pImport.ImportAddressTableRVA)

iterator thunks*(
    imageBase: ModuleHandle, 
    pImport: PIMAGE_IMPORT_DESCRIPTOR|PIMAGE_DELAYLOAD_DESCRIPTOR
): (PIMAGE_THUNK_DATA, PIMAGE_THUNK_DATA) =
    let
        origThunks  = GET_ORIGINAL_THUNK(imageBase, pImport)
        firstThunks = GET_FIRST_THUNK(imageBase, pImport)
    var index = 0
    while origThunks[index].u1.AddressOfData != 0:
        yield (addr origThunks[index], addr firstThunks[index])
        inc index

iterator imports*(imp: PIMAGE_IMPORT_DESCRIPTOR): PIMAGE_IMPORT_DESCRIPTOR =
    let imports = cast[ptr UncheckedArray[IMAGE_IMPORT_DESCRIPTOR]](imp)
    var index   = 0
    while imports[index].Name != 0:
        yield imports[index]
        inc index

template IMPORT_DIRECTORY*(imageBase: ModuleHandle, directory: PIMAGE_DATA_DIRECTORY): PIMAGE_IMPORT_DESCRIPTOR =
    cast[PIMAGE_IMPORT_DESCRIPTOR](imageBase +% directory.VirtualAddress)

func getImportDirectoryHeader*(imageBase: ModuleHandle): NtResult[PIMAGE_DATA_DIRECTORY] =
    let impDir = ? imageBase.getDirectoryHeader IMAGE_DIRECTORY_ENTRY_IMPORT
    if impDir.Size == 0 or impDir.VirtualAddress == 0:
        err DirectoryEmpty
    else:
        ok impDir

func getImportDirectory*(imageBase: ModuleHandle): NtResult[PIMAGE_IMPORT_DESCRIPTOR] =
    let header = ? getImportDirectoryHeader imageBase
    ok IMPORT_DIRECTORY(imageBase, header)

## Delayed Imports
##------------------
iterator dImports*(delay: PIMAGE_DELAYLOAD_DESCRIPTOR): PIMAGE_DELAYLOAD_DESCRIPTOR =
    let delayImps   = cast[ptr UncheckedArray[IMAGE_DELAYLOAD_DESCRIPTOR]](delay)
    var index       = 0
    while delayImps[index].DllNameRVA != 0:
        yield delayImps[index]
        inc index

template DELAY_IMPORT_DIRECTORY*(imageBase: ModuleHandle, directory: PIMAGE_DATA_DIRECTORY): PIMAGE_DELAYLOAD_DESCRIPTOR =
    cast[PIMAGE_DELAYLOAD_DESCRIPTOR](imageBase +% directory.VirtualAddress)

func getDelayedImportDirectoryHeader*(imageBase: ModuleHandle): NtResult[PIMAGE_DATA_DIRECTORY] =
    let delayDir = ? imageBase.getDirectoryHeader IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
    if delayDir.Size == 0 or delayDir.VirtualAddress == 0:
        err DirectoryEmpty
    else:
        ok delayDir

func getDelayedImportDirectory*(imageBase: ModuleHandle): NtResult[PIMAGE_DELAYLOAD_DESCRIPTOR] =
    let header = ? getDelayedImportDirectoryHeader imageBase
    ok DELAY_IMPORT_DIRECTORY(imageBase, header)

## Relocations
##------------------
iterator relocs*(reloc: PIMAGE_BASE_RELOCATION): PIMAGE_BASE_RELOCATION =
    var 
        reloc   = cast[ptr UncheckedArray[IMAGE_BASE_RELOCATION]](reloc)
        index   = 0
    while reloc[index].VirtualAddress != 0:
        yield reloc[index]
        inc index

iterator fixups*(reloc: PIMAGE_BASE_RELOCATION): PIMAGE_FIXUP_ENTRY =
    var
        fixups  = cast[ptr UncheckedArray[PIMAGE_FIXUP_ENTRY]](reloc +! sizeof(IMAGE_BASE_RELOCATION))
        index   = 0
    while fixups[index] != reloc +! reloc.SizeOfBlock:
        yield fixups[index]
        inc index

template RELOCATION_DIRECTORY*(imageBase: ModuleHandle, directory: PIMAGE_DATA_DIRECTORY): PIMAGE_BASE_RELOCATION =
    cast[PIMAGE_BASE_RELOCATION](imageBase +% directory.VirtualAddress)

func getRelocationDirectoryHeader*(imageBase: ModuleHandle): NtResult[PIMAGE_DATA_DIRECTORY] =
    let relocDir = ? imageBase.getDirectoryHeader IMAGE_DIRECTORY_ENTRY_BASERELOC
    if relocDir.Size == 0 or relocDir.VirtualAddress == 0:
        err DirectoryEmpty
    else:
        ok relocDir

func getRelocationDirectory*(imageBase: ModuleHandle): NtResult[PIMAGE_BASE_RELOCATION] =
    let header = ? getRelocationDirectoryHeader imageBase
    ok RELOCATION_DIRECTORY(imageBase, header)

## Thread Local Storage
##------------------
iterator tlsCallbacks*(pTlsDir: PIMAGE_TLS_DIRECTORY): PIMAGE_TLS_CALLBACK =
    let callbacks = cast[ptr UncheckedArray[PIMAGE_TLS_CALLBACK]](pTlsDir.AddressOfCallbacks)
    var index = 0
    while not callbacks[index].isNil():
        yield callbacks[index]
        inc index

template TLS_DIRECTORY*(imageBase: ModuleHandle, directory: PIMAGE_DATA_DIRECTORY): PIMAGE_TLS_DIRECTORY =
    cast[PIMAGE_TLS_DIRECTORY](imageBase +% directory.VirtualAddress)

func getTLSDirectoryHeader*(imageBase: ModuleHandle): NtResult[PIMAGE_DATA_DIRECTORY] =
    let tlsDir = ? imageBase.getDirectoryHeader IMAGE_DIRECTORY_ENTRY_TLS
    if tlsDir.Size == 0 or tlsDir.VirtualAddress == 0:
        err DirectoryEmpty
    else:
        ok tlsDir

func getTLSDirectory*(imageBase: ModuleHandle): NtResult[PIMAGE_TLS_DIRECTORY] =
    let header = ? getTLSDirectoryHeader imageBase
    ok TLS_DIRECTORY(imageBase, header)


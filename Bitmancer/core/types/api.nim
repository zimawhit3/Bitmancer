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
    exceptions, ntmmapi, sync
export
    exceptions, ntmmapi, sync

## NT Exported Functions
##-----------------------------------------------

## TODO: Move this somewhere appropriate...
type
    CFile* = object
        cptr*:       cstring
        cnt*:        SIZE_T
        base*:       cstring
        flag*:       SIZE_T
        file*:       SIZE_T
        charBuf*:    SIZE_T
        bufSize*:    SIZE_T
        tmpFname*:   cstring

    CFilePtr* = ptr CFile ## The type representing a file handle.

type
    ## MSVCRT
    ##-----------------------------------------------
    iob_func*   = proc: CFilePtr {.cdecl, gcsafe.}
    fileno*     = proc(f: CFilePtr): SIZE_T {.cdecl, gcsafe.}
    fwrite*     = proc(b: PVOID, size, n: SIZE_T, f: CFilePtr): SIZE_T {.cdecl, gcsafe.}
    set_mode*   = proc(fd, mode: SIZE_T): SIZE_T {.cdecl, gcsafe.}
    fflush*     = proc(stream: CFilePtr): SIZE_T {.cdecl, gcsafe.}
    
    ## Ntdll
    ##-----------------------------------------------
    
    ## NT/ZW
    ##-----------------------
    NtAllocateVirtualMemory* = proc(
        processHandle:  HANDLE, 
        baseAddress:    var PVOID, 
        zeroBits:       ULONG_PTR, 
        regionSize:     var SIZE_T, 
        allocationType: ULONG, 
        protect:        ULONG
    ): NTSTATUS {.stdcall, gcsafe.}
    
    NtClose* = proc(
        handle: HANDLE
    ): NTSTATUS {.stdcall, gcsafe.}

    NtCreateSection* = proc(
        sectionHandle: var HANDLE,
        desiredAccess: ACCESS_MASK,
        objAttributes: POBJECT_ATTRIBUTES,
        maximumSize: PLARGE_INTEGER,
        sectionPageProt: ULONG,
        allocAttributes: ULONG,
        fileHandle: HANDLE
    ): NTSTATUS {.stdcall, gcsafe.}

    NtFlushInstructionCache* = proc(
        handle:     HANDLE,
        baseAddr:   PVOID,
        numBytes:   SIZE_T
    ): BOOL {.stdcall, gcsafe.}

    NtFreeVirtualMemory* = proc(
        processHandle:  HANDLE, 
        baseAddress:    var PVOID, 
        regionSize:     var SIZE_T, 
        freeType:       ULONG
    ): NTSTATUS {.stdcall, gcsafe.}

    NtMapViewOfSection* = proc(
        sectionHandle:  HANDLE,
        processHandle:  HANDLE,
        baseAddress:    var PVOID,
        zeroBits:       ULONG_PTR,
        commitSz:       SIZE_T,
        sectionOffset:  PLARGE_INTEGER,
        viewSize:       var SIZE_T,
        inheritDisp:    ULONG,
        allocType:      ULONG,
        win32Protect:   ULONG
    ): NTSTATUS {.stdcall, gcsafe.}

    NtOpenSection* = proc(
        sectionHandle:  var HANDLE,
        desiredAccess:  ACCESS_MASK,
        objAttributes:  POBJECT_ATTRIBUTES
    ): NTSTATUS {.stdcall, gcsafe.}

    NtOpenFile* = proc(
        fileHandle:     var HANDLE,
        desiredAccess:  ACCESS_MASK,
        objAttributes:  POBJECT_ATTRIBUTES,
        ioStatusBlock:  var IO_STATUS_BLOCK,
        shareAccess:    ULONG,
        openOptions:    ULONG
    ): NTSTATUS {.stdcall, gcsafe.}

    NtProtectVirtualMemory* = proc(
        processHandle:  HANDLE,
        baseAddress:    var PVOID,
        numBytes:       var SIZE_T,
        newAccessMask:  ULONG,
        oldAccessMask:  PULONG
    ): NTSTATUS {.stdcall, gcsafe.}

    NtQueryInformationProcess* = proc(
        procHandle:     HANDLE,
        procInfoClass:  PROCESSINFOCLASS,
        procInfo:       PVOID,
        procInfoLen:    ULONG,
        retLen:         PULONG
    ): NTSTATUS {.stdcall, gcsafe.}

    NtQueryPerformanceCounter* = proc(
        perfCounter:    var LARGE_INTEGER,
        perfFreq:       PLARGE_INTEGER
    ): NTSTATUS {.stdcall, gcsafe.}

    NtQuerySystemInformation* = proc(
        sysInfoClass:   SYSTEM_INFORMATION_CLASS,
        sysInfo:        PVOID,
        sysInfoLen:     ULONG,
        retLen:         PULONG
    ): NTSTATUS {.stdcall, gcsafe.}
    
    NtQuerySystemTime* = proc(
        systemTime: var LARGE_INTEGER
    ): NTSTATUS {.stdcall, gcsafe.}

    NtQueryVirtualMemory* = proc(
        hProcess:       HANDLE,
        baseAddress:    PVOID,
        miClass:        MEMORY_INFORMATION_CLASS,
        mi:             PVOID,
        miLen:          SIZE_T,
        retLen:         PSIZE_T
    ): NTSTATUS {.stdcall, gcsafe.}
    
    NtUnmapViewOfSection* = proc(
        hProcess:       HANDLE,
        baseAddress:    PVOID
    ): NTSTATUS {.stdcall, gcsafe.}

    NtWriteVirtualMemory* = proc(
        hProcess:       HANDLE,
        baseAddress:    PVOID,
        buffer:         PVOID,
        bytesToWrite:   ULONG,
        bytesWritten:   PULONG
    ): NTSTATUS {.stdcall, gcsafe.}

    ## Rtl
    ##-----------------------
    RtlAddVectoredExceptionHandler* = proc(
        first:      ULONG,
        handler:    PVECTORED_EXCEPTION_HANDLER
    ): HANDLE {.stdcall, gcsafe.}

    RtlAnsiStringToUnicodeString* = proc(
        destinationString:  PUNICODE_STRING,
        sourceString:       PANSI_STRING,
        allocateDestString: BOOLEAN
    ): NTSTATUS {.stdcall, gcsafe.}
    
    RtlAcquireSRWLockExclusive* = proc(
        lock: PRTL_SRWLOCK
    ) {.stdcall, gcsafe.}

    RtlReleaseSRWLockExclusive* = proc(
        lock: PRTL_SRWLOCK
    ) {.stdcall, gcsafe.}

    RtlDeleteFunctionTable* = proc(
        pTableEntry: PIMAGE_RUNTIME_FUNCTION_ENTRY
    ): BOOLEAN {.stdcall, gcsafe.}

    RtlCompareMemory* = proc(
        dst: PVOID,
        src: PVOID,
        size: SIZE_T
    ): SIZE_T {.cdecl, gcsafe.}

    RtlCopyMemory* = proc(
        dst: PVOID,
        src: PVOID,
        size: SIZE_T
    ): PVOID {.cdecl, gcsafe.}

    RtlCreateHeap* = proc(
        flags:      ULONG,
        heapBase:   PVOID,
        resvSize:   SIZE_T,
        commitSize: SIZE_T,
        lock:       PVOID,
        params:     PRTL_HEAP_PARAMETERS
    ): PVOID {.cdecl, gcsafe.}

    RtlInitAnsiString* = proc(
        destinationString:  PANSI_STRING,
        sourceString:       PCSZ
    ): VOID {.stdcall, gcsafe.}

    RtlInitializeSRWLock* = proc(
        srwLock: var RTL_SRWLOCK
    ) {.stdcall, gcsafe.}

    RtlLeaveCriticalSection* = proc(
        critSection: PRTL_CRITICAL_SECTION
    ): NTSTATUS {.stdcall, gcsafe.}

    RtlPcToFileHeader* = proc(
        pcValue:        PVOID,
        baseOfImage:    ptr PVOID
    ): PVOID {.stdcall, gcsafe.}

    RtlAllocateHeap* = proc(
        heapHandle: HANDLE,
        flags:      ULONG,
        size:       SIZE_T
    ): PVOID {.stdcall, gcsafe.}

    RtlEnterCriticalSection* = proc(
        criticalSection: PRTL_CRITICAL_SECTION
    ): NTSTATUS {.stdcall, gcsafe.}

    RtlFreeHeap* = proc(
        heapHandle:  HANDLE,
        flags:       ULONG,
        baseAddress: PVOID
    ): LOGICAL {.stdcall, gcsafe.}

    RtlInitUnicodeString* = proc(
        dstString:  var UNICODE_STRING,
        srcString:  PCWSTR
    ) {.stdcall, gcsafe.}
    
    RtlFreeUnicodeString* = proc(
        uniString:  PUNICODE_STRING
    ) {.stdcall, gcsafe.}
    
    RtlHashUnicodeString* = proc(
        uniString:          PUNICODE_STRING,
        caseInSensitive:    BOOLEAN,
        hashAlgo:           ULONG,
        hashValue:          var ULONG
    ): NTSTATUS {.stdcall, gcsafe.}

    RtlMoveMemory* = proc(
        dst: PVOID,
        src: PVOID,
        size: SIZE_T
    ) {.cdecl, gcsafe.}

    RtlRbInsertNodeEx* = proc(
        rbTree: PRTL_RB_TREE,
        parent: PRTL_BALANCED_NODE,
        right:  BOOLEAN,
        node:   PRTL_BALANCED_NODE
    ) {.stdcall, gcsafe.}

    RtlRbRemoveNode* = proc(
        rbTree: PRTL_RB_TREE,
        node:   PRTL_BALANCED_NODE
    ) {.stdcall, gcsafe.}
    
    RtlWaitForCriticalSection* = proc(
        crit: PRTL_CRITICAL_SECTION
    ) {.stdcall, gcsafe.}
    
    ## Ldr
    ##-----------------------
    LdrControlFlowGuardEnforced* = proc(): bool {.stdcall, gcsafe.}

    LdrLoadDll* = proc(
        pathToFile:     PWCHAR,
        flags:          ULONG,
        moduleFileName: PUNICODE_STRING,
        moduleHandle:   PHANDLE
    ): NTSTATUS {.stdcall, gcsafe.}

    LdrGetProcedureAddress* = proc(
        moduleHandle:   PVOID,
        procName:       PANSI_STRING,
        procOrd:        ULONG,
        procAddr:       ptr PVOID
    ): NTSTATUS {.stdcall, gcsafe.}

    LdrProtectMrData* = proc(
        p: ULONG
    ) {.stdcall, gcsafe.}

    ## Kernel32
    ##------------------------
    LoadLibrary* = proc(lpLibFileName: LPCSTR): HMODULE {.stdcall, gcsafe.}




import winim except SYSTEM_BASIC_INFORMATION, SYSTEM_INFORMATION_CLASS, MEMORY_BASIC_INFORMATION
import
    ../Bitmancer/core/obfuscation/hash,
    ../Bitmancer/ntdll,
    unittest

{.passC:"-masm=intel".}

suite "Test Syscalls":

    let 
        Ntdll       = ModuleHandle cast[PVOID](GetModuleHandle("ntdll.dll"))
        Kernel32    = ModuleHandle cast[PVOID](GetModuleHandle("KERNEL32.DLL"))
        eatSyscall  = cstring "NtAccessCheckByType"
        iatSyscall  = cstring "NtMapViewOfSection"
        eatpSyscall = GetProcAddress(cast[HMODULE](Ntdll.PVOID), eatSyscall)
        iatpSyscall = GetProcAddress(cast[HMODULE](Ntdll.PVOID), iatSyscall)
        eattheSSN   = WORD 0x0063
        iattheSSN   = WORD 0x0028

    test "Gates":
        checkpoint "Hell's Gate"
        let hellsGateEat = bHellsGateEat(Ntdll, eatSyscall)
        check:
            hellsGateEat.isOk() == true
            hellsGateEat.get().pSyscall == eatpSyscall
            hellsGateEat.get().wSyscall == eattheSSN
            hellsGateEat.get().isHooked == false
        
        let hellsGateIat = bHellsGateIat(Ntdll, Kernel32, iatSyscall)
        check:
            hellsGateIat.isOk() == true
            hellsGateIat.get().pSyscall == iatpSyscall
            hellsGateIat.get().wSyscall == iattheSSN
            hellsGateIat.get().isHooked == false

        checkpoint "Halos' Gate"
        let halosGateEat = bHalosGateEat(Ntdll, eatSyscall)
        check:
            halosGateEat.isOk() == true
            halosGateEat.get().pSyscall == eatpSyscall
            halosGateEat.get().wSyscall == eattheSSN
            halosGateEat.get().isHooked == false

        let halosGateIat = bHellsGateIat(Ntdll, Kernel32, iatSyscall)
        check:
            halosGateIat.isOk() == true
            halosGateIat.get().pSyscall == iatpSyscall
            halosGateIat.get().wSyscall == iattheSSN
            halosGateIat.get().isHooked == false

        checkpoint "Tartarus Gate"
        let tartarusGateEat = bTartarusGateEat(Ntdll, eatSyscall)
        check:
            tartarusGateEat.isOk() == true
            tartarusGateEat.get().pSyscall == eatpSyscall
            tartarusGateEat.get().wSyscall == eattheSSN
            tartarusGateEat.get().isHooked == false

        let tartarusGateIat = bTartarusGateIat(Ntdll, Kernel32, iatSyscall)
        check:
            tartarusGateIat.isOk() == true
            tartarusGateIat.get().pSyscall == iatpSyscall
            tartarusGateIat.get().wSyscall == iattheSSN
            tartarusGateIat.get().isHooked == false

    test "LdrThunks":
        let ldrThunks = bLdrThunks(Ntdll, eatSyscall)
        check:
            ldrThunks.isOk()
            ldrThunks.get().wSyscall == eattheSSN
            ldrThunks.get().isHooked == false
        
    test "ZwCounter":

        checkpoint "Zwcounter Exception Table EAT"
        let zwCounterExceptionsEat = bZwCounterEatExc(Ntdll, eatSyscall)
        check:
            zwCounterExceptionsEat.isOk() == true
            zwCounterExceptionsEat.get().pSyscall == eatpSyscall
            zwCounterExceptionsEat.get().wSyscall == eattheSSN
            zwCounterExceptionsEat.get().isHooked == false
        
        checkpoint "ZwCounter Highest Address EAT"
        let zwCounterEat    = bZwCounterEatHighest(Ntdll, eatSyscall)
        check:
            zwCounterEat.isOk() == true
            zwCounterEat.get().pSyscall == eatpSyscall
            zwCounterEat.get().wSyscall == eattheSSN
            zwCounterEat.get().isHooked == false

        checkpoint "ZwCounter Highest Address IAT"
        let zwCounterIat = bZwCounterIat(Kernel32, iatSyscall)
        check:
            zwCounterIat.isOk() == true
            zwCounterIat.get().pSyscall == iatpSyscall
            zwCounterIat.get().wSyscall == iattheSSN
            zwCounterIat.get().isHooked == false
        
suite "Ntdll Syscall Wrappers":
        
    test "objects":
        
        checkpoint "NtOpenFile"
        var ntdllstring {.stackStringW.} = "\\??\\C:\\Windows\\System32\\ntdll.dll"
        var 
            fileHandle      = HANDLE(0)
            objAttributes   = OBJECT_ATTRIBUTES()
            desiredAccess   = ACCESS_MASK(FILE_READ_DATA or GENERIC_READ)
            ioBlock         = IO_STATUS_BLOCK()
            shareAccess     = ULONG(FILE_SHARE_READ)
            openAccess      = ULONG(0)
            objPath         = UNICODE_STRING()
            objBuffer       = cast[PCWSTR](addr ntdllstring[0])

        RTL_INIT_EMPTY_UNICODE_STRING(objPath, objBuffer, objBuffer.len.USHORT)
        InitializeObjectAttributes(addr objAttributes, addr objPath, OBJ_CASE_INSENSITIVE, HANDLE(0), NULL)

        let status1 = eNtOpenFile(
            fileHandle,
            desiredAccess,
            addr objAttributes,
            ioBlock,
            shareAccess,
            openAccess
        )
        check:
            status1.isOk() == true
            fileHandle != 0
        
        checkpoint "NtCreateSection"
        var sectionHandle = HANDLE(0)
        let status2 = eNtCreateSection(
            sectionHandle,
            STANDARD_RIGHTS_REQUIRED or SECTION_MAP_READ or SECTION_QUERY,
            NULL,
            NULL,
            PAGE_READONLY,
            SEC_IMAGE,
            fileHandle
        )
        check:
            status2.isOk() == true
            sectionHandle != 0
        
        checkpoint "NtMapViewOfSection"
        var
            pCleanNtdll = PVOID(NULL)
            viewSize    = SIZE_T(0)

        let status3 = eNtMapViewOfSection(
            sectionHandle,
            RtlCurrentProcess(),
            pCleanNtdll,
            0,
            0,
            NULL,
            viewSize,
            1,
            0,
            PAGE_READONLY
        )
        check:
            status3.isOk == true
            pCleanNtdll.isNil() == false
        
        checkpoint "NtUnmapViewOfSection"
        let status4 = eNtUnmapViewOfSection(
            RtlCurrentProcess(),
            pCleanNtdll
        )
        check:
            status4.isOk() == true
        
        checkpoint "NtCreateSection"
        var knownDlls {.stackStringW.}  = "\\KnownDlls\\ntdll.dll"
        var
            sHandle = HANDLE(0)
            objAttr = OBJECT_ATTRIBUTES()
            objP    = UNICODE_STRING()
            objB    = cast[PCWSTR](addr knownDlls[0])

        RTL_INIT_EMPTY_UNICODE_STRING(objP, objB, objB.len.USHORT)
        InitializeObjectAttributes(addr objAttr, addr objP, 0, sHandle, NULL)
        
        let status7 = eNtOpenSection(
            sHandle,
            ACCESS_MASK(SECTION_MAP_READ),
            addr objAttr
        )
        check:
            status7.isOk() == true
            sHandle != 0
        
        checkpoint "NtClose"
        let status5 = eNtClose(sectionHandle)
        check:
            status5.isOk() == true

        let status6 = eNtClose(fileHandle)
        check:
            status6.isOk() == true

        let status8 = eNtClose(sHandle)
        check:
            status8.isOK() == true

    test "procthreads":
        let status = eNtFlushInstructionCache(RtlCurrentProcess(), NULL, 0)
        check:
            status.isOk() == true

    test "query":
        
        checkpoint "NtQuerySystemInformation"
        var sytemInfo = SYSTEM_BASIC_INFORMATION()
        let status1 = eNtQuerySystemInformation(
            cast[PVOID](addr sytemInfo), 
            SYSTEM_INFORMATION_CLASS.SystemBasicInformation, 
            sizeOf(SYSTEM_BASIC_INFORMATION)
        )
        check:
            status1.isOk() == true
            sytemInfo.PageSize == 0x1000

        checkpoint "NtQueryPerformanceCounter"
        var perfCounter = LARGE_INTEGER()
        let status2 = eNtQueryPerformanceCounter(
            perfCounter,
            NULL
        )
        check:
            status2.isOk() == true
            perfCounter.LowPart != 0 or perfCounter.HighPart != 0

        checkpoint "NtQuerySystemTime"
        var systemTime = LARGE_INTEGER()
        let status3 = eNtQuerySystemTime(systemTime)
        check:
            status3.isOk() == true
            systemTime.LowPart != 0 or systemTime.HighPart != 0

        checkpoint "NtQueryVirtualMemory"
        let NtdllBase   = NTDLL_BASE()
        var memInfo     = MEMORY_BASIC_INFORMATION()
        
        let status4 = eNtQueryVirtualMemory(
            RtlCurrentProcess(),
            NtdllBase.get().PVOID,
            cast[PVOID](addr memInfo),
            MEMORY_INFORMATION_CLASS.MemoryBasicInformation,
            sizeOf(MEMORY_BASIC_INFORMATION),
            NULL
        )
        check:
            status4.isOk() == true
            NtdllBase.get().PVOID == memInfo.BaseAddress

    test "vm":
        var 
            alloc   = PVOID(NULL)
            allocSz = SIZE_T 0x1000

        checkpoint "NtAllocateVirtualMemory"
        let status1 = eNtAllocateVirtualMemory(
            RtlCurrentProcess(),
            alloc,
            allocSz,
            MEM_RESERVE or MEM_COMMIT,
            PAGE_READONLY
        )
        check:
            status1.isOk() == true
            alloc.isNil() == false

        checkpoint "NtProtectVirtualMemory"
        var old = ULONG(0)
        let status2 = eNtProtectVirtualMemory(
            alloc,
            allocSz,
            PAGE_READWRITE,
            addr old
        )
        check:
            status2.isOk() == true
            old == PAGE_READONLY
        
        checkpoint "NtWriteVirtualMemory"
        var 
            writeStuff      = 0x12345678
            bytesWritten    = ULONG(0) 

        let status3 = eNtWriteVirtualMemory(
            RtlCurrentProcess(),
            alloc,
            addr writeStuff,
            8,
            addr bytesWritten
        )
        check:
            status3.isOk() == true
            bytesWritten == 8

        checkpoint "NtFreeVirtualMemory"
        let status4 = eNtFreeVirtualMemory(
            RtlCurrentProcess(),
            alloc,
            allocSz,
            MEM_RELEASE
        )
        check:
            status4.isOk() == true

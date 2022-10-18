

import
    winim/winstr,
    ../Bitmancer/core/obfuscation/hash,
    ../Bitmancer/rtl,
    unittest

suite "Test RTL functions":

    test "Heap":
        let alloc = PROCESS_HEAP_ALLOC(pointer)
        check:
            alloc.isOk()
        
        let free = PROCESS_HEAP_FREE(alloc.get())
        check:
            free.isOk()

    test "Locks":
        
        checkpoint "SRW Locks"
        var srwlock = RTL_SRWLOCK()

        let status1 = eRtlInitializeSRWLock(srwlock)
        check:
            status1.isOk()
        
        let status2 = eRtlAcquireSRWLockExclusive srwlock
        check:
            status2.isOk()

        let status3 = eRtlReleaseSRWLockExclusive srwlock
        check:
            status3.isOk()

        checkpoint "Critical Sections"
        let peblock = NtCurrentPeb().FastPebLock
        
        let status5 = eRtlEnterCriticalSection peblock
        check:
            status5.isOk()

        let status6 = eRtlLeaveCriticalSection peblock
        check:
            status6.isOk()

    test "RedBlack":
        let
            pHead       = LDR_LIST_ORDER(NtCurrentPeb(), MemoryOrder)
            pCurr       = LDR_LINK_ORDER(pHead.Flink, MemoryOrder)
            ntdllEntry  = getLdrEntry(NtdllHash, MemoryOrder)
            pNode       = LDR_INDEX_ORDER(pCurr, BaseAddress)
            root        = getFirstNode pNode
            baseTree    = getBaseAddressIndexTree()
        var ntdllNode   = addr ntdllEntry.get().BaseAddressIndexNode
        check:
            baseTree.isOk()

        let 
            parent = NODE_PARENT_NODE(ntdllNode)
            remove = eRtlRbRemoveNode(baseTree.get(), ntdllNode)
        check:
            remove.isOk()
            CHILD_ENTRY_RIGHT(parent).isNil()

        let insert = eRtlRbInsertNodeEx(
            baseTree.get(),
            root.get(),
            TRUE,
            ntdllNode
        )
        check:
            insert.isOk()
            NODE_PARENT_NODE(ntdllNode) != parent

    test "Shlwapi":
        let
            system32string  = L"C:\\Windows\\System32\\ntdll.dll"
            drivestring     = L"C:\\ntdll.dll"
            driveDir        = L"C:\\"
            cdrivedirstring = L"C:"
            filestring      = L"ntdll.dll"
            notfilestring   = L"C:\\foo\\"

        let 
            system32    = cPathFindFileNameW(system32string)
            cDrive      = cPathFindFileNameW(driveString)
            cDriveDir   = cPathFindFileNameW(driveDir)
            file        = cPathFindFileNameW(filestring)
            cDrv        = cPathFindFileNameW(cdrivedirstring)
            notfile     = cPathFindFileNameW(notfilestring)

        check:
            system32.isOk()
            $system32.get() == $filestring

            cDrive.isOk()
            $cDrive.get() == $filestring
            
            cDriveDir.isOk()
            $cDriveDir.get() == $driveDir
            
            file.isOk()
            $file.get() == $filestring

            cDrv.isOk()
            $cDrv.get() == $cdrivedirstring

            notfile.isOk()
            $notfile.get() == $notfilestring

    test "Str":
        var 
            uniString   = UNICODE_STRING()
            buffer      = L"ntdll.dll"
        
        checkpoint "RtlInitUnicodeString"

        let status1 = eRtlInitUnicodeString(uniString, buffer)
        check:
            status1.isOk()

        let hash = eRtlHashUnicodeString(addr uniString, TRUE, 0)
        check:
            hash.isOk()
            hash.get() != 0

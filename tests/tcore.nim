

import
    winim,
    ../Bitmancer/core/obfuscation/hash,
    ../Bitmancer/core,
    unittest

{.push hint[XDeclaredButNotUsed]: off.}

const
    ntdllH = ctDjb2 "ntdll.dll"
    NTDLLH = ctDjb2 "NTDLL.DLL"

suite "Test suite for core/modules and core/ntloader":
    let 
        ntdllModule = GetModuleHandle("ntdll.dll")
        msvcrt      = GetModuleHandle("msvcrt.dll")
        kernel32    = GetModuleHandle("KERNEL32.DLL")
        ntdllA      = cstring "ntdll.dll"
        NTDLLA      = cstring "NTDLL.DLL"
        ntdllW      = winstrConverterStringToLPWSTR "ntdll.dll"
        NTDLLW      = winstrConverterStringToLPWSTR "NTDLL.DLL"

    test "[List] Retrieve ldr entry with ansi string":
        
        checkpoint "Load Order Lists"
        let loentry = getLdrEntryListA(ntdllA, LoadOrder)
        check:
            loentry.isOk() == true
            loentry.get().DLLBase == cast[PVOID](ntdllModule)

        checkpoint "Memory Order List"
        let moentry = getLdrEntryListA(ntdllA, MemoryOrder)
        check:
            moentry.isOk() == true
            moentry.get().DLLBase == cast[PVOID](ntdllModule)

        checkpoint "Init Order List"
        let ioentry = getLdrEntryListA(ntdllA, InitializationOrder)
        check:
            ioentry.isOk() == true
            ioentry.get().DLLBase == cast[PVOID](ntdllModule)

        checkpoint "Case sensitive"
        let csentry = getLdrEntryListA(NTDLLA, MemoryOrder)
        check:
            csentry.isErr() == true
            csentry.error() == LdrEntryNotFound

    test "[List] Retrieve ldr entry with hash":

        checkpoint "Load Order Lists"
        let loentry = getLdrEntryListH(ntdllH, LoadOrder)
        check:
            loentry.isOk() == true
            loentry.get().DLLBase == cast[PVOID](ntdllModule)

        checkpoint "Memory Order List"
        let moentry = getLdrEntryListH(ntdllH, MemoryOrder)
        check:
            moentry.isOk() == true
            moentry.get().DLLBase == cast[PVOID](ntdllModule)

        checkpoint "Init Order List"
        let ioentry = getLdrEntryListH(ntdllH, InitializationOrder)
        check:
            ioentry.isOk() == true
            ioentry.get().DLLBase == cast[PVOID](ntdllModule)

        checkpoint "Case sensitive"
        let csentry = getLdrEntryListH(NTDLLH, MemoryOrder)
        check:
            csentry.isErr() == true
            csentry.error() == LdrEntryNotFound
    
    test "[List] Retrieve ldr entry with wide string":
        
        checkpoint "Load Order Lists"
        let loentry = getLdrEntryListW(ntdllW, LoadOrder)
        check:
            loentry.isOk() == true
            loentry.get().DLLBase == cast[PVOID](ntdllModule)

        checkpoint "Memory Order List"
        let moentry = getLdrEntryListW(ntdllW, MemoryOrder)
        check:
            moentry.isOk() == true
            moentry.get().DLLBase == cast[PVOID](ntdllModule)

        checkpoint "Init Order List"
        let ioentry = getLdrEntryListW(ntdllW, InitializationOrder)
        check:
            ioentry.isOk() == true
            ioentry.get().DLLBase == cast[PVOID](ntdllModule)

        checkpoint "Case sensitive"
        let csentry = getLdrEntryListW(NTDLLW, MemoryOrder)
        check:
            csentry.isErr() == true
            csentry.error() == LdrEntryNotFound

    test "[List] Retrieve ldr entry with backwards iterator":
        var found = false
        for entry in listBackwardEntries InitializationOrder:
            if ntdllH == HASH_W entry.BaseDllName:
                found = true
                break
        check: found == true

    test "[List] NTDLL Extended":
        let ntdll = getNtdllModuleHandleEx(MemoryOrder)
        check:
            ntdll.isOk() == true
            ntdll.get() == ModuleHandle cast[PVOID](ntdllModule)

    let 
        k32     = getLdrEntryListA("KERNEL32.DLL", MemoryOrder)
        pHead   = LDR_LIST_ORDER(NtCurrentPeb(), MemoryOrder)
        pCurr   = LDR_LINK_ORDER(pHead.Flink, MemoryOrder)
    
    test "[Index] Get the tree and tree root":
        
        checkpoint "BaseAddress Index Root"
        let 
            k32BaseNode = addr k32.get().BaseAddressIndexNode
            pBaseNode   = LDR_INDEX_ORDER(pCurr, BaseAddress)
            baseRoot    = getFirstNode(pBaseNode)
        check:
            baseRoot.isOk() == true
            baseRoot.get() == k32BaseNode
            getFirstNode(k32BaseNode).isOk() == true
            getFirstNode(k32BaseNode).get() == k32BaseNode

        checkpoint "MappingInfo Index Root"
        let 
            k32MapNode  = addr k32.get().MappingInfoIndexNode
            pMapNode    = LDR_INDEX_ORDER(pCurr, MappingInfo)
            mapRoot     = getFirstNode(pMapNode)
        check:
            mapRoot.isOk() == true
            mapRoot.get() == k32MapNode
            getFirstNode(k32MapNode).isOk() == true
            getFirstNode(k32MapNode).get() == k32MapNode

        checkpoint "BaseAddressIndex Tree"
        let baseTree = getBaseAddressIndexTree()
        check:
            baseTree.isOk()
        
        checkpoint "MappingInfoIndex Tree"
        let mappingTree = getMappingInfoIndexTree()
        check:
            mappingTree.isOk()
            
    test "[Index] Retrieve ldr entry with ansi string":

        checkpoint "BaseAddress Index"
        let baEntry = getLdrEntryIndexA(ntdllA, MemoryOrder, BaseAddress)
        check:
            baEntry.isOk() == true
            baEntry.get().DLLBase == cast[PVOID](ntdllModule)

        checkpoint "MappingInfo Index"
        let miEntry = getLdrEntryIndexA(ntdllA, MemoryOrder, MappingInfo)
        check:
            miEntry.isOk() == true
            miEntry.get().DLLBase == cast[PVOID](ntdllModule)

    test "[Index] Retrieve ldr entry with hash":
        
        checkpoint "BaseAddress Index"
        let baEntry = getLdrEntryIndexH(ntdllH, MemoryOrder, BaseAddress)
        check:
            baEntry.isOk() == true
            baEntry.get().DLLBase == cast[PVOID](ntdllModule)

        checkpoint "MappingInfo Index"
        let miEntry = getLdrEntryIndexH(ntdllH, MemoryOrder, MappingInfo)
        check:
            miEntry.isOk() == true
            miEntry.get().DLLBase == cast[PVOID](ntdllModule)

    test "[Index] Retrieve ldr entry with wide string":
        
        checkpoint "BaseAddress Index"
        let baEntry = getLdrEntryIndexW(ntdllW, MemoryOrder, BaseAddress)
        check:
            baEntry.isOk() == true
            baEntry.get().DLLBase == cast[PVOID](ntdllModule)

        checkpoint "MappingInfo Index"
        let miEntry = getLdrEntryIndexW(ntdllW, MemoryOrder, MappingInfo)
        check:
            miEntry.isOk() == true
            miEntry.get().DLLBase == cast[PVOID](ntdllModule)
    
    test "[Modules] GetModuleHandle":
        let
            crt     = CRT_BASE()
            k32     = KERNEL32_BASE()
            ntdll   = NTDLL_BASE()

        checkpoint "CRT"
        check:
            crt.isOk() == true
            crt.get() == ModuleHandle cast[PVOID](msvcrt)
        
        checkpoint "kernel32"
        check:
            k32.isOk() == true
            k32.get() == ModuleHandle cast[PVOID](kernel32)
        
        checkpoint "ntdll"
        check:
            ntdll.isOk() == true
            ntdll.get() == ModuleHandle cast[PVOID](ntdllModule)
            
        test "[Modules] RemoveldrEntry":
            ##
    
suite "Test Suite for procedures":
    let 
        ntdll           = GetModuleHandle("ntdll.dll")
        randomFunction  = GetProcAddress(ntdll, "NtMapViewOfSection")

    test "GetProcAddressEAT":
        let myntdll = NTDLL_BASE()
        check:
            myntdll.isOk() == true

        let pRandomFunction = getProcAddress(myntdll.get(), rtDjb2(cstring "NtMapViewOfSection"))
        check:
            pRandomFunction.isOk() == true
            pRandomFunction.get() == randomFunction

    test "GetProcAddressIAT":
        let 
            myntdll = NTDLL_BASE()
            k32     = KERNEL32_BASE()
        check:
            myntdll.isOk() == true
            k32.isOk() == true

        let pRandomFunction = getProcAddressEx(myntdll.get(), k32.get(), rtDjb2(cstring "NtMapViewOfSection"))
        check:
            pRandomFunction.isOk() == true
            pRandomFunction.get() == randomFunction












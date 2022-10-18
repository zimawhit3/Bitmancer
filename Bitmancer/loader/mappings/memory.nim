

import
    ../ldrbase
export
    ldrbase

## In Memory DLLs
##  Load DLLs/COFFs into memory FROM memory. *WIP*
##------------------------------------------------------------------------

## TODO: Test & iron this out

## Compile Time Settings
##------------------------------------------------------------------------
const
    ## Allocation Granularity
    ##  When mapping an in memory DLL, allocate memory based on the virtual memory allocation granularity 
    ##  and commit memory based on the virtual memory page sizes.
    ##---------------------------------------------------------------------
    UseSystemGranularity* {.booldefine.} = true

## COFF
##------------------------------------
proc ldrMapMemoryCOFF(ctx: PLoadContext): NtResult[void] =
    ## TODO

proc ldrUnmapMemoryCOFF(ctx: PLoadContext): NtResult[void] =
    ## TODO

## Images
##------------------------------------
proc ldrMapMemoryImage(ctx: PLoadContext): NtResult[void] =
    genSyscall(NtAllocateVirtualMemory)
    genSyscall(NtFreeVirtualMemory)
    
    ## Verify the buffer's image is valid
    if not LDR_MODULE_VALID ctx:
        return err ImageInvalid
    
    var
        moduleBase  = PVOID(NULL)
        moduleSize  = SIZE_T(0)
        commitFail  = false
    let 
        Ntdll           = ? NTDLL_BASE()
        NtHeaders       = ? imageNtHeader ctx.buffer.ModuleHandle
        NtAllocSyscall  = getNtAllocateVirtualMemory(Ntdll, ModuleHandle(NULL))
        NtFreeSyscall   = getNtFreeVirtualMemory(Ntdll, ModuleHandle(NULL))
    
    moduleBase = cast[PVOID](NtHeaders.OptionalHeader.ImageBase)
    moduleSize = NtHeaders.OptionalHeader.SizeOfImage

    when UseSystemGranularity:
        var 
            dwAllocGran = ULONG(0)
            dwPageSize  = ULONG(0)
            currentBase = PVOID(NULL)
            mbi         = MEMORY_BASIC_INFORMATION()
            sysInfo     = SYSTEM_BASIC_INFORMATION()
        
        if GET_BASIC_SYSTEM_INFO(sysInfo).isOk():
            dwAllocGran = sysInfo.AllocationGranularity
            dwPageSize  = sysInfo.PageSize
        else:
            dwAllocGran = 0xFA00
            dwPageSize  = 0x1000
    
        ## Check if module's desired base address is available
        let 
            vmResvCount = ULONG((moduleSize /% dwAllocGran) + 1)
            vmPageCount = ULONG((vmResvCount /% dwPageSize) + 1)
    
        if vmResvCount > 1:
            ## We can't let the kernel assign us an address, since we need a contigious block of memory spanning
            ## `vmResvCount`. Instead, find a suitable address by randomly querying page-aligned virtual 
            ## addresses. 
            ## 
            ## TODO
            var 
                contigiousBlocks    = 0
                contigiousBase      = moduleBase
            while contigiousBlocks != vmResvCount:
                block searchBase:
                    for i in 0 ..< vmResvCount:
                        
                        ? GET_BASIC_VM_INFO(RtlCurrentProcess(), contigiousBase, mbi, NULL)
                        
                        if mbi.State == MEM_FREE:
                            inc contigiousBlocks
                            contigiousBase = contigiousBase +! dwAllocGran
                        
                        else:
                            contigiousBlocks    = 0
                            #contigiousBase      = PAGE_BOUNDARY(rand(0x10000000 .. 0x70000000), dwPageSize)
                            break searchBase

        else:
            ## If not available, let the kernel assign us an address
            ? GET_BASIC_VM_INFO(RtlCurrentProcess(), moduleBase, mbi, NULL)
            if mbi.State != MEM_FREE:
                moduleBase = NULL
        
        ## Reserve Memory
        ##-------------------
        var szLen   = SIZE_T(dwAllocGran)
        currentBase = moduleBase
        
        for i in 0 ..< vmResvCount:
            let status = NtAllocateVirtualMemoryWrapper(
                RtlCurrentProcess(), 
                currentBase, 
                0, 
                szLen, 
                MEM_RESERVE, 
                PAGE_READWRITE,
                NtAllocSyscall.wSyscall,
                NtAllocSyscall.pSyscall,
                NtAllocSyscall.pFunction
            )
            if not NT_SUCCESS status:
                szLen       = SIZE_T(0)
                currentBase = moduleBase
                discard NtFreeVirtualMemoryWrapper(
                    RtlCurrentProcess(),
                    currentBase,
                    szLen,
                    MEM_RELEASE,
                    NtFreeSyscall.wSyscall,
                    NtFreeSyscall.pSyscall,
                    NtFreeSyscall.pFunction
                )
                
                ## If we reserved more than 1 block, release them
                if i > 0:
                    for j in 1 .. i:
                        szLen       = SIZE_T(0)
                        currentBase = moduleBase +! (j * dwAllocGran)
                        discard NtFreeVirtualMemoryWrapper(
                            RtlCurrentProcess(),
                            currentBase,
                            szLen,
                            MEM_RELEASE,
                            NtFreeSyscall.wSyscall,
                            NtFreeSyscall.pSyscall,
                            NtFreeSyscall.pFunction
                        )
                
                return err InsufficientMemory

            if i == 0:
                moduleBase = currentBase
            
            currentBase = cast[PVOID](cast[ULONG_PTR](currentBase) +% dwAllocGran)

        ## Commit Memory
        ##-------------------
        var currOffset = ULONG(0)

        block commitLoop:
            for i in 0 ..< vmResvCount:
                for j in 0 ..< vmPageCount:    
                    
                    ## Commit memory in sequences of `dwPageSize` pages.
                    currOffset  = (i * dwAllocGran) +% (j * dwPageSize)
                    currentBase = moduleBase +! currOffset

                    if currOffset > moduleSize:
                        break commitLoop

                    if not NT_SUCCESS NtAllocateVirtualMemoryWrapper(
                        RtlCurrentProcess(), 
                        currentBase, 
                        0, 
                        szLen, 
                        MEM_COMMIT, 
                        PAGE_READWRITE,
                        NtAllocSyscall.wSyscall,
                        NtAllocSyscall.pSyscall,
                        NtAllocSyscall.pFunction
                    ):
                        commitFail = true
                        break commitLoop
                    
                    copyMem(currentBase, ctx.buffer +! currOffset, dwPageSize)
        
        ## Free Reserved
        ##-------------------
        if commitFail:
            for i in 0 ..< vmResvCount:
                szLen       = SIZE_T(0)
                currentBase = moduleBase +! ((i * dwAllocGran))
                discard NtFreeVirtualMemoryWrapper(
                    RtlCurrentProcess(), 
                    currentBase, 
                    szLen, 
                    MEM_RELEASE,
                    NtFreeSyscall.wSyscall,
                    NtFreeSyscall.pSyscall,
                    NtFreeSyscall.pFunction
                )
            return err InsufficientMemory
        
    else:
        if not NT_SUCCESS NtAllocateVirtualMemoryWrapper(
            RtlCurrentProcess(), 
            moduleBase, 
            moduleSize, 
            MEM_RESERVE or MEM_COMMIT,
            PAGE_READWRITE,
            NtAllocSyscall.wSyscall,
            NtAllocSyscall.pSyscall,
            NtAllocSyscall.pFunction
        ): return err InsufficientMemory
        
        copyMem(moduleBase, ctx.buffer, pNtHeaders.OptionalHeader.SizeOfHeaders)
        
        for section in pNtHeaders.sections():
            copyMem(
                moduleBase.offset section.VirtualAddress,
                ctx.buffer.offset section.PointerToRawData,
                section.SizeOfRawData 
            )
    
    ctx.entry.DLLBase       = moduleBase
    ctx.entry.SizeOfImage   = ULONG(moduleSize)
    ok()

proc ldrUnmapMemoryImage(ctx: PLoadContext): NtResult[void] =
    genSyscall(NtFreeVirtualMemory)
    let 
        Ntdll           = ? NTDLL_BASE()
        NtFreeSyscall   = getNtFreeVirtualMemory(Ntdll, ModuleHandle(NULL))
    var tmpSize                 = SIZE_T(0)
    when UseSystemGranularity:
        var 
            sysInfo     = SYSTEM_BASIC_INFORMATION()
            currentBase = PVOID(NULL)
        let 
            dwAllocGran =
                if GET_BASIC_SYSTEM_INFO(sysInfo).isOk():
                    sysInfo.AllocationGranularity
                else:
                    0xFA00
            vmResvCount = ULONG((ctx.entry.SizeOfImage /% dwAllocGran) + 1)

        for i in 0 ..< vmResvCount:
            tmpSize     = SIZE_T(0)
            currentBase = ctx.entry.DLLBase +! (i * dwAllocGran)
            discard NtFreeVirtualMemoryWrapper(
                RtlCurrentProcess(), 
                currentBase, 
                tmpSize, 
                MEM_RELEASE,
                NtFreeSyscall.wSyscall,
                NtFreeSyscall.pSyscall,
                NtFreeSyscall.pFunction
            )

    else:
        discard NtFreeVirtualMemoryWrapper(
            RtlCurrentProcess(), 
            ctx.entry.DLLBase, 
            tmpSize, 
            MEM_RELEASE,
            NtFreeSyscall.wSyscall,
            NtFreeSyscall.pSyscall,
            NtFreeSyscall.pFunction
        )
    
    ctx.entry.DLLBase       = NULL
    ctx.entry.SizeOfImage   = 0
    ok()

## Public Map / Unmap
##------------------------------------
proc ldrMapMemoryModule*(ctx: PLoadContext): NtResult[void] {.inline.} =
    if ctx.flags && FORMAT_IMAGE:   ldrMapMemoryImage ctx
    elif ctx.flags && FORMAT_COFF:  ldrMapMemoryCOFF ctx
    else:                           err InvalidFlags

proc ldrUnmapMemoryModule*(ctx: PLoadContext): NtResult[void] {.inline.} =
    if ctx.flags && FORMAT_IMAGE:   ldrUnmapMemoryImage ctx
    elif ctx.flags && FORMAT_COFF:  ldrUnmapMemoryCOFF ctx
    else:                           err InvalidFlags

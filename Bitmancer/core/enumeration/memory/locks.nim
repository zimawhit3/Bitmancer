

import
    ".."/../[ntloader, utils],
    procedures

export
    errors, results, types

func enumFindLock64*(fStart, tFunction: PVOID, callIndex: int): NtResult[PRTL_SRWLOCK] =
    ## Search the target function `fStart` for the first call to the target
    ## function `tFunction`, then parses and grabs the lock from the preceding
    ## instruction loading it in to the RCX register.
    ## TODO: a less naive solution...
    let
        Ntdll   = ? NTDLL_BASE()
        fEnd    = ? searchFunctionEnd(Ntdll, fStart)
        pCall   = ? searchCallToTargetFunction(fStart, fEnd, tFunction, callIndex)
        pLea    = cast[PBYTE](pCall -! 0x7)

    ## Check to make sure the LEA is a rip-relative rel32 instruction to RCX.
    if pLea[] == 0x48 and cast[PBYTE](pLea +! 1)[] == 0x8D and cast[PBYTE](pLea +! 2)[] == 0x0D:

        ## Grab the rip-relative address from the lea to RCX, as that will hold the address of the lock.
        let 
            dataSection     = ? getDataSection Ntdll
            rel32           = cast[PDWORD](pLea +! 0x3)[]
            lock            = cast[PRTL_SRWLOCK](pLea +! rel32 +! 0x7)
        ## Check to make sure it's contained in the data section.
        if lock > SECTION_START(Ntdll, dataSection) and lock < SECTION_END(Ntdll, dataSection):
            return ok lock

    err LockNotFound    

func enumFindLock32*(fStart, tFunction: PVOID, callIndex: int): NtResult[PRTL_SRWLOCK] =
    ##

template enumFindLock*(fStart, tFunction: PVOID, callIndex: int): NtResult[PRTL_SRWLOCK] =
    when defined(cpu64):    enumFindLock64(fStart, tFunction, callIndex)
    else:                   enumFindLock32(fStart, tFunction, callIndex)

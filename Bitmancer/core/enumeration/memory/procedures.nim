
import
    ".."/../[pe, utils]

export
    pe

func searchCallToTargetFunction*(fStart, fEnd, target: PVOID, callIndex: int): NtResult[PVOID] =
    var 
        currentAddr = fStart
        index       = 0
    while currentAddr != fEnd:
        if currentAddr.isCallInstruction():
            ## Offset should be: Address of Call + Offset + Length of Instruction (0x5)
            let rel32 = cast[PDWORD](currentAddr +! 1)[] + 0x5
            if currentAddr +! rel32 == target:
                if index == callIndex:
                    return ok currentAddr
                inc index
        inc currentAddr
    err SearchNotFound

func searchCall*(fStart, fEnd: PVOID, callIndex: int): NtResult[PVOID] =
    var 
        currentAddr = fStart
        index       = 0
    while currentAddr != fEnd:
        if currentAddr.isCallInstruction():
            if index == callIndex:
                return ok currentAddr
            inc index
        inc currentAddr
    err SearchNotFound

func searchFunctionEnd*(imageBase: ModuleHandle, functionBase: PVOID): NtResult[PVOID] =
    let ExcDirectory = ? getExceptionDirectory imageBase
    for entry in runtimeFunctions ExcDirectory:
        if imageBase +% entry.BeginAddress == functionBase:
            return ok imageBase +% entry.EndAddress
    err SearchNotFound

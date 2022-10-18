
import
    base
export
    base

type
    DllMain* = proc(hinstDLL: HINSTANCE, fdwReason: DWORD, lpReserved: LPVOID): BOOL {.stdcall, gcsafe.}

## Import Directory
##-----------------------------------------------
type
    IMAGE_FIXUP_ENTRY* {.pure.} = object
        Offset* {.bitsize: 12.}:    WORD
        Type*   {.bitsize: 4.}:     WORD
    PIMAGE_FIXUP_ENTRY* = ptr IMAGE_FIXUP_ENTRY

## Load Config Directory
##-----------------------------------------------
when defined(cpu64):
    const
        SECURITY_COOKIE_INITIAL* = 0x00002B992DDFA232

else:
    const
        SECURITY_COOKIE_INITIAL* = 0xBB40E64E

const
    SECURITY_COOKIE_16BIT_INITIAL* = 0xBB40
    
type
    IMAGE_LOAD_CONFIG_CODE_INTEGRITY* {.pure.} = object
        Flags*:         USHORT
        Catalog*:       USHORT
        CatalogOffset*: uint32
        Reserved*:      uint32

when defined(cpu64):
    type
        IMAGE_LOAD_CONFIG_DIRECTORY64* {.pure.} = object
            Size*:                                      DWORD
            TimeDateStamp*:                             DWORD
            MajorVersion*:                              WORD
            MinorVersion*:                              WORD
            GlobalFlagsClear*:                          DWORD
            GlobalFlagsSet*:                            DWORD
            CriticalSectionDefaultTimeout*:             DWORD
            DeCommitFreeBlockThreshold*:                ULONGLONG
            DeCommitTotalFreeThreshold*:                ULONGLONG
            LockPrefixTable*:                           ULONGLONG
            MaximumAllocationSize*:                     ULONGLONG
            VirtualMemoryThreshold*:                    ULONGLONG
            ProcessAffinityMask*:                       ULONGLONG
            ProcessHeapFlags*:                          DWORD
            CSDVersion*:                                WORD
            DependentLoadFlags*:                        WORD
            EditList*:                                  ULONGLONG
            SecurityCookie*:                            ULONGLONG
            SEHandlerTable*:                            ULONGLONG
            SEHandlerCount*:                            ULONGLONG
            GuardCFCheckFunctionPointer*:               ULONGLONG
            GuardCFDispatchFunctionPointer*:            ULONGLONG
            GuardCFFunctionTable*:                      ULONGLONG
            GuardCFFunctionCount*:                      ULONGLONG
            GuardFlags*:                                DWORD
            CodeIntegrity*:                             IMAGE_LOAD_CONFIG_CODE_INTEGRITY
            GuardAddressTakenIatEntryTable*:            ULONGLONG
            GuardAddressTakenIatEntryCount*:            ULONGLONG
            GuardLongJumpTargetTable*:                  ULONGLONG
            GuardLongJumpTargetCount*:                  ULONGLONG
            DynamicValueRelocTable*:                    ULONGLONG
            CHPEMetadataPointer*:                       ULONGLONG
            GuardRFFailureRoutine*:                     ULONGLONG
            GuardRFFailureRoutineFunctionPointer*:      ULONGLONG
            DynamicValueRelocTableOffset*:              DWORD
            DynamicValueRelocTableSection*:             WORD
            Reserved2*:                                 WORD
            GuardRFVerifyStackPointerFunctionPointer*:  ULONGLONG
            HotPatchTableOffset*:                       DWORD
            Reserved3*:                                 DWORD
            EnclaveConfigurationPointer*:               ULONGLONG
            VolatileMetadataPointer*:                   ULONGLONG
            GuardEHContinuationTable*:                  ULONGLONG
            GuardEHContinuationCount*:                  ULONGLONG
            GuardXFGCheckFunctionPointer*:              ULONGLONG
            GuardXFGDispatchFunctionPointer*:           ULONGLONG
            GuardXFGTableDispatchFunctionPointer*:      ULONGLONG
            CastGuardOsDeterminedFailureMode*:          ULONGLONG
            GuardMemcpyFunctionPointer*:                ULONGLONG
        PIMAGE_LOAD_CONFIG_DIRECTORY64* = ptr IMAGE_LOAD_CONFIG_DIRECTORY64
        PIMAGE_LOAD_CONFIG_DIRECTORY* = PIMAGE_LOAD_CONFIG_DIRECTORY64
else:
    ## TODO






    
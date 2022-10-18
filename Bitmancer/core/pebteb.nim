

import
    errors, intrinsics, types, utils
    
export
    errors, types

const
    TEB_OFFSET_64 = 0x30
    TEB_OFFSET_32 = 0x18
    PEB_OFFSET_64 = 0x60
    PEB_OFFSET_32 = 0x30
    KUSER_SHARED_DATA_ADDRESS = 0x7FFE0000

template NT_RESULT*(status: NTSTATUS, body: untyped): Result[type(body), NtError] =
    if status >= 0:
        when body is void:
            ok()
        else:
            var t = body
            ok t
    else:
        err SyscallFailure

func NtCurrentTeb*(): PTEB {.inline, codeGenDecl: "__forceinline $# $#$#".} =
    when defined(cpu64):    cast[PTEB](readgsqword(TEB_OFFSET_64))
    elif defined(i386):     cast[PTEB](readfsdword(TEB_OFFSET_32))

func NtCurrentPeb*(): PPEB {.inline, codeGenDecl: "__forceinline $# $#$#".} =
    when defined(cpu64):    cast[PPEB](readgsqword(PEB_OFFSET_64))
    elif defined(i386):     cast[PPEB](readfsdword(PEB_OFFSET_32))

func NtKUserSharedData*(): PKUSER_SHARED_DATA {.inline.} =
    cast[PKUSER_SHARED_DATA](KUSER_SHARED_DATA_ADDRESS)

func RtlProcessHeap*(): HANDLE {.inline.} =
    cast[HANDLE](NtCurrentPeb().ProcessHeap)

template RtlCurrentProcess*(): HANDLE =
    HANDLE(-1)

func GetApiSet*(): PAPI_SET_NAMESPACE {.inline.} =
    NtCurrentPeb().ApiSetMap

func GetProcessId*(): UINT_PTR {.inline.} =
    cast[UINT_PTR](NtCurrentTeb().ClientId.UniqueProcess)

func GetStackBase*(): PVOID {.inline.} =
    NtCurrentTeb().NtTib.StackBase

func GetStackLimit*(): PVOID {.inline.} =
    NtCurrentTeb().NtTib.StackLimit

func GetThreadId*(): UINT_PTR {.inline.} =
    cast[UINT_PTR](NtCurrentTeb().ClientId.UniqueThread)

func GetTickCount*(): ULONGLONG {.inline.} =
    let kusd = NtKUserSharedData()
    cast[ULONGLONG]((cast[uint64](kusd.Union3.TickCount) * cast[uint64](kusd.TickCountMultiplier)) shr 0x18)

func GetSystemTime*(): PLARGE_INTEGER {.inline.} =
    cast[PLARGE_INTEGER](addr NtKUserSharedData().SystemTime)
  
func GetLoaderLock*(): PRTL_CRITICAL_SECTION {.inline.} =
    NtCurrentPeb().LoaderLock

func GetPebFastLock*(): PRTL_CRITICAL_SECTION {.inline.} =
    NtCurrentPeb().FastPebLock

func OsBuildNumber*(): USHORT {.inline.} =
    NtCurrentPeb().OSBuildNumber

func OSMajorVersion*(): ULONG {.inline.} =
    NtCurrentPeb().OSMajorVersion

func OSMinorVersion*(): ULONG {.inline.} =
    NtCurrentPeb().OSMinorVersion

## LDR_DATA_TABLE_ENTRY Bit Fields
##------------------------------------------------------------------------
const
    PackagedBinary*             = 0
    MarkedForRemoval*           = 1
    ImageDll*                   = 2
    LoadNotificationSent*       = 3
    TelemetryEntryProcessed*    = 4
    ProcessStaticImport*        = 5
    InLegacyLists*              = 6
    InIndexes*                  = 7
    ShimDll*                    = 8
    InExceptionTable*           = 9
    ReservedFlags1*             = 10
    LoadInProgress*             = 12
    LoadConfigProcessed*        = 13
    EntryProcessed*             = 14
    ProtectDelayLoad*           = 15
    ReservedFlags3*             = 16
    DontCallForThreads*         = 18
    ProcessAttachCalled*        = 19
    ProcessAttachFailed*        = 20
    CorDeferredValidate*        = 21
    CorImage*                   = 22
    DontRelocate*               = 23
    CorILOnly*                  = 24
    ChpeImage*                  = 25
    ChpeEmulatorImage*          = 26
    ReservedFlags5*             = 27
    Redirected*                 = 28
    ReservedFlags6*             = 29
    CompatDatabaseProcessed*    = 31

func setBit*(entry: PLDR_DATA_TABLE_ENTRY, bit: Natural) {.inline.} =
    type T = type(entry.Union_2.Flags)
    let mask = 1.T shl bit
    entry.Union_2.Flags |= mask

func clearBit*(entry: PLDR_DATA_TABLE_ENTRY, bit: Natural) {.inline.} =
    type T = type(entry.Union_2.Flags)
    let mask = 1.T
    entry.Union_2.Flags &= not mask

func isSet*(entry: PLDR_DATA_TABLE_ENTRY, bit: Natural): bool {.inline.} =
    type T = type(entry.Union_2.Flags)
    ((entry.Union_2.Flags shr bit) and 1.T) != 0


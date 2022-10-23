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
    intrinsics, ntresult, types, utils
    
export
    ntresult, types

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

func ntCurrentTeb*(): PTEB {.inline, codeGenDecl: "__forceinline $# $#$#".} =
    when defined(cpu64):    cast[PTEB](readgsqword(TEB_OFFSET_64))
    elif defined(i386):     cast[PTEB](readfsdword(TEB_OFFSET_32))

func ntCurrentPeb*(): PPEB {.inline, codeGenDecl: "__forceinline $# $#$#".} =
    when defined(cpu64):    cast[PPEB](readgsqword(PEB_OFFSET_64))
    elif defined(i386):     cast[PPEB](readfsdword(PEB_OFFSET_32))

func ntKUserSharedData*(): PKUSER_SHARED_DATA {.inline.} =
    cast[PKUSER_SHARED_DATA](KUSER_SHARED_DATA_ADDRESS)

func rtlProcessHeap*(): HANDLE {.inline.} =
    cast[HANDLE](ntCurrentPeb().ProcessHeap)

template rtlCurrentProcess*(): HANDLE =
    HANDLE(-1)

func getApiSet*(): PAPI_SET_NAMESPACE {.inline.} =
    ntCurrentPeb().ApiSetMap

func getProcessId*(): UINT_PTR {.inline.} =
    cast[UINT_PTR](ntCurrentTeb().ClientId.UniqueProcess)

func getStackBase*(): PVOID {.inline.} =
    ntCurrentTeb().NtTib.StackBase

func getStackLimit*(): PVOID {.inline.} =
    ntCurrentTeb().NtTib.StackLimit

func getThreadId*(): UINT_PTR {.inline.} =
    cast[UINT_PTR](ntCurrentTeb().ClientId.UniqueThread)

func getTickCount*(): ULONGLONG {.inline.} =
    let kusd = ntKUserSharedData()
    cast[ULONGLONG]((cast[uint64](kusd.Union3.TickCount) * cast[uint64](kusd.TickCountMultiplier)) shr 0x18)

func getSystemTime*(): PLARGE_INTEGER {.inline.} =
    cast[PLARGE_INTEGER](addr ntKUserSharedData().SystemTime)
  
func getLoaderLock*(): PRTL_CRITICAL_SECTION {.inline.} =
    ntCurrentPeb().LoaderLock

func getPebFastLock*(): PRTL_CRITICAL_SECTION {.inline.} =
    ntCurrentPeb().FastPebLock

func getOSBuildNumber*(): USHORT {.inline.} =
    ntCurrentPeb().OSBuildNumber

func getOSMajorVersion*(): ULONG {.inline.} =
    ntCurrentPeb().OSMajorVersion

func getOSMinorVersion*(): ULONG {.inline.} =
    ntCurrentPeb().OSMinorVersion

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


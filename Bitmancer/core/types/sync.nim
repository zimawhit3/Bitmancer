

import 
    base
export
    base

## SRW Locks
##-----------------------------------------------
type
    RTL_SRWLOCK_STRUCT_1* {.pure.} = object
        Locked*         {.bitsize:1.}:  ULONGLONG
        Waiting*        {.bitsize:1.}:  ULONGLONG
        Waking*         {.bitsize:1.}:  ULONGLONG
        MultipleShared* {.bitsize:1.}:  ULONGLONG
        Shared*         {.bitsize:60.}: ULONGLONG

    RTL_SRWLOCK* {.pure, union.} = object
        Struct1*:   RTL_SRWLOCK_STRUCT_1
        Value*:     ULONGLONG
        Ptr*:       PVOID
    PRTL_SRWLOCK* = ptr RTL_SRWLOCK


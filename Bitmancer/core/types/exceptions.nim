
import
    loader
export
    loader
    
type 
    ## Dynamic/Runtime Function Table
    ##------------------------------------
    FUNCTION_TABLE_TYPE* = enum
        RF_Sorted,
        RF_Unsorted,
        RF_Callback,
        RF_Kernel_Dynamic

    RUNTIME_FUNCTION_TABLE_CALLBACK* = proc(arg1: ULONGLONG, arg2: PVOID): PIMAGE_RUNTIME_FUNCTION_ENTRY

    RUNTIME_FUNCTION_TABLE* {.pure.} = object
        ListEntry*:                 LIST_ENTRY
        FunctionTable*:             PIMAGE_RUNTIME_FUNCTION_ENTRY
        TimeStamp*:                 LARGE_INTEGER
        MinimumAddress*:            ULONGLONG
        MaximumAddress*:            ULONGLONG
        BaseAddress*:               ULONGLONG
        Callback*:                  RUNTIME_FUNCTION_TABLE_CALLBACK
        Context*:                   PVOID
        OutOfProcessCallbackDll*:   PWCHAR
        Type*:                      FUNCTION_TABLE_TYPE
        EntryCount*:                ULONG
        TreeNodeMin*:               RTL_BALANCED_NODE
        TreeNodeMax*:               RTL_BALANCED_NODE
    PRUNTIME_FUNCTION_TABLE* = ptr RUNTIME_FUNCTION_TABLE

    IMAGE_RUNTIME_FUNCTION_ENTRY_UNION_1* {.pure, union.} = object
        UnwindInfoAddress*: ULONG
        UnwindData*:        ULONG

    IMAGE_RUNTIME_FUNCTION_ENTRY* {.pure.} = object
        BeginAddress*:  ULONG
        EndAddress*:    ULONG
        Union1*:        IMAGE_RUNTIME_FUNCTION_ENTRY_UNION_1
    PIMAGE_RUNTIME_FUNCTION_ENTRY* = ptr IMAGE_RUNTIME_FUNCTION_ENTRY

    ## Inverted Function Table
    ##------------------------------------
    INVERTED_FUNCTION_TABLE_ENTRY_UNION* {.pure, union.} = object
        FunctionTable*: PIMAGE_RUNTIME_FUNCTION_ENTRY
        DynamicTable*:  PRUNTIME_FUNCTION_TABLE

    INVERTED_FUNCTION_TABLE_ENTRY* {.pure.} = object
        Union1*:        INVERTED_FUNCTION_TABLE_ENTRY_UNION
        ImageBase*:     PVOID
        SizeOfImage*:   ULONG
        SizeOfTable*:   ULONG

    INVERTED_FUNCTION_TABLE* {.pure.} = object
        CurrentSize*:   ULONG
        MaximumSize*:   ULONG
        Epoch*:         ULONG
        Overflow*:      ULONG
        TableEntries*:  array[512, INVERTED_FUNCTION_TABLE_ENTRY]
    PINVERTED_FUNCTION_TABLE* = ptr INVERTED_FUNCTION_TABLE



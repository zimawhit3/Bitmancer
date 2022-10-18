

import
    base

export
    base

## Api Set Types
##------------------------------------------------------------------------
const

    ## Api Schemas
    ##------------------------------------
    API_SET_SCHEMA_VERSION_V6*  = 0x00000006
    API_SET_SCHEMA_VERSION_V4*  = 0x00000004
    API_SET_SCHEMA_VERSION_V3*  = 0x00000003
    API_SET_SCHEMA_VERSION_V2*  = 0x00000002

    API_SET_SCHEMA_FLAGS_SEALED*            = 0x00000001
    API_SET_SCHEMA_FLAGS_HOST_EXTENSION*    = 0x00000002
    API_SET_SCHEMA_ENTRY_FLAGS_SEALED*      = 0x00000001
    API_SET_SCHEMA_ENTRY_FLAGS_EXTENSION*   = 0x00000002

type
    ## API Sets
    ##------------------------------------
    API_SET_NAMESPACE* {.pure.} = object
        Version*:   ULONG
    PAPI_SET_NAMESPACE* = ptr API_SET_NAMESPACE

    ## API Set Version 6 | Windows 10
    ##------------------------------------
    API_SET_VALUE_ENTRY_V6* {.pure.} = object
        Flags*:         ULONG
        NameOffset*:    ULONG
        NameLength*:    ULONG
        ValueOffset*:   ULONG
        ValueLength*:   ULONG
    PAPI_SET_VALUE_ENTRY_V6* = ptr API_SET_VALUE_ENTRY_V6
    
    API_SET_HASH_ENTRY_V6* {.pure.} = object
        Hash*:  ULONG
        Index*: ULONG
    PAPI_SET_HASH_ENTRY_V6* = ptr API_SET_HASH_ENTRY_V6
    
    API_SET_NAMESPACE_ENTRY_V6* {.pure.} = object
        Flags*:         ULONG
        NameOffset*:    ULONG
        NameLength*:    ULONG
        HashedLength*:  ULONG
        ValueOffset*:   ULONG
        ValueCount*:    ULONG
    PAPI_SET_NAMESPACE_ENTRY_V6* = ptr API_SET_NAMESPACE_ENTRY_V6
    
    API_SET_NAMESPACE_V6* {.pure.} = object
        Version*:       ULONG
        Size*:          ULONG
        Flags*:         ULONG
        Count*:         ULONG
        EntryOffset*:   ULONG
        HashOffset*:    ULONG
        HashFactor*:    ULONG
    PAPI_SET_NAMESPACE_V6* = ptr API_SET_NAMESPACE_V6

    ## API Set Version 4 | Windows 8.1
    ##------------------------------------
    API_SET_VALUE_ENTRY_V4* {.pure.} = object
        Flags*:         ULONG
        NameOffset*:    ULONG
        NameLength*:    ULONG
        ValueOffset*:   ULONG
        ValueLength*:   ULONG
    PAPI_SET_VALUE_ENTRY_V4* = ptr API_SET_VALUE_ENTRY_V4

    API_SET_VALUE_ARRAY_V4* {.pure.} = object
        Flags*: ULONG
        Count*: ULONG
        Array*: array[ANYSIZE_ARRAY, API_SET_VALUE_ENTRY_V4]
    PAPI_SET_VALUE_ARRAY_V4* = ptr API_SET_VALUE_ARRAY_V4

    API_SET_NAMESPACE_ENTRY_V4* {.pure.} = object
        Flags*:         ULONG
        NameOffset*:    ULONG
        NameLength*:    ULONG
        AliasOffset*:   ULONG
        AliasLength*:   ULONG
        DataOffset*:    ULONG
    PAPI_SET_NAMESPACE_ENTRY_V4* = ptr API_SET_NAMESPACE_ENTRY_V4

    API_SET_NAMESPACE_ARRAY_V4* {.pure.} = object
        Version*:   ULONG
        Size*:      ULONG
        Flags*:     ULONG
        Count*:     ULONG
        Array*:     array[ANYSIZE_ARRAY, API_SET_NAMESPACE_ENTRY_V4]
    PAPI_SET_NAMESPACE_ARRAY_V4* = ptr API_SET_NAMESPACE_ARRAY_V4

    ## API Set Version 3 | Windows 8
    ##------------------------------------
    API_SET_VALUE_ENTRY_V3* {.pure.} = object
        NameOffset*:    ULONG
        NameLength*:    ULONG
        ValueOffset*:   ULONG
        ValueLength*:   ULONG
    PAPI_SET_VALUE_ENTRY_V3* = ptr API_SET_VALUE_ENTRY_V3

    API_SET_VALUE_ARRAY_V3* {.pure.} = object
        Count*: ULONG
        Array*: array[ANYSIZE_ARRAY, API_SET_VALUE_ENTRY_V3]
    PAPI_SET_VALUE_ARRAY_V3* = ptr API_SET_VALUE_ARRAY_V3

    API_SET_NAMESPACE_ENTRY_V3* {.pure.} = object
        NameOffset*:    ULONG
        NameLength*:    ULONG
        DataOffset*:    ULONG
    PAPI_SET_NAMESPACE_ENTRY_V3* = ptr API_SET_NAMESPACE_ENTRY_V3

    API_SET_NAMESPACE_ARRAY_V3* {.pure.} = object
        Version*:   ULONG
        Count*:     ULONG
        Array*:     array[ANYSIZE_ARRAY, API_SET_NAMESPACE_ENTRY_V3]
    PAPI_SET_NAMESPACE_ARRAY_V3* = ptr API_SET_NAMESPACE_ARRAY_V3



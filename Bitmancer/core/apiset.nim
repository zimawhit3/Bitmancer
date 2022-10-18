

import
    pebteb, str, utils

export
    pebteb

## ApiSets 
##------------------------------------------------------------------------
const
    API_SET_PREFIX_API_W*       = ULONGLONG 0x002D004900500041 # L"API-"
    API_SET_PREFIX_API_A*       = ULONG 0x2D495041
    API_SET_PREFIX_EXT_W*       = ULONGLONG 0x002D005400580045 # L"EXT-"
    API_SET_PREFIX_EXT_A*       = ULONG 0x2D545845
    API_SET_DLL_EXTENSTION_W*   = ULONGLONG 0x004C004C0044002E # L".DLL"

## Helpers
##------------------------------------
func isApiSetLib*(ws: PWSTR): bool =
    ## Check the name begins with "api-" or "ext-"
    var prefix = cast[PQWORD](ws)[]
    prefix &= (not 0x0000002000200020)
    prefix == API_SET_PREFIX_API_W or prefix == API_SET_PREFIX_EXT_W

func isApiSetLib*(cs: cstring): bool =
    ## Check the name begins with "API-" or "EXT-"
    var prefix = cast[PDWORD](cs)[]
    prefix &= (not 0x202020)
    prefix == API_SET_PREFIX_API_A or prefix == API_SET_PREFIX_EXT_A

## Private
##------------------------------------------------------------------------

## V3
##------------------------------------
func resolveApiSetV3(apiset: PAPI_SET_NAMESPACE, apisetName: var UNICODE_STRING): NtResult[void] =
    ## TODO

## V4
##------------------------------------
template API_SET_NAMESPACE_ENTRY_NAME_V4(apiSet: PAPI_SET_NAMESPACE_ARRAY_V4, entry: PAPI_SET_NAMESPACE_ENTRY_V4): PWSTR =
    cast[PWSTR](apiSet +! entry.DataOffset)

template API_SET_NAMESPACE_ENTRY_DATA_V4(apiSet: PAPI_SET_NAMESPACE_ARRAY_V4, entry: PAPI_SET_NAMESPACE_ENTRY_V4): PAPI_SET_VALUE_ARRAY_V4 =
    cast[PAPI_SET_VALUE_ARRAY_V4](apiSet +! entry.DataOffset)

template API_SET_VALUE_ENTRY_VALUE_V4(apiSet: PAPI_SET_NAMESPACE_ARRAY_V4, entry: PAPI_SET_VALUE_ENTRY_V4): PWSTR =
    cast[PWSTR](apiSet +! entry.ValueOffset)

func searchForApiSetV4(apiSet: PAPI_SET_NAMESPACE_ARRAY_V4, asn: PWSTR, asnLen: USHORT): NtResult[PAPI_SET_NAMESPACE_ENTRY_V4] =
    var
        lowerBound  = ULONG(0)
        index       = ULONG(0)
        upperBound  = ULONG(apiSet.Count - 1)
        entry       = PAPI_SET_NAMESPACE_ENTRY_V4(NULL)
    while upperBound >= lowerBound:
        index   = (upperBound + lowerBound) shr 1
        entry   = apiSet.Array[index]

        let cmp = cmpMem(asn, API_SET_NAMESPACE_ENTRY_NAME_V4(apiSet, entry), asnLen)
        if cmp < 0:
            upperBound = index - 1
        elif cmp > 0:
            lowerBound = index + 1
        else:
            return ok entry
    err ApiSetNotFound

func getApiSetNameExtV4(asn: PUNICODE_STRING): NtResult[UNICODE_STRING] =
    var asnNoExt = UNICODE_STRING()

    if asn.Length < sizeOf(API_SET_PREFIX_API_W).USHORT or (not isApiSetLib(asn.Buffer)):
        return err ApiSetNotFound
        
    ## Skip prefix
    asnNoExt.Length         = asn.Length - sizeOf(API_SET_PREFIX_API_W).USHORT
    asnNoExt.MaximumLength  = asnNoExt.Length
    asnNoExt.Buffer         = cast[PWSTR](asn.Buffer +! sizeOf(API_SET_PREFIX_API_W))

    ## lop off the '.DLL'
    if asnNoExt.Length >= sizeOf(API_SET_DLL_EXTENSTION_W).USHORT:
        let extIndex = (asnNoExt.Length.int - sizeOf(API_SET_DLL_EXTENSTION_W)) /% sizeOf(WCHAR)
        if cast[PWCHAR](asnNoExt.Buffer +! extIndex)[] == TEXTW('.'):
            asnNoExt.Length -= sizeOf(API_SET_DLL_EXTENSTION_W).USHORT
    ok asnNoExt

func resolveApiSetV4(apiSet: PAPI_SET_NAMESPACE_ARRAY_V4, apisetName: var UNICODE_STRING): NtResult[void] =
    let 
        asnNoExt    = ? getApiSetNameExtV4(apiSetName)
        nsEntry     = ? searchForApiSetV4(apiSet, asnNoExt.Buffer, USHORT(asnNoExt.Length.int /% sizeOf(WCHAR)))
        vArray      = API_SET_NAMESPACE_ENTRY_DATA_V4(apiSet, nsEntry)
    if vArray.Count == 0:
        return err ApiSetNotFound
    
    let libEntry = addr vArray.Array[0]
    apisetName.Length        = libEntry.ValueLength.USHORT
    apisetName.MaximumLength = apisetName.Length
    apisetName.Buffer        = API_SET_VALUE_ENTRY_VALUE_V4(apiSet, libEntry)
    ok()

## V6
##------------------------------------
template API_SET_NAMESPACE_ENTRY_NAME_V6(apiSet: PAPI_SET_NAMESPACE_V6, entry: PAPI_SET_NAMESPACE_ENTRY_V6): PWSTR =
    cast[PWSTR](apiSet +! entry.NameOffset)

template API_SET_VALUE_ENTRY_VALUE_V6(apiSet: PAPI_SET_NAMESPACE_V6, entry: PAPI_SET_VALUE_ENTRY_V6): PWCHAR =
    cast[PWCHAR](apiSet +! entry.ValueOffset)

template API_SET_NAMESPACE_VALUE_ENTRY_V6(
    apiSet: PAPI_SET_NAMESPACE_V6, 
    entry: PAPI_SET_NAMESPACE_ENTRY_V6,
    index: int
): PAPI_SET_VALUE_ENTRY_V6 =
    cast[PAPI_SET_VALUE_ENTRY_V6](apiSet +! entry.ValueOffset +! (index * sizeOf(API_SET_VALUE_ENTRY_V6)))

template API_SET_NAMESPACE_ENTRY_V6(apiSet: PAPI_SET_NAMESPACE_V6, index: ULONG): PAPI_SET_NAMESPACE_ENTRY_V6 =
    cast[PAPI_SET_NAMESPACE_ENTRY_V6](apiSet +! apiSet.EntryOffset +! (index * sizeOf(API_SET_NAMESPACE_ENTRY_V6)))

template API_SET_HASH_ENTRY_V6(apiSet: PAPI_SET_NAMESPACE_V6, index: int): PAPI_SET_HASH_ENTRY_V6 =
    cast[PAPI_SET_HASH_ENTRY_V6](apiSet +! apiSet.HashOffset +! (index * sizeOf(API_SET_HASH_ENTRY_V6)))

func hashApiSetNameV6(asn: PWSTR, asnLen: USHORT, hf: ULONG): ULONG =
    let wideCArray = cast[ptr UncheckedArray[WCHAR]](asn)
    for i in 0 ..< asnLen.int:
        result = (result * hf) + ULONG(LOWER_CASE(wideCArray[i]))

func findApiSetEntryV6(apiSet: PAPI_SET_NAMESPACE_V6, key: ULONG): NtResult[PAPI_SET_NAMESPACE_ENTRY_V6] =
    var 
        currEntry   = PAPI_SET_HASH_ENTRY_V6(NULL)
        entry       = PAPI_SET_NAMESPACE_ENTRY_V6(NULL)
        index       = LONG(0)
        lowBound    = LONG(0)
        upperBound  = apiSet.Count - 1

    while upperBound >= lowBound:
        index       = (lowBound + upperBound) shr 1
        currEntry   = API_SET_HASH_ENTRY_V6(apiSet, index)
        if key <% currEntry.Hash:
            upperBound = index - 1'i32
        elif key >% currEntry.Hash:
            lowBound = index + 1'i32
        else:
            entry = API_SET_NAMESPACE_ENTRY_V6(apiSet, currEntry.Index)
            break

    if upperBound < lowBound:
        err ApiSetNotFound
    else:
        ok entry

func searchForApiSetV6(apiSet: PAPI_SET_NAMESPACE_V6, asn: PWSTR, asnLen: USHORT) : NtResult[PAPI_SET_NAMESPACE_ENTRY_V6] =
    let 
        hashKey = hashApiSetNameV6(asn, asnLen, apiSet.HashFactor)
        nsEntry = ? findApiSetEntryV6(apiSet, hashKey)
    if cmpMem(asn, API_SET_NAMESPACE_ENTRY_NAME_V6(apiSet, nsEntry), asnLen) == 0:
        ok nsEntry
    else:
        err ApiSetNotFound

func searchForApiSetHostV6(
    apiSet: PAPI_SET_NAMESPACE_V6, 
    nsEntry: PAPI_SET_NAMESPACE_ENTRY_V6, 
    parent: PWSTR,
    parentLen: USHORT
): NtResult[PAPI_SET_VALUE_ENTRY_V6] =
    var 
        vEntry      = API_SET_NAMESPACE_VALUE_ENTRY_V6(apiSet, nsEntry, 0)
        upperBound  = nsEntry.ValueCount - 1
        lowerBound  = 1'i32
        index       = 0'i32
        cmp         = 0'i32

    if upperBound == 0:
        return ok vEntry
    
    while lowerBound <= upperBound:
        index   = (lowerBound + upperBound) shr 1
        vEntry  = API_SET_NAMESPACE_VALUE_ENTRY_V6(apiSet, nsEntry, index)
        cmp = cmpUnicodeStrings(
            parent, 
            parentLen.SIZE_T, 
            API_SET_VALUE_ENTRY_VALUE_V6(apiSet, vEntry), 
            SIZE_T(vEntry.NameLength /% sizeOf(WCHAR)),
            true
        )

        if cmp < 0:
            upperBound = index - 1
        elif cmp > 0:
            lowerBound = index + 1
        else:
            return ok vEntry
    
    ok API_SET_NAMESPACE_VALUE_ENTRY_V6(apiSet, nsEntry, 0)

func getApiSetNameExtLengthV6(asn: UNICODE_STRING): NtResult[USHORT] =
    if asn.Length < sizeOf(API_SET_PREFIX_API_W).USHORT or not isApiSetLib(asn.Buffer):
        return err ApiSetNotFound
    var 
        buflen  = asn.Length.int
        pwchar  = cast[PWCHAR](asn.Buffer +! buflen)
    
    ## Remove everything after the last hyphen
    while pwchar[] != TEXTW('-'):
        if buflen <= 1:
            break
        buflen -= sizeOf(WCHAR)
        dec pwchar

    let noExtLength = USHORT(bufLen /% sizeOf(WCHAR))    
    if noExtLength == 0:
        err ApiSetNotFound
    else:
        ok noExtLength

func resolveApiSetV6(apiSet: PAPI_SET_NAMESPACE_V6, apiSetName: var UNICODE_STRING, parent: PUNICODE_STRING): NtResult[void] =
    let 
        asnLen  = ? getApiSetNameExtLengthV6(apiSetName)
        nsEntry = ? searchForApiSetV6(apiSet, apiSetName.Buffer, asnLen)
        vEntry = 
            if nsEntry.ValueCount > 1 and (not parent.isNil()):
                ? searchForApiSetHostV6(apiSet, nsEntry, parent.Buffer, parent.Length)
            elif nsEntry.ValueCount > 0:
                API_SET_NAMESPACE_VALUE_ENTRY_V6(apiSet, nsEntry, 0)
            else:
                return err ApiSetNotFound
    copyToBuffer(apiSetName, API_SET_VALUE_ENTRY_VALUE_V6(apiSet, vEntry), USHORT(vEntry.ValueLength))
    ok()

## Public
##------------------------------------------------------------------------
func resolveApiSet*(apiSetName: var UNICODE_STRING, parent: PUNICODE_STRING = NULL): NtResult[void] =
    let apiset  = GetApiSet()    
    if apiset.Version == API_SET_SCHEMA_VERSION_V3:
        resolveApiSetV3(apiset, apiSetName)
    
    elif apiset.Version == API_SET_SCHEMA_VERSION_V4:
        resolveApiSetV4(cast[PAPI_SET_NAMESPACE_ARRAY_V4](apiset), apiSetName)

    elif apiset.Version == API_SET_SCHEMA_VERSION_V6:
        resolveApiSetV6(cast[PAPI_SET_NAMESPACE_V6](apiset), apiSetName, parent)

    else:
        err ApiSetSchemaNotSupported


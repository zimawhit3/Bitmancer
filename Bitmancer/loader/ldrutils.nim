

import
    ldrbase

export
    ldrbase

## TODO: Should prbably move these elsewhere...

proc ldrPrepareForwardString*(): NtResult[UNICODE_STRING] =
    var fs = ? new UNICODE_STRING
    fs.addDrivePrefixU()
    fs.addSystem32DirectoryU()
    ok fs

proc ldrResolveApiSet*(apiSetName: cstring): NtResult[UNICODE_STRING] =
    var asn = ? new UNICODE_STRING
    asn.add apiSetName
    ? resolveApiSet(asn, NULL)
    ok asn

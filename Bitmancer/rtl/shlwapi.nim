

import
    ../core
export
    core

func cPathFindFileNameW*(path: LPCWSTR): NtResult[LPCWSTR] =
    if not path.isNil():
        var 
            tmp = cast[ptr UncheckedArray[WCHAR]](path)
            i   = 0
        result = ok path
        while tmp[i] != 0:
            if (tmp[i] == TEXTW('\\') or tmp[i] == TEXTW(':') or tmp[i] == TEXTW('/')) and (tmp[i+1] != 0) and 
                (tmp[i+1] != TEXTW('\\')) and (tmp[i+1] != TEXTW('/')):
                result = ok cast[LPCWSTR](addr tmp[i+1])
            if (tmp[i] == TEXTW('\\') and tmp[i+1] == 0):
                return ok path
            inc i     
    else:
        result = err InvalidBuffer

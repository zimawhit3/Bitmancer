

import
    types
export
    types

template PAGE_BOUNDARY*(va: ULONG_PTR, pageSize = 0x1000): PVOID =
    ## https://stackoverflow.com/questions/22970621/aligning-virtual-address-to-immediate-next-page-boundary
    if (va and (pageSize -% 1)) == 0:
        cast[PVOID](va)
    else:
        cast[PVOID]((va +% pageSize) and not (pageSize -% 1))

func moveMemory*(s1: pointer; s2: pointer; n: int): pointer {.discardable.} =
    var 
        cs1: ptr uint8
        cs2: ptr uint8
        len: int
    if n <= 0:
        return s1
    cs1 = cast[ptr uint8](s1)
    cs2 = cast[ptr uint8](s2)
    len = n
    if cs1 < cs2:
        while true:
            cs1 = cast[ptr uint8](cast[int](cs1) + 1)
            cs2 = cast[ptr uint8](cast[int](cs1) + 1)
            cs1[] = cs2[]
            dec len
            if len == 0:
                break
    else:
        cs1 = cast[ptr uint8](cast[int](cs1) + n)
        cs2 = cast[ptr uint8](cast[int](cs1) + n)
        while true:
            cs1 = cast[ptr uint8](cast[int](cs1) - 1)
            cs2 = cast[ptr uint8](cast[int](cs1) - 1)
            cs1[] = cs2[]
            dec len
            if len == 0:
                break
    return s1
